//! Whether a `users` list actually governs the inbound it was given to.
//!
//! The engine's promise for a dynamic inbound is narrow and absolute: the registry is
//! that inbound's *sole* credential authority. Two things can quietly break it, and
//! both look like success from the caller's side.
//!
//! - **A target the list does not reach.** One inbound is a tree, and a `users` list
//!   is accepted on the strength of any one target consulting the registry. A sibling
//!   target with no credential of its own then admits everybody, on an inbound the API
//!   reports as having users.
//! - **A protocol swapped underneath the list.** A reload rebuilds the handlers from a
//!   new config while keeping the registry, so an update can replace the protocol that
//!   was consulting it with one that does not.
//!
//! The second is the sharper of the two: it turns an inbound that was authenticating
//! into one that is not, at runtime, through an ordinary control-plane call -- and the
//! reported protocol and user count both keep describing what it used to be.

mod common;

use common::*;
use serde_json::json;
use shoes_engine::{InboundSpec, UserSpec};

const ALICE: &str = "11111111-1111-4111-8111-111111111111";

fn user(id: &str, uuid: &str) -> UserSpec {
    UserSpec {
        id: Some(id.to_string()),
        uuid: Some(uuid.to_string()),
        password: None,
        enabled: true,
        max_conns: None,
        upload_limit_bps: None,
        download_limit_bps: None,
    }
}

/// A TLS inbound with a VLESS target and one more, keyed by SNI.
fn two_targets(address: std::net::SocketAddr, other: serde_json::Value) -> serde_json::Value {
    json!({
        "address": address.to_string(),
        "protocol": {
            "type": "tls",
            "tls_targets": {
                "vless.example.com": {
                    "cert": test_cert(),
                    "key": test_key(),
                    "protocol": {"type": "vless"},
                },
                "other.example.com": {
                    "cert": test_cert(),
                    "key": test_key(),
                    "protocol": other,
                },
            },
        },
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_list_governs_every_target_it_is_given_to() {
    let mut checks = Checks::new("user lists govern the whole inbound");
    let engine = engine().await;

    // -- 1. a sibling target with no credential of its own ----------------------
    //
    // `credential_kinds` is non-empty because of the VLESS half, which is what used
    // to let these through. Each of these targets would then serve every client that
    // reached its SNI, on an inbound reporting `users: Some(1)`.
    checks.section("1. targets that authenticate nobody");
    for (label, target) in [
        ("socks with no credential", json!({"type": "socks"})),
        ("http with no credential", json!({"type": "http"})),
        ("mixed with no credential", json!({"type": "mixed"})),
        (
            "port-forward, which has no notion of a user",
            json!({"type": "portforward", "targets": ["127.0.0.1:9"]}),
        ),
    ] {
        checks.refused(
            label,
            engine
                .add_inbound(InboundSpec {
                    tag: format!("open-{label}"),
                    config: two_targets(free_addr(), target),
                    users: Some(vec![user("alice", ALICE)]),
                })
                .await,
            "users",
        );
    }

    // -- 2. but a credential of its own is not the same as no credential --------
    //
    // The rule is about targets that admit *everyone*, not about mixing protocols.
    // A socks target with a password authenticates -- just not per-user -- and
    // refusing it would break a legitimate config for no gain.
    checks.section("2. a sibling target that does authenticate");
    checks.that(
        "socks with a username and password is allowed alongside vless",
        engine
            .add_inbound(InboundSpec {
                tag: "socks-auth".into(),
                config: two_targets(
                    free_addr(),
                    json!({"type": "socks", "username": "u", "password": "p"}),
                ),
                users: Some(vec![user("alice", ALICE)]),
            })
            .await
            .is_ok(),
    );
    checks.that(
        "and so is snell, whose password is mandatory",
        engine
            .add_inbound(InboundSpec {
                tag: "snell".into(),
                config: two_targets(
                    free_addr(),
                    json!({"type": "snell", "cipher": "aes-128-gcm", "password": "p"}),
                ),
                users: Some(vec![user("alice", ALICE)]),
            })
            .await
            .is_ok(),
    );

    checks.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reload_cannot_swap_the_protocol_out_from_under_the_users() {
    let mut checks = Checks::new("reload keeps the credential shape");
    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let addr = free_addr();
    engine
        .add_inbound(InboundSpec {
            tag: "t".into(),
            config: vless_inbound(addr, true),
            users: Some(vec![user("alice", ALICE)]),
        })
        .await
        .expect("a dynamic vless inbound should start");

    // -- 1. the swap that turns authentication off ------------------------------
    //
    // This is the one that matters. SOCKS with no credential consults nothing, so
    // before this was refused the inbound became an open proxy on a live port while
    // `list_inbounds` went on reporting a VLESS inbound with one user.
    checks.section("1. swapping to a protocol that authenticates nobody");
    checks.refused(
        "vless -> socks is refused",
        engine
            .update_inbound(InboundSpec {
                tag: "t".into(),
                config: json!({
                    "address": addr.to_string(),
                    "protocol": {"type": "socks"},
                }),
                users: None,
            })
            .await,
        "users",
    );
    checks.that(
        "so an unauthenticated client still cannot get through",
        denied(addr, sink.address).await,
    );

    // -- 2. the swap that turns it off for everyone already registered ----------
    //
    // Fails closed rather than open, and is just as invisible: every user holds a
    // uuid and a trojan handler will never ask for one, so the inbound would report
    // one happy user who cannot connect.
    checks.section("2. swapping to a different credential shape");
    checks.refused(
        "vless -> trojan is refused",
        engine
            .update_inbound(InboundSpec {
                tag: "t".into(),
                config: json!({
                    "address": addr.to_string(),
                    "protocol": {"type": "trojan"},
                }),
                users: None,
            })
            .await,
        "authenticates with",
    );

    // -- 3. the swap that is genuinely fine ------------------------------------
    //
    // VMess reads the same 16-byte uuid VLESS does, so alice's credential still
    // means alice. Allowing it is the point of stating the rule as "the credential
    // shape may not change" rather than "the protocol may not change".
    checks.section("3. a protocol with the same credential shape");
    let updated = engine
        .update_inbound(InboundSpec {
            tag: "t".into(),
            config: vmess_inbound(addr, true),
            users: None,
        })
        .await;
    checks.that("vless -> vmess is allowed", updated.is_ok());
    checks.eq(
        "and the report follows the swap rather than naming what it used to be",
        updated.map(|i| i.protocol).unwrap_or_default(),
        "Vmess".to_string(),
    );
    checks.eq(
        "the users survive it",
        engine.list_users("t").map(|u| u.len()).unwrap_or(0),
        1,
    );

    // Alice's uuid still authenticates, now over VMess -- the same record, so her
    // counters carried across too.
    let leg = start_leg(&engine, "leg", vmess_chain(addr, ALICE, "any")).await;
    checks.eq(
        "and alice reaches the sink under the new protocol",
        reach(leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );

    checks.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_classic_inbound_still_reports_what_it_became() {
    let mut checks = Checks::new("classic reload reporting");
    let engine = engine().await;

    // No registry, so none of the rules above apply -- a classic inbound may become
    // whatever its config says. What it may not do is keep reporting the protocol it
    // was created as.
    let addr = free_addr();
    engine
        .add_inbound(classic(
            "c",
            json!({"address": addr.to_string(), "protocol": {"type": "socks"}}),
        ))
        .await
        .expect("a classic socks inbound should start");

    let updated = engine
        .update_inbound(InboundSpec {
            tag: "c".into(),
            config: json!({
                "address": addr.to_string(),
                "protocol": {"type": "http", "username": "u", "password": "p"},
            }),
            users: None,
        })
        .await;
    checks.that("the swap is allowed", updated.is_ok());
    checks.eq(
        "and the report names the protocol now serving",
        updated.map(|i| i.protocol).unwrap_or_default(),
        "HTTP".to_string(),
    );
    checks.eq(
        "listing agrees with the call that made the change",
        engine
            .list_inbounds()
            .into_iter()
            .find(|i| i.tag == "c")
            .map(|i| i.protocol)
            .unwrap_or_default(),
        "HTTP".to_string(),
    );

    checks.finish();
}
