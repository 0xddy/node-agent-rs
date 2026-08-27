//! Phase 4 acceptance: RCU config reloads, and Phase 1's smooth handover.
//!
//! The property: **a config swap changes where new connections go and leaves
//! established ones exactly as they were.** Not "mostly", and not "after a drain" --
//! a connection reads its handler once, when it is accepted, so it is pinned to the
//! generation it started on and a later swap is not something it can observe.
//!
//! # How a swap is made visible
//!
//! Sections 3 and 4 are the decisive pair. A rule with `override_address` sends every
//! connection to a fixed destination regardless of what the client asked for, so
//! *which sink answers* names the generation of rules the connection is running
//! under. One connection is opened before the swap and finished after it; another is
//! opened after. They must answer differently, and the fact that they do is the whole
//! claim.

mod common;

use std::time::Duration;

use common::*;
use serde_json::json;
use shoes_engine::{EngineError, InboundSpec};
use tokio::io::AsyncWriteExt;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";

#[tokio::test(flavor = "multi_thread")]
async fn config_swaps_are_forward_looking() {
    let mut checks = Checks::new("rcu reload");

    let engine = engine().await;
    let sink_a = Sink::start("A").await;
    let sink_b = Sink::start("B").await;
    let echo = UdpEcho::start().await;
    // Nothing listens here. It is what the client asks for once the rules override
    // the destination, so a connection that succeeds can only have been redirected.
    let nowhere = free_addr();

    let vless = free_addr();
    engine
        .add_inbound(dynamic(
            "vless",
            vless_inbound_with_rules(vless, true, allow_all()),
        ))
        .await
        .expect("the inbound should start");
    engine.add_user("vless", user("alice", ALICE)).unwrap();
    let leg = start_leg(&engine, "leg", vless_chain(vless, ALICE)).await;

    // -- 1. baseline ----------------------------------------------------------
    checks.section("1. baseline");
    checks.eq(
        "alice reaches the sink she asked for",
        reach(leg, sink_a.address).await.ok(),
        Some("A".to_string()),
    );
    checks.that(
        "udp works",
        udp_roundtrip(leg, echo.address, Duration::from_secs(3)).await,
    );
    let first = info(&engine, "vless");
    checks.eq("one listener group is running", first.listeners, 1);
    checks.eq(
        "it is bound where it was asked to be",
        first.bind.clone(),
        vec![vless.to_string()],
    );

    // -- 2. a reload carries the registry over -------------------------------
    //
    // The users are not part of the config, so a config swap must not be able to
    // lose them -- including their counters, which an embedder may be billing on.
    checks.section("2. users survive a reload");
    transfer(leg, sink_a.address, 4096, 4096)
        .await
        .expect("move some bytes so the counters are non-zero");
    let before = quiet(&engine, "vless", "alice").await;
    checks.that("alice has counted traffic", before.rx > 0 && before.tx > 0);

    let reloaded = engine
        .update_inbound(classic(
            "vless",
            vless_inbound_with_rules(vless, true, allow_all()),
        ))
        .await;
    if let Err(EngineError::ReloadRequired(message)) = reloaded {
        checks.that(
            "a logical-flow protocol requests physical listener replacement",
            message.contains("logical flows"),
        );
        let after = quiet(&engine, "vless", "alice").await;
        checks.eq(
            "refusing the in-place reload preserves user counters",
            (after.tx, after.rx, after.total_conns),
            (before.tx, before.rx, before.total_conns),
        );
        checks.that(
            "the original generation remains usable",
            reach(leg, sink_a.address).await.is_ok(),
        );
        checks.finish();
        return;
    }
    let reloaded = reloaded.expect("an unexpected reload error should fail the test");
    checks.detail(
        "the revision advanced",
        reloaded.revision > first.revision,
        format!("{} -> {}", first.revision, reloaded.revision),
    );
    checks.eq("the user is still registered", reloaded.users, Some(1));

    let after = quiet(&engine, "vless", "alice").await;
    checks.eq(
        "and her counters came through untouched",
        (after.tx, after.rx, after.total_conns),
        (before.tx, before.rx, before.total_conns),
    );
    checks.that(
        "alice still authenticates after the swap",
        reach(leg, sink_a.address).await.is_ok(),
    );

    // -- 3. open a connection, then swap the rules under it -------------------
    checks.section("3. swap the rules under a live connection");
    let mut held = Socks::connect(leg, sink_a.address)
        .await
        .expect("open a connection to hold across the swap");
    held.write_all(b"wh").await.expect("send half a request");
    // Let the first half reach sink A, so the connection is genuinely established
    // end to end rather than merely accepted at the socks leg.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let redirected = engine
        .update_inbound(classic(
            "vless",
            vless_inbound_with_rules(vless, true, redirect_to(sink_b.address)),
        ))
        .await
        .expect("swapping in an override rule should be accepted");

    // -- 4. the decisive pair -------------------------------------------------
    checks.section("4. new rules for new connections only");
    checks.eq(
        "a new connection is redirected to B, though it asked for nowhere",
        reach(leg, nowhere).await.ok(),
        Some("B".to_string()),
    );

    held.write_all(b"o\n")
        .await
        .expect("finish the held request");
    checks.eq(
        "the connection held across the swap still answers A",
        read_line(&mut held).await.ok(),
        Some("A".to_string()),
    );
    drop(held);

    // -- 5. nothing rebound -------------------------------------------------
    //
    // A swap that quietly closed and reopened the socket would pass section 4 by
    // accident, so the listener identity is worth asserting separately.
    checks.section("5. the listener was not replaced");
    checks.detail(
        "the revision advanced again",
        redirected.revision > reloaded.revision,
        format!("{} -> {}", reloaded.revision, redirected.revision),
    );
    checks.eq(
        "the listener count is unchanged",
        redirected.listeners,
        first.listeners,
    );
    checks.eq(
        "the bind set is unchanged",
        redirected.bind.clone(),
        first.bind.clone(),
    );
    checks.eq(
        "the address is still claimed exactly once",
        engine
            .status()
            .bound_addresses
            .iter()
            // A claim names the socket, not just the address: `:443` over TCP and
            // `:443` over QUIC are two of them.
            .filter(|a| a.starts_with(&vless.to_string()))
            .count(),
        1,
    );

    // -- 6. protocol settings swap, not just routing -------------------------
    //
    // `udp_enabled` lives in the protocol handler rather than in the rules, so it
    // exercises a different part of the rebuilt tree than section 4 does.
    checks.section("6. protocol settings swap too");
    engine
        .update_inbound(classic(
            "vless",
            vless_inbound_with_rules(vless, false, allow_all()),
        ))
        .await
        .expect("disabling udp should be accepted");
    checks.that(
        "udp is refused once disabled",
        !udp_roundtrip(leg, echo.address, Duration::from_secs(2)).await,
    );
    checks.that(
        "tcp is unaffected",
        reach(leg, sink_a.address).await.is_ok(),
    );

    engine
        .update_inbound(classic(
            "vless",
            vless_inbound_with_rules(vless, true, allow_all()),
        ))
        .await
        .expect("re-enabling udp should be accepted");
    checks.that(
        "udp works again once re-enabled",
        udp_roundtrip(leg, echo.address, Duration::from_secs(3)).await,
    );

    // -- 7. what a reload refuses -------------------------------------------
    //
    // Every refusal here is a change that cannot be rolled back if it half-succeeds:
    // rebinding a socket, or reconciling a whole user list against a live registry.
    // Refusing is the honest answer, and the message has to name the way out.
    checks.section("7. refusals");
    let steady = info(&engine, "vless");

    checks.refused(
        "reloading an unknown tag",
        engine
            .update_inbound(classic("nope", vless_inbound(vless, true)))
            .await,
        "no such inbound tag",
    );
    checks.refused(
        "a reload carrying a user list",
        engine
            .update_inbound(InboundSpec {
                tag: "vless".into(),
                config: vless_inbound(vless, true),
                users: Some(vec![user("alice", ALICE)]),
            })
            .await,
        "cannot carry users",
    );
    checks.refused(
        "moving the listen address in place",
        engine
            .update_inbound(classic("vless", vless_inbound(free_addr(), true)))
            .await,
        "cannot change the listen set in place",
    );
    checks.refused(
        "a config that does not parse",
        engine
            .update_inbound(classic("vless", json!({"address": vless.to_string()})))
            .await,
        "invalid inbound config",
    );
    checks.refused(
        "adding a second inbound on a claimed address",
        engine
            .add_inbound(dynamic("other", vless_inbound(vless, true)))
            .await,
        "is already used by inbound vless",
    );
    checks.refused(
        "reusing a tag",
        engine
            .add_inbound(dynamic("vless", vless_inbound(free_addr(), true)))
            .await,
        "inbound tag already registered",
    );

    let still = info(&engine, "vless");
    checks.eq(
        "no refusal changed the running inbound",
        (still.revision, still.listeners, still.bind.clone()),
        (steady.revision, steady.listeners, steady.bind.clone()),
    );
    checks.that(
        "and it still carries traffic",
        reach(leg, sink_a.address).await.is_ok(),
    );

    // -- 8. removal frees the port at once, and spares the connections -------
    //
    // This is Phase 1's handover property. `remove_inbound` awaits the listener
    // letting go of its socket, which is what makes the address immediately
    // re-usable; the connections it already accepted are not its to close.
    checks.section("8. removal");
    let mut surviving = Socks::connect(leg, sink_a.address)
        .await
        .expect("open a connection to hold across the removal");
    surviving
        .write_all(b"wh")
        .await
        .expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    engine
        .remove_inbound("vless")
        .await
        .expect("the inbound should be removable");
    checks.that("the tag is gone", engine.get_inbound("vless").is_none());
    checks.that(
        "the address is no longer claimed",
        !engine.status().bound_addresses.contains(&vless.to_string()),
    );

    // Binding the same address again is the test that the socket was really released
    // rather than merely forgotten.
    engine
        .add_inbound(dynamic(
            "vless",
            vless_inbound_with_rules(vless, true, redirect_to(sink_b.address)),
        ))
        .await
        .expect("the freed address should be immediately re-bindable");
    engine.add_user("vless", user("alice", ALICE)).unwrap();

    surviving
        .write_all(b"o\n")
        .await
        .expect("finish the request held across the removal");
    checks.eq(
        "the connection held across the removal still answers A",
        read_line(&mut surviving).await.ok(),
        Some("A".to_string()),
    );
    drop(surviving);

    checks.eq(
        "and the replacement inbound serves the new rules",
        reach(leg, nowhere).await.ok(),
        Some("B".to_string()),
    );

    // -- 9. the engine's own view is consistent ------------------------------
    checks.section("9. final state");
    let status = engine.status();
    checks.eq("every inbound is accounted for", status.inbounds, 2);
    checks.eq(
        "the tags are the ones we added",
        engine
            .list_inbounds()
            .iter()
            .map(|i| i.tag.clone())
            .collect::<Vec<_>>(),
        vec!["leg".to_string(), "vless".to_string()],
    );
    checks.eq(
        "the replacement inbound's registry starts fresh",
        engine.list_users("vless").map(|u| u.len()).unwrap_or(0),
        1,
    );

    checks.finish();
}

/// QUIC-native selectors are not all safe to swap just because the physical
/// listener remains unchanged. A TUIC connection can open new TCP and UDP logical
/// flows for its whole lifetime, so swapping only the selector would let a retired
/// connection continue admitting work under the old rules. The embedding runtime
/// handles this explicit signal by hard-replacing the inbound.
#[tokio::test(flavor = "multi_thread")]
async fn tuic_rules_only_update_requires_replacement() {
    let engine = engine().await;
    let address = free_addr();
    engine
        .add_inbound(dynamic(
            "tuic",
            tuic_inbound_with_rules(address, allow_all()),
        ))
        .await
        .expect("the TUIC inbound should start");

    let result = engine
        .update_inbound(classic(
            "tuic",
            tuic_inbound_with_rules(address, redirect_to(free_addr())),
        ))
        .await;
    assert!(
        matches!(
            &result,
            Err(EngineError::ReloadRequired(message))
                if message.contains("logical flows") && message.contains("replace the inbound")
        ),
        "a TUIC rules update must request hard replacement, got {result:?}"
    );
    assert_eq!(info(&engine, "tuic").revision, 0);
}

/// Hysteria2 gains the same long-lived logical-flow lifetime when UDP is enabled:
/// one authenticated QUIC association may create destinations after a rules swap.
#[tokio::test(flavor = "multi_thread")]
async fn udp_enabled_hysteria2_rules_update_requires_replacement() {
    let engine = engine().await;
    let address = free_addr();
    let mut initial = hysteria2_inbound(address, true);
    initial["rules"] = allow_all();
    engine
        .add_inbound(dynamic("hysteria2", initial))
        .await
        .expect("the Hysteria2 inbound should start");

    let mut updated = hysteria2_inbound(address, true);
    updated["rules"] = redirect_to(free_addr());
    let result = engine.update_inbound(classic("hysteria2", updated)).await;
    assert!(
        matches!(
            &result,
            Err(EngineError::ReloadRequired(message))
                if message.contains("logical flows") && message.contains("replace the inbound")
        ),
        "a UDP-enabled Hysteria2 rules update must request hard replacement, got {result:?}"
    );
    assert_eq!(info(&engine, "hysteria2").revision, 0);
}

/// With UDP disabled, each Hysteria2 TCP request is pinned to the selector loaded
/// for that request. There is no long-lived UDP association that can create later
/// destinations, so a rules-only RCU update remains safe.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_only_hysteria2_rules_update_remains_rcu_safe() {
    let engine = engine().await;
    let address = free_addr();
    let mut initial = hysteria2_inbound(address, false);
    initial["rules"] = allow_all();
    engine
        .add_inbound(dynamic("hysteria2", initial))
        .await
        .expect("the Hysteria2 inbound should start");
    let before = info(&engine, "hysteria2");

    let mut updated = hysteria2_inbound(address, false);
    updated["rules"] = redirect_to(free_addr());
    let after = engine
        .update_inbound(classic("hysteria2", updated))
        .await
        .expect("TCP-only Hysteria2 should accept a rules-only RCU update");

    assert!(after.revision > before.revision);
    assert_eq!(after.listeners, before.listeners);
    assert_eq!(after.bind, before.bind);
}

#[tokio::test(flavor = "multi_thread")]
async fn path_backed_certificates_still_reload_after_lock_free_preparation() {
    let engine = engine().await;
    let address = free_addr();
    let fixture = |name: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
            .to_string_lossy()
            .into_owned()
    };
    let mut config = hysteria2_inbound(address, false);
    config["quic_settings"]["cert"] = json!(fixture("test.crt"));
    config["quic_settings"]["key"] = json!(fixture("test.key"));

    engine
        .add_inbound(dynamic("path-backed-quic", config.clone()))
        .await
        .expect("file-backed certificate and key should start the inbound");
    let before = info(&engine, "path-backed-quic");
    let after = engine
        .update_inbound(classic("path-backed-quic", config))
        .await
        .expect("file-backed certificate validation should feed the ordinary reload path");

    assert!(after.revision > before.revision);
    assert_eq!(after.listeners, before.listeners);
    assert_eq!(after.bind, before.bind);
}

/// A reload rebuilds handlers. Everything below a handler therefore cannot change,
/// and the only honest answer to a config that changes one is to refuse it.
///
/// Reporting success instead is worse than it sounds. The caller's next act after
/// rotating a certificate is to stop worrying about the old one -- so a swap that
/// returns `Ok` while the endpoint goes on presenting the previous cert is a
/// rotation that never happened and nothing says so.
#[tokio::test(flavor = "multi_thread")]
async fn listener_settings_are_refused_rather_than_ignored() {
    let mut checks = Checks::new("listener-fixed settings");
    let engine = engine().await;

    // -- 1. tcp: the accept loop reads `tcp_settings` once, before it starts ----
    checks.section("1. tcp_settings");
    let tcp = free_addr();
    let with_no_delay = |value: bool| {
        json!({
            "address": tcp.to_string(),
            "protocol": {"type": "socks", "udp_enabled": false},
            "tcp_settings": {"no_delay": value},
            "rules": allow_all(),
        })
    };
    engine
        .add_inbound(classic("tcp", with_no_delay(true)))
        .await
        .expect("the inbound should start");

    checks.refused(
        "turning no_delay off is refused",
        engine
            .update_inbound(classic("tcp", with_no_delay(false)))
            .await,
        "tcp_settings.no_delay",
    );
    checks.that(
        "an otherwise identical config still reloads",
        engine
            .update_inbound(classic("tcp", with_no_delay(true)))
            .await
            .is_ok(),
    );
    // Omitting the section entirely must compare equal to writing its default,
    // or every caller who leaves it out would be told they changed something.
    checks.that(
        "and so does one that omits the section, since its default matches",
        engine
            .update_inbound(classic(
                "tcp",
                json!({
                    "address": tcp.to_string(),
                    "protocol": {"type": "socks", "udp_enabled": false},
                    "rules": allow_all(),
                }),
            ))
            .await
            .is_ok(),
    );

    // -- 2. quic: the endpoint owns the certificate, not the handler ------------
    // TCP-only Hysteria2 is intentionally used here so the fixed-listener field
    // comparison is reached; its UDP-enabled form requires hard replacement even
    // for a rules-only update and is covered above.
    checks.section("2. quic_settings");
    let quic = free_addr();
    engine
        .add_inbound(dynamic("quic", hysteria2_inbound(quic, false)))
        .await
        .expect("the quic inbound should start");

    let mut different_alpn = hysteria2_inbound(quic, false);
    different_alpn["quic_settings"]["alpn_protocols"] = json!(["h3", "something-else"]);
    checks.refused(
        "changing the alpn list is refused",
        engine.update_inbound(classic("quic", different_alpn)).await,
        "quic_settings.alpn_protocols",
    );

    let mut different_cert = hysteria2_inbound(quic, false);
    different_cert["quic_settings"]["cert"] = json!(format!("{}\n", test_cert()));
    checks.refused(
        "and so is rotating the certificate, which is the one that matters",
        engine.update_inbound(classic("quic", different_cert)).await,
        "quic_settings.cert",
    );

    checks.that(
        "the unchanged config still reloads, so rules remain swappable",
        engine
            .update_inbound(classic("quic", hysteria2_inbound(quic, false)))
            .await
            .is_ok(),
    );

    checks.finish();
}
