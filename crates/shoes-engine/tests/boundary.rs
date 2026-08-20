//! Boundary cases the earlier phases quietly depend on.
//!
//! None of these move bytes. They are about the seams -- places where the dynamic
//! layer and shoes' own config schema meet and could plausibly disagree without
//! anything looking wrong.

mod common;

use common::*;
use serde_json::json;
use shoes_engine::InboundSpec;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";

#[tokio::test(flavor = "multi_thread")]
async fn boundary_cases() {
    let mut checks = Checks::new("boundaries");
    let engine = engine().await;

    // -- A. a nested protocol is still named in the report ---------------------
    //
    // The protocol an inbound reports comes from walking the config to whatever
    // actually terminates the connection. A TLS inbound that carries everything in
    // `default_target` has nothing at the top level to name, and an earlier version
    // reported an empty string for it -- true of the top-level object, useless to a
    // caller listing inbounds.
    checks.section("A. a nested protocol is reported");
    let tls = free_addr();
    let info = engine
        .add_inbound(dynamic("tls", tls_vless_inbound(tls)))
        .await
        .expect("a default-target-only tls inbound should start");
    checks.eq(
        "the protocol is named",
        info.protocol.clone(),
        "TLS".to_string(),
    );
    checks.that("the protocol is not blank", !info.protocol.is_empty());
    checks.eq("it is in dynamic mode", info.users, Some(0));

    // -- B. the placeholder pass must not touch client credentials -------------
    //
    // Dynamic mode fills in the *server* credential shoes' schema demands but the
    // registry overrules. An outbound's credential in the same config is a real
    // credential belonging to a real upstream, and overwriting it would break the
    // chain in a way nothing would report.
    checks.section("B. outbound credentials are left alone");
    let upstream = free_addr();
    let chained = free_addr();
    let result = engine
        .add_inbound(dynamic(
            "chained",
            json!({
                "address": chained.to_string(),
                "protocol": {"type": "vless", "udp_enabled": true},
                "rules": [{
                    "masks": "0.0.0.0/0",
                    "action": "allow",
                    "client_chain": vless_chain(upstream, BOB),
                }],
            }),
        ))
        .await;
    checks.that(
        "a dynamic inbound may chain onward to an authenticated outbound",
        result.is_ok(),
    );

    // -- C. a server credential beside `users` is a contradiction --------------
    //
    // Accepting it would mean silently discarding whichever of the two the caller
    // meant, so it is refused rather than resolved.
    checks.section("C. a config credential beside a user list");
    checks.refused(
        "a top-level credential is refused in dynamic mode",
        engine
            .add_inbound(dynamic(
                "conflict",
                json!({
                    "address": free_addr().to_string(),
                    "protocol": {"type": "vless", "user_id": ALICE},
                }),
            ))
            .await,
        "remove `user_id`",
    );

    // -- D. and the same at depth ---------------------------------------------
    //
    // The check has to walk, not glance at the top level -- a credential hidden under
    // a TLS target is exactly as contradictory and considerably easier to miss.
    checks.section("D. a nested config credential");
    checks.refused(
        "a credential under a tls target is refused too",
        engine
            .add_inbound(dynamic(
                "conflict-deep",
                json!({
                    "address": free_addr().to_string(),
                    "protocol": {
                        "type": "tls",
                        "default_target": {
                            "cert": test_cert(),
                            "key": test_key(),
                            "protocol": {"type": "vless", "user_id": ALICE},
                        },
                    },
                }),
            ))
            .await,
        "remove `user_id`",
    );

    // -- E. classic mode is untouched -----------------------------------------
    //
    // The whole point of the micro-injection is that an inbound with no `users` field
    // behaves exactly as upstream shoes does: its config credential is the authority
    // and no registry is attached. If that stopped holding, every existing config
    // would be affected by a feature it never asked for.
    checks.section("E. classic mode");
    let classic_addr = free_addr();
    let classic_info = engine
        .add_inbound(classic(
            "classic",
            json!({
                "address": classic_addr.to_string(),
                "protocol": {"type": "vless", "user_id": ALICE, "udp_enabled": true},
            }),
        ))
        .await
        .expect("a classic inbound with its own credential should start");
    checks.eq("no registry is attached", classic_info.users, None);
    checks.that(
        "so it has no user list to read",
        engine.list_users("classic").is_err(),
    );
    checks.refused(
        "and users cannot be added to it",
        engine.add_user("classic", user("alice", ALICE)),
        "was created without a `users` list",
    );

    // A classic inbound's credential is still the authority: alice's uuid is the one
    // in the config, so she connects, and nobody else does.
    let sink = Sink::start("sink").await;
    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(classic_addr, ALICE)).await;
    let bob_leg = start_leg(&engine, "leg-bob", vless_chain(classic_addr, BOB)).await;
    checks.eq(
        "the config credential authenticates",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that("and nothing else does", denied(bob_leg, sink.address).await);

    // -- F. an empty user list is not the same as no user list ----------------
    checks.section("F. empty versus absent");
    checks.eq(
        "`users: []` means dynamic mode with nobody in it",
        engine
            .add_inbound(InboundSpec {
                tag: "empty".into(),
                config: vless_inbound(free_addr(), true),
                users: Some(vec![]),
            })
            .await
            .expect("an empty user list should be accepted")
            .users,
        Some(0),
    );
    checks.refused(
        "an empty tag is refused",
        engine
            .add_inbound(dynamic("   ", vless_inbound(free_addr(), true)))
            .await,
        "tag must not be empty",
    );

    checks.finish();
}
