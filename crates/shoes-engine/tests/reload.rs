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
use shoes_api::InboundSpec;
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
        .await
        .expect("reloading with an equivalent config should be accepted");
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
            .filter(|a| *a == &vless.to_string())
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
