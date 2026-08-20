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

use common::tuic as tu;
use common::*;
use serde_json::json;
use shoes_engine::InboundSpec;
use tokio::io::AsyncWriteExt;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";
const ALICE_PASSWORD: &str = "alice-password";

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

/// The same property, on an inbound that has no handler to swap.
///
/// Hysteria2 and TUIC authenticate inside their own QUIC accept loops, so they never
/// build a `TcpServerHandler` and the `HandlerSlot` the test above exercises does not
/// exist for them. Until `SelectorSlot`, `update_inbound` refused them outright and
/// the only way to change their rules was to remove and re-add the inbound -- which
/// drops every established connection, i.e. exactly the thing this suite exists to
/// prevent.
///
/// What a rule slot reaches is *only* the rules, so section 4 is as important as the
/// swap itself: a setting the accept loop read once, before it started, has to be
/// refused rather than silently ignored.
#[tokio::test(flavor = "multi_thread")]
async fn a_quic_native_inbound_swaps_its_rules_in_place() {
    let mut checks = Checks::new("rcu reload on a quic-native inbound");

    let engine = engine().await;
    let sink_a = Sink::start("A").await;
    let sink_b = Sink::start("B").await;
    // Never listened on. Every rule below overrides the destination, so a connection
    // that reached anything at all proves which generation it was routed by.
    let nowhere = free_addr();

    let tuic = free_addr();
    engine
        .add_inbound(dynamic(
            "tuic",
            tuic_inbound_with_rules(tuic, redirect_to(sink_a.address)),
        ))
        .await
        .expect("a tuic inbound with rules should start");
    engine
        .add_user("tuic", tuic_user("alice", ALICE, ALICE_PASSWORD))
        .expect("alice should be accepted");

    let first = info(&engine, "tuic");

    // -- 1. the inbound routes by its starting rules --------------------------
    checks.section("1. the starting generation");
    checks.eq(
        "alice reaches A, though she asked for nowhere",
        tu::reach(tuic, ALICE, ALICE_PASSWORD, nowhere).await.ok(),
        Some("A".to_string()),
    );
    checks.eq("no swap has happened yet", first.revision, 0);

    // -- 2. hold a connection open across the swap ----------------------------
    checks.section("2. swap the rules under a live connection");
    let held_client = tu::TuicClient::connect(tuic, ALICE, ALICE_PASSWORD)
        .await
        .expect("alice should authenticate");
    let mut held = held_client
        .open_tcp(nowhere)
        .await
        .expect("alice should open a proxied stream");
    held.write_all(b"wh").await.expect("send half a request");
    // Let the first half reach sink A, so the connection is established end to end
    // rather than merely accepted at the QUIC layer.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let before = quiet(&engine, "tuic", "alice").await;
    let redirected = engine
        .update_inbound(classic(
            "tuic",
            tuic_inbound_with_rules(tuic, redirect_to(sink_b.address)),
        ))
        .await
        .expect("a rules-only swap should be accepted on a quic-native inbound");

    // -- 3. the decisive pair -------------------------------------------------
    checks.section("3. new rules for new connections only");
    checks.eq(
        "a new connection is redirected to B",
        tu::reach(tuic, ALICE, ALICE_PASSWORD, nowhere).await.ok(),
        Some("B".to_string()),
    );

    held.write_all(b"o\n")
        .await
        .expect("finish the held request");
    checks.eq(
        "the connection held across the swap still answers A",
        held.read_line().await.ok(),
        Some("A".to_string()),
    );
    drop(held);
    drop(held_client);

    checks.detail(
        "the revision advanced",
        redirected.revision > first.revision,
        format!("{} -> {}", first.revision, redirected.revision),
    );
    checks.eq(
        "the listener count is unchanged -- nothing rebound",
        redirected.listeners,
        first.listeners,
    );
    checks.eq(
        "and the bind set is unchanged",
        redirected.bind.clone(),
        first.bind.clone(),
    );

    // -- 4. what a rule slot cannot reach -------------------------------------
    //
    // `zero_rtt_handshake` is read once, before the accept loop starts. Accepting it
    // here would report success for a setting that never took effect.
    checks.section("4. settings the accept loop baked in are refused");
    let mut with_zero_rtt = tuic_inbound_with_rules(tuic, redirect_to(sink_b.address));
    with_zero_rtt["protocol"]["zero_rtt_handshake"] = json!(true);
    checks.refused(
        "changing zero_rtt_handshake in place is refused",
        engine.update_inbound(classic("tuic", with_zero_rtt)).await,
        "zero_rtt_handshake",
    );
    checks.eq(
        "the inbound kept serving the rules it had",
        tu::reach(tuic, ALICE, ALICE_PASSWORD, nowhere).await.ok(),
        Some("B".to_string()),
    );
    checks.eq(
        "and stayed on the revision it had",
        info(&engine, "tuic").revision,
        redirected.revision,
    );

    // -- 5. users and counters came through -----------------------------------
    checks.section("5. the registry survived the swap");
    let after = quiet(&engine, "tuic", "alice").await;
    checks.detail(
        "alice's counters carried across the swap",
        after.tx >= before.tx && after.rx >= before.rx,
        format!(
            "tx {} -> {}, rx {} -> {}",
            before.tx, after.tx, before.rx, after.rx
        ),
    );
    checks.eq(
        "and she is still the only user",
        engine.list_users("tuic").map(|u| u.len()).unwrap_or(0),
        1,
    );
    checks.that(
        "a user added after the swap authenticates too",
        engine
            .add_user("tuic", tuic_user("bob", BOB, "bob-password"))
            .is_ok(),
    );
    checks.eq(
        "bob reaches B like everyone else",
        tu::reach(tuic, BOB, "bob-password", nowhere).await.ok(),
        Some("B".to_string()),
    );

    checks.finish();
}
