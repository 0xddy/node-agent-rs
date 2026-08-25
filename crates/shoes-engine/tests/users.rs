//! Phase 2 acceptance: in-memory, lock-free, per-inbound users.
//!
//! The property the phase exists for: **one VLESS inbound, users added at runtime,
//! each authenticated independently, and removing one closes that user's existing
//! connections without disturbing anyone else.**

mod common;

use std::time::Duration;

use common::*;
use shoes_engine::UserSpec;
use tokio::io::AsyncWriteExt;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";

#[tokio::test(flavor = "multi_thread")]
async fn dynamic_users_authenticate_independently() {
    let mut checks = Checks::new("dynamic users");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, true)))
        .await
        .expect("a vless inbound with an empty user list should start");

    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(vless, ALICE)).await;
    let bob_leg = start_leg(&engine, "leg-bob", vless_chain(vless, BOB)).await;

    // -- 1. an empty registry is the authority, so it authenticates nobody -------
    checks.section("1. empty registry");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "vless" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        denied(alice_leg, sink.address).await,
    );

    // -- 2. adding users takes effect without restarting the listener -----------
    checks.section("2. add users at runtime");
    checks.that(
        "alice is accepted",
        engine.add_user("vless", user("alice", ALICE)).is_ok(),
    );
    checks.that(
        "bob is accepted",
        engine.add_user("vless", user("bob", BOB)).is_ok(),
    );
    checks.eq(
        "the inbound now reports two users",
        engine.list_users("vless").map(|u| u.len()).unwrap_or(0),
        2,
    );

    // -- 3. each user authenticates on their own credential ---------------------
    checks.section("3. independent authentication");
    checks.eq(
        "alice reaches the sink",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.eq(
        "bob reaches the sink",
        reach(bob_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );

    // A user whose uuid the registry has never seen is refused, which is what says
    // the registry is genuinely the authority rather than a filter in front of a
    // config credential that would have let anyone through.
    let stranger = start_leg(
        &engine,
        "leg-stranger",
        vless_chain(vless, "44444444-4444-4444-8444-444444444444"),
    )
    .await;
    checks.that(
        "an unknown uuid is refused",
        denied(stranger, sink.address).await,
    );

    // -- 4. listing users must not hand credentials back out -------------------
    checks.section("4. listing does not echo credentials");
    let listed = engine
        .list_users("vless")
        .expect("the inbound has a registry");
    let rendered = format!("{listed:?}");
    checks.that(
        "no uuid appears in the listing",
        !rendered.contains(ALICE) && !rendered.contains(BOB),
    );
    checks.that(
        "the ids do appear",
        rendered.contains("alice") && rendered.contains("bob"),
    );

    // -- 5. a disabled user is indistinguishable from an unknown one ------------
    checks.section("5. disabled users");
    engine
        .add_user("vless", disabled_user("bob", BOB))
        .expect("re-adding bob as disabled should be accepted");
    checks.that(
        "bob is refused while disabled",
        denied(bob_leg, sink.address).await,
    );
    checks.that(
        "alice is unaffected by bob being disabled",
        reach(alice_leg, sink.address).await.is_ok(),
    );
    engine
        .add_user("vless", user("bob", BOB))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        reach(bob_leg, sink.address).await.is_ok(),
    );

    // -- 6. removal actively closes the user's existing connections -------------
    checks.section("6. removing a user closes their open connections");
    let mut held = Socks::connect(bob_leg, sink.address)
        .await
        .expect("bob should be able to open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    checks.that(
        "bob's held connection is registered before removal",
        wait_for("bob's held connection to authenticate", || {
            engine
                .get_user("vless", "bob")
                .is_ok_and(|user| user.conns == 1)
        })
        .await,
    );

    let removed =
        tokio::time::timeout(Duration::from_secs(5), engine.remove_user("vless", "bob")).await;
    checks.that(
        "bob is removed only after his connection closes",
        matches!(removed, Ok(Ok(ref user)) if user.conns == 0),
    );
    checks.that(
        "a new bob connection is refused",
        denied(bob_leg, sink.address).await,
    );
    checks.that(
        "alice still works after bob is removed",
        reach(alice_leg, sink.address).await.is_ok(),
    );

    let bob_closed = tokio::time::timeout(Duration::from_secs(2), async {
        match held.write_all(b"o\n").await {
            Err(_) => true,
            Ok(()) => read_line(&mut held).await.is_err(),
        }
    })
    .await;
    checks.that(
        "bob's already-open connection is actively closed",
        matches!(bob_closed, Ok(true)),
    );
    drop(held);

    engine
        .add_user("vless", user("bob", BOB))
        .expect("the same id can be added with a fresh connection lifecycle");
    checks.that(
        "a re-added bob receives a fresh usable connection token",
        reach(bob_leg, sink.address).await.is_ok(),
    );

    // -- 7. bad users are refused whole, never half-applied --------------------
    checks.section("7. rejected users");
    let before = engine.list_users("vless").map(|u| u.len()).unwrap_or(0);

    checks.refused(
        "a malformed uuid is refused",
        engine.add_user("vless", user("mallory", "not-a-uuid")),
        "Invalid uuid",
    );
    checks.refused(
        "a credential this protocol cannot use is refused",
        engine.add_user(
            "vless",
            UserSpec {
                id: Some("mallory".into()),
                uuid: None,
                password: Some("hunter2".into()),
                enabled: true,
                max_conns: None,
                upload_limit_bps: None,
                download_limit_bps: None,
            },
        ),
        "does not authenticate by password",
    );
    checks.refused(
        "a user with no credential at all is refused",
        engine.add_user(
            "vless",
            UserSpec {
                id: Some("mallory".into()),
                uuid: None,
                password: None,
                enabled: true,
                max_conns: None,
                upload_limit_bps: None,
                download_limit_bps: None,
            },
        ),
        "needs a credential",
    );
    checks.refused(
        "claiming alice's uuid under another id is refused",
        engine.add_user("vless", user("mallory", ALICE)),
        "already belongs to user alice",
    );
    checks.refused(
        "adding a user to an unknown inbound is refused",
        engine.add_user("nope", user("mallory", BOB)),
        "no such inbound tag",
    );
    checks.refused(
        "removing an unknown user is refused",
        engine.remove_user("vless", "mallory").await,
        "no such user",
    );

    checks.eq(
        "no rejected user was partially applied",
        engine.list_users("vless").map(|u| u.len()).unwrap_or(0),
        before,
    );
    checks.that(
        "alice's credential still works after the duplicate attempt",
        reach(alice_leg, sink.address).await.is_ok(),
    );

    // -- 8. traffic lands on the registry entry that authorised it -------------
    //
    // Detail is Phase 3's business; all that matters here is that the counters
    // belong to the user rather than to the inbound.
    checks.section("8. traffic is attributed to the user");
    let start = quiet(&engine, "vless", "alice").await;
    transfer(alice_leg, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");
    let after = quiet(&engine, "vless", "alice").await;
    let (tx, rx) = delta(&start, &after);

    checks.detail("alice's upload was counted", rx > 1000, format!("rx={rx}"));
    checks.detail(
        "alice's download was counted",
        tx > 8000,
        format!("tx={tx}"),
    );
    checks.detail(
        "the download is the larger direction, as sent",
        tx > rx,
        format!("tx={tx} rx={rx}"),
    );
    checks.that(
        "alice's connection count returned to zero",
        after.conns == 0,
    );
    checks.that("alice's connections were tallied", after.total_conns > 0);

    checks.finish();
}

/// A user's connection ceiling is the only bound on what one valid credential can
/// cost the host, so it is worth proving end to end rather than at the registry.
/// Every protocol's per-connection state -- UDP sessions, multiplexed tunnels,
/// buffers -- is a multiplier on this number.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_ceiling_bounds_one_credential() {
    let mut checks = Checks::new("connection ceiling");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, true)))
        .await
        .expect("a vless inbound should start");
    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(vless, ALICE)).await;

    let mut capped = user("alice", ALICE);
    capped.max_conns = Some(1);
    engine
        .add_user("vless", capped)
        .expect("a capped user should be accepted");

    checks.section("1. the ceiling is reported");
    checks.eq(
        "alice's ceiling is visible in her status",
        engine.get_user("vless", "alice").map(|u| u.max_conns).ok(),
        Some(1),
    );

    checks.section("2. the first connection is admitted");
    // Half a request, so the connection authenticates and then stays open rather
    // than completing and releasing its slot.
    let mut held = Socks::connect(alice_leg, sink.address)
        .await
        .expect("alice's first connection should open");
    held.write_all(b"wh").await.expect("send half a request");
    checks.that(
        "alice's held connection is registered",
        wait_for("alice's held connection to authenticate", || {
            engine
                .get_user("vless", "alice")
                .is_ok_and(|user| user.conns == 1)
        })
        .await,
    );

    checks.section("3. the second is refused while the first is open");
    checks.that(
        "a second connection on the same credential is refused",
        denied(alice_leg, sink.address).await,
    );
    checks.eq(
        "the refusal did not raise the live count",
        engine.get_user("vless", "alice").map(|u| u.conns).ok(),
        Some(1),
    );
    let after_refusal = engine
        .get_user("vless", "alice")
        .expect("alice is still registered");
    checks.eq(
        "a refused connection is not counted as an authentication",
        after_refusal.total_conns,
        1,
    );

    checks.section("4. the held connection still works");
    // The point of refusing rather than evicting: the connection already carrying
    // traffic is the one that survives.
    held.write_all(
        b"o
",
    )
    .await
    .expect("finish the request");
    checks.eq(
        "the first connection still reaches the sink",
        read_line(&mut held).await.ok(),
        Some("sink".to_string()),
    );

    checks.section("5. closing it frees the slot");
    drop(held);
    checks.that(
        "the live count returns to zero",
        wait_for("alice's held connection to close", || {
            engine
                .get_user("vless", "alice")
                .is_ok_and(|user| user.conns == 0)
        })
        .await,
    );
    checks.eq(
        "a new connection is admitted again",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );

    checks.section("6. raising the ceiling admits more at once");
    let mut raised = user("alice", ALICE);
    raised.max_conns = Some(3);
    engine
        .add_user("vless", raised)
        .expect("raising the ceiling should be accepted");

    let mut open = Vec::new();
    for _ in 0..3 {
        let mut stream = Socks::connect(alice_leg, sink.address)
            .await
            .expect("a connection under the raised ceiling should open");
        stream.write_all(b"wh").await.expect("send half a request");
        open.push(stream);
    }
    checks.that(
        "three connections are held at once",
        wait_for("three of alice's connections to authenticate", || {
            engine
                .get_user("vless", "alice")
                .is_ok_and(|user| user.conns == 3)
        })
        .await,
    );
    checks.that(
        "the fourth is refused",
        denied(alice_leg, sink.address).await,
    );
    drop(open);

    checks.finish();
}

/// The pending-handshake gate must hand its permits back.
///
/// A permit that outlives its handshake is far worse than no gate at all: the
/// listener would wedge after `MAX_PENDING_PER_SOURCE` connections from one address
/// and refuse everything after that, forever, with no error to explain it. Every
/// connection here completes and closes, so a listener that stops answering partway
/// through is a leaked permit.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_permits_are_returned_after_the_handshake() {
    use shoes::tcp::handshake_gate::MAX_PENDING_PER_SOURCE;

    let mut checks = Checks::new("handshake permits");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, true)))
        .await
        .expect("a vless inbound should start");
    engine
        .add_user("vless", user("alice", ALICE))
        .expect("alice should be accepted");
    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(vless, ALICE)).await;

    // Comfortably past the per-source share, all from 127.0.0.1 -- which is the one
    // address every one of these connections has.
    let rounds = MAX_PENDING_PER_SOURCE * 3;
    let mut reached = 0usize;
    for _ in 0..rounds {
        if matches!(reach(alice_leg, sink.address).await, Ok(ref name) if name == "sink") {
            reached += 1;
        } else {
            break;
        }
    }

    checks.eq(
        "every sequential connection past the per-source share still connects",
        reached,
        rounds,
    );

    checks.finish();
}
