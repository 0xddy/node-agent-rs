//! Phase 2 acceptance: in-memory, lock-free, per-inbound users.
//!
//! The property the phase exists for: **one VLESS inbound, users added at runtime,
//! each authenticated independently, and removing one does not disturb a connection
//! the other -- or the removed user themselves -- already has open.**

mod common;

use std::time::Duration;

use common::*;
use shoes_api::UserSpec;
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

    // -- 6. removal is forward-looking only ------------------------------------
    //
    // This is the acceptance criterion. A connection bob already holds must run to
    // completion: it was authorised when it started, and the registry lookup that
    // authorised it does not happen again.
    checks.section("6. removing a user leaves their open connection alone");
    let mut held = Socks::connect(bob_leg, sink.address)
        .await
        .expect("bob should be able to open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    // Give the request's first half time to traverse the chain, so the connection is
    // genuinely established upstream rather than merely accepted locally.
    tokio::time::sleep(Duration::from_millis(200)).await;

    checks.that("bob is removed", engine.remove_user("vless", "bob").is_ok());
    checks.that(
        "a new bob connection is refused",
        denied(bob_leg, sink.address).await,
    );
    checks.that(
        "alice still works after bob is removed",
        reach(alice_leg, sink.address).await.is_ok(),
    );

    held.write_all(b"o\n").await.expect("send the second half");
    checks.eq(
        "bob's already-open connection still completes",
        read_line(&mut held).await.ok(),
        Some("sink".to_string()),
    );
    drop(held);

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
        engine.remove_user("vless", "mallory"),
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
