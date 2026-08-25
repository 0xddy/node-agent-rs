//! Acceptance: per-user bandwidth limits.
//!
//! # Reading the assertions
//!
//! These run against the real clock, so the assertions are deliberately
//! one-sided wherever a machine's speed could matter. The **floor** is the load
//! bearing half: a token bucket cannot deliver bytes faster than its rate, so
//! `(payload - burst) / rate` is a hard lower bound that holds on a fast
//! developer machine and a loaded CI runner alike. Upper bounds appear only
//! where the contrast is an order of magnitude -- an unlimited transfer over
//! loopback finishes in milliseconds, not hundreds of them.
//!
//! # What would break without this
//!
//! Three failure modes, each silent in production:
//!
//! - a limit that is never consulted, so the cap simply does not exist;
//! - a limit applied per *connection*, which any client defeats by opening two;
//! - a limit applied to the wrong direction, which nobody notices until a user
//!   reports that their downloads are fine and their uploads are not.
//!
//! Sections 1, 3 and 5 exist for exactly those three.

mod common;

use std::time::{Duration, Instant};

use common::*;
use shoes_engine::UserSpec;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";

/// 16 Mbit/s, which is 2 MiB/s exactly and keeps the arithmetic legible.
const RATE_BPS: u64 = 16 * 1024 * 1024;
const RATE_BYTES_PER_SEC: usize = 2 * 1024 * 1024;

/// The bucket's burst, which the limiter clamps to one mebibyte. This much of
/// every transfer is free, and the floor below has to account for it.
const BURST: usize = 1024 * 1024;

const PAYLOAD: usize = 3 * 1024 * 1024;

/// The shortest a limited transfer can possibly take: everything past the free
/// burst, paced at the configured rate.
///
/// Shaded slightly under the exact figure (1000ms) because the final chunk's
/// debt is settled after that chunk has already reached the client, and because
/// timer granularity should not decide whether this suite passes.
const FLOOR: Duration = Duration::from_millis(850);

/// Comfortably longer than loopback needs for three mebibytes -- that transfer
/// is a few milliseconds of work -- and comfortably under [`FLOOR`], so the two
/// cases cannot be confused for one another.
const UNLIMITED_CEILING: Duration = Duration::from_millis(750);

fn limited_user(id: &str, uuid: &str, upload_bps: u64, download_bps: u64) -> UserSpec {
    UserSpec {
        upload_limit_bps: Some(upload_bps),
        download_limit_bps: Some(download_bps),
        ..user(id, uuid)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bandwidth_limits_are_enforced_per_user() {
    let mut checks = Checks::new("per-user bandwidth limits");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, false)))
        .await
        .expect("the vless inbound should start");
    engine
        .add_user("vless", limited_user("alice", ALICE, RATE_BPS, RATE_BPS))
        .unwrap();
    engine.add_user("vless", user("bob", BOB)).unwrap();

    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(vless, ALICE)).await;
    let bob_leg = start_leg(&engine, "leg-bob", vless_chain(vless, BOB)).await;

    // -- 1. a download limit paces the transfer without losing bytes ----------
    checks.section("1. the download limit is enforced");
    quiet(&engine, "vless", "alice").await;
    let started = Instant::now();
    let received = transfer(alice_leg, sink.address, 0, PAYLOAD)
        .await
        .expect("the limited download should still complete");
    let elapsed = started.elapsed();

    checks.eq("every byte still arrived", received, PAYLOAD);
    checks.at_least("the transfer was paced", elapsed, FLOOR);

    // -- 2. the limit is the user's, not the inbound's ------------------------
    checks.section("2. an unlimited user on the same inbound");
    quiet(&engine, "vless", "bob").await;
    let started = Instant::now();
    let received = transfer(bob_leg, sink.address, 0, PAYLOAD)
        .await
        .expect("bob's download should complete");
    let bob_elapsed = started.elapsed();

    checks.eq("bob received everything", received, PAYLOAD);
    checks.at_most(
        "bob is not slowed by alice's limit",
        bob_elapsed,
        UNLIMITED_CEILING,
    );

    // -- 3. one bucket per user, not per connection ---------------------------
    checks.section("3. concurrent connections share the allowance");
    quiet(&engine, "vless", "alice").await;
    let half = PAYLOAD / 2;
    let started = Instant::now();
    let (first, second) = tokio::join!(
        transfer(alice_leg, sink.address, 0, half),
        transfer(alice_leg, sink.address, 0, half),
    );
    let elapsed = started.elapsed();

    checks.eq("the first half arrived", first.unwrap_or(0), half);
    checks.eq("the second half arrived", second.unwrap_or(0), half);
    checks.at_least("two connections do not buy two allowances", elapsed, FLOOR);

    // -- 4. the upload direction is limited independently ---------------------
    checks.section("4. the upload limit is enforced separately");
    engine
        .add_user("vless", limited_user("alice", ALICE, RATE_BPS, 0))
        .expect("alice should accept a download-only relaxation");
    quiet(&engine, "vless", "alice").await;

    // The sink writes its single reply byte only after reading the whole
    // upload, so this round trip really does measure the upload direction.
    let started = Instant::now();
    transfer(alice_leg, sink.address, PAYLOAD, 1)
        .await
        .expect("the limited upload should complete");
    let upload_elapsed = started.elapsed();
    checks.at_least("the upload was paced", upload_elapsed, FLOOR);

    quiet(&engine, "vless", "alice").await;
    let started = Instant::now();
    let received = transfer(alice_leg, sink.address, 0, PAYLOAD)
        .await
        .expect("the now-unlimited download should complete");
    let download_elapsed = started.elapsed();
    checks.eq("the download still arrived in full", received, PAYLOAD);
    checks.at_most(
        "clearing the download limit left the upload limit alone",
        download_elapsed,
        UNLIMITED_CEILING,
    );

    // -- 5. limits can be lifted ----------------------------------------------
    checks.section("5. removing the limit");
    engine
        .add_user("vless", user("alice", ALICE))
        .expect("alice should accept having her limits cleared");
    quiet(&engine, "vless", "alice").await;

    let started = Instant::now();
    let received = transfer(alice_leg, sink.address, 0, PAYLOAD)
        .await
        .expect("the unlimited download should complete");
    let elapsed = started.elapsed();
    checks.eq("everything arrived", received, PAYLOAD);
    checks.at_most("the limit is gone", elapsed, UNLIMITED_CEILING);

    // A user record with no limit fields must report no limit, so an operator
    // reading the engine back cannot be told a cap is in force when it is not.
    let info = engine.get_user("vless", "alice").unwrap();
    checks.eq(
        "the report agrees there is no upload cap",
        info.upload_limit_bps,
        0,
    );
    checks.eq(
        "the report agrees there is no download cap",
        info.download_limit_bps,
        0,
    );

    checks.finish();
}

/// A rate that is re-sent unchanged must not act as a fresh allowance.
///
/// The panel this engine serves re-sends a node's whole user list on every
/// periodic sync. If each of those resets the bucket, a user on a one-minute
/// sync gets a free burst a minute and the limit quietly stops meaning
/// anything -- the kind of bug that only shows up as an unexplained bandwidth
/// bill.
#[tokio::test(flavor = "multi_thread")]
async fn re_sending_an_unchanged_user_does_not_reset_the_bucket() {
    let mut checks = Checks::new("idempotent limit updates");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, false)))
        .await
        .expect("the vless inbound should start");
    engine
        .add_user("vless", limited_user("alice", ALICE, RATE_BPS, RATE_BPS))
        .unwrap();
    let leg = start_leg(&engine, "leg", vless_chain(vless, ALICE)).await;

    // Spend the free burst, then re-apply the identical record repeatedly.
    transfer(leg, sink.address, 0, BURST)
        .await
        .expect("the opening burst should complete");
    for _ in 0..8 {
        engine
            .add_user("vless", limited_user("alice", ALICE, RATE_BPS, RATE_BPS))
            .expect("re-sending an unchanged user should succeed");
    }
    quiet(&engine, "vless", "alice").await;

    let started = Instant::now();
    let received = transfer(leg, sink.address, 0, 2 * RATE_BYTES_PER_SEC)
        .await
        .expect("the paced download should complete");
    let elapsed = started.elapsed();

    checks.eq("everything arrived", received, 2 * RATE_BYTES_PER_SEC);
    checks.at_least(
        "eight identical updates did not hand out eight bursts",
        elapsed,
        FLOOR,
    );

    checks.finish();
}
