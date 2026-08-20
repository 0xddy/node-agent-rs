//! Phase 3 acceptance: per-user byte accounting at the relay point.
//!
//! What is being measured is **wire bytes on the inbound's own connection** -- the
//! meter sits under the protocol stack, so TLS records, VLESS headers and UDP framing
//! are all counted. Measuring it there is a decision, not an accident: it is the
//! number a billing or quota layer needs, because it is what the link actually
//! carried.
//!
//! # Reading the assertions
//!
//! The lower bound on each counter is the boring half. The **upper** bound is what
//! these tests are for: double counting -- metering a stream that has already been
//! metered further in, or adding a byte on both the poll and the completion -- shows
//! up as roughly twice the transfer size, and nothing else here would notice.

mod common;

use common::*;
use tokio::io::AsyncWriteExt;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";
const CAROL: &str = "33333333-3333-4333-8333-333333333333";

/// Room for protocol overhead on top of the payload: the VLESS request header, the
/// command line the sink is asked with, and TCP-level framing the meter also sees.
const SLACK: u64 = 512;
const UPLOAD: usize = 64 * 1024;
const DOWNLOAD: usize = 192 * 1024;
const PACKET: usize = 1200;
const PACKETS: usize = 8;

#[tokio::test(flavor = "multi_thread")]
async fn traffic_is_metered_per_user() {
    let mut checks = Checks::new("traffic accounting");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let vless = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(vless, true)))
        .await
        .expect("the plain vless inbound should start");
    engine.add_user("vless", user("alice", ALICE)).unwrap();
    engine.add_user("vless", user("bob", BOB)).unwrap();

    let alice_leg = start_leg(&engine, "leg-alice", vless_chain(vless, ALICE)).await;
    let bob_leg = start_leg(&engine, "leg-bob", vless_chain(vless, BOB)).await;

    // -- 1. both directions are counted, once each ----------------------------
    checks.section("1. a measured transfer");
    let before = quiet(&engine, "vless", "alice").await;
    let received = transfer(alice_leg, sink.address, UPLOAD, DOWNLOAD)
        .await
        .expect("alice's transfer should complete");
    checks.eq("the whole download arrived", received, DOWNLOAD);

    let after = quiet(&engine, "vless", "alice").await;
    let (tx, rx) = delta(&before, &after);
    checks.within(
        "the upload is counted as rx, once",
        rx,
        UPLOAD as u64,
        UPLOAD as u64 + SLACK,
    );
    checks.within(
        "the download is counted as tx, once",
        tx,
        DOWNLOAD as u64,
        DOWNLOAD as u64 + SLACK,
    );
    checks.eq(
        "one connection was tallied",
        after.total_conns - before.total_conns,
        1,
    );

    // -- 2. counters do not bleed between users -------------------------------
    checks.section("2. isolation between users");
    let alice_mark = quiet(&engine, "vless", "alice").await;
    let bob_before = quiet(&engine, "vless", "bob").await;
    transfer(bob_leg, sink.address, UPLOAD, DOWNLOAD)
        .await
        .expect("bob's transfer should complete");
    let bob_after = quiet(&engine, "vless", "bob").await;
    let alice_now = quiet(&engine, "vless", "alice").await;

    let (bob_tx, bob_rx) = delta(&bob_before, &bob_after);
    checks.within(
        "bob's upload landed on bob",
        bob_rx,
        UPLOAD as u64,
        UPLOAD as u64 + SLACK,
    );
    checks.within(
        "bob's download landed on bob",
        bob_tx,
        DOWNLOAD as u64,
        DOWNLOAD as u64 + SLACK,
    );
    checks.eq(
        "alice's counters did not move",
        delta(&alice_mark, &alice_now),
        (0, 0),
    );

    // -- 3. live connections are visible while they are open -------------------
    //
    // `conns` is what makes the counters readable at all: it is the barrier that says
    // no meter is still running, so a total taken after it hits zero is final.
    checks.section("3. the live connection count");
    let mut held = Socks::connect(alice_leg, sink.address)
        .await
        .expect("open a connection to hold");
    held.write_all(b"hold\n")
        .await
        .expect("send the hold command");

    checks.that(
        "the open connection is counted",
        wait_for("alice to report an open connection", || {
            engine
                .get_user("vless", "alice")
                .map(|u| u.conns == 1)
                .unwrap_or(false)
        })
        .await,
    );

    drop(held);
    checks.that(
        "closing it brings the count back to zero",
        wait_for("alice's connection to close", || {
            engine
                .get_user("vless", "alice")
                .map(|u| u.conns == 0)
                .unwrap_or(false)
        })
        .await,
    );

    // -- 4. udp is metered on the same counters -------------------------------
    //
    // VLESS carries UDP inside its own framed stream, so these bytes pass the same
    // meter the TCP bytes do -- which is the point: a user's total is their total.
    checks.section("4. udp datagrams");
    let udp_before = quiet(&engine, "vless", "alice").await;
    let echoed = udp_burst(alice_leg, echo.address, PACKET, PACKETS)
        .await
        .expect("the udp association should work");
    checks.eq("every datagram came back", echoed, PACKETS);

    let udp_after = quiet(&engine, "vless", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    let total = (PACKET * PACKETS) as u64;
    checks.within(
        "the sent datagrams are counted once",
        udp_rx,
        total,
        total + SLACK,
    );
    checks.within(
        "the echoed datagrams are counted once",
        udp_tx,
        total,
        total + SLACK,
    );

    // -- 5. a tls inbound charges its own user, handshake included -------------
    //
    // The meter is installed when the connection is accepted, but the user is not
    // known until the VLESS header inside TLS has been read. The bytes spent getting
    // there are held aside and handed to the user at bind, so a 16-byte transfer
    // still shows a full handshake's worth of traffic. Without that handover those
    // bytes would silently vanish from every TLS user's total.
    checks.section("5. tls, and the pre-auth handshake");
    let tls = free_addr();
    engine
        .add_inbound(dynamic("tls", tls_vless_inbound(tls)))
        .await
        .expect("the tls inbound should start");
    engine.add_user("tls", user("carol", CAROL)).unwrap();
    let carol_leg = start_leg(
        &engine,
        "leg-carol",
        tls_vless_chain(tls, CAROL, "e2e.test"),
    )
    .await;

    let carol_start = engine.get_user("tls", "carol").expect("carol exists");
    checks.eq(
        "carol starts with nothing counted",
        (carol_start.tx, carol_start.rx),
        (0, 0),
    );

    let alice_mark = quiet(&engine, "vless", "alice").await;
    transfer(carol_leg, sink.address, 16, 16)
        .await
        .expect("carol's small transfer should complete");
    let carol_after = quiet(&engine, "tls", "carol").await;

    // Lower bounds only. A TLS handshake's size depends on the cipher suite and the
    // certificate, neither of which this test should be asserting; what matters is
    // that it is far more than the 16 bytes of payload, which it can only be if the
    // pre-auth bytes were handed over.
    checks.detail(
        "carol was charged for the client handshake",
        carol_after.rx > 250,
        format!("rx={}", carol_after.rx),
    );
    checks.detail(
        "carol was charged for the server handshake",
        carol_after.tx > 700,
        format!("tx={}", carol_after.tx),
    );

    let alice_now = quiet(&engine, "vless", "alice").await;
    checks.eq(
        "alice was not charged for carol's connection",
        delta(&alice_mark, &alice_now),
        (0, 0),
    );

    // A second connection must not re-charge the first one's handshake.
    let carol_mark = carol_after;
    transfer(carol_leg, sink.address, 16, 16)
        .await
        .expect("carol's second transfer should complete");
    let carol_second = quiet(&engine, "tls", "carol").await;
    let (second_tx, second_rx) = delta(&carol_mark, &carol_second);
    checks.detail(
        "the second connection is charged separately",
        second_rx > 0 && second_tx > 0,
        format!("tx={second_tx} rx={second_rx}"),
    );
    checks.detail(
        "and is not charged the first connection's bytes again",
        second_rx < carol_mark.rx * 2 && second_tx < carol_mark.tx * 2,
        format!(
            "tx={second_tx} rx={second_rx} vs first tx={} rx={}",
            carol_mark.tx, carol_mark.rx
        ),
    );
    checks.eq(
        "carol has two connections on record",
        carol_second.total_conns,
        2,
    );

    checks.finish();
}
