//! Hysteria2 acceptance: multi-user through the HTTP/3 auth header.
//!
//! Hysteria2 is the simplest credential in this crate and the most awkward to test.
//!
//! Simple, because there is no derivation to get wrong: the client sends its password
//! in cleartext in a `hysteria-auth` header on a `POST https://hysteria/auth`, and the
//! server's answer -- status **233** -- is the whole handshake. One registry lookup
//! either finds the user or does not.
//!
//! Awkward, because of *where* that happens. Hysteria2 does not go through a
//! `TcpServerHandler` like VLESS or Shadowsocks; it authenticates inside its own QUIC
//! accept loop, once per connection, before any proxied stream exists. Three
//! consequences shape this suite:
//!
//! - A connection is the billing unit, not a stream. Every stream and every datagram
//!   multiplexed over one QUIC connection lands on the user resolved at auth, so
//!   `total_conns` counts connections and a client that opens ten streams is still one.
//! - The accounting context cannot ride a task-local the way the TCP path's does,
//!   because each of the server's loops runs in a task of its own. It is passed
//!   explicitly instead, and a suite that only checked TCP would leave the UDP and
//!   datagram loops unproven -- hence section 6.
//! - There is no Hysteria2 client in shoes to build the far half of the chain from, so
//!   these tests speak QUIC and HTTP/3 directly. See [`common::hysteria2`].

mod common;

use std::time::Duration;

use common::hysteria2 as hy2;
use common::*;

const ALICE: &str = "alice-password";
const BOB: &str = "bob-password";
const STRANGER: &str = "nobody-registered-this";

/// Users registered between alice and bob, so neither sits at an edge of the table.
const FILLER: usize = 8;

#[tokio::test(flavor = "multi_thread")]
async fn hysteria2_users_are_found_by_their_password() {
    let mut checks = Checks::new("hysteria2 password authentication");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let hy = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(hy, true)))
        .await
        .expect("a hysteria2 inbound with an empty user list should start");

    // -- 1. an empty registry authenticates nobody ------------------------------
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "hy2" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        hy2::denied(hy, ALICE, sink.address).await,
    );
    checks.that(
        "and it has an empty user list rather than no list at all",
        engine
            .list_users("hy2")
            .map(|u| u.is_empty())
            .unwrap_or(false),
    );

    // -- 2. a crowd, so a hit has to be the right entry --------------------------
    checks.section("2. users added at runtime");
    engine
        .add_user("hy2", password_user("alice", ALICE))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user(
                "hy2",
                password_user(&format!("filler-{n}"), &format!("filler-{n}-password")),
            )
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("hy2", password_user("bob", BOB))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("hy2").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. each password authenticates its own user -----------------------------
    checks.section("3. each password reaches the proxy");
    checks.eq(
        "alice reaches the sink",
        hy2::reach(hy, ALICE, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.eq(
        "bob reaches the sink",
        hy2::reach(hy, BOB, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "an unregistered password is refused",
        hy2::denied(hy, STRANGER, sink.address).await,
    );
    // A prefix of a live password must not match: the lookup is over the whole value.
    checks.that(
        "a prefix of alice's password is refused",
        hy2::denied(hy, &ALICE[..6], sink.address).await,
    );

    // -- 4. a miss is billed to nobody ------------------------------------------
    checks.section("4. failed attempts are billed to nobody");
    let filler_zero = quiet(&engine, "hy2", "filler-0").await;
    checks.eq(
        "a user nobody named has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 5. traffic lands on the authenticated user ------------------------------
    checks.section("5. attribution");
    let alice_before = quiet(&engine, "hy2", "alice").await;
    let bob_before = quiet(&engine, "hy2", "bob").await;

    hy2::transfer(hy, ALICE, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "hy2", "alice").await;
    let bob_after = quiet(&engine, "hy2", "bob").await;
    let (alice_tx, alice_rx) = delta(&alice_before, &alice_after);
    let (bob_tx, bob_rx) = delta(&bob_before, &bob_after);

    checks.detail(
        "alice's upload was counted",
        alice_rx > 1000,
        format!("rx={alice_rx}"),
    );
    checks.detail(
        "alice's download was counted",
        alice_tx > 8000,
        format!("tx={alice_tx}"),
    );
    checks.detail(
        "none of it landed on bob",
        (bob_tx, bob_rx) == (0, 0),
        format!("tx={bob_tx} rx={bob_rx}"),
    );

    // -- 6. the datagram loops are metered too ----------------------------------
    //
    // Hysteria2 UDP does not ride a stream: it goes in QUIC datagrams, read and
    // written by a loop in a task of its own. That task cannot see a task-local, so if
    // the context were not handed to it explicitly this is where the bytes would go
    // missing -- silently, with TCP still adding up perfectly.
    checks.section("6. udp");
    let udp_before = quiet(&engine, "hy2", "alice").await;
    checks.that(
        "a datagram makes the round trip",
        hy2::udp_roundtrip(hy, ALICE, echo.address, Duration::from_secs(5)).await,
    );
    let udp_after = quiet(&engine, "hy2", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    checks.detail(
        "the datagram was counted on alice's record",
        udp_tx > 0 && udp_rx > 0,
        format!("tx={udp_tx} rx={udp_rx}"),
    );

    // A burst, to show the count tracks volume rather than being a fixed cost paid
    // once. The bounds are loose on purpose: what is counted is datagram length,
    // which includes the session and address headers but not QUIC's own per-packet
    // overhead, so the exact figure is not something a test should pin down.
    let burst_before = quiet(&engine, "hy2", "alice").await;
    let echoed = hy2::udp_burst(hy, ALICE, echo.address, 512, 8)
        .await
        .expect("a burst of datagrams should be carried");
    let burst_after = quiet(&engine, "hy2", "alice").await;
    let (burst_tx, burst_rx) = delta(&burst_before, &burst_after);
    checks.eq("all eight datagrams came back", echoed, 8);
    checks.within("the upload is near 8x512", burst_rx, 4096, 6144);
    checks.within("and so is the download", burst_tx, 4096, 6144);

    // -- 7. a disabled user looks absent ---------------------------------------
    checks.section("7. disabled users");
    engine
        .add_user("hy2", disabled_password_user("bob", BOB))
        .expect("re-adding bob as disabled should be accepted");
    let bob_disabled = quiet(&engine, "hy2", "bob").await;
    checks.that(
        "bob is refused while disabled",
        hy2::denied(hy, BOB, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine.get_user("hy2", "bob").map(|u| u.total_conns).ok(),
        Some(bob_disabled.total_conns),
    );
    checks.that(
        "alice is unaffected",
        hy2::reach(hy, ALICE, sink.address).await.is_ok(),
    );
    engine
        .add_user("hy2", password_user("bob", BOB))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        hy2::reach(hy, BOB, sink.address).await.is_ok(),
    );

    // -- 8. removal closes the authenticated QUIC connection --------------------
    checks.section("8. removing a user closes their QUIC connection");
    let held_client = hy2::Hysteria2Client::connect(hy, BOB)
        .await
        .expect("bob should be able to authenticate");
    let mut held = held_client
        .open_tcp(sink.address)
        .await
        .expect("bob should be able to open a stream");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let removed =
        tokio::time::timeout(Duration::from_secs(5), engine.remove_user("hy2", "bob")).await;
    checks.that(
        "bob is removed after his QUIC connection drains",
        matches!(removed, Ok(Ok(ref user)) if user.conns == 0),
    );
    checks.that(
        "a new bob connection is refused",
        hy2::denied(hy, BOB, sink.address).await,
    );
    checks.that(
        "alice still works after bob is removed",
        hy2::reach(hy, ALICE, sink.address).await.is_ok(),
    );

    let closed = match held.write_all(b"o\n").await {
        Err(_) => true,
        Ok(()) => held.read_line().await.is_err(),
    };
    checks.that("bob's already-open stream is actively closed", closed);
    checks.that(
        "the removed user's old QUIC connection cannot open another stream",
        held_client.open_tcp(sink.address).await.is_err(),
    );
    drop(held);
    drop(held_client);

    checks.finish();
}

/// One QUIC connection, many streams, one user.
///
/// This is the property that makes Hysteria2's accounting different in kind from the
/// TCP protocols': there, each connection authenticates for itself, so `total_conns`
/// and "number of handshakes" are the same number. Here a client authenticates once
/// and then multiplexes, and an implementation that counted per stream instead would
/// still look right on every other check in this file.
#[tokio::test(flavor = "multi_thread")]
async fn one_connection_carries_many_streams_for_one_user() {
    let mut checks = Checks::new("hysteria2 connection multiplexing");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let hy = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(hy, false)))
        .await
        .expect("the inbound should start");
    engine
        .add_user("hy2", password_user("alice", ALICE))
        .expect("alice should be accepted");

    let client = hy2::Hysteria2Client::connect(hy, ALICE)
        .await
        .expect("alice should authenticate");
    checks.eq(
        "the server reports udp disabled, as configured",
        client.udp_enabled,
        false,
    );
    // Polled rather than read straight off: the server answers 233 and *then* binds
    // the accounting context, so a client that has seen the response has not
    // necessarily been counted yet. A handful of milliseconds, but a real race.
    checks.that(
        "authenticating opened one connection",
        wait_for("alice's connection to be counted", || {
            engine
                .get_user("hy2", "alice")
                .map(|u| u.conns == 1)
                .unwrap_or(false)
        })
        .await,
    );

    for n in 0..4 {
        let mut stream = client
            .open_tcp(sink.address)
            .await
            .unwrap_or_else(|e| panic!("stream {n} should open: {e}"));
        stream.write_all(b"who\n").await.expect("send a request");
        checks.eq(
            &format!("stream {n} reaches the sink"),
            stream.read_line().await.ok(),
            Some("sink".to_string()),
        );
    }

    checks.eq(
        "four streams are still one connection",
        engine.get_user("hy2", "alice").map(|u| u.conns).ok(),
        Some(1),
    );
    checks.eq(
        "and one connection in the total",
        engine.get_user("hy2", "alice").map(|u| u.total_conns).ok(),
        Some(1),
    );
    let while_open = engine.get_user("hy2", "alice").expect("alice should exist");
    checks.that(
        "all four streams were counted on it",
        while_open.tx > 0 && while_open.rx > 0,
    );

    drop(client);
    let after = quiet(&engine, "hy2", "alice").await;
    checks.eq("closing it releases the count", after.conns, 0);
    checks.that(
        "and her totals survive the close",
        after.tx >= while_open.tx && after.rx >= while_open.rx,
    );

    checks.finish();
}

/// A failed outbound setup is a logical-stream failure, not a successful Hysteria2
/// handshake followed by EOF and not a reason to retire the shared QUIC connection.
#[tokio::test(flavor = "multi_thread")]
async fn failed_tcp_stream_is_reported_and_the_quic_connection_stays_usable() {
    let mut checks = Checks::new("hysteria2 tcp setup failure isolation");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let hy = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(hy, false)))
        .await
        .expect("the inbound should start");
    engine
        .add_user("hy2", password_user("alice", ALICE))
        .expect("alice should be accepted");

    let client = hy2::Hysteria2Client::connect(hy, ALICE)
        .await
        .expect("alice should authenticate");

    // Nothing is listening on this freshly released address. The old server replied
    // status=0 before attempting the dial, so this call incorrectly returned Ok and
    // the client only discovered the failure when it tried to use the stream.
    let refused = free_addr();
    checks.that(
        "a refused outbound is returned in the TCP response as status=1",
        client.open_tcp(refused).await.is_err(),
    );

    let mut stream = client
        .open_tcp(sink.address)
        .await
        .expect("a second stream on the same QUIC connection should still open");
    stream.write_all(b"who\n").await.expect("send a request");
    checks.eq(
        "the next stream on the same connection still reaches its destination",
        stream.read_line().await.ok(),
        Some("sink".to_string()),
    );

    checks.finish();
}

/// Rotating a password: the old one has to stop working the moment the new one starts,
/// and the user's counters have to survive.
///
/// The index is keyed on the password itself, so a rotation moves the entry. An
/// implementation that inserted the new key without retiring the old would leave a
/// revoked password working indefinitely, with nothing in the user's listing to show
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn rotating_a_password_revokes_the_old_one() {
    let mut checks = Checks::new("hysteria2 password rotation");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let first = "alice-first";
    let second = "alice-second";

    let hy = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(hy, false)))
        .await
        .expect("the inbound should start");

    engine
        .add_user("hy2", password_user("alice", first))
        .expect("alice should be accepted");
    checks.that(
        "alice's first password works",
        hy2::reach(hy, first, sink.address).await.is_ok(),
    );
    hy2::transfer(hy, first, sink.address, 512, 512)
        .await
        .expect("alice should be able to move bytes");
    let before = quiet(&engine, "hy2", "alice").await;
    checks.that("her traffic was counted", before.tx > 0 && before.rx > 0);

    engine
        .add_user("hy2", password_user("alice", second))
        .expect("rotating alice's password should be accepted");
    checks.eq(
        "she is still one user",
        engine.list_users("hy2").map(|u| u.len()).unwrap_or(0),
        1,
    );
    checks.that(
        "the retired password is refused",
        hy2::denied(hy, first, sink.address).await,
    );
    checks.that(
        "the new password works",
        hy2::reach(hy, second, sink.address).await.is_ok(),
    );

    let after = quiet(&engine, "hy2", "alice").await;
    checks.that(
        "her counters carried over",
        after.tx >= before.tx && after.rx >= before.rx,
    );

    checks.refused(
        "a duplicate password is refused",
        engine.add_user("hy2", password_user("bob", second)),
        "alice",
    );

    checks.finish();
}

/// What an operator may and may not say about a Hysteria2 inbound's credentials.
///
/// A password is the only credential form here, and the config's own `password` field
/// has to go: unlike a Shadowsocks identity PSK it names nothing but the single user it
/// belongs to, so leaving it live alongside a registry would be a second authority that
/// answers to nobody.
#[tokio::test(flavor = "multi_thread")]
async fn a_dynamic_hysteria2_inbound_takes_only_passwords() {
    let mut checks = Checks::new("hysteria2 credential eligibility");

    let engine = engine().await;

    checks.section("1. a declared password is refused, not overwritten");
    checks.refused(
        "a dynamic inbound may not carry its own password",
        engine
            .add_inbound(dynamic(
                "declared",
                hysteria2_inbound_with_password(free_addr(), "hunter2", false),
            ))
            .await,
        "password",
    );

    checks.section("2. users need a password and nothing else");
    let hy = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(hy, false)))
        .await
        .expect("the inbound should start");
    checks.refused(
        "a uuid is refused",
        engine.add_user("hy2", user("alice", "b85798ef-e9dc-46a4-9a87-8da4499d36d0")),
        "does not authenticate by uuid",
    );
    checks.refused(
        "and so is a user with no credential at all",
        engine.add_user(
            "hy2",
            shoes_engine::UserSpec {
                id: Some("nobody".to_string()),
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
    checks.that(
        "a password is accepted",
        engine
            .add_user("hy2", password_user("alice", ALICE))
            .is_ok(),
    );

    checks.finish();
}

/// The upstream path: an inbound whose password comes from its own config.
///
/// The multi-user work replaced an inline string comparison in the accept loop with a
/// registry lookup. In classic mode the registry is built from that same config
/// password, so this is the check that the substitution left the single-user case
/// behaving exactly as it did -- including that such an inbound is not metered, because
/// there is no user list for an embedder to read counters from.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_hysteria2_password_still_works() {
    let mut checks = Checks::new("hysteria2 in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let hy = free_addr();
    engine
        .add_inbound(classic(
            "hy2",
            hysteria2_inbound_with_password(hy, "supersecret", true),
        ))
        .await
        .expect("a classic hysteria2 inbound should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "hy2").users,
        None,
    );
    checks.that(
        "and has no users to list",
        engine.list_users("hy2").is_err(),
    );

    checks.eq(
        "the configured password reaches the sink",
        hy2::reach(hy, "supersecret", sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "any other password is refused",
        hy2::denied(hy, "hunter2", sink.address).await,
    );
    checks.that(
        "udp works on the classic path too",
        hy2::udp_roundtrip(hy, "supersecret", echo.address, Duration::from_secs(5)).await,
    );

    checks.finish();
}
