//! TUIC v5 acceptance: multi-user through a uuid and the password its token is keyed
//! with.
//!
//! TUIC is the first credential in this crate that is two values at once, and the
//! only one where finding the user is not the same thing as authenticating them.
//!
//! `AUTHENTICATE` carries a uuid in cleartext and, beside it, 32 bytes produced from
//! that user's password *and* the QUIC connection's exported keying material. So the
//! registry cannot answer yes or no: it answers "this uuid belongs to alice, whose
//! password is X", and the handler derives the expected token and decides. Three
//! consequences shape this suite:
//!
//! - Half a credential must authenticate nobody. A uuid alone is public -- it goes
//!   over the wire in the clear -- so section 3 checks that a right uuid with a wrong
//!   password is refused just as firmly as an unknown uuid, and that a user added
//!   with only one of the two is refused outright.
//! - The lookup deliberately does not count the authentication, because it happens
//!   before the token is checked. Section 4 is what would catch that being counted
//!   anyway: a stranger's uuid, or a live user's uuid with the wrong password, must
//!   leave `total_conns` untouched.
//! - As with Hysteria2, a connection is the billing unit rather than a stream, and
//!   the accounting context cannot ride a task local because each of the server's
//!   four loops runs in a task of its own. Sections 6 and 7 cover both UDP relay
//!   modes, which are separate code paths: `native` rides QUIC datagrams, `quic`
//!   rides uni streams.
//!
//! There is no TUIC client in shoes to build the far half of the chain from, so these
//! tests speak QUIC and TUIC directly. See [`common::tuic`].

mod common;

use std::time::Duration;

use common::tuic as tu;
use common::*;

const ALICE_UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
const ALICE_PASSWORD: &str = "alice-password";
const BOB_UUID: &str = "11111111-1111-4111-8111-111111111111";
const BOB_PASSWORD: &str = "bob-password";
const STRANGER_UUID: &str = "22222222-2222-4222-8222-222222222222";

/// Users registered between alice and bob, so neither sits at an edge of the table.
const FILLER: usize = 8;

fn filler_uuid(n: usize) -> String {
    format!("3333333{n}-3333-4333-8333-333333333333")
}

#[tokio::test(flavor = "multi_thread")]
async fn tuic_users_are_found_by_their_uuid_and_password() {
    let mut checks = Checks::new("tuic uuid + password authentication");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let tuic = free_addr();
    engine
        .add_inbound(dynamic("tuic", tuic_inbound(tuic)))
        .await
        .expect("a tuic inbound with an empty user list should start");

    // -- 1. an empty registry authenticates nobody ------------------------------
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "tuic" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        tu::denied(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address).await,
    );
    checks.that(
        "and it has an empty user list rather than no list at all",
        engine
            .list_users("tuic")
            .map(|u| u.is_empty())
            .unwrap_or(false),
    );

    // -- 2. a crowd, so a hit has to be the right entry --------------------------
    checks.section("2. users added at runtime");
    engine
        .add_user("tuic", tuic_user("alice", ALICE_UUID, ALICE_PASSWORD))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user(
                "tuic",
                tuic_user(
                    &format!("filler-{n}"),
                    &filler_uuid(n),
                    &format!("filler-{n}-password"),
                ),
            )
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("tuic", tuic_user("bob", BOB_UUID, BOB_PASSWORD))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("tuic").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. both halves are needed, and only together ----------------------------
    checks.section("3. each credential reaches the proxy, and half of one does not");
    checks.eq(
        "alice reaches the sink",
        tu::reach(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address)
            .await
            .ok(),
        Some("sink".to_string()),
    );
    checks.eq(
        "bob reaches the sink",
        tu::reach(tuic, BOB_UUID, BOB_PASSWORD, sink.address)
            .await
            .ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "an unregistered uuid is refused",
        tu::denied(tuic, STRANGER_UUID, ALICE_PASSWORD, sink.address).await,
    );
    // The sharp one. The uuid is not a secret -- it crosses the wire in cleartext --
    // so an implementation that authenticated on it alone would pass every other
    // check in this file while letting anyone in who had watched a handshake.
    checks.that(
        "alice's uuid with the wrong password is refused",
        tu::denied(tuic, ALICE_UUID, BOB_PASSWORD, sink.address).await,
    );
    checks.that(
        "and alice's password under bob's uuid is refused",
        tu::denied(tuic, BOB_UUID, ALICE_PASSWORD, sink.address).await,
    );
    // A prefix must not match: the token is derived from the whole value.
    checks.that(
        "a prefix of alice's password is refused",
        tu::denied(tuic, ALICE_UUID, &ALICE_PASSWORD[..6], sink.address).await,
    );

    // -- 4. a miss is billed to nobody ------------------------------------------
    //
    // The registry finds a user before the token is checked, so this is where a
    // `note_auth` in the wrong place would show up: alice's record would count every
    // stranger who guessed her uuid.
    checks.section("4. failed attempts are billed to nobody");
    let alice_probed = quiet(&engine, "tuic", "alice").await;
    checks.that(
        "a wrong password against alice's uuid is still refused",
        tu::denied(tuic, ALICE_UUID, "not-her-password", sink.address).await,
    );
    let alice_after_probe = quiet(&engine, "tuic", "alice").await;
    checks.eq(
        "and did not count as one of alice's connections",
        alice_after_probe.total_conns,
        alice_probed.total_conns,
    );
    checks.eq(
        "nor did it move any of her bytes",
        delta(&alice_probed, &alice_after_probe),
        (0, 0),
    );

    let filler_zero = quiet(&engine, "tuic", "filler-0").await;
    checks.eq(
        "a user nobody named has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 5. traffic lands on the authenticated user ------------------------------
    checks.section("5. attribution");
    let alice_before = quiet(&engine, "tuic", "alice").await;
    let bob_before = quiet(&engine, "tuic", "bob").await;

    tu::transfer(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "tuic", "alice").await;
    let bob_after = quiet(&engine, "tuic", "bob").await;
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

    // -- 6. udp over datagrams -- TUIC's `native` relay mode ---------------------
    //
    // Not a stream, so there is nothing for the meter wrapper to sit on: quinn owns
    // the datagram and the loop that builds one is the only place its size is known.
    // Both of those loops run in tasks of their own, which is why the context is
    // handed to them explicitly -- and why this section would go quietly to zero if
    // it were not.
    checks.section("6. udp in native mode (datagrams)");
    let udp_before = quiet(&engine, "tuic", "alice").await;
    checks.that(
        "a datagram makes the round trip",
        tu::udp_roundtrip(
            tuic,
            ALICE_UUID,
            ALICE_PASSWORD,
            echo.address,
            Duration::from_secs(5),
        )
        .await,
    );
    let udp_after = quiet(&engine, "tuic", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    checks.detail(
        "the datagram was counted on alice's record",
        udp_tx > 0 && udp_rx > 0,
        format!("tx={udp_tx} rx={udp_rx}"),
    );

    // A burst, to show the count tracks volume rather than being a fixed cost paid
    // once. The bounds are loose on purpose: what is counted is datagram length,
    // which includes the session and address headers but not QUIC's own per-packet
    // overhead, so the exact figure is not something a test should pin down. The
    // upper bound is the interesting half -- it is what catches double counting.
    let burst_before = quiet(&engine, "tuic", "alice").await;
    let echoed = tu::udp_burst(tuic, ALICE_UUID, ALICE_PASSWORD, echo.address, 512, 8)
        .await
        .expect("a burst of datagrams should be carried");
    let burst_after = quiet(&engine, "tuic", "alice").await;
    let (burst_tx, burst_rx) = delta(&burst_before, &burst_after);
    checks.eq("all eight datagrams came back", echoed, 8);
    checks.within("the upload is near 8x512", burst_rx, 4096, 6144);
    checks.within("and so is the download", burst_tx, 4096, 6144);

    // -- 7. udp over uni streams -- TUIC's `quic` relay mode ---------------------
    //
    // A different code path end to end: the client's packet arrives on a stream it
    // opened, and the reply goes out on one the *server* opens. Both are metered by
    // wrapping the stream rather than by counting explicitly, so a suite that stopped
    // at section 6 would leave that half unproven.
    checks.section("7. udp in quic mode (uni streams)");
    let stream_udp_before = quiet(&engine, "tuic", "alice").await;
    checks.that(
        "a packet makes the round trip over uni streams",
        tu::udp_stream_roundtrip(
            tuic,
            ALICE_UUID,
            ALICE_PASSWORD,
            echo.address,
            Duration::from_secs(5),
        )
        .await,
    );
    let stream_udp_after = quiet(&engine, "tuic", "alice").await;
    let (stream_udp_tx, stream_udp_rx) = delta(&stream_udp_before, &stream_udp_after);
    checks.detail(
        "it was counted on alice's record in both directions",
        stream_udp_tx > 0 && stream_udp_rx > 0,
        format!("tx={stream_udp_tx} rx={stream_udp_rx}"),
    );

    // -- 8. a disabled user looks absent ---------------------------------------
    checks.section("8. disabled users");
    engine
        .add_user("tuic", disabled_tuic_user("bob", BOB_UUID, BOB_PASSWORD))
        .expect("re-adding bob as disabled should be accepted");
    let bob_disabled = quiet(&engine, "tuic", "bob").await;
    checks.that(
        "bob is refused while disabled",
        tu::denied(tuic, BOB_UUID, BOB_PASSWORD, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine.get_user("tuic", "bob").map(|u| u.total_conns).ok(),
        Some(bob_disabled.total_conns),
    );
    checks.that(
        "alice is unaffected",
        tu::reach(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address)
            .await
            .is_ok(),
    );
    engine
        .add_user("tuic", tuic_user("bob", BOB_UUID, BOB_PASSWORD))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        tu::reach(tuic, BOB_UUID, BOB_PASSWORD, sink.address)
            .await
            .is_ok(),
    );

    // -- 9. removal is forward-looking only ------------------------------------
    //
    // TUIC resolves a user once, at auth, and the connection holds the context it
    // found. Removing the user takes their uuid out of the index; it does not reach
    // into a live connection, which is the smooth-handover property the whole design
    // rests on.
    checks.section("9. removing a user leaves their open connection alone");
    let held_client = tu::TuicClient::connect(tuic, BOB_UUID, BOB_PASSWORD)
        .await
        .expect("bob should be able to authenticate");
    let mut held = held_client
        .open_tcp(sink.address)
        .await
        .expect("bob should be able to open a stream");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    checks.that("bob is removed", engine.remove_user("tuic", "bob").is_ok());
    checks.that(
        "a new bob connection is refused",
        tu::denied(tuic, BOB_UUID, BOB_PASSWORD, sink.address).await,
    );
    checks.that(
        "alice still works after bob is removed",
        tu::reach(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address)
            .await
            .is_ok(),
    );

    held.write_all(b"o\n").await.expect("send the second half");
    checks.eq(
        "bob's already-open stream still completes",
        held.read_line().await.ok(),
        Some("sink".to_string()),
    );
    drop(held);
    drop(held_client);

    checks.finish();
}

/// One QUIC connection, many streams, one user.
///
/// TUIC authenticates once and then multiplexes, so `total_conns` counts QUIC
/// connections rather than handshakes-per-stream. An implementation that bound a
/// context per stream would still look right on every other check in this file.
#[tokio::test(flavor = "multi_thread")]
async fn one_connection_carries_many_streams_for_one_user() {
    let mut checks = Checks::new("tuic connection accounting");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let tuic = free_addr();
    engine
        .add_inbound(dynamic("tuic", tuic_inbound(tuic)))
        .await
        .expect("the inbound should start");
    engine
        .add_user("tuic", tuic_user("alice", ALICE_UUID, ALICE_PASSWORD))
        .expect("alice should be accepted");

    let before = quiet(&engine, "tuic", "alice").await;
    checks.eq("alice starts with no connections", before.total_conns, 0);

    let client = tu::TuicClient::connect(tuic, ALICE_UUID, ALICE_PASSWORD)
        .await
        .expect("alice should authenticate");

    let mut streams = Vec::new();
    for _ in 0..5 {
        let mut stream = client
            .open_tcp(sink.address)
            .await
            .expect("a proxied stream should open");
        stream.write_all(b"hold\n").await.expect("hold the stream");
        streams.push(stream);
    }

    checks.that(
        "the connection is counted while it is live",
        wait_for("alice's connection to register", || {
            engine
                .get_user("tuic", "alice")
                .map(|u| u.conns == 1)
                .unwrap_or(false)
        })
        .await,
    );
    checks.eq(
        "five streams over one connection is one connection",
        engine.get_user("tuic", "alice").map(|u| u.total_conns).ok(),
        Some(1),
    );

    drop(streams);
    drop(client);

    let after = quiet(&engine, "tuic", "alice").await;
    checks.eq("the connection closes cleanly", after.conns, 0);
    checks.eq("and is still counted once", after.total_conns, 1);
    checks.detail(
        "the streams' bytes all landed on alice",
        after.rx > 0,
        format!("rx={}", after.rx),
    );

    checks.finish();
}

/// Rotating either half revokes the old pair.
///
/// The two halves live in different places -- the uuid is an index key, the password
/// is carried on the entry -- so they can fail to be retired for different reasons,
/// and each needs its own check.
#[tokio::test(flavor = "multi_thread")]
async fn rotating_either_half_revokes_the_old_credential() {
    let mut checks = Checks::new("tuic credential rotation");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let tuic = free_addr();
    engine
        .add_inbound(dynamic("tuic", tuic_inbound(tuic)))
        .await
        .expect("the inbound should start");
    engine
        .add_user("tuic", tuic_user("alice", ALICE_UUID, ALICE_PASSWORD))
        .expect("alice should be accepted");

    checks.section("1. the original credential works");
    checks.that(
        "alice reaches the sink",
        tu::reach(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address)
            .await
            .is_ok(),
    );
    let before = quiet(&engine, "tuic", "alice").await;

    checks.section("2. rotating the password");
    engine
        .add_user("tuic", tuic_user("alice", ALICE_UUID, "second-password"))
        .expect("rotating alice's password should be accepted");
    checks.that(
        "the new password works",
        tu::reach(tuic, ALICE_UUID, "second-password", sink.address)
            .await
            .is_ok(),
    );
    checks.that(
        "the old one does not",
        tu::denied(tuic, ALICE_UUID, ALICE_PASSWORD, sink.address).await,
    );

    checks.section("3. rotating the uuid");
    engine
        .add_user("tuic", tuic_user("alice", STRANGER_UUID, "second-password"))
        .expect("rotating alice's uuid should be accepted");
    checks.that(
        "the new uuid works",
        tu::reach(tuic, STRANGER_UUID, "second-password", sink.address)
            .await
            .is_ok(),
    );
    checks.that(
        "the old one does not",
        tu::denied(tuic, ALICE_UUID, "second-password", sink.address).await,
    );

    checks.section("4. it is still the same user underneath");
    let after = quiet(&engine, "tuic", "alice").await;
    checks.detail(
        "alice's counters carried across both rotations",
        after.total_conns > before.total_conns && after.rx >= before.rx,
        format!(
            "total_conns {} -> {}",
            before.total_conns, after.total_conns
        ),
    );
    checks.eq(
        "and there is still exactly one alice",
        engine.list_users("tuic").map(|u| u.len()).unwrap_or(0),
        1,
    );

    checks.finish();
}

/// A TUIC user needs both fields, and the inbound may not declare either itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_dynamic_tuic_inbound_needs_both_halves() {
    let mut checks = Checks::new("tuic credential eligibility");

    let engine = engine().await;

    checks.section("1. a declared credential is refused, not overwritten");
    checks.refused(
        "a dynamic inbound may not carry its own uuid and password",
        engine
            .add_inbound(dynamic(
                "declared",
                tuic_inbound_with_credential(free_addr(), ALICE_UUID, "hunter2"),
            ))
            .await,
        "this inbound has a `users` list",
    );

    checks.section("2. users need both halves");
    let tuic = free_addr();
    engine
        .add_inbound(dynamic("tuic", tuic_inbound(tuic)))
        .await
        .expect("the inbound should start");
    checks.refused(
        "a uuid on its own is refused",
        engine.add_user("tuic", user("alice", ALICE_UUID)),
        "both `uuid` and `password`",
    );
    checks.refused(
        "a password on its own is refused",
        engine.add_user("tuic", password_user("alice", ALICE_PASSWORD)),
        "both `uuid` and `password`",
    );
    checks.refused(
        "and so is a user with no credential at all",
        engine.add_user(
            "tuic",
            shoes_engine::UserSpec {
                id: Some("nobody".to_string()),
                uuid: None,
                password: None,
                enabled: true,
            },
        ),
        "needs a credential",
    );
    checks.that(
        "the pair is accepted",
        engine
            .add_user("tuic", tuic_user("alice", ALICE_UUID, ALICE_PASSWORD))
            .is_ok(),
    );
    checks.refused(
        "a second user may not claim alice's uuid",
        engine.add_user("tuic", tuic_user("mallory", ALICE_UUID, "mallory-password")),
        "alice",
    );
    // Passwords are not index keys here -- the uuid is -- so two users sharing one is
    // not a conflict, and refusing it would be a rule with nothing behind it.
    checks.that(
        "but two users may share a password under different uuids",
        engine
            .add_user("tuic", tuic_user("bob", BOB_UUID, ALICE_PASSWORD))
            .is_ok(),
    );

    checks.finish();
}

/// The upstream path: an inbound whose uuid and password come from its own config.
///
/// The multi-user work replaced an inline comparison in the accept loop with a
/// registry lookup. In classic mode the registry is built from that same config pair,
/// so this is the check that the substitution left the single-user case behaving
/// exactly as it did -- including that such an inbound is not metered, because there
/// is no user list for an embedder to read counters from.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_tuic_credential_still_works() {
    let mut checks = Checks::new("tuic in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let tuic = free_addr();
    engine
        .add_inbound(classic(
            "tuic",
            tuic_inbound_with_credential(tuic, ALICE_UUID, "supersecret"),
        ))
        .await
        .expect("a classic tuic inbound should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "tuic").users,
        None,
    );
    checks.that(
        "and has no users to list",
        engine.list_users("tuic").is_err(),
    );

    checks.eq(
        "the configured credential reaches the sink",
        tu::reach(tuic, ALICE_UUID, "supersecret", sink.address)
            .await
            .ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "another uuid is refused",
        tu::denied(tuic, BOB_UUID, "supersecret", sink.address).await,
    );
    checks.that(
        "and so is the right uuid with another password",
        tu::denied(tuic, ALICE_UUID, "hunter2", sink.address).await,
    );
    checks.that(
        "udp works on the classic path too",
        tu::udp_roundtrip(
            tuic,
            ALICE_UUID,
            "supersecret",
            echo.address,
            Duration::from_secs(5),
        )
        .await,
    );

    checks.finish();
}
