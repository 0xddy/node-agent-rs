//! VMess acceptance: multi-user for a protocol that puts no identifier on the wire.
//!
//! Every other inbound the engine drives sends something a server can index on --
//! VLESS puts a uuid in the clear, Trojan a hex digest. VMess sends sixteen encrypted
//! bytes holding nothing but a timestamp and its checksum, so the server has no
//! choice but to try each registered user's key until one of them opens.
//!
//! That makes authentication a *search*, and a search fails in ways a lookup cannot:
//! it can stop at the first entry and never reach the rest, it can bill the users it
//! tried and rejected, and it can let anyone in by falling back to the credential
//! shoes' config schema insisted on. None of those is visible from a single-user
//! test, which is why this file works with a crowd.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;

const ALICE: &str = "11111111-1111-4111-8111-111111111111";
const BOB: &str = "22222222-2222-4222-8222-222222222222";
const STRANGER: &str = "44444444-4444-4444-8444-444444444444";

/// Users registered between alice and bob, so that neither is the first key tried.
const FILLER: usize = 16;

fn filler_uuid(n: usize) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}

#[tokio::test(flavor = "multi_thread")]
async fn vmess_users_are_found_by_trial_decryption() {
    let mut checks = Checks::new("vmess trial decryption");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let vmess = free_addr();
    engine
        .add_inbound(dynamic("vmess", vmess_inbound(vmess, true)))
        .await
        .expect("a vmess inbound with an empty user list should start");

    // Two ciphers, so a pass here says the trial found the user before either side
    // knew which cipher the payload would use.
    let alice_leg = start_leg(
        &engine,
        "leg-alice",
        vmess_chain(vmess, ALICE, "aes-128-gcm"),
    )
    .await;
    let bob_leg = start_leg(
        &engine,
        "leg-bob",
        vmess_chain(vmess, BOB, "chacha20-poly1305"),
    )
    .await;
    let stranger_leg = start_leg(
        &engine,
        "leg-stranger",
        vmess_chain(vmess, STRANGER, "aes-128-gcm"),
    )
    .await;

    // -- 1. nothing to try means nobody gets in ---------------------------------
    //
    // The sharpest check in the file, because shoes' schema requires a `user_id` on
    // a vmess inbound and the engine fills that field with a throwaway uuid it never
    // tells anyone. If the handler still consulted its own config, an inbound with
    // zero users would authenticate whoever guessed that value -- and, worse, this
    // is the one protocol where a config credential cannot be spotted in a log,
    // since nothing identifying is ever sent in the clear.
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "vmess" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        denied(alice_leg, sink.address).await,
    );

    // -- 2. a crowd, so the trial has to walk past the wrong answers -------------
    checks.section("2. users added at runtime");
    engine
        .add_user("vmess", user("alice", ALICE))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user("vmess", user(&format!("filler-{n}"), &filler_uuid(n)))
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("vmess", user("bob", BOB))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("vmess").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. both ends of the set authenticate ----------------------------------
    //
    // Alice was registered first and bob last. Neither position is special to a hash
    // lookup; to a linear trial they are the two that catch a loop which stops early
    // or never starts.
    checks.section("3. first and last are both found");
    checks.eq(
        "alice reaches the sink on aes-128-gcm",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.eq(
        "bob reaches the sink on chacha20-poly1305",
        reach(bob_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "an unregistered uuid is refused",
        denied(stranger_leg, sink.address).await,
    );

    // -- 4. a rejected trial is not a connection --------------------------------
    //
    // Every registered user's key was tried against the stranger's auth id and all of
    // them failed. A trial that noted the attempt before checking whether it
    // succeeded would leave that failure on somebody's counters -- most likely on
    // whichever entry the loop reached first.
    checks.section("4. failed attempts are billed to nobody");
    let filler_zero = quiet(&engine, "vmess", "filler-0").await;
    checks.eq(
        "a user who was only ever tried has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 5. traffic lands on the user the trial identified ----------------------
    checks.section("5. attribution");
    let alice_before = quiet(&engine, "vmess", "alice").await;
    let bob_before = quiet(&engine, "vmess", "bob").await;

    transfer(alice_leg, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "vmess", "alice").await;
    let bob_after = quiet(&engine, "vmess", "bob").await;
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

    // -- 6. udp is attributed to the same record --------------------------------
    checks.section("6. udp");
    let udp_before = quiet(&engine, "vmess", "alice").await;
    checks.that(
        "a datagram makes the round trip",
        udp_roundtrip(alice_leg, echo.address, Duration::from_secs(5)).await,
    );
    let udp_after = quiet(&engine, "vmess", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    checks.detail(
        "the datagram was counted on alice's record",
        udp_tx > 0 && udp_rx > 0,
        format!("tx={udp_tx} rx={udp_rx}"),
    );

    // -- 7. a disabled user is indistinguishable from an unknown one ------------
    //
    // For VMess this is a statement about the trial, not about a lookup: bob's key
    // still opens his auth id, so the entry has to decline *after* recognising him
    // rather than by failing to be found.
    checks.section("7. disabled users");
    engine
        .add_user("vmess", disabled_user("bob", BOB))
        .expect("re-adding bob as disabled should be accepted");
    checks.that(
        "bob is refused while disabled",
        denied(bob_leg, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine.get_user("vmess", "bob").map(|u| u.total_conns).ok(),
        Some(bob_after.total_conns),
    );
    checks.that(
        "alice is unaffected",
        reach(alice_leg, sink.address).await.is_ok(),
    );
    engine
        .add_user("vmess", user("bob", BOB))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        reach(bob_leg, sink.address).await.is_ok(),
    );

    // -- 8. removal closes existing sessions -----------------------------------
    checks.section("8. removing a user closes their open connection");
    let mut held = Socks::connect(bob_leg, sink.address)
        .await
        .expect("bob should be able to open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let removed =
        tokio::time::timeout(Duration::from_secs(5), engine.remove_user("vmess", "bob")).await;
    checks.that(
        "bob is removed after his connection drains",
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

    let closed = match held.write_all(b"o\n").await {
        Err(_) => true,
        Ok(()) => read_line(&mut held).await.is_err(),
    };
    checks.that("bob's already-open connection is actively closed", closed);
    drop(held);

    checks.finish();
}

/// The upstream path: a vmess inbound whose credential comes from its own config.
///
/// `VmessTcpServerHandler` now takes a registry where it used to hold a uuid, and in
/// classic mode the factory hands it a one-entry registry built from that same uuid.
/// This is the check that the substitution left the config-driven behaviour alone --
/// including the part where the declared user is the *only* one accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_vmess_user_still_works() {
    let mut checks = Checks::new("vmess in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vmess = free_addr();
    let mut config = vmess_inbound(vmess, true);
    config["protocol"]["user_id"] = ALICE.into();
    engine
        .add_inbound(classic("vmess", config))
        .await
        .expect("a vmess inbound declaring its own user should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "vmess").users,
        None,
    );

    let alice_leg = start_leg(
        &engine,
        "leg-alice",
        vmess_chain(vmess, ALICE, "aes-128-gcm"),
    )
    .await;
    let stranger_leg = start_leg(
        &engine,
        "leg-stranger",
        vmess_chain(vmess, STRANGER, "aes-128-gcm"),
    )
    .await;

    checks.eq(
        "the configured uuid reaches the sink",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "any other uuid is refused",
        denied(stranger_leg, sink.address).await,
    );

    checks.finish();
}

/// A recorded VMess handshake prefix must not open a second connection.
///
/// The auth id is the first sixteen bytes on the wire and it is, by construction,
/// openable by anyone who copies it -- it carries a timestamp and a checksum sealed
/// with the user's key, and nothing that proves the sender holds that key. So the
/// only thing standing between a passive observer and a connection billed to
/// somebody else is the server remembering the ids it has already admitted.
#[tokio::test(flavor = "multi_thread")]
async fn a_recorded_auth_id_cannot_be_used_twice() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    /// Sits in front of the inbound and keeps a copy of each client's first sixteen
    /// bytes, which is exactly the auth id, before passing everything through.
    async fn record_auth_ids(upstream: SocketAddr) -> (SocketAddr, mpsc::Receiver<[u8; 16]>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut server = TcpStream::connect(upstream).await?;
                    let mut auth_id = [0u8; 16];
                    client.read_exact(&mut auth_id).await?;
                    let _ = tx.send(auth_id).await;
                    server.write_all(&auth_id).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
                    Ok::<_, std::io::Error>(())
                });
            }
        });
        (address, rx)
    }

    let mut checks = Checks::new("vmess auth id replay");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let vmess = free_addr();
    engine
        .add_inbound(dynamic("vmess", vmess_inbound(vmess, true)))
        .await
        .expect("a vmess inbound should start");
    engine
        .add_user("vmess", user("alice", ALICE))
        .expect("alice should be accepted");

    let (relay, mut auth_ids) = record_auth_ids(vmess).await;
    let alice_leg = start_leg(
        &engine,
        "leg-alice",
        vmess_chain(relay, ALICE, "aes-128-gcm"),
    )
    .await;

    checks.section("1. the genuine connection works and is observed");
    checks.eq(
        "alice reaches the sink through the recorder",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    let recorded = tokio::time::timeout(Duration::from_secs(5), auth_ids.recv())
        .await
        .ok()
        .flatten()
        .expect("the recorder should have captured alice's auth id");

    checks.section("2. replaying it is refused");
    let mut replay = TcpStream::connect(vmess)
        .await
        .expect("the inbound should accept the TCP connection");
    replay
        .write_all(&recorded)
        .await
        .expect("the recorded auth id should be writable");

    // Refusal shows up as the server hanging up. Without the filter it would instead
    // sit waiting for the rest of the header until the 60 second setup deadline, so a
    // timeout here is the failure -- not a slow pass.
    let mut discard = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(10), replay.read(&mut discard)).await;
    checks.that(
        "the server hangs up on a replayed auth id",
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
    );

    checks.section("3. the user is unharmed");
    checks.eq(
        "alice can still connect afterwards",
        reach(alice_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    let alice = engine
        .get_user("vmess", "alice")
        .expect("alice is registered");
    checks.eq(
        "the refused replay was not counted as one of her connections",
        alice.total_conns,
        2,
    );

    checks.finish();
}
