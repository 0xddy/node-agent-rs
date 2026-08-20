//! AnyTLS acceptance: multi-user through the SHA-256 of a password.
//!
//! AnyTLS is the third protocol here to authenticate on a password, and the third to
//! do it with a different derivation: Trojan sends 56 hex characters of SHA-224,
//! Hysteria2 sends the cleartext, AnyTLS sends 32 raw bytes of SHA-256. One
//! `password` field on a user serves all three, and each is indexed separately —
//! which is exactly what section 3 checks, because a registry that shared an index
//! between them would let a credential be accepted in a form its owner never sends.
//!
//! What makes it different in kind is the **two-stage lookup**. AnyTLS peeks at the
//! first 8 bytes of a connection and, on a miss, diverts it to a fallback destination
//! without waiting for the remaining 24 — that is what stops a prober from hanging
//! the handler. So the registry answers a question it answers for nobody else:
//! "might this be a credential?", before the credential is complete.
//!
//! That probe is deliberately *not* a lookup, and in particular it ignores whether a
//! user is enabled. Answering `false` for a suspended user would divert their
//! connections to the fallback while a live user's went to the handler, which is an
//! observable difference an attacker could use to enumerate suspensions. That
//! property is pinned by unit tests in `shoes::dynamic::static_registry` and
//! `shoes_engine::users`, because it is about where a connection is *sent* rather
//! than what it gets back, and a client cannot see the difference.
//!
//! Unlike the Hysteria2 and TUIC suites this one needs no hand-written client: shoes
//! has an AnyTLS client, so the chain is the usual socks-inbound-with-a-`client_chain`.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;

const ALICE: &str = "alice-password";
const BOB: &str = "bob-password";
const STRANGER: &str = "nobody-registered-this";

/// Users registered between alice and bob, so neither sits at an edge of the table.
const FILLER: usize = 8;

#[tokio::test(flavor = "multi_thread")]
async fn anytls_users_are_found_by_their_hashed_password() {
    let mut checks = Checks::new("anytls password authentication");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let anytls = free_addr();
    engine
        .add_inbound(dynamic("anytls", tls_anytls_inbound(anytls, true)))
        .await
        .expect("an anytls inbound with an empty user list should start");

    let alice_leg = start_leg(&engine, "alice-leg", tls_anytls_chain(anytls, ALICE, true)).await;
    let bob_leg = start_leg(&engine, "bob-leg", tls_anytls_chain(anytls, BOB, true)).await;
    let stranger_leg = start_leg(
        &engine,
        "stranger-leg",
        tls_anytls_chain(anytls, STRANGER, true),
    )
    .await;

    // -- 1. an empty registry authenticates nobody ------------------------------
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "anytls" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        denied(alice_leg, sink.address).await,
    );

    // -- 2. a crowd, so a hit has to be the right entry --------------------------
    checks.section("2. users added at runtime");
    engine
        .add_user("anytls", password_user("alice", ALICE))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user(
                "anytls",
                password_user(&format!("filler-{n}"), &format!("filler-{n}-password")),
            )
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("anytls", password_user("bob", BOB))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("anytls").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. each password authenticates its own user -----------------------------
    checks.section("3. each password reaches the proxy");
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
    checks.that(
        "an unregistered password is refused",
        denied(stranger_leg, sink.address).await,
    );

    // -- 4. a miss is billed to nobody ------------------------------------------
    checks.section("4. failed attempts are billed to nobody");
    let filler_zero = quiet(&engine, "anytls", "filler-0").await;
    checks.eq(
        "a user nobody named has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 5. traffic lands on the authenticated user ------------------------------
    //
    // AnyTLS authenticates inline, before it spawns its session, so the task local
    // reaches the meter and the TLS handshake read before the credential is handed
    // over to whoever turns out to own it.
    checks.section("5. attribution");
    let alice_before = quiet(&engine, "anytls", "alice").await;
    let bob_before = quiet(&engine, "anytls", "bob").await;

    transfer(alice_leg, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "anytls", "alice").await;
    let bob_after = quiet(&engine, "anytls", "bob").await;
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
    checks.detail(
        "the TLS handshake was handed over rather than dropped",
        alice_rx > 1024 + 32,
        format!("rx={alice_rx} for a 1024 byte upload plus a 32 byte credential"),
    );

    // -- 6. udp over tcp --------------------------------------------------------
    checks.section("6. udp");
    let udp_before = quiet(&engine, "anytls", "alice").await;
    checks.that(
        "a datagram makes the round trip",
        udp_roundtrip(alice_leg, echo.address, Duration::from_secs(5)).await,
    );
    let udp_after = quiet(&engine, "anytls", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    checks.detail(
        "and was counted on alice's record",
        udp_tx > 0 && udp_rx > 0,
        format!("tx={udp_tx} rx={udp_rx}"),
    );

    // -- 7. a disabled user looks absent ---------------------------------------
    checks.section("7. disabled users");
    engine
        .add_user("anytls", disabled_password_user("bob", BOB))
        .expect("re-adding bob as disabled should be accepted");
    let bob_disabled = quiet(&engine, "anytls", "bob").await;
    checks.that(
        "bob is refused while disabled",
        denied(bob_leg, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine.get_user("anytls", "bob").map(|u| u.total_conns).ok(),
        Some(bob_disabled.total_conns),
    );
    checks.that(
        "alice is unaffected",
        reach(alice_leg, sink.address).await.is_ok(),
    );
    engine
        .add_user("anytls", password_user("bob", BOB))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        reach(bob_leg, sink.address).await.is_ok(),
    );

    // -- 8. rotation -----------------------------------------------------------
    //
    // The hash is the index key and its prefix is a second one, so a rotation has two
    // things to retire. A stale prefix would not be visible from here -- it only
    // decides whether the handler keeps reading -- but a stale hash would.
    checks.section("8. rotating a password revokes the old one");
    let rotated_leg = start_leg(
        &engine,
        "rotated-leg",
        tls_anytls_chain(anytls, "bob-second-password", true),
    )
    .await;
    engine
        .add_user("anytls", password_user("bob", "bob-second-password"))
        .expect("rotating bob's password should be accepted");
    checks.that(
        "the new password works",
        reach(rotated_leg, sink.address).await.is_ok(),
    );
    checks.that("the old one does not", denied(bob_leg, sink.address).await);
    checks.eq(
        "and it is still the same bob underneath",
        engine.list_users("anytls").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 9. removal is forward-looking only ------------------------------------
    checks.section("9. removing a user leaves their open connection alone");
    let mut held = Socks::connect(rotated_leg, sink.address)
        .await
        .expect("bob should open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    checks.that(
        "bob is removed",
        engine.remove_user("anytls", "bob").is_ok(),
    );
    checks.that(
        "a new bob connection is refused",
        denied(rotated_leg, sink.address).await,
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

    checks.finish();
}

/// A dynamic AnyTLS inbound may not carry users of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_dynamic_anytls_inbound_takes_only_passwords() {
    let mut checks = Checks::new("anytls credential eligibility");

    let engine = engine().await;

    checks.section("1. a declared user list is refused, not overwritten");
    checks.refused(
        "a dynamic inbound may not carry its own users",
        engine
            .add_inbound(dynamic(
                "declared",
                tls_anytls_inbound_with_users(free_addr(), &[("alice", "hunter2")], false),
            ))
            .await,
        "users",
    );

    checks.section("2. users need a password and nothing else");
    let anytls = free_addr();
    engine
        .add_inbound(dynamic("anytls", tls_anytls_inbound(anytls, false)))
        .await
        .expect("the inbound should start");
    checks.refused(
        "a uuid is refused",
        engine.add_user(
            "anytls",
            user("alice", "b85798ef-e9dc-46a4-9a87-8da4499d36d0"),
        ),
        "does not authenticate by uuid",
    );
    checks.that(
        "a password is accepted",
        engine
            .add_user("anytls", password_user("alice", ALICE))
            .is_ok(),
    );
    checks.refused(
        "and a second user may not claim it",
        engine.add_user("anytls", password_user("mallory", ALICE)),
        "alice",
    );

    checks.finish();
}

/// The upstream path: an inbound whose users come from its own config.
///
/// AnyTLS is the first protocol converted whose config was *already* multi-user, so
/// this checks more than the single-user fallback the others needed: every user the
/// config declares has to end up in the static registry, or a plain YAML deployment
/// would silently lose all but one of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_anytls_user_list_still_works() {
    let mut checks = Checks::new("anytls in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let anytls = free_addr();
    engine
        .add_inbound(classic(
            "anytls",
            tls_anytls_inbound_with_users(
                anytls,
                &[("alice", ALICE), ("bob", BOB), ("carol", "carol-password")],
                true,
            ),
        ))
        .await
        .expect("a classic anytls inbound should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "anytls").users,
        None,
    );
    checks.that(
        "and has no users to list",
        engine.list_users("anytls").is_err(),
    );

    for (name, password) in [("alice", ALICE), ("bob", BOB), ("carol", "carol-password")] {
        let leg = start_leg(
            &engine,
            &format!("{name}-leg"),
            tls_anytls_chain(anytls, password, true),
        )
        .await;
        checks.eq(
            &format!("{name} reaches the sink"),
            reach(leg, sink.address).await.ok(),
            Some("sink".to_string()),
        );
    }

    let stranger = start_leg(
        &engine,
        "stranger-leg",
        tls_anytls_chain(anytls, STRANGER, true),
    )
    .await;
    checks.that(
        "an undeclared password is refused",
        denied(stranger, sink.address).await,
    );

    checks.finish();
}
