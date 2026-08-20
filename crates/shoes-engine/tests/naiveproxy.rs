//! NaiveProxy acceptance: multi-user through HTTP Basic, and metering across a spawn.
//!
//! NaiveProxy's credential is the plainest in this crate — base64 of
//! `username:password` in a `proxy-authorization` header — and its accounting is the
//! trickiest, for a reason that has nothing to do with the credential.
//!
//! Every other TCP protocol here authenticates *inline on the task that accepted the
//! connection*, so the meter's task local reaches it. NaiveProxy does not: hyper owns
//! the task from `serve_connection` onward, and the credential is not read until a
//! request arrives on it. Task locals do not cross `tokio::spawn`, so the context is
//! captured before the spawn and carried in the service config instead. Section 4 is
//! what would catch that being got wrong — and it would be got wrong *silently*, with
//! every byte still flowing correctly and every user's counters sitting at zero.
//!
//! The other thing worth stating: the user's `id` is the **username half of the
//! credential**. `UserSpec` has no `username` field, and adding one for a single
//! protocol is a worse trade than saying plainly that on a naive inbound the id is
//! part of the credential — so renaming a user rotates it, which section 6 pins.
//!
//! One H2 connection carries many CONNECTs, so as with Hysteria2 and TUIC the billing
//! unit is the connection rather than the request.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;

const ALICE_PASSWORD: &str = "alice-password";
const BOB_PASSWORD: &str = "bob-password";

/// Users registered between alice and bob, so neither sits at an edge of the table.
const FILLER: usize = 8;

#[tokio::test(flavor = "multi_thread")]
async fn naive_users_are_found_by_their_basic_credential() {
    let mut checks = Checks::new("naiveproxy basic authentication");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let naive = free_addr();
    engine
        .add_inbound(dynamic("naive", tls_naive_inbound(naive, true)))
        .await
        .expect("a naive inbound with an empty user list should start");

    let alice_leg = start_leg(
        &engine,
        "alice-leg",
        tls_naive_chain(naive, "alice", ALICE_PASSWORD),
    )
    .await;
    let bob_leg = start_leg(
        &engine,
        "bob-leg",
        tls_naive_chain(naive, "bob", BOB_PASSWORD),
    )
    .await;
    // The right password under the wrong username, which must be as dead as a wrong
    // password: the credential is the pair, base64'd together.
    let mixed_leg = start_leg(
        &engine,
        "mixed-leg",
        tls_naive_chain(naive, "bob", ALICE_PASSWORD),
    )
    .await;

    // -- 1. an empty registry authenticates nobody ------------------------------
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "naive" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        denied(alice_leg, sink.address).await,
    );

    // -- 2. a crowd, so a hit has to be the right entry --------------------------
    checks.section("2. users added at runtime");
    engine
        .add_user("naive", password_user("alice", ALICE_PASSWORD))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user(
                "naive",
                password_user(&format!("filler-{n}"), &format!("filler-{n}-password")),
            )
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("naive", password_user("bob", BOB_PASSWORD))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("naive").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. the pair authenticates, neither half alone ---------------------------
    checks.section("3. each credential reaches the proxy");
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
        "alice's password under bob's username is refused",
        denied(mixed_leg, sink.address).await,
    );

    // -- 4. traffic lands on the authenticated user ------------------------------
    //
    // The section this suite exists for. The meter's task local cannot reach the
    // hyper task that reads the credential, so if the context were not captured
    // before the spawn every number below would be zero while the transfer itself
    // still succeeded.
    checks.section("4. attribution across the hyper spawn");
    let alice_before = quiet(&engine, "naive", "alice").await;
    let bob_before = quiet(&engine, "naive", "bob").await;

    transfer(alice_leg, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "naive", "alice").await;
    let bob_after = quiet(&engine, "naive", "bob").await;
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
        "alice's connection was counted",
        alice_after.total_conns > alice_before.total_conns,
        format!(
            "{} -> {}",
            alice_before.total_conns, alice_after.total_conns
        ),
    );

    // -- 5. a miss is billed to nobody ------------------------------------------
    checks.section("5. failed attempts are billed to nobody");
    let filler_zero = quiet(&engine, "naive", "filler-0").await;
    checks.eq(
        "a user nobody named has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 6. the id is half the credential ---------------------------------------
    checks.section("6. renaming rotates the credential");
    let renamed_leg = start_leg(
        &engine,
        "renamed-leg",
        tls_naive_chain(naive, "bob-renamed", BOB_PASSWORD),
    )
    .await;
    engine
        .add_user("naive", password_user("bob-renamed", BOB_PASSWORD))
        .expect("adding bob under a new id should be accepted");
    checks.that(
        "the new id works",
        reach(renamed_leg, sink.address).await.is_ok(),
    );
    checks.that(
        "and the old one still does, because it is a separate user",
        reach(bob_leg, sink.address).await.is_ok(),
    );
    checks.that(
        "removing the old id revokes it",
        engine.remove_user("naive", "bob").is_ok(),
    );
    checks.that(
        "the old credential no longer authenticates",
        denied(bob_leg, sink.address).await,
    );

    // -- 7. rotating a password ---------------------------------------------------
    checks.section("7. rotating a password revokes the old one");
    let rotated_leg = start_leg(
        &engine,
        "rotated-leg",
        tls_naive_chain(naive, "bob-renamed", "bob-second-password"),
    )
    .await;
    engine
        .add_user("naive", password_user("bob-renamed", "bob-second-password"))
        .expect("rotating the password should be accepted");
    checks.that(
        "the new password works",
        reach(rotated_leg, sink.address).await.is_ok(),
    );
    checks.that(
        "the old one does not",
        denied(renamed_leg, sink.address).await,
    );

    // -- 8. a disabled user looks absent ---------------------------------------
    checks.section("8. disabled users");
    engine
        .add_user(
            "naive",
            disabled_password_user("bob-renamed", "bob-second-password"),
        )
        .expect("re-adding bob as disabled should be accepted");
    let bob_disabled = quiet(&engine, "naive", "bob-renamed").await;
    checks.that(
        "bob is refused while disabled",
        denied(rotated_leg, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine
            .get_user("naive", "bob-renamed")
            .map(|u| u.total_conns)
            .ok(),
        Some(bob_disabled.total_conns),
    );
    checks.that(
        "alice is unaffected",
        reach(alice_leg, sink.address).await.is_ok(),
    );

    // -- 9. removal is forward-looking only ------------------------------------
    checks.section("9. removing a user leaves their open connection alone");
    let mut held = Socks::connect(alice_leg, sink.address)
        .await
        .expect("alice should open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    checks.that(
        "alice is removed",
        engine.remove_user("naive", "alice").is_ok(),
    );
    checks.that(
        "a new alice connection is refused",
        denied(alice_leg, sink.address).await,
    );

    held.write_all(b"o\n").await.expect("send the second half");
    checks.eq(
        "alice's already-open connection still completes",
        read_line(&mut held).await.ok(),
        Some("sink".to_string()),
    );

    checks.finish();
}

/// A dynamic NaiveProxy inbound may not carry users of its own.
///
/// It also must not panic on an empty registry, which is what `UserLookup::new`'s
/// `assert!(!credentials.is_empty())` used to do -- on the very first thing an
/// operator would try.
#[tokio::test(flavor = "multi_thread")]
async fn a_dynamic_naive_inbound_starts_with_no_users_at_all() {
    let mut checks = Checks::new("naiveproxy credential eligibility");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    checks.section("1. an empty registry starts rather than panicking");
    let naive = free_addr();
    checks.that(
        "an inbound with no users at all comes up",
        engine
            .add_inbound(dynamic("naive", tls_naive_inbound(naive, false)))
            .await
            .is_ok(),
    );
    let leg = start_leg(
        &engine,
        "leg",
        tls_naive_chain(naive, "alice", ALICE_PASSWORD),
    )
    .await;
    checks.that("and authenticates nobody", denied(leg, sink.address).await);

    checks.section("2. a declared user list is refused, not overwritten");
    checks.refused(
        "a dynamic inbound may not carry its own users",
        engine
            .add_inbound(dynamic(
                "declared",
                tls_naive_inbound_with_users(free_addr(), &[("a", "u", "p")], false),
            ))
            .await,
        "users",
    );

    checks.section("3. users need a password");
    checks.refused(
        "a uuid is refused",
        engine.add_user(
            "naive",
            user("alice", "b85798ef-e9dc-46a4-9a87-8da4499d36d0"),
        ),
        "does not authenticate by uuid",
    );
    checks.that(
        "a password is accepted",
        engine
            .add_user("naive", password_user("alice", ALICE_PASSWORD))
            .is_ok(),
    );
    checks.eq(
        "and now she connects",
        reach(leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );

    checks.finish();
}

/// The upstream path: an inbound whose users come from its own config.
///
/// As with AnyTLS, NaiveProxy's config is already multi-user, so classic mode has to
/// load all of them. It also has a `name` field distinct from `username`, which the
/// dynamic path collapses into the id -- here they stay separate, and the reported
/// identity is the name.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_naive_user_list_still_works() {
    let mut checks = Checks::new("naiveproxy in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let naive = free_addr();
    engine
        .add_inbound(classic(
            "naive",
            tls_naive_inbound_with_users(
                naive,
                &[
                    ("alice", "alice-user", ALICE_PASSWORD),
                    ("bob", "bob-user", BOB_PASSWORD),
                    ("carol", "carol-user", "carol-password"),
                ],
                true,
            ),
        ))
        .await
        .expect("a classic naive inbound should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "naive").users,
        None,
    );
    checks.that(
        "and has no users to list",
        engine.list_users("naive").is_err(),
    );

    for (username, password) in [
        ("alice-user", ALICE_PASSWORD),
        ("bob-user", BOB_PASSWORD),
        ("carol-user", "carol-password"),
    ] {
        let leg = start_leg(
            &engine,
            &format!("{username}-leg"),
            tls_naive_chain(naive, username, password),
        )
        .await;
        checks.eq(
            &format!("{username} reaches the sink"),
            reach(leg, sink.address).await.ok(),
            Some("sink".to_string()),
        );
    }

    let stranger = start_leg(
        &engine,
        "stranger-leg",
        tls_naive_chain(naive, "nobody", "nothing"),
    )
    .await;
    checks.that(
        "an undeclared credential is refused",
        denied(stranger, sink.address).await,
    );

    checks.finish();
}
