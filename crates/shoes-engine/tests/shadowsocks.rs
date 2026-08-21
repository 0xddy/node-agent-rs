//! Shadowsocks 2022 acceptance: multi-user through the extensible identity header.
//!
//! Shadowsocks has no user field. What it has, under the 2022 spec with an AES cipher,
//! is a block a client prefixes to its salt: `AES-ECB(identity_subkey, blake3(uPSK))`,
//! where the subkey is derived from the *inbound's* PSK and the salt. The server
//! decrypts one block and looks the sixteen bytes up in its table.
//!
//! That arrangement puts two secrets in play at once and the failure modes all come
//! from confusing them:
//!
//! - The identity PSK is written in the inbound's config and names the *inbound*. It is
//!   not a credential and not a session key, so it must never be accepted as one --
//!   which is what a client that sends no identity header would be asking for.
//! - The user's PSK arrives named rather than sent, and it is what the session keys are
//!   derived from. Deriving them from the identity PSK instead would produce a server
//!   that authenticates correctly and then cannot decrypt anything.
//!
//! Neither is visible from a single-user test: with one key both roles collapse onto
//! the same bytes and every mix-up still works.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;

/// The inbound's own key. Every client below sends it as its outermost identity key.
const IDENTITY: &str = "inbound-identity";
const CIPHER: &str = "aes-128-gcm";
const KEY_LEN: usize = 16;

/// Users registered between alice and bob, so neither sits at an edge of the table.
const FILLER: usize = 8;

#[tokio::test(flavor = "multi_thread")]
async fn shadowsocks_users_are_found_by_their_identity_header() {
    let mut checks = Checks::new("shadowsocks 2022 identity headers");

    let engine = engine().await;
    let sink = Sink::start("sink").await;
    let echo = UdpEcho::start().await;

    let identity = psk(IDENTITY, KEY_LEN);
    let alice_key = psk("alice", KEY_LEN);
    let bob_key = psk("bob", KEY_LEN);
    let stranger_key = psk("stranger", KEY_LEN);

    let ss = free_addr();
    engine
        .add_inbound(dynamic("ss", ss_inbound(ss, CIPHER, &identity, true)))
        .await
        .expect("a 2022 shadowsocks inbound with an empty user list should start");

    let alice_leg = start_leg(
        &engine,
        "leg-alice",
        ss_chain(ss, CIPHER, &identity, &alice_key, true),
    )
    .await;
    let bob_leg = start_leg(
        &engine,
        "leg-bob",
        ss_chain(ss, CIPHER, &identity, &bob_key, true),
    )
    .await;
    let stranger_leg = start_leg(
        &engine,
        "leg-stranger",
        ss_chain(ss, CIPHER, &identity, &stranger_key, true),
    )
    .await;
    // Knows the inbound's key and sends no identity header -- an ordinary single-user
    // client, which is exactly what a fallback to `self.key` would let in.
    let bare_leg = start_leg(
        &engine,
        "leg-bare",
        ss_chain_without_identity(ss, CIPHER, &identity, true),
    )
    .await;

    // -- 1. an empty registry authenticates nobody ------------------------------
    checks.section("1. an empty registry authenticates nobody");
    checks.that(
        "the inbound is listed with zero users",
        engine
            .list_inbounds()
            .iter()
            .any(|i| i.tag == "ss" && i.users == Some(0)),
    );
    checks.that(
        "alice cannot connect before she is added",
        denied(alice_leg, sink.address).await,
    );
    checks.that(
        "and neither can a client holding the inbound's own key",
        denied(bare_leg, sink.address).await,
    );

    // -- 2. a crowd, so a hit has to be the right entry --------------------------
    checks.section("2. users added at runtime");
    engine
        .add_user("ss", psk_user("alice", &alice_key))
        .expect("alice should be accepted");
    for n in 0..FILLER {
        engine
            .add_user(
                "ss",
                psk_user(
                    &format!("filler-{n}"),
                    &psk(&format!("filler-{n}"), KEY_LEN),
                ),
            )
            .unwrap_or_else(|e| panic!("filler-{n} should be accepted: {e}"));
    }
    engine
        .add_user("ss", psk_user("bob", &bob_key))
        .expect("bob should be accepted");
    checks.eq(
        "every user is registered",
        engine.list_users("ss").map(|u| u.len()).unwrap_or(0),
        FILLER + 2,
    );

    // -- 3. the named user is the one that gets in -------------------------------
    //
    // The session keys are derived from whichever PSK the header named. If they came
    // from the identity PSK instead, the lookup would still succeed and the very next
    // AEAD tag would fail -- so reaching the sink is what separates the two.
    checks.section("3. each user's own key carries their session");
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
        "an unregistered key is refused",
        denied(stranger_leg, sink.address).await,
    );
    checks.that(
        "the inbound's own key is still not a credential",
        denied(bare_leg, sink.address).await,
    );

    // -- 4. a miss is billed to nobody ------------------------------------------
    checks.section("4. failed attempts are billed to nobody");
    let filler_zero = quiet(&engine, "ss", "filler-0").await;
    checks.eq(
        "a user nobody named has no connections",
        filler_zero.total_conns,
        0,
    );
    checks.eq("and no traffic", (filler_zero.tx, filler_zero.rx), (0, 0));

    // -- 5. traffic lands on the named user -------------------------------------
    checks.section("5. attribution");
    let alice_before = quiet(&engine, "ss", "alice").await;
    let bob_before = quiet(&engine, "ss", "bob").await;

    transfer(alice_leg, sink.address, 1024, 8192)
        .await
        .expect("alice should be able to move bytes");

    let alice_after = quiet(&engine, "ss", "alice").await;
    let bob_after = quiet(&engine, "ss", "bob").await;
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

    // -- 6. udp rides the same stream, so it needs no second lookup --------------
    //
    // shoes has no standalone shadowsocks UDP server: datagrams travel UDP-over-TCP
    // inside the stream the identity header opened. So this is a check that the one
    // resolution at handshake covers both directions of both transports.
    checks.section("6. udp");
    let udp_before = quiet(&engine, "ss", "alice").await;
    checks.that(
        "a datagram makes the round trip",
        udp_roundtrip(alice_leg, echo.address, Duration::from_secs(5)).await,
    );
    let udp_after = quiet(&engine, "ss", "alice").await;
    let (udp_tx, udp_rx) = delta(&udp_before, &udp_after);
    checks.detail(
        "the datagram was counted on alice's record",
        udp_tx > 0 && udp_rx > 0,
        format!("tx={udp_tx} rx={udp_rx}"),
    );

    // -- 7. a disabled user looks absent ---------------------------------------
    checks.section("7. disabled users");
    let mut disabled = psk_user("bob", &bob_key);
    disabled.enabled = false;
    engine
        .add_user("ss", disabled)
        .expect("re-adding bob as disabled should be accepted");
    checks.that(
        "bob is refused while disabled",
        denied(bob_leg, sink.address).await,
    );
    checks.eq(
        "a refused attempt did not count as a connection",
        engine.get_user("ss", "bob").map(|u| u.total_conns).ok(),
        Some(bob_after.total_conns),
    );
    checks.that(
        "alice is unaffected",
        reach(alice_leg, sink.address).await.is_ok(),
    );
    engine
        .add_user("ss", psk_user("bob", &bob_key))
        .expect("re-enabling bob should be accepted");
    checks.that(
        "bob works again once re-enabled",
        reach(bob_leg, sink.address).await.is_ok(),
    );

    // -- 8. removal is forward-looking only ------------------------------------
    checks.section("8. removing a user leaves their open connection alone");
    let mut held = Socks::connect(bob_leg, sink.address)
        .await
        .expect("bob should be able to open a connection");
    held.write_all(b"wh").await.expect("send half a request");
    tokio::time::sleep(Duration::from_millis(200)).await;

    checks.that("bob is removed", engine.remove_user("ss", "bob").is_ok());
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

    checks.finish();
}

/// Rotating a user's key: the old one has to stop working the moment the new one
/// starts, and the user's counters have to survive.
///
/// The 2022 index is keyed on `blake3(uPSK)`, so a rotation changes the key the table
/// is indexed under. An implementation that inserted the new name without retiring the
/// old would leave a revoked key working indefinitely, and nothing about the user's
/// listing would show it.
#[tokio::test(flavor = "multi_thread")]
async fn rotating_a_psk_revokes_the_old_one() {
    let mut checks = Checks::new("shadowsocks key rotation");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let identity = psk(IDENTITY, KEY_LEN);
    let first = psk("alice-first", KEY_LEN);
    let second = psk("alice-second", KEY_LEN);

    let ss = free_addr();
    engine
        .add_inbound(dynamic("ss", ss_inbound(ss, CIPHER, &identity, false)))
        .await
        .expect("the inbound should start");

    let old_leg = start_leg(
        &engine,
        "leg-old",
        ss_chain(ss, CIPHER, &identity, &first, false),
    )
    .await;
    let new_leg = start_leg(
        &engine,
        "leg-new",
        ss_chain(ss, CIPHER, &identity, &second, false),
    )
    .await;

    engine
        .add_user("ss", psk_user("alice", &first))
        .expect("alice should be accepted");
    checks.that(
        "alice's first key works",
        reach(old_leg, sink.address).await.is_ok(),
    );
    transfer(old_leg, sink.address, 512, 512)
        .await
        .expect("alice should be able to move bytes");
    let before = quiet(&engine, "ss", "alice").await;
    checks.that("her traffic was counted", before.tx > 0 && before.rx > 0);

    engine
        .add_user("ss", psk_user("alice", &second))
        .expect("rotating alice's key should be accepted");
    checks.eq(
        "she is still one user",
        engine.list_users("ss").map(|u| u.len()).unwrap_or(0),
        1,
    );
    checks.that(
        "the retired key is refused",
        denied(old_leg, sink.address).await,
    );
    checks.that(
        "the new key works",
        reach(new_leg, sink.address).await.is_ok(),
    );

    let after = quiet(&engine, "ss", "alice").await;
    checks.that(
        "her counters carried over",
        after.tx >= before.tx && after.rx >= before.rx,
    );

    // A second user cannot claim the key alice is using.
    checks.refused(
        "a duplicate key is refused",
        engine.add_user("ss", psk_user("bob", &second)),
        "alice",
    );

    checks.finish();
}

/// The refusals: which shadowsocks inbounds may take a `users` list at all.
///
/// Only 2022 with an AES cipher can tell users apart, because only there is there a
/// construction for the identity header. Accepting `users` on any other shadowsocks
/// inbound would be fail-open -- the list would sit there unconsulted while the config
/// password kept letting everyone in.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_aes_2022_ciphers_accept_a_user_list() {
    let mut checks = Checks::new("shadowsocks registry eligibility");

    let engine = engine().await;
    let identity_16 = psk(IDENTITY, 16);
    let identity_32 = psk(IDENTITY, 32);

    checks.section("1. the two AES ciphers are registry-backed");
    for (n, (cipher, identity)) in [("aes-128-gcm", &identity_16), ("aes-256-gcm", &identity_32)]
        .into_iter()
        .enumerate()
    {
        let tag = format!("aes-{n}");
        let result = engine
            .add_inbound(dynamic(
                &tag,
                ss_inbound(free_addr(), cipher, identity, false),
            ))
            .await;
        checks.detail(
            &format!("{cipher} accepts a user list"),
            result.is_ok(),
            format!("{result:?}"),
        );
    }

    checks.section("2. the key length has to match the cipher");
    // 2022 keys are raw material, so a 16 byte key is not a short aes-256-gcm key --
    // it is one that cipher can never load. Refused when the user is added, not at a
    // handshake nobody is watching.
    checks.refused(
        "a 32 byte psk on an aes-128-gcm inbound is refused",
        engine.add_user("aes-0", psk_user("alice", &psk("alice", 32))),
        "16 byte psk",
    );
    checks.refused(
        "and a 16 byte psk on an aes-256-gcm inbound",
        engine.add_user("aes-1", psk_user("alice", &psk("alice", 16))),
        "32 byte psk",
    );
    checks.that(
        "the right length is accepted",
        engine
            .add_user("aes-1", psk_user("alice", &psk("alice", 32)))
            .is_ok(),
    );

    checks.section("3. everything else is refused a user list");
    // chacha20 has no bare-block construction to build an identity header from, and
    // legacy shadowsocks has no header at all. Both stay single-user.
    //
    // The two are refused by different checks, and the messages say so. chacha20 is
    // named as a target that cannot act on a registry -- the check that also covers
    // it sharing an inbound with a protocol that can -- while legacy shadowsocks
    // falls out of the broader "nothing here authenticates through the registry".
    checks.refused(
        "2022 chacha20 cannot take users",
        engine
            .add_inbound(dynamic(
                "chacha",
                ss_inbound(free_addr(), "chacha20-ietf-poly1305", &identity_32, false),
            ))
            .await,
        "only the aes ciphers carry the identity header",
    );
    checks.refused(
        "legacy shadowsocks cannot take users",
        engine
            .add_inbound(dynamic(
                "legacy",
                serde_json::json!({
                    "address": free_addr().to_string(),
                    "protocol": {"type": "ss", "cipher": "aes-256-gcm", "password": "hunter2"},
                }),
            ))
            .await,
        "user registry",
    );

    checks.finish();
}

/// The upstream path: a single-user 2022 inbound whose key comes from its own config.
///
/// The multi-user work put a branch in front of `setup_server_stream` and changed how
/// the client writes its salt. This is the check that neither disturbed the ordinary
/// case, where there is no identity header and the config key *is* the session key.
#[tokio::test(flavor = "multi_thread")]
async fn a_config_declared_shadowsocks_key_still_works() {
    let mut checks = Checks::new("shadowsocks in classic mode");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let key = psk("classic", KEY_LEN);
    let other = psk("other", KEY_LEN);

    let ss = free_addr();
    engine
        .add_inbound(classic("ss", ss_inbound(ss, CIPHER, &key, true)))
        .await
        .expect("a classic 2022 inbound should start");

    checks.eq(
        "the inbound reports no registry",
        info(&engine, "ss").users,
        None,
    );

    let good_leg = start_leg(
        &engine,
        "leg-good",
        ss_chain_without_identity(ss, CIPHER, &key, true),
    )
    .await;
    let wrong_leg = start_leg(
        &engine,
        "leg-wrong",
        ss_chain_without_identity(ss, CIPHER, &other, true),
    )
    .await;

    checks.eq(
        "the configured key reaches the sink",
        reach(good_leg, sink.address).await.ok(),
        Some("sink".to_string()),
    );
    checks.that(
        "any other key is refused",
        denied(wrong_leg, sink.address).await,
    );
    checks.that(
        "udp works on the classic path too",
        udp_roundtrip(
            good_leg,
            UdpEcho::start().await.address,
            Duration::from_secs(5),
        )
        .await,
    );

    checks.finish();
}
