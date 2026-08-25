//! Acceptance: Salamander obfuscation on a Hysteria2 inbound.
//!
//! # What is actually being proved
//!
//! That obfuscation is *applied*, not merely implemented. A unit test can only
//! show that one implementation agrees with itself; the interesting failure is
//! an obfuscation layer that is configured, reported as active, and silently
//! bypassed -- which looks identical to a working one from the server's side and
//! is only visible as "the censor still blocks us".
//!
//! So the load-bearing assertions here are the **negative** ones. A plain client
//! must not reach an obfuscated inbound, and an obfuscated client must not reach
//! a plain one. If either of those succeeds, the layer is doing nothing.
//!
//! # Why failure looks like a timeout
//!
//! Salamander sits underneath QUIC, so a mismatch is not an authentication
//! failure -- there is no authentication yet. The handshake bytes are simply
//! unintelligible, the peer discards them as malformed, and nothing is ever
//! answered. Every negative case therefore has to be bounded by a deadline
//! rather than waiting for a rejection that will never arrive.

mod common;

use std::time::Duration;

use common::*;

const PASSWORD: &str = "alice-hysteria-password";
const OBFS: &str = "salamander-shared-secret";

/// Long enough that a slow runner is not mistaken for a blocked handshake, short
/// enough that six negative cases do not dominate the suite.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(6);

/// True if the client got all the way to carrying traffic.
async fn obfuscated_reaches(
    server: std::net::SocketAddr,
    password: &str,
    obfs: &str,
    dest: std::net::SocketAddr,
    expected: &str,
) -> bool {
    let attempt = async {
        let client = hysteria2::Hysteria2Client::connect_obfuscated(server, password, obfs).await?;
        let mut stream = client.open_tcp(dest).await?;
        stream.write_all(b"who\n").await?;
        stream.read_line().await
    };
    matches!(
        tokio::time::timeout(HANDSHAKE_DEADLINE, attempt).await,
        Ok(Ok(name)) if name == expected
    )
}

/// True if a *plain* client got through.
async fn plain_reaches(
    server: std::net::SocketAddr,
    password: &str,
    dest: std::net::SocketAddr,
    expected: &str,
) -> bool {
    matches!(
        tokio::time::timeout(HANDSHAKE_DEADLINE, hysteria2::reach(server, password, dest)).await,
        Ok(Ok(name)) if name == expected
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn salamander_obfuscation_gates_the_quic_handshake() {
    let mut checks = Checks::new("hysteria2 salamander");

    let engine = engine().await;
    let sink = Sink::start("sink").await;

    let obfuscated = free_addr();
    engine
        .add_inbound(dynamic(
            "obfs",
            hysteria2_inbound_obfuscated(obfuscated, OBFS, false),
        ))
        .await
        .expect("the obfuscated hysteria2 inbound should start");
    engine
        .add_user("obfs", password_user("alice", PASSWORD))
        .expect("alice should be accepted");

    let plain = free_addr();
    engine
        .add_inbound(dynamic("plain", hysteria2_inbound(plain, false)))
        .await
        .expect("the plain hysteria2 inbound should start");
    engine
        .add_user("plain", password_user("alice", PASSWORD))
        .expect("alice should be accepted on the plain inbound too");

    // -- 1. the happy path ----------------------------------------------------
    checks.section("1. matching obfuscation carries traffic");
    checks.that(
        "an obfuscated client reaches the obfuscated inbound",
        obfuscated_reaches(obfuscated, PASSWORD, OBFS, sink.address, &sink.name).await,
    );

    // -- 2. obfuscation is actually on the wire -------------------------------
    checks.section("2. mismatched obfuscation blocks the handshake");
    checks.that(
        "a plain client cannot reach an obfuscated inbound",
        !plain_reaches(obfuscated, PASSWORD, sink.address, &sink.name).await,
    );
    checks.that(
        "a wrong obfuscation password cannot reach it either",
        !obfuscated_reaches(obfuscated, PASSWORD, "wrong-obfs", sink.address, &sink.name).await,
    );
    checks.that(
        "an obfuscated client cannot reach a plain inbound",
        !obfuscated_reaches(plain, PASSWORD, OBFS, sink.address, &sink.name).await,
    );

    // -- 3. obfuscation is not authentication ---------------------------------
    checks.section("3. the two layers stay independent");
    checks.that(
        "correct obfuscation with a bad password is still refused",
        !obfuscated_reaches(
            obfuscated,
            "not-alices-password",
            OBFS,
            sink.address,
            &sink.name,
        )
        .await,
    );
    // And the plain inbound still behaves exactly as it did before this feature
    // existed, which is what makes the default safe to leave alone.
    checks.that(
        "the plain inbound is unaffected",
        plain_reaches(plain, PASSWORD, sink.address, &sink.name).await,
    );

    // -- 4. user management still works underneath ----------------------------
    checks.section("4. users can still be managed on an obfuscated inbound");
    engine
        .remove_user("obfs", "alice")
        .await
        .expect("alice should be removable");
    checks.that(
        "a removed user is refused even with correct obfuscation",
        !obfuscated_reaches(obfuscated, PASSWORD, OBFS, sink.address, &sink.name).await,
    );

    checks.finish();
}

/// Obfuscation is baked into the accept loop's socket, so a reload cannot change
/// it in place -- and must say so by name rather than accepting the new config
/// and quietly continuing with the old obfuscation.
#[tokio::test(flavor = "multi_thread")]
async fn changing_obfuscation_is_refused_by_name() {
    let mut checks = Checks::new("salamander reload refusal");

    let engine = engine().await;
    let address = free_addr();
    // Deliberately *not* tagged "obfs": the assertions below look for the word
    // in the refusal message, and a tag of that name would match a refusal that
    // had nothing to do with obfuscation.
    engine
        .add_inbound(dynamic(
            "hy2",
            hysteria2_inbound_obfuscated(address, OBFS, false),
        ))
        .await
        .expect("the obfuscated inbound should start");

    // `classic` rather than `dynamic` for the same reason: an update carrying a
    // users list is refused before the protocol comparison is ever reached, so
    // using one here would pass without exercising the obfs guard at all.
    checks.refused(
        "rotating the obfuscation password is refused",
        engine
            .update_inbound(classic(
                "hy2",
                hysteria2_inbound_obfuscated(address, "a-different-secret", false),
            ))
            .await,
        "obfs",
    );
    checks.refused(
        "turning obfuscation off is refused",
        engine
            .update_inbound(classic("hy2", hysteria2_inbound(address, false)))
            .await,
        "obfs",
    );

    // A control: an update that changes nothing must be accepted, so the two
    // refusals above are attributable to the obfuscation field and not to the
    // engine refusing every update of this inbound.
    checks.that(
        "an unchanged update is still accepted",
        engine
            .update_inbound(classic(
                "hy2",
                hysteria2_inbound_obfuscated(address, OBFS, false),
            ))
            .await
            .is_ok(),
    );

    checks.finish();
}
