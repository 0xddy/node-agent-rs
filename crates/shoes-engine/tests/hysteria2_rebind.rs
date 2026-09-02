//! A client whose source address changes mid-connection must keep working.
//!
//! QUIC is built to survive this: the connection is named by its connection ID, not
//! by the 4-tuple, so a NAT rebinding under load -- or Hysteria2 port hopping --
//! becomes a path migration rather than a disconnect. sing-box relies on exactly
//! that, and binds one `net.UDPConn` per inbound.
//!
//! A `SO_REUSEPORT` fan-out breaks the premise. The kernel picks the receiving
//! socket by hashing the datagram's 4-tuple, so a connection is pinned to one
//! endpoint only while the peer's address holds still. Change the source port and
//! the packets are delivered to a *different* `quinn::Endpoint`, which holds no such
//! connection and cannot migrate it.
//!
//! This only reproduces where `SO_REUSEPORT` exists, so the multi-endpoint half is
//! Unix-only; the single-endpoint half runs everywhere.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::hysteria2::Hysteria2Client;
use common::*;
use tokio::net::UdpSocket;

const PASSWORD: &str = "alice-rebinding";

/// A relay that forwards to `server`, and swaps its own source port when told to.
///
/// That swap is what a NAT rebinding looks like from the server: same client, same
/// connection ID, new 4-tuple.
struct RebindingPath {
    entry: SocketAddr,
    rebind: Arc<AtomicBool>,
}

async fn rebinding_path(server: SocketAddr) -> RebindingPath {
    let facing_client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("relay bind"));
    let entry = facing_client.local_addr().expect("relay address");
    let rebind = Arc::new(AtomicBool::new(false));

    let upstream = Arc::new(tokio::sync::Mutex::new(
        UdpSocket::bind("127.0.0.1:0").await.expect("relay bind"),
    ));
    let peer: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::new(std::sync::Mutex::new(None));

    // client -> server, through whichever upstream socket is current
    {
        let (rx, upstream, seen, rebind) = (
            Arc::clone(&facing_client),
            Arc::clone(&upstream),
            Arc::clone(&peer),
            Arc::clone(&rebind),
        );
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, source)) = rx.recv_from(&mut buf).await {
                *seen.lock().unwrap() = Some(source);
                let mut current = upstream.lock().await;
                if rebind.swap(false, Ordering::SeqCst) {
                    // A fresh socket is a fresh source port: the rebinding.
                    if let Ok(replacement) = UdpSocket::bind("127.0.0.1:0").await {
                        *current = replacement;
                    }
                }
                let _ = current.send_to(&buf[..n], server).await;
            }
        });
    }

    // server -> client, always reading from the socket that is current
    {
        let (tx, upstream, peer) = (
            Arc::clone(&facing_client),
            Arc::clone(&upstream),
            Arc::clone(&peer),
        );
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let received = {
                    let current = upstream.lock().await;
                    // Bounded so a rebinding is picked up promptly rather than
                    // leaving this task parked on the retired socket.
                    tokio::time::timeout(Duration::from_millis(20), current.recv_from(&mut buf))
                        .await
                };
                let Ok(Ok((n, _))) = received else { continue };
                let client = *peer.lock().unwrap();
                if let Some(client) = client {
                    let _ = tx.send_to(&buf[..n], client).await;
                }
            }
        });
    }

    RebindingPath { entry, rebind }
}

async fn reaches(client: &Hysteria2Client, sink: &Sink) -> io::Result<String> {
    let mut stream = client.open_tcp(sink.address).await?;
    stream.write_all(b"who\n").await?;
    stream.read_line().await
}

/// `None` leaves `num_endpoints` out of the config entirely, so the listener
/// resolves whatever the shipped default is -- which is the thing worth asserting,
/// since the default is what every deployment runs.
async fn survives_a_rebinding(num_endpoints: Option<usize>) -> Result<(), String> {
    let engine = engine().await;
    let sink = Sink::start("rebind-sink").await;
    let server = free_addr();

    let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
    if let Some(num_endpoints) = num_endpoints {
        config["quic_settings"]["num_endpoints"] = serde_json::json!(num_endpoints);
    }
    engine
        .add_inbound(dynamic("hy2", config))
        .await
        .map_err(|e| format!("inbound with num_endpoints={num_endpoints:?} should start: {e}"))?;
    engine
        .add_user("hy2", password_user("alice", PASSWORD))
        .map_err(|e| format!("alice should be accepted: {e}"))?;

    let path = rebinding_path(server).await;
    let client = Hysteria2Client::connect_with_rates_bps(path.entry, PASSWORD, 0, 0)
        .await
        .map_err(|e| format!("alice should authenticate: {e}"))?;

    // Prove the path works before disturbing it, so a failure after the rebinding
    // cannot be blamed on the relay.
    match tokio::time::timeout(Duration::from_secs(5), reaches(&client, &sink)).await {
        Ok(Ok(name)) if name == "rebind-sink" => {}
        other => return Err(format!("the connection was not usable before rebinding: {other:?}")),
    }

    path.rebind.store(true, Ordering::SeqCst);

    // Give the migration a generous window: quinn revalidates the new path before
    // it will send at full rate, and that is fine -- only survival is asserted.
    match tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(name) = reaches(&client, &sink).await {
                if name == "rebind-sink" {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    {
        Ok(()) => Ok(()),
        Err(_) => Err("the connection never recovered after the source port changed".to_string()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_listener_survives_a_source_port_change() {
    let mut checks = Checks::new("hysteria2 rebinding, shipped default");
    // Deliberately not pinned to 1: this asserts the default a deployment gets,
    // so raising the fan-out again fails here rather than in production.
    let result = survives_a_rebinding(None).await;
    checks.detail(
        "the connection migrates to the client's new address",
        result.is_ok(),
        format!("{result:?}"),
    );
    checks.finish();
}

/// Demonstrates why `num_endpoints > 1` is not a transparent optimisation.
///
/// Ignored by default because it documents a limitation rather than a guarantee,
/// and because the outcome is a lottery: a rebinding survives only when the new
/// source port happens to hash back to the socket that owns the connection, so a
/// single trial proves nothing. Observed failure rates have ranged from under half
/// to eleven in twelve on the same machine -- it depends on which ephemeral ports
/// the kernel hands out. What is *not* variable is that some connections are lost
/// permanently, which is enough to disqualify the fan-out.
///
/// Run it with `cargo test --test hysteria2_rebind -- --ignored --nocapture`.
///
/// A multi-socket QUIC server has to dispatch by connection ID to get this right;
/// the kernel's 4-tuple hash cannot, because a migration is precisely a change of
/// 4-tuple.
#[cfg(unix)]
#[ignore = "documents that a SO_REUSEPORT fan-out cannot reliably migrate connections"]
#[tokio::test(flavor = "multi_thread")]
async fn a_reuseport_fan_out_loses_connections_on_a_source_port_change() {
    const TRIALS: usize = 10;
    let mut lost = 0;
    for trial in 0..TRIALS {
        let result = survives_a_rebinding(Some(8)).await;
        println!("trial {trial}: {result:?}");
        if result.is_err() {
            lost += 1;
        }
    }
    println!("num_endpoints=8: {lost} of {TRIALS} rebindings lost the connection");
    assert!(
        lost > 0,
        "a fan-out that never loses a rebinding would make the single-endpoint          default in validate.rs worth revisiting"
    );
}
