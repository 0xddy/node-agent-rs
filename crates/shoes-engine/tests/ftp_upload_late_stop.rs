//! Regressions for STOP_SENDING after the Hysteria2 success response.
//!
//! The destination deliberately responds before consuming a queued upload. This
//! is a generic TCP half-close contract test, not a claim about FileZilla's wire
//! behavior. A peer cancelling its receive direction must not cancel its upload.

mod common;

use std::io;
use std::time::Duration;

use common::hysteria2::Hysteria2Client;
use common::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "late-stop-upload-password";
const PAYLOAD_SIZE: usize = 4 * 1024 * 1024 + 189;

async fn upload_after_response(stop_reading: bool, reverse_payload: bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        let engine = engine().await;
        let server = free_addr();
        let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
        config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
        engine
            .add_inbound(dynamic("late-stop-upload", config))
            .await
            .expect("start Hysteria2 inbound");
        engine
            .add_user("late-stop-upload", password_user("alice", PASSWORD))
            .expect("add upload user");

        let socket = tokio::net::TcpSocket::new_v4().expect("create target socket");
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(1).unwrap();
        let target = listener.local_addr().unwrap();
        let (release_target, target_gate) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            target_gate.await.map_err(io::Error::other)?;
            if reverse_payload {
                stream.write_all(b"late target response\r\n").await?;
            }
            // A FIN only closes the target's write direction; it keeps accepting
            // the upload. A late payload additionally exercises QUIC poll_write.
            stream.shutdown().await?;
            let mut received = Vec::new();
            let mut chunk = [0; 16 * 1024];
            let error = loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break None,
                    Ok(n) => {
                        received.extend_from_slice(&chunk[..n]);
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => break Some(error.to_string()),
                }
            };
            Ok::<_, io::Error>((received, error))
        });

        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
            .await
            .expect("authenticate upload client");
        // Waiting for the response guarantees the initial response was Sent,
        // excluding the separate PeerStopped-during-outbound-setup branch.
        let mut stream = client.open_tcp(target).await.expect("read TCP success");
        let payload: Vec<u8> = (0..PAYLOAD_SIZE)
            .map(|offset| ((offset * 31 + offset / 188) % 251) as u8)
            .collect();
        stream.send.write_all(&payload).await.expect("enqueue upload");
        stream.send.finish().expect("finish upload direction");
        assert_eq!(
            stream.send.stopped().await.expect("acknowledge upload"),
            None,
            "all upload bytes and FIN should reach the proxy before the target reads"
        );
        if stop_reading {
            stream.recv.stop(0u32.into()).expect("cancel reverse direction");
            // Allow the local STOP_SENDING to arrive before the target is allowed
            // to write. The target gate makes the slow-read backlog deterministic.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        release_target.send(()).expect("release target");
        let (received, error) = destination.await.unwrap().unwrap();
        eprintln!(
            "late-stop upload: stop={stop_reading}, reverse_payload={reverse_payload}, expected={}, received={}, error={error:?}",
            payload.len(),
            received.len()
        );
        assert_eq!(received.len(), payload.len(), "target upload is truncated");
        assert_eq!(Sha256::digest(&received), Sha256::digest(&payload));
        assert!(error.is_none(), "target must observe clean EOF: {error:?}");
        // Keep the physical QUIC connection and handles alive until target EOF.
        drop(stream);
        if stop_reading && reverse_payload {
            let probe = Sink::start("late-stop-connection-alive").await;
            let mut next_stream = client
                .open_tcp(probe.address)
                .await
                .expect("late STOP must leave the same QUIC connection usable");
            next_stream.write_all(b"who\n").await.unwrap();
            assert_eq!(next_stream.read_line().await.unwrap(), probe.name);
        }
        drop(client);
    })
    .await
    .expect("late reverse cancellation scenario must finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_late_reverse_stop_and_target_fin() {
    upload_after_response(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_target_reverse_payload_without_stop() {
    upload_after_response(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_late_reverse_stop_and_target_payload() {
    upload_after_response(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observed_reverse_stop_is_reset_before_upload_fin() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let engine = engine().await;
        let server = free_addr();
        engine
            .add_inbound(dynamic("reset-upload", hysteria2_inbound(server, false)))
            .await
            .unwrap();
        engine
            .add_user("reset-upload", password_user("alice", PASSWORD))
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (prefix_received, ready) = tokio::sync::oneshot::channel();
        let (release_target, target_gate) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (mut target, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 1];
            target.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [b'a']);
            prefix_received.send(()).unwrap();
            target_gate.await.unwrap();
            // Force the proxy to observe Stopped in poll_write, while the upload
            // direction stays open. Merely receiving STOP is a different case.
            target.write_all(b"cancelled response").await.unwrap();
            target.shutdown().await.unwrap();
            let mut tail = Vec::new();
            target.read_to_end(&mut tail).await.unwrap();
            tail
        });
        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
            .await
            .unwrap();
        let mut stream = client.open_tcp(address).await.unwrap();
        stream.write_all(b"a").await.unwrap();
        ready.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let resets_before = client.stats().frame_rx.reset_stream;
        stream.recv.stop(42u32.into()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        release_target.send(()).unwrap();
        let reset_arrived = tokio::time::timeout(Duration::from_secs(2), async {
            while client.stats().frame_rx.reset_stream == resets_before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            reset_arrived.is_ok(),
            "an observed STOP must send RESET_STREAM before the upload ends"
        );
        // Resetting the server's response must leave the opposite direction usable.
        stream.write_all(b"remaining upload").await.unwrap();
        stream.send.finish().unwrap();
        assert_eq!(destination.await.unwrap(), b"remaining upload");
        drop(stream);
        drop(client);
    })
    .await
    .expect("the half-close reset scenario must finish");
}
