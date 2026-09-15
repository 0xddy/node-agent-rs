//! FTP-style data connections carry an upload and then close without reading.
//!
//! A QUIC FIN completes the upload direction; STOP_SENDING only closes the unused
//! reverse direction. Neither event may discard already accepted upload bytes.
//! These tests use a slow TCP destination and verify its complete byte count and
//! SHA-256, rather than treating success from the client's write as delivery.

mod common;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use common::hysteria2::Hysteria2Client;
use common::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "ftp-upload-password";
const UPLOAD_SIZES: [usize; 3] = [64 * 1024 + 17, 1024 * 1024 + 31, 4 * 1024 * 1024 + 189];
const CASE_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug)]
struct ReceivedUpload {
    bytes: usize,
    sha256: [u8; 32],
    error: Option<String>,
}

struct SlowUploadSink {
    address: SocketAddr,
    task: tokio::task::JoinHandle<io::Result<ReceivedUpload>>,
}

impl SlowUploadSink {
    async fn start() -> io::Result<Self> {
        Self::start_with_socks_gate(None).await
    }

    async fn start_with_socks_gate(
        gate: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> io::Result<Self> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_recv_buffer_size(16 * 1024)?;
        socket.bind("127.0.0.1:0".parse().unwrap())?;
        let listener = socket.listen(1)?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let gated_socks = gate.is_some();
            if let Some(gate) = gate {
                // A minimal SOCKS5 outbound: hold CONNECT success until the test
                // releases it, so Hysteria2 cannot write its TCP status yet.
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await?;
                if greeting != [5, 1, 0] {
                    return Err(io::Error::other("unexpected SOCKS5 greeting"));
                }
                stream.write_all(&[5, 0]).await?;
                let mut request = [0; 10];
                stream.read_exact(&mut request).await?;
                if request[..4] != [5, 1, 0, 1] {
                    return Err(io::Error::other("expected an IPv4 SOCKS5 CONNECT"));
                }
                gate.await.map_err(io::Error::other)?;
                let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 21];
                // Put destination data in the same write as CONNECT success to
                // exercise outbound early data after the reverse QUIC direction
                // has stopped. It must not cancel the independent upload either.
                response.extend_from_slice(b"220 upload destination ready\r\n");
                stream.write_all(&response).await?;
            }
            // The uploader must be able to close before the destination consumes
            // everything buffered in QUIC and the proxy's outbound TCP socket.
            tokio::time::sleep(Duration::from_millis(150)).await;
            if gated_socks {
                // Also leave data in the live reverse stream after handshake
                // processing has finished. The proxy must consume it to avoid
                // closing a TCP socket with unread bytes and resetting the peer.
                stream.write_all(b"upload in progress\r\n").await?;
            }
            let mut bytes = 0;
            let mut sha256 = Sha256::new();
            let mut chunk = [0; 32 * 1024];
            let error = loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break None,
                    Ok(count) => {
                        bytes += count;
                        sha256.update(&chunk[..count]);
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => break Some(error.to_string()),
                }
            };
            Ok(ReceivedUpload {
                bytes,
                sha256: sha256.finalize().into(),
                error,
            })
        });
        Ok(Self { address, task })
    }
}

impl Drop for SlowUploadSink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn check_uploads(stop_reading: bool) {
    let engine = engine().await;
    let server = free_addr();
    let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
    config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
    engine
        .add_inbound(dynamic("ftp-upload", config))
        .await
        .expect("start upload inbound");
    engine
        .add_user("ftp-upload", password_user("alice", PASSWORD))
        .expect("add upload user");
    // Keep a realistic 16 MiB local send window. All test files fit inside it,
    // so write_all can return before the peer has received the complete file.
    let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
        .await
        .expect("authenticate upload client");
    let mut checks = Checks::new(if stop_reading {
        "FTP upload after reverse STOP_SENDING"
    } else {
        "FTP upload with FIN only"
    });

    for fast_open in [false, true] {
        for size in UPLOAD_SIZES {
            let payload: Vec<u8> = (0..size)
                .map(|offset| ((offset * 31 + offset / 188) % 251) as u8)
                .collect();
            let expected_hash: [u8; 32] = Sha256::digest(&payload).into();
            let mut sink = SlowUploadSink::start()
                .await
                .expect("start TCP upload sink");
            let result = tokio::time::timeout(CASE_TIMEOUT, async {
                let mut stream = if fast_open {
                    // Upload-only clients never read the TCP response. The early
                    // stop can arrive before the server writes that response.
                    client.open_tcp_fast_open(sink.address, &payload).await?
                } else {
                    let mut stream = client.open_tcp(sink.address).await?;
                    stream.write_all(&payload).await?;
                    stream
                };
                stream.send.finish().map_err(io::Error::other)?;
                if stop_reading {
                    stream.recv.stop(0u32.into()).map_err(io::Error::other)?;
                }
                // Hold both the stream handles and the authenticated connection
                // until the destination sees EOF. Dropping the client would close
                // the whole connection and invalidate the half-close assertion.
                let received = (&mut sink.task).await.map_err(io::Error::other)??;
                drop(stream);
                Ok::<_, io::Error>(received)
            })
            .await;
            let label = format!("size={size}, fast_open={fast_open}, stop_reading={stop_reading}");
            let complete = matches!(
                &result,
                Ok(Ok(received))
                    if received.bytes == size
                        && received.sha256 == expected_hash
                        && received.error.is_none()
            );
            checks.detail(&label, complete, format!("{result:?}"));
        }
    }

    // A failure confined to one data stream must not terminate its multiplexed
    // connection. This also keeps connection lifetime explicit in this test.
    let probe = Sink::start("upload-connection-alive").await;
    let probe_result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = client.open_tcp(probe.address).await?;
        stream.write_all(b"who\n").await?;
        stream.read_line().await
    })
    .await;
    checks.detail(
        "same QUIC connection remains usable",
        matches!(&probe_result, Ok(Ok(name)) if name == &probe.name),
        format!("{probe_result:?}"),
    );
    checks.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ftp_style_upload_with_fin_preserves_all_bytes() {
    check_uploads(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ftp_style_upload_with_fin_and_reverse_stop_preserves_all_bytes() {
    check_uploads(true).await;
}

#[tokio::test]
async fn ftp_style_upload_survives_reverse_stop_before_outbound_setup_completes() {
    tokio::time::timeout(CASE_TIMEOUT, async {
        let engine = engine().await;
        let (release_setup, setup_gate) = tokio::sync::oneshot::channel();
        let mut sink = SlowUploadSink::start_with_socks_gate(Some(setup_gate))
            .await
            .expect("start gated SOCKS5 upload sink");
        let server = free_addr();
        let mut config = hysteria2_inbound(server, false);
        config["rules"] = serde_json::json!([{
            "masks": "0.0.0.0/0",
            "action": "allow",
            "client_chain": [{
                "address": sink.address.to_string(),
                "protocol": {"type": "socks"}
            }]
        }]);
        engine
            .add_inbound(dynamic("gated-ftp-upload", config))
            .await
            .expect("start upload inbound with gated outbound");
        engine
            .add_user("gated-ftp-upload", password_user("alice", PASSWORD))
            .expect("add upload user");
        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
            .await
            .expect("authenticate upload client");
        let payload: Vec<u8> = (0..UPLOAD_SIZES[2])
            .map(|offset| (offset % 251) as u8)
            .collect();
        let expected_hash: [u8; 32] = Sha256::digest(&payload).into();
        let mut stream = client
            .open_tcp_fast_open("127.0.0.1:21".parse().unwrap(), &payload)
            .await
            .expect("enqueue the complete upload without reading TCP status");
        stream.send.finish().expect("finish the upload direction");
        stream
            .recv
            .stop(0u32.into())
            .expect("stop the unused read direction");
        // Wait for the server to acknowledge every upload byte and FIN while
        // outbound setup is still gated. This removes the race between an
        // immediate loopback connect and the client closing its read direction.
        assert_eq!(
            stream.send.stopped().await.expect("acknowledge the upload"),
            None,
            "the server must accept the complete upload direction"
        );
        release_setup.send(()).expect("release outbound setup");
        let received = (&mut sink.task)
            .await
            .expect("upload sink task should finish")
            .expect("read the uploaded file");
        assert_eq!(received.bytes, payload.len(), "{received:?}");
        assert_eq!(received.sha256, expected_hash, "{received:?}");
        assert!(received.error.is_none(), "{received:?}");
        drop(stream);
        drop(client);
    })
    .await
    .expect("the gated upload scenario must finish within its deadline");
}
