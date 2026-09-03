//! Speed-test phase transitions: large downloads immediately followed by uploads.
//! The TCP fixture uses bounded buffers and can also serve the optional official
//! sing-quic client, so that both halves need not share the same QUIC implementation.

mod common;

use common::hysteria2::Hysteria2Client;
use common::*;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::JoinSet;

const PASSWORD: &str = "download-switch-alice";
const OTHER_PASSWORD: &str = "download-switch-bob";
const CHUNK: usize = 64 * 1024;
const STREAMS: usize = 4;
const DOWNLOAD_PER_STREAM: usize = 128 * 1024 * 1024;
const UPLOAD_PER_STREAM: usize = 32 * 1024 * 1024;

struct BoundedPeer {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl BoundedPeer {
    async fn start() -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept(), if workers.len() < 32 => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        workers.spawn(async move {
                            let command = read_line(&mut stream).await?;
                            if command == "who" {
                                return stream.write_all(b"bounded-peer\n").await;
                            }
                            let sizes: Vec<usize> = command.split_whitespace()
                                .map(str::parse).collect::<Result<_, _>>()
                                .map_err(io::Error::other)?;
                            if sizes.len() != 2 || sizes.iter().any(|&n| n > 1024 * 1024 * 1024) {
                                return Err(io::Error::other("invalid transfer command"));
                            }
                            let mut buffer = vec![0; CHUNK];
                            let mut remaining = sizes[0];
                            while remaining != 0 {
                                let n = remaining.min(CHUNK);
                                stream.read_exact(&mut buffer[..n]).await?;
                                if buffer[..n].iter().any(|&b| b != b'x') {
                                    return Err(io::Error::other("upload payload mismatch"));
                                }
                                remaining -= n;
                            }
                            buffer.fill(b'y');
                            remaining = sizes[1];
                            while remaining != 0 {
                                let n = remaining.min(CHUNK);
                                stream.write_all(&buffer[..n]).await?;
                                remaining -= n;
                            }
                            stream.shutdown().await
                        });
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {}
                }
            }
        });
        Ok(Self { address, task })
    }
}

impl Drop for BoundedPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(brutal: bool) -> (shoes_engine::Engine, SocketAddr, BoundedPeer) {
    let engine = engine().await;
    let server = free_addr();
    let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
    config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(!brutal);
    engine
        .add_inbound(dynamic("hy2-phase-switch", config))
        .await
        .unwrap();
    engine
        .add_user("hy2-phase-switch", password_user("alice", PASSWORD))
        .unwrap();
    engine
        .add_user("hy2-phase-switch", password_user("bob", OTHER_PASSWORD))
        .unwrap();
    (engine, server, BoundedPeer::start().await.unwrap())
}

async fn probe(client: &Hysteria2Client, target: SocketAddr) -> io::Result<()> {
    let mut stream = client.open_tcp(target).await?;
    stream.write_all(b"who\n").await?;
    if stream.read_line().await? != "bounded-peer" {
        return Err(io::Error::other("liveness response mismatch"));
    }
    Ok(())
}

async fn phase(
    client: &Arc<Hysteria2Client>,
    server: SocketAddr,
    target: SocketAddr,
    upload: bool,
) {
    let progress = Arc::new(AtomicU64::new(0));
    let started = Arc::new(Notify::new());
    let mut jobs = JoinSet::new();
    for index in 0..STREAMS {
        let client = Arc::clone(client);
        let progress = Arc::clone(&progress);
        let started = Arc::clone(&started);
        jobs.spawn(async move {
            let mut stream = client.open_tcp(target).await?;
            let (up, down) = if upload {
                (UPLOAD_PER_STREAM, 1)
            } else {
                (0, DOWNLOAD_PER_STREAM)
            };
            stream
                .write_all(format!("{up} {down}\n").as_bytes())
                .await?;
            if index == 0 {
                started.notify_one();
            }
            let mut buffer = vec![b'x'; CHUNK];
            let mut remaining = up;
            while remaining != 0 {
                let n = remaining.min(CHUNK);
                stream
                    .send
                    .write_all(&buffer[..n])
                    .await
                    .map_err(io::Error::other)?;
                remaining -= n;
                progress.fetch_add(n as u64, Ordering::Relaxed);
            }
            remaining = down;
            while remaining != 0 {
                let n = remaining.min(CHUNK);
                stream
                    .recv
                    .read_exact(&mut buffer[..n])
                    .await
                    .map_err(io::Error::other)?;
                if buffer[..n].iter().any(|&b| b != b'y') {
                    return Err(io::Error::other("download payload mismatch"));
                }
                remaining -= n;
                if !upload {
                    progress.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
            if stream
                .recv
                .read(&mut buffer[..1])
                .await
                .map_err(io::Error::other)?
                .is_some()
            {
                return Err(io::Error::other("unexpected data after transfer"));
            }
            Ok::<_, io::Error>(())
        });
    }
    let started_at = Instant::now();
    let expected = STREAMS
        * if upload {
            UPLOAD_PER_STREAM
        } else {
            DOWNLOAD_PER_STREAM
        };
    let probes = async {
        started.notified().await;
        assert!(
            progress.load(Ordering::Relaxed) < expected as u64,
            "probes must start during transfer"
        );
        tokio::try_join!(probe(client, target), async {
            let other = Hysteria2Client::connect(server, OTHER_PASSWORD).await?;
            probe(&other, target).await
        })?;
        Ok::<_, io::Error>(())
    };
    let transfers = async {
        while let Some(job) = jobs.join_next().await {
            job.map_err(io::Error::other)??;
        }
        Ok::<_, io::Error>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        tokio::try_join!(transfers, probes)
    })
    .await;
    println!(
        "phase upload={upload}, bytes={}, elapsed={:?}, stats={:?}, close={:?}, result={result:?}",
        progress.load(Ordering::Relaxed),
        started_at.elapsed(),
        client.stats(),
        client.close_reason()
    );
    result
        .expect("phase timed out")
        .expect("phase and both liveness probes should succeed");
    assert_eq!(progress.load(Ordering::Relaxed), expected as u64);
}

async fn download_then_upload(brutal: bool) {
    let (_engine, server, peer) = fixture(brutal).await;
    let client = Arc::new(
        Hysteria2Client::connect_with_rates_bps(
            server,
            PASSWORD,
            64 * 1024 * 1024,
            64 * 1024 * 1024,
        )
        .await
        .unwrap(),
    );
    assert_eq!(client.advertised_receive_auto, !brutal);
    phase(&client, server, peer.address, false).await;
    // Keep the QUIC transport alive and switch immediately, as speed tests do.
    phase(&client, server, peer.address, true).await;
    tokio::time::timeout(Duration::from_secs(5), probe(&client, peer.address))
        .await
        .unwrap()
        .unwrap();
    assert!(client.close_reason().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bbr_large_download_immediately_followed_by_upload() {
    download_then_upload(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brutal_large_download_immediately_followed_by_upload() {
    download_then_upload(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "build tests/interop/sing-quic-switch and set EXTERNAL_HY2_CLIENT to its executable"]
async fn official_go_client_download_then_upload() {
    let executable =
        std::env::var_os("EXTERNAL_HY2_CLIENT").expect("EXTERNAL_HY2_CLIENT is required");
    let (_engine, server, peer) = fixture(false).await;
    let output = tokio::time::timeout(
        Duration::from_secs(130),
        tokio::process::Command::new(executable)
            .kill_on_drop(true)
            .arg(server.to_string())
            .arg(peer.address.to_string())
            .arg(PASSWORD)
            .output(),
    )
    .await
    .expect("Go client timed out")
    .expect("start Go client");
    println!(
        "Go stdout:\n{}\nGo stderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "official Go client failed");
}
