//! Liveness coverage for a Hysteria2 connection under speed-test-style upload.
//!
//! Small request/response transfers do not exercise this path. When fixed bandwidth
//! is negotiated, a production client activates Brutal after authentication and may
//! multiplex several large TCP uploads over one QUIC connection. The connection and
//! inbound must keep scheduling control traffic and unrelated clients while those
//! streams are hot, and the original connection must remain usable afterwards.
//!
//! A bounded UDP relay also checks recovery from mild upload loss and reordering.
//! This is not a substitute for reproducing an affected client's actual WAN path.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::hysteria2::{Hysteria2Client, Hysteria2Stream};
use common::*;

const PASSWORD: &str = "alice-upload-pressure";
const UPLOAD_STREAMS: usize = 4;
const BYTES_PER_STREAM: usize = 2 * 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;
const SEND_BPS: u64 = 4_000_000;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// A TCP destination that temporarily stops reading after the upload command.
/// Its small receive window makes QUIC, rather than the local TCP socket, retain
/// incoming STREAM frames until the destination resumes consuming the payload.
struct PausedUploadSink {
    address: SocketAddr,
    received: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl PausedUploadSink {
    async fn start(upload_bytes: usize) -> io::Result<Self> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_recv_buffer_size(16 * 1024)?;
        socket.bind("127.0.0.1:0".parse().unwrap())?;
        let listener = socket.listen(1)?;
        let address = listener.local_addr()?;
        let received = Arc::new(AtomicU64::new(0));
        let task_received = Arc::clone(&received);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let command = read_line(&mut stream).await?;
            if command != format!("{upload_bytes} 1") {
                return Err(io::Error::other("unexpected paused-upload command"));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut chunk = vec![0; CHUNK_SIZE];
            let mut remaining = upload_bytes;
            while remaining != 0 {
                let capacity = remaining.min(chunk.len());
                let count = stream.read(&mut chunk[..capacity]).await?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "paused upload closed early",
                    ));
                }
                remaining -= count;
                task_received.fetch_add(count as u64, Ordering::Relaxed);
            }
            stream.write_all(b"y").await?;
            stream.flush().await
        });
        Ok(Self {
            address,
            received,
            task,
        })
    }
}

impl Drop for PausedUploadSink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One client's upload path with deterministic loss and adjacent-packet reordering.
/// The reverse path stays intact so an upload failure can be distinguished from a
/// deliberately disconnected server. Only one pending datagram is ever retained.
struct ImpairedUploadPath {
    address: SocketAddr,
    dropped: Arc<AtomicU64>,
    reordered: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl ImpairedUploadPath {
    async fn start(server: SocketAddr) -> io::Result<Self> {
        let downstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        upstream.connect(server).await?;
        let address = downstream.local_addr()?;
        let dropped = Arc::new(AtomicU64::new(0));
        let reordered = Arc::new(AtomicU64::new(0));
        let task_dropped = Arc::clone(&dropped);
        let task_reordered = Arc::clone(&reordered);
        let task = tokio::spawn(async move {
            let mut upload = vec![0; 65535];
            let mut download = vec![0; 65535];
            let mut client = None;
            let mut packets = 0_u64;
            let mut held: Option<(Vec<u8>, tokio::time::Instant)> = None;
            loop {
                let flush_at = held
                    .as_ref()
                    .map(|(_, deadline)| *deadline)
                    .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));
                tokio::select! {
                    packet = downstream.recv_from(&mut upload) => {
                        let (size, peer) = packet?;
                        if *client.get_or_insert(peer) != peer {
                            continue;
                        }
                        packets += 1;
                        // Leave startup untouched; impair only a sustained transfer.
                        if packets > 100 && packets.is_multiple_of(401) {
                            task_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if let Some((previous, _)) = held.take() {
                            upstream.send(&upload[..size]).await?;
                            upstream.send(&previous).await?;
                            task_reordered.fetch_add(1, Ordering::Relaxed);
                        } else if packets > 100 && packets.is_multiple_of(127) {
                            held = Some((
                                upload[..size].to_vec(),
                                tokio::time::Instant::now() + Duration::from_millis(2),
                            ));
                        } else {
                            upstream.send(&upload[..size]).await?;
                        }
                    }
                    packet = upstream.recv(&mut download) => {
                        let size = packet?;
                        if let Some(peer) = client {
                            downstream.send_to(&download[..size], peer).await?;
                        }
                    }
                    _ = tokio::time::sleep_until(flush_at), if held.is_some() => {
                        if let Some((previous, _)) = held.take() {
                            upstream.send(&previous).await?;
                        }
                    }
                }
            }
        });
        Ok(Self {
            address,
            dropped,
            reordered,
            task,
        })
    }
}

impl Drop for ImpairedUploadPath {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn download_on(
    client: &Hysteria2Client,
    dest: SocketAddr,
    started: tokio::sync::oneshot::Sender<()>,
) -> io::Result<()> {
    const DOWNLOAD_BYTES: usize = 1024 * 1024;
    let mut stream = client.open_tcp(dest).await?;
    stream
        .write_all(format!("0 {DOWNLOAD_BYTES}\n").as_bytes())
        .await?;
    // Confirm a real request is in flight. The uploader may then continue while
    // this probe receives its payload; it does not wait for download completion.
    let _ = started.send(());
    let mut remaining = DOWNLOAD_BYTES;
    let mut chunk = vec![0; CHUNK_SIZE];
    while remaining != 0 {
        let count = remaining.min(chunk.len());
        stream
            .recv
            .read_exact(&mut chunk[..count])
            .await
            .map_err(io::Error::other)?;
        if chunk[..count].iter().any(|byte| *byte != b'y') {
            return Err(io::Error::other("download payload was corrupted"));
        }
        remaining -= count;
    }
    Ok(())
}

async fn check_large_auto_upload(impaired: bool, backpressured: bool) {
    const UPLOAD_BYTES: usize = 128 * 1024 * 1024;
    const MILESTONES: [usize; 2] = [16 * 1024 * 1024, 64 * 1024 * 1024];
    let engine = engine().await;
    let sink = Sink::start("auto-upload-sink").await;
    let paused_sink = if backpressured {
        Some(
            PausedUploadSink::start(UPLOAD_BYTES)
                .await
                .expect("start backpressured TCP sink"),
        )
    } else {
        None
    };
    let upload_address = paused_sink
        .as_ref()
        .map_or(sink.address, |sink| sink.address);
    let server = free_addr();
    let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
    config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
    engine
        .add_inbound(dynamic("hy2-auto-upload", config))
        .await
        .expect("the auto-bandwidth inbound should start");
    engine
        .add_user("hy2-auto-upload", password_user("alice", PASSWORD))
        .expect("alice should be accepted");
    let relay = if impaired {
        Some(
            ImpairedUploadPath::start(server)
                .await
                .expect("start UDP relay"),
        )
    } else {
        None
    };
    let target = relay.as_ref().map_or(server, |relay| relay.address);
    let client = Hysteria2Client::connect_with_rates_bps(target, PASSWORD, SEND_BPS, SEND_BPS)
        .await
        .expect("alice should authenticate");
    assert!(client.advertised_receive_auto);
    assert_eq!(
        client.negotiated_send_bps, 0,
        "the client should retain BBR"
    );

    let sent = AtomicU64::new(0);
    let (milestone_tx, mut milestone_rx) = tokio::sync::mpsc::channel(MILESTONES.len());
    let upload = async {
        let mut stream = client
            .open_tcp_fast_open(upload_address, format!("{UPLOAD_BYTES} 1\n").as_bytes())
            .await?;
        let chunk = vec![b'x'; CHUNK_SIZE];
        for bytes in (CHUNK_SIZE..=UPLOAD_BYTES).step_by(CHUNK_SIZE) {
            stream
                .send
                .write_all(&chunk)
                .await
                .map_err(io::Error::other)?;
            sent.store(bytes as u64, Ordering::Relaxed);
            if MILESTONES.contains(&bytes) {
                let (same_started, same_start) = tokio::sync::oneshot::channel();
                let (independent_started, independent_start) = tokio::sync::oneshot::channel();
                milestone_tx
                    .send((bytes, same_started, independent_started))
                    .await
                    .map_err(|_| io::Error::other("upload probes stopped before the milestone"))?;
                // A previous probe may still be downloading when the next
                // milestone is reached. Wait only until both new requests have
                // started, so a queued milestone cannot be observed after upload
                // completion and make the overlap assertion depend on timing.
                let (same_start, independent_start) = tokio::join!(same_start, independent_start);
                same_start.map_err(|_| io::Error::other("same-connection probe did not start"))?;
                independent_start
                    .map_err(|_| io::Error::other("independent-connection probe did not start"))?;
            }
        }
        drop(milestone_tx);
        stream.read_tcp_response().await?;
        let mut acknowledgement = [0];
        stream
            .recv
            .read_exact(&mut acknowledgement)
            .await
            .map_err(io::Error::other)?;
        if acknowledgement != [b'y'] {
            return Err(io::Error::other(
                "upload sink did not acknowledge all bytes",
            ));
        }
        Ok::<(), io::Error>(())
    };
    let probes = async {
        let mut reports = Vec::new();
        while let Some((bytes, same_started, independent_started)) = milestone_rx.recv().await {
            let overlap = sent.load(Ordering::Relaxed) < UPLOAD_BYTES as u64;
            let same = tokio::time::timeout(
                PROBE_TIMEOUT,
                download_on(&client, sink.address, same_started),
            );
            let independent = tokio::time::timeout(PROBE_TIMEOUT, async {
                let other = Hysteria2Client::connect(server, PASSWORD).await?;
                download_on(&other, sink.address, independent_started).await
            });
            let (same, independent) = tokio::join!(same, independent);
            reports.push((bytes, overlap, same, independent));
        }
        reports
    };
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(upload, probes)
    })
    .await;
    let path = client.stats().path;
    let faults = relay.as_ref().map(|relay| {
        (
            relay.dropped.load(Ordering::Relaxed),
            relay.reordered.load(Ordering::Relaxed),
            relay.task.is_finished(),
        )
    });
    println!(
        "128 MiB upload: impaired={impaired}, backpressured={backpressured}, elapsed={:?}, enqueued={}, path={path:?}, faults={faults:?}, result={outcome:?}",
        started.elapsed(),
        sent.load(Ordering::Relaxed),
    );
    // Always probe both scopes after failure as well: one broken QUIC connection
    // does not establish that the listener or node-agent process has failed.
    let (same_after, independent_after) = tokio::join!(
        tokio::time::timeout(PROBE_TIMEOUT, name_on(&client, sink.address)),
        tokio::time::timeout(
            PROBE_TIMEOUT,
            common::hysteria2::reach(server, PASSWORD, sink.address)
        ),
    );
    println!("post-upload liveness: same={same_after:?}, independent={independent_after:?}");
    if let Some(sink) = &paused_sink {
        println!(
            "backpressured TCP peer received {} bytes",
            sink.received.load(Ordering::Relaxed)
        );
    }
    let (upload, reports) = outcome.expect("the 128 MiB upload should finish within 120 seconds");
    upload.expect("all 128 MiB should reach the TCP destination");
    assert_eq!(reports.len(), MILESTONES.len());
    for (bytes, overlap, same, independent) in reports {
        assert!(
            overlap,
            "probe at {bytes} bytes should overlap active upload"
        );
        assert!(
            matches!(same, Ok(Ok(()))),
            "same connection at {bytes}: {same:?}"
        );
        assert!(
            matches!(independent, Ok(Ok(()))),
            "independent connection at {bytes}: {independent:?}"
        );
    }
    assert!(matches!(same_after, Ok(Ok(ref name)) if name == &sink.name));
    assert!(matches!(independent_after, Ok(Ok(ref name)) if name == &sink.name));
    if let Some((dropped, reordered, stopped)) = faults {
        assert!(
            dropped > 0 && reordered > 0,
            "both impairments should be exercised"
        );
        assert!(!stopped, "the UDP relay should remain alive");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_bandwidth_128_mib_upload_keeps_both_connections_responsive() {
    check_large_auto_upload(false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_bandwidth_128_mib_upload_recovers_from_loss_and_reordering() {
    check_large_auto_upload(true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_bandwidth_128_mib_upload_survives_tcp_backpressure() {
    check_large_auto_upload(false, true).await;
}

async fn name_on(client: &Hysteria2Client, dest: SocketAddr) -> io::Result<String> {
    let mut stream = client.open_tcp(dest).await?;
    stream.write_all(b"who\n").await?;
    stream.read_line().await
}

async fn upload(
    mut stream: Hysteria2Stream,
    start: Arc<tokio::sync::Barrier>,
    started: tokio::sync::mpsc::UnboundedSender<()>,
) -> io::Result<()> {
    stream
        .write_all(format!("{BYTES_PER_STREAM} 1\n").as_bytes())
        .await?;
    start.wait().await;

    let chunk = vec![b'x'; CHUNK_SIZE];
    let mut remaining = BYTES_PER_STREAM;
    let mut first = true;
    while remaining != 0 {
        let count = remaining.min(chunk.len());
        stream.write_all(&chunk[..count]).await?;
        remaining -= count;
        if first {
            let _ = started.send(());
            first = false;
        }
    }

    // The sink replies only after consuming the declared byte count.  Seeing this
    // byte therefore proves the upload reached the TCP peer, rather than merely
    // being accepted into Quinn's local send buffer.
    let mut acknowledgement = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(15),
        stream.recv.read_exact(&mut acknowledgement),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upload acknowledgement timed out"))?
    .map_err(|error| io::Error::other(format!("upload acknowledgement failed: {error}")))?;
    if acknowledgement != [b'y'] {
        return Err(io::Error::other(
            "upload sink returned an invalid acknowledgement",
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_server_bandwidth_allows_uploads_past_receive_windows() {
    const UPLOAD_BYTES: usize = 24 * 1024 * 1024;
    let engine = engine().await;
    let sink = Sink::start("large-upload-sink").await;

    for ignore_client_bandwidth in [false, true] {
        let server = free_addr();
        let tag = format!("hy2-zero-{ignore_client_bandwidth}");
        let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
        config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(ignore_client_bandwidth);
        engine
            .add_inbound(dynamic(&tag, config))
            .await
            .expect("the zero-bandwidth inbound should start");
        engine
            .add_user(&tag, password_user("alice", PASSWORD))
            .expect("alice should be accepted");

        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, SEND_BPS, SEND_BPS)
            .await
            .expect("alice should authenticate");
        assert_eq!(client.advertised_receive_auto, ignore_client_bandwidth);
        assert_eq!(
            client.negotiated_send_bps,
            if ignore_client_bandwidth { 0 } else { SEND_BPS }
        );

        // Cross both the 8 MiB stream window and the 20 MiB connection window.
        // Fast open also exercises a client sending before it reads TCP status.
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let mut stream = client
                .open_tcp_fast_open(sink.address, format!("{UPLOAD_BYTES} 1\n").as_bytes())
                .await?;
            let chunk = vec![b'x'; CHUNK_SIZE];
            for _ in 0..UPLOAD_BYTES / CHUNK_SIZE {
                stream
                    .send
                    .write_all(&chunk)
                    .await
                    .map_err(io::Error::other)?;
            }
            stream.read_tcp_response().await?;
            let mut acknowledgement = [0u8; 1];
            stream
                .recv
                .read_exact(&mut acknowledgement)
                .await
                .map_err(io::Error::other)?;
            assert_eq!(acknowledgement, [b'y']);
            Ok::<(), io::Error>(())
        })
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "ignore_client_bandwidth={ignore_client_bandwidth}: {result:?}; path={:?}",
            client.stats().path
        );
        assert_eq!(
            tokio::time::timeout(PROBE_TIMEOUT, name_on(&client, sink.address))
                .await
                .expect("the connection should remain responsive")
                .expect("the next stream should succeed"),
            sink.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_brutal_upload_does_not_wedge_the_connection_or_inbound() {
    let mut checks = Checks::new("hysteria2 sustained upload liveness");
    let engine = engine().await;
    let sink = Sink::start("upload-sink").await;
    let server = free_addr();

    // Hysteria2's up/down negotiation is independent in the two directions. Both
    // sides declare 32 Mbps here, as real speed-test clients normally do. The four
    // concurrent streams exercise the shared QUIC scheduler and make the probes
    // below overlap active upload work.
    engine
        .add_inbound(dynamic(
            "hy2",
            hysteria2_inbound_with_bandwidth(server, 32, 32, false),
        ))
        .await
        .expect("the Hysteria2 inbound should start");
    engine
        .add_user("hy2", password_user("alice", PASSWORD))
        .expect("alice should be accepted");

    let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, SEND_BPS, SEND_BPS)
        .await
        .expect("alice should authenticate with fixed rates in both directions");
    checks.eq(
        "the client activated the server-capped upload rate",
        client.negotiated_send_bps,
        SEND_BPS,
    );

    let start = Arc::new(tokio::sync::Barrier::new(UPLOAD_STREAMS + 1));
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut uploads = Vec::with_capacity(UPLOAD_STREAMS);
    for index in 0..UPLOAD_STREAMS {
        let stream = client
            .open_tcp(sink.address)
            .await
            .unwrap_or_else(|error| panic!("upload stream {index} should open: {error}"));
        uploads.push(tokio::spawn(upload(
            stream,
            Arc::clone(&start),
            started_tx.clone(),
        )));
    }
    drop(started_tx);
    start.wait().await;
    for index in 0..UPLOAD_STREAMS {
        tokio::time::timeout(Duration::from_secs(5), started_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("upload stream {index} did not start"))
            .unwrap_or_else(|| panic!("upload stream {index} ended before reporting progress"));
    }
    checks.that(
        "the liveness probes overlap active upload work",
        uploads.iter().any(|task| !task.is_finished()),
    );
    let upload_started_at = Instant::now();

    // Probe both scopes concurrently.  The first has to share stream scheduling and
    // congestion state with the upload; the second proves one busy connection cannot
    // starve the listener or the rest of the runtime.
    let same_connection = tokio::time::timeout(PROBE_TIMEOUT, name_on(&client, sink.address));
    let independent_connection = tokio::time::timeout(
        PROBE_TIMEOUT,
        common::hysteria2::reach(server, PASSWORD, sink.address),
    );
    let (same_connection, independent_connection) =
        tokio::join!(same_connection, independent_connection);
    checks.detail(
        "the busy QUIC connection still serves a new TCP stream",
        matches!(same_connection, Ok(Ok(ref name)) if name == "upload-sink"),
        format!("{same_connection:?}"),
    );
    checks.detail(
        "the inbound still accepts and serves another client",
        matches!(independent_connection, Ok(Ok(ref name)) if name == "upload-sink"),
        format!("{independent_connection:?}"),
    );

    let upload_result = tokio::time::timeout(Duration::from_secs(10), async {
        for (index, task) in uploads.iter_mut().enumerate() {
            task.await
                .map_err(|error| format!("upload task {index} panicked: {error}"))?
                .map_err(|error| format!("upload stream {index} failed: {error}"))?;
        }
        Ok::<(), String>(())
    })
    .await;
    let upload_elapsed = upload_started_at.elapsed();
    let path = client.stats().path;
    checks.detail(
        "the Brutal congestion window admits two full-size datagrams",
        path.cwnd > 2 * u64::from(path.current_mtu),
        format!("cwnd={}, mtu={}", path.cwnd, path.current_mtu),
    );
    checks.detail(
        "all sustained uploads reach their TCP destination",
        matches!(upload_result, Ok(Ok(()))),
        format!(
            "{upload_result:?}; elapsed={upload_elapsed:?}, rtt={:?}, cwnd={}, mtu={}, sent_packets={}, lost_packets={}",
            path.rtt, path.cwnd, path.current_mtu, path.sent_packets, path.lost_packets,
        ),
    );
    if !matches!(&upload_result, Ok(Ok(()))) {
        for task in &uploads {
            task.abort();
        }
    }

    let after = tokio::time::timeout(PROBE_TIMEOUT, name_on(&client, sink.address)).await;
    checks.detail(
        "the same QUIC connection remains usable after the upload",
        matches!(after, Ok(Ok(ref name)) if name == "upload-sink"),
        format!("{after:?}"),
    );

    checks.finish();
}
