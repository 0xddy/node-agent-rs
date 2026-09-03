//! Bounded localhost checks for a noncompliant HY2 client's application isolation.
//! These do not simulate upstream link saturation or promise equal throughput
//! between connections authenticated as the same user.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::hysteria2::{Hysteria2Client, Hysteria2Stream};
use common::*;

const ABUSIVE_PASSWORD: &str = "isolation-abusive";
const HEALTHY_PASSWORD: &str = "isolation-healthy";
const CHUNK_SIZE: usize = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

async fn name_on(client: &Hysteria2Client, destination: SocketAddr) -> io::Result<String> {
    let mut stream = client.open_tcp(destination).await?;
    stream.write_all(b"who\n").await?;
    stream.read_line().await
}

async fn download_on(client: &Hysteria2Client, destination: SocketAddr) -> io::Result<()> {
    let mut stream = client.open_tcp(destination).await?;
    stream.write_all(b"0 1048576\n").await?;
    let mut chunk = vec![0; CHUNK_SIZE];
    for _ in 0..1024 * 1024 / CHUNK_SIZE {
        stream
            .recv
            .read_exact(&mut chunk)
            .await
            .map_err(io::Error::other)?;
        if chunk.iter().any(|byte| *byte != b'y') {
            return Err(io::Error::other("download payload changed"));
        }
    }
    Ok(())
}

async fn upload_to_sink(
    mut stream: Hysteria2Stream,
    bytes: usize,
    started: tokio::sync::mpsc::Sender<()>,
    completed: &AtomicUsize,
) -> io::Result<()> {
    let chunk = vec![b'x'; CHUNK_SIZE];
    for index in 0..bytes / CHUNK_SIZE {
        stream
            .send
            .write_all(&chunk)
            .await
            .map_err(io::Error::other)?;
        if index == 0 {
            started
                .send(())
                .await
                .map_err(|_| io::Error::other("probe stopped"))?;
        }
        if index % 16 == 0 {
            tokio::task::yield_now().await;
        }
    }
    stream.read_tcp_response().await?;
    let mut acknowledged = [0];
    stream
        .recv
        .read_exact(&mut acknowledged)
        .await
        .map_err(io::Error::other)?;
    if acknowledged != [b'y'] {
        return Err(io::Error::other(
            "TCP sink did not acknowledge the complete upload",
        ));
    }
    completed.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_brutal_connections_share_server_upload_limit_without_stopping_other_users() {
    const USER_RATE_BITS: u64 = 16 * 1024 * 1024;
    const FORCED_RATE_BYTES: u64 = 128 * 1024 * 1024;
    const BYTES_PER_CONNECTION: usize = 3 * 1024 * 1024;
    // Aggregate payload is 6 MiB. At 2 MiB/s with at most 1 MiB burst, it
    // requires 2.5 seconds. Two accidental per-connection buckets take ~1 second.
    const AGGREGATE_FLOOR: Duration = Duration::from_millis(2250);

    let engine = engine().await;
    let sink = Sink::start("limited-isolation-sink").await;
    let server = free_addr();
    let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
    config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
    engine.add_inbound(dynamic("hy2", config)).await.unwrap();
    let mut limited = password_user("abusive", ABUSIVE_PASSWORD);
    limited.upload_limit_bps = Some(USER_RATE_BITS);
    engine.add_user("hy2", limited).unwrap();
    engine
        .add_user("hy2", password_user("healthy", HEALTHY_PASSWORD))
        .unwrap();

    let (first, second) = tokio::join!(
        Hysteria2Client::connect_with_rates_bps(server, ABUSIVE_PASSWORD, 0, FORCED_RATE_BYTES),
        Hysteria2Client::connect_with_rates_bps(server, ABUSIVE_PASSWORD, 0, FORCED_RATE_BYTES),
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    for client in [&first, &second] {
        assert!(client.advertised_receive_auto);
        assert_eq!(client.negotiated_send_bps, 0);
        client.force_brutal_send_bps(FORCED_RATE_BYTES).unwrap();
    }
    let header = format!("{BYTES_PER_CONNECTION} 1\n");
    let (first_stream, second_stream) = tokio::join!(
        first.open_tcp_fast_open(sink.address, header.as_bytes()),
        second.open_tcp_fast_open(sink.address, header.as_bytes()),
    );
    let (first_stream, second_stream) = (first_stream.unwrap(), second_stream.unwrap());
    let before = engine.get_user("hy2", "abusive").unwrap();
    assert_eq!(before.conns, 2);
    let completed = AtomicUsize::new(0);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(2);
    let uploads = async {
        let start = Instant::now();
        let result = tokio::try_join!(
            upload_to_sink(
                first_stream,
                BYTES_PER_CONNECTION,
                started_tx.clone(),
                &completed
            ),
            upload_to_sink(second_stream, BYTES_PER_CONNECTION, started_tx, &completed),
        );
        (result, start.elapsed())
    };
    let probes = async {
        for _ in 0..2 {
            started_rx.recv().await.expect("both uploads should start");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let overlap = completed.load(Ordering::Relaxed) < 2;
        let same = tokio::time::timeout(PROBE_TIMEOUT, download_on(&first, sink.address));
        let other = tokio::time::timeout(PROBE_TIMEOUT, async {
            let client = Hysteria2Client::connect(server, HEALTHY_PASSWORD).await?;
            name_on(&client, sink.address).await
        });
        let start = Instant::now();
        let (same, other) = tokio::join!(same, other);
        (overlap, same, other, start.elapsed())
    };
    let ((uploaded, elapsed), (overlap, same, other, probe_elapsed)) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(uploads, probes)
        })
        .await
        .expect("bounded upload and probes should finish");
    let after = engine.get_user("hy2", "abusive").unwrap();
    println!(
        "forced Brutal: connections=2, forced_bytes_per_second={FORCED_RATE_BYTES}, user_bits_per_second={USER_RATE_BITS}, acknowledged_payload={}, measured_rx_delta={}, upload_elapsed={elapsed:?}, overlap={overlap}, same_download={same:?}, healthy_user={other:?}, probe_elapsed={probe_elapsed:?}, first_path={:?}, second_path={:?}",
        2 * BYTES_PER_CONNECTION,
        after.rx - before.rx,
        first.stats().path,
        second.stats().path,
    );
    uploaded.expect("both TCP destinations should acknowledge every byte");
    assert!(
        elapsed >= AGGREGATE_FLOOR,
        "aggregate upload escaped the server limit: {elapsed:?}"
    );
    assert!(
        overlap,
        "probes must begin while the limited uploads are active"
    );
    assert!(
        matches!(same, Ok(Ok(()))),
        "same-connection download failed: {same:?}"
    );
    assert!(
        matches!(other, Ok(Ok(ref name)) if name == &sink.name),
        "healthy user failed: {other:?}"
    );
    assert_eq!(completed.load(Ordering::Relaxed), 2);
    assert!(after.rx - before.rx >= (2 * BYTES_PER_CONNECTION) as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_datagrams_do_not_stop_a_healthy_user_on_the_same_listener() {
    const FLOOD_DURATION: Duration = Duration::from_secs(2);
    const MAX_DATAGRAMS: u64 = 100_000;
    const BATCH_SIZE: u64 = 64;
    let engine = engine().await;
    let sink = Sink::start("malformed-isolation-sink").await;
    let server = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(server, true)))
        .await
        .unwrap();
    engine
        .add_user("hy2", password_user("abusive", ABUSIVE_PASSWORD))
        .unwrap();
    engine
        .add_user("hy2", password_user("healthy", HEALTHY_PASSWORD))
        .unwrap();
    let abusive = Hysteria2Client::connect_with_rates_bps(server, ABUSIVE_PASSWORD, 0, 0)
        .await
        .unwrap();
    let before = abusive.stats();
    let submitted = AtomicU64::new(0);
    let running = AtomicBool::new(false);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let payloads = [
        Bytes::from_static(&[0, 0, 0]), // Too short for the fixed HY2 fields.
        Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 0, 0]), // Zero fragment count.
        Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 1, 0x80]), // Truncated address varint.
        Bytes::from_static(&[0, 0, 0, 1, 0, 0, 0, 1, 1, 0xff]), // Non-UTF-8 address.
    ];
    let flood = async {
        let mut start_signal = Some(started_tx);
        let start = Instant::now();
        running.store(true, Ordering::Relaxed);
        let result = async {
            while start.elapsed() < FLOOD_DURATION
                && submitted.load(Ordering::Relaxed) < MAX_DATAGRAMS
            {
                for _ in 0..BATCH_SIZE {
                    let count = submitted.load(Ordering::Relaxed);
                    if count >= MAX_DATAGRAMS {
                        break;
                    }
                    abusive.send_raw_datagram(payloads[count as usize % payloads.len()].clone())?;
                    submitted.fetch_add(1, Ordering::Relaxed);
                }
                if submitted.load(Ordering::Relaxed) >= 256
                    && let Some(signal) = start_signal.take()
                {
                    let _ = signal.send(());
                }
                // Keep the test producer cooperative even though send_datagram is
                // synchronous, and bound offered traffic independently of CPU speed.
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Ok::<(), io::Error>(())
        }
        .await;
        running.store(false, Ordering::Relaxed);
        (result, start.elapsed())
    };
    let probes = async {
        started_rx
            .await
            .expect("the malformed generator should begin");
        let mut reports = Vec::new();
        for _ in 0..3 {
            let active_before = running.load(Ordering::Relaxed);
            let offered = submitted.load(Ordering::Relaxed);
            let start = Instant::now();
            let reply = tokio::time::timeout(PROBE_TIMEOUT, async {
                let healthy = Hysteria2Client::connect(server, HEALTHY_PASSWORD).await?;
                name_on(&healthy, sink.address).await
            })
            .await;
            let active_after = running.load(Ordering::Relaxed);
            reports.push((offered, active_before, active_after, reply, start.elapsed()));
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        reports
    };
    let ((flood_result, elapsed), reports) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(flood, probes)
    })
    .await
    .expect("malformed generator and liveness checks should finish");
    let after = abusive.stats();
    let submitted = submitted.load(Ordering::Relaxed);
    let transmitted = after.frame_tx.datagram - before.frame_tx.datagram;
    let packets = after.path.sent_packets - before.path.sent_packets;
    let metered = engine.get_user("hy2", "abusive").unwrap();
    println!(
        "malformed DATAGRAM isolation: offered={submitted}, transmitted_frames={transmitted}, sent_packets={packets}, metered_rx={}, elapsed={elapsed:?}, reports={reports:?}, path={:?}",
        metered.rx, after.path
    );
    flood_result.expect("malformed application input should not close its QUIC connection");
    assert!((256..=MAX_DATAGRAMS).contains(&submitted));
    assert!(
        transmitted >= 256 && packets > 0,
        "actual QUIC traffic must reach the path"
    );
    assert!(
        metered.rx > 0,
        "the server must consume and meter malformed datagrams"
    );
    for (offered, active_before, active_after, reply, _) in reports {
        assert!(
            active_before && active_after,
            "healthy request at offered={offered} must overlap continuing malformed traffic"
        );
        assert!(
            matches!(reply, Ok(Ok(ref name)) if name == &sink.name),
            "healthy request failed: {reply:?}"
        );
    }
    assert_eq!(
        tokio::time::timeout(PROBE_TIMEOUT, name_on(&abusive, sink.address))
            .await
            .unwrap()
            .unwrap(),
        sink.name,
        "malformed datagrams must not poison later valid traffic on their connection",
    );
}
