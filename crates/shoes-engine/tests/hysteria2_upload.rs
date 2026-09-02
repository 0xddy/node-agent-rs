//! Liveness coverage for a Hysteria2 connection under speed-test-style upload.
//!
//! Small request/response transfers do not exercise this path. When fixed bandwidth
//! is negotiated, a production client activates Brutal after authentication and may
//! multiplex several large TCP uploads over one QUIC connection. The connection and
//! inbound must keep scheduling control traffic and unrelated clients while those
//! streams are hot, and the original connection must remain usable afterwards.
//!
//! This loopback test does not create deterministic loss or reordering. It therefore
//! does not reproduce or guard against Quinn's `TooManyChunks` receive-buffer error.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::hysteria2::{Hysteria2Client, Hysteria2Stream};
use common::*;

const PASSWORD: &str = "alice-upload-pressure";
const UPLOAD_STREAMS: usize = 4;
const BYTES_PER_STREAM: usize = 2 * 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;
const SEND_BPS: u64 = 4_000_000;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

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
