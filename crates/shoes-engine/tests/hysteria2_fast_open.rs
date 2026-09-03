//! An upload performed the way a real Hysteria2 client performs one.
//!
//! sing-quic's `clientConn.Write` puts the TCP request frame and the first payload
//! chunk in a single write, with 64..512 bytes of padding, and `clientConn.Read`
//! does not touch the response until the application first reads. So a client that
//! is uploading keeps filling the stream while the server is still parsing the
//! request, resolving the destination and dialling the outbound -- and the reply it
//! eventually reads has to arrive intact behind all of that.
//!
//! The rest of this suite opens streams with `open_tcp`, which writes no padding and
//! waits for status before returning. That is convenient for tests that assert on
//! byte counts, but it means none of them cover the ordering above.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::hysteria2::Hysteria2Client;
use common::*;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const PASSWORD: &str = "alice-fast-open";
const CHUNK: usize = 64 * 1024;

/// Counts every byte that arrives, with no request line to read first: a fast-open
/// stream's payload begins immediately.
async fn counting_sink() -> (SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the sink");
    let address = listener.local_addr().expect("read back the sink address");
    let received = Arc::new(AtomicU64::new(0));

    let counter = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut scratch = vec![0u8; CHUNK];
                loop {
                    match stream.read(&mut scratch).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => counter.fetch_add(n as u64, Ordering::Relaxed),
                    };
                }
            });
        }
    });
    (address, received)
}

async fn upload(total_bytes: usize) -> Result<u64, String> {
    let engine = engine().await;
    let (destination, received) = counting_sink().await;
    let server = free_addr();
    engine
        .add_inbound(dynamic(
            "hy2",
            hysteria2_inbound_with_bandwidth(server, 0, 0, false),
        ))
        .await
        .map_err(|e| format!("the Hysteria2 inbound should start: {e}"))?;
    engine
        .add_user("hy2", password_user("alice", PASSWORD))
        .map_err(|e| format!("alice should be accepted: {e}"))?;

    let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
        .await
        .map_err(|e| format!("alice should authenticate: {e}"))?;

    let first = vec![b'x'; CHUNK.min(total_bytes)];
    let mut stream = client
        .open_tcp_fast_open(destination, &first)
        .await
        .map_err(|e| format!("the fast-open request should be accepted: {e}"))?;

    let chunk = vec![b'y'; CHUNK];
    let mut written = first.len();
    while written < total_bytes {
        let count = (total_bytes - written).min(CHUNK);
        stream
            .send
            .write_all(&chunk[..count])
            .await
            .map_err(|e| format!("the upload stalled after {written} bytes: {e}"))?;
        written += count;
    }

    // Only now, exactly as `clientConn.Read` does.
    tokio::time::timeout(Duration::from_secs(15), stream.read_tcp_response())
        .await
        .map_err(|_| "the TCP response never arrived".to_string())?
        .map_err(|e| format!("the TCP response was not readable: {e}"))?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while received.load(Ordering::Relaxed) < written as u64 {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = io::sink();
    Ok(received.load(Ordering::Relaxed))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fast_open_upload_is_delivered_and_still_answers_with_its_status() {
    let mut checks = Checks::new("hysteria2 fast-open upload");

    // A single small upload, which is what a web form does: it has to work on its
    // own, not merely in aggregate.
    let small = upload(64 * 1024).await;
    checks.detail(
        "a one-chunk upload arrives in full",
        matches!(small, Ok(n) if n == 64 * 1024),
        format!("{small:?}"),
    );

    // Past the point where the client can no longer be holding the whole upload in
    // one write, so the request frame and the payload are genuinely separated.
    let large = upload(16 * 1024 * 1024).await;
    checks.detail(
        "a sustained upload arrives in full",
        matches!(large, Ok(n) if n == 16 * 1024 * 1024),
        format!("{large:?}"),
    );

    checks.finish();
}
