//! What a Hysteria2 client sees when it holds many proxied connections at once.
//!
//! One logical flow is one proxied TCP connection, held for that connection's whole
//! life -- keep-alive idle time included. A browsing session accumulates them and a
//! speed test's parallel connections land on top, so a busy client reaches counts
//! that a request/response test never does.
//!
//! Two properties matter, and the second is the one that bit: the ceiling has to be
//! clear of ordinary use, and reaching it has to *fail* rather than stall. When the
//! advertised `max_concurrent_bidi_streams` equals the application's own limit,
//! quinn withholds `MAX_STREAMS` credit and the peer's `open_bi` blocks with no
//! error and no timeout -- which from the client side is indistinguishable from the
//! whole node having died, since established flows keep working while every new
//! connection hangs.

mod common;

use std::time::Duration;

use common::hysteria2::{Hysteria2Client, Hysteria2Stream};
use common::*;

const PASSWORD: &str = "alice-many-flows";

/// Comfortably past the 256 that shipped, and past what a browser plus a speed test
/// reaches, without making the test's own socket count unreasonable.
const CONCURRENT_FLOWS: usize = 300;

/// A refusal has to arrive on a human timescale. The bug under test produced no
/// answer at all, so any bound well under a stalled connection's lifetime works.
const REFUSAL_BUDGET: Duration = Duration::from_secs(5);

/// Opens one proxied flow and parks it: `hold` makes the sink read until the peer
/// goes away, so the flow stays live and keeps holding its slot.
async fn hold_one(client: &Hysteria2Client, sink: &Sink) -> std::io::Result<Hysteria2Stream> {
    let mut stream = client.open_tcp(sink.address).await?;
    stream.write_all(b"hold\n").await?;
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread")]
async fn many_concurrent_flows_are_served_and_the_ceiling_refuses_rather_than_stalls() {
    let mut checks = Checks::new("hysteria2 concurrent flow ceiling");
    let engine = engine().await;
    let sink = Sink::start("ceiling-sink").await;
    let server = free_addr();

    engine
        .add_inbound(dynamic(
            "hy2",
            hysteria2_inbound_with_bandwidth(server, 0, 0, false),
        ))
        .await
        .expect("the Hysteria2 inbound should start");
    engine
        .add_user("hy2", password_user("alice", PASSWORD))
        .expect("alice should be accepted");

    let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
        .await
        .expect("alice should authenticate");

    // Each open is bounded: the regression's signature is that it never returns, so
    // a hang has to be a failure here rather than a hung test.
    let mut held = Vec::with_capacity(CONCURRENT_FLOWS);
    let mut outcome = Ok(());
    for index in 0..CONCURRENT_FLOWS {
        match tokio::time::timeout(REFUSAL_BUDGET, hold_one(&client, &sink)).await {
            Ok(Ok(stream)) => held.push(stream),
            Ok(Err(error)) => {
                outcome = Err(format!("flow {index} was refused: {error}"));
                break;
            }
            Err(_) => {
                outcome = Err(format!("flow {index} neither opened nor was refused"));
                break;
            }
        }
    }
    checks.detail(
        "a client can hold many concurrent proxied flows on one connection",
        outcome.is_ok() && held.len() == CONCURRENT_FLOWS,
        format!("{} of {CONCURRENT_FLOWS} held; {outcome:?}", held.len()),
    );

    // With that many flows parked, an unrelated request must still be served. This
    // is the user-visible half: the browser opening one more connection.
    let probe = tokio::time::timeout(REFUSAL_BUDGET, async {
        let mut stream = client.open_tcp(sink.address).await?;
        stream.write_all(b"who\n").await?;
        stream.read_line().await
    })
    .await;
    checks.detail(
        "a new flow is still served while many others are parked",
        matches!(probe, Ok(Ok(ref name)) if name == "ceiling-sink"),
        format!("{probe:?}"),
    );

    // Releasing them must return the capacity rather than leak it.
    held.clear();
    let after = tokio::time::timeout(REFUSAL_BUDGET, async {
        let mut stream = client.open_tcp(sink.address).await?;
        stream.write_all(b"who\n").await?;
        stream.read_line().await
    })
    .await;
    checks.detail(
        "capacity comes back once the flows are released",
        matches!(after, Ok(Ok(ref name)) if name == "ceiling-sink"),
        format!("{after:?}"),
    );

    checks.finish();
}
