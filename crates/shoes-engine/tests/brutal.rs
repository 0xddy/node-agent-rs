//! Acceptance: Hysteria2 bandwidth negotiation and per-connection Brutal setup.
//!
//! The request and response carry bytes per second even though configuration uses
//! Mbps. A successful authenticated connection with a non-zero request also proves
//! the live Quinn connection was built with the switchable controller: auth treats
//! failure to locate and activate that connection's controller as fatal.

mod common;

use common::hysteria2::Hysteria2Client;
use common::*;

const PASSWORD: &str = "alice-brutal-password";

async fn connect_and_name(
    server: std::net::SocketAddr,
    receive_bps: u64,
    sink: &Sink,
) -> std::io::Result<(u64, bool, String)> {
    let client = Hysteria2Client::connect_with_receive_bps(server, PASSWORD, receive_bps).await?;
    let advertised = client.advertised_receive_bps;
    let auto = client.advertised_receive_auto;
    let mut stream = client.open_tcp(sink.address).await?;
    stream.write_all(b"who\n").await?;
    Ok((advertised, auto, stream.read_line().await?))
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_and_download_bandwidths_negotiate_independently() {
    let mut checks = Checks::new("hysteria2 brutal negotiation");
    let engine = engine().await;
    let sink = Sink::start("brutal-sink").await;

    let cases = [
        // (tag, up Mbps, down Mbps, client RX B/s, ignore, advertised B/s, auto)
        ("both", 100, 200, 20_000_000, false, 25_000_000, false),
        ("download-only", 0, 37, 4_000_000, false, 4_625_000, false),
        ("upload-only", 80, 0, 20_000_000, false, 0, false),
        // Numeric zero is uncapped. It deliberately does not force the client's
        // upload half onto BBR the way the literal `auto` value would.
        ("uncapped", 100, 0, 0, false, 0, false),
        ("ignored", 0, 0, 20_000_000, true, 0, true),
    ];

    for (
        tag,
        up_mbps,
        down_mbps,
        client_receive_bps,
        ignore_client_bandwidth,
        expected_advertised,
        expected_auto,
    ) in cases
    {
        let address = free_addr();
        let mut config = hysteria2_inbound_with_bandwidth(address, up_mbps, down_mbps, false);
        if ignore_client_bandwidth {
            config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
        }
        engine
            .add_inbound(dynamic(tag, config))
            .await
            .unwrap_or_else(|e| panic!("{tag} inbound should start: {e}"));
        engine
            .add_user(tag, password_user("alice", PASSWORD))
            .unwrap_or_else(|e| panic!("{tag} should accept alice: {e}"));

        match connect_and_name(address, client_receive_bps, &sink).await {
            Ok((advertised, auto, name)) => {
                checks.eq(
                    &format!("{tag} advertises only its download direction"),
                    advertised,
                    expected_advertised,
                );
                checks.eq(
                    &format!("{tag} selects the expected fixed/auto response"),
                    auto,
                    expected_auto,
                );
                checks.eq(
                    &format!("{tag} carries traffic after controller negotiation"),
                    name,
                    sink.name.clone(),
                );
            }
            Err(error) => checks.that(
                &format!("{tag} authenticates with its CC request: {error}"),
                false,
            ),
        }
    }

    checks.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_either_bandwidth_rebuilds_the_quic_listener() {
    let mut checks = Checks::new("hysteria2 brutal reload refusal");
    let engine = engine().await;
    let address = free_addr();

    engine
        .add_inbound(dynamic(
            "hy2",
            hysteria2_inbound_with_bandwidth(address, 100, 200, false),
        ))
        .await
        .expect("the initial inbound should start");

    checks.refused(
        "changing the server send rate is refused by name",
        engine
            .update_inbound(classic(
                "hy2",
                hysteria2_inbound_with_bandwidth(address, 101, 200, false),
            ))
            .await,
        "up_mbps",
    );
    checks.refused(
        "changing the advertised receive rate is refused by name",
        engine
            .update_inbound(classic(
                "hy2",
                hysteria2_inbound_with_bandwidth(address, 100, 201, false),
            ))
            .await,
        "down_mbps",
    );
    let mut ignored = hysteria2_inbound_with_bandwidth(address, 100, 200, false);
    ignored["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
    checks.refused(
        "changing client-bandwidth policy is refused by name",
        engine.update_inbound(classic("hy2", ignored)).await,
        "ignore_client_bandwidth",
    );
    checks.that(
        "an unchanged bandwidth configuration remains reloadable",
        engine
            .update_inbound(classic(
                "hy2",
                hysteria2_inbound_with_bandwidth(address, 100, 200, false),
            ))
            .await
            .is_ok(),
    );

    checks.finish();
}
