//! Real routed traffic exercises the runtime observer and collector together.
//! Web classification limits analytics; it must never limit traffic forwarding
//! or the separate per-user billing meter.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::analysis::default_config;
use node_agent::analysis::Collector;
use node_agent::runtime::{CompiledInbound, NodeRuntime, RuntimeConfig, ShoesRuntime};
use serde_json::json;
use shoes_api::InboundSpec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const NODE: &str = "web-analysis-node";
const TAG: &str = "web-analysis-inbound";
const USER: &str = "42";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const UUID_BYTES: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const HTTP_REQUEST: &[u8] = b"GET /watch HTTP/1.1\r\nHost: WWW.YouTube.COM.:8080\r\n\r\n";
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";

async fn fixture() -> (ShoesRuntime, Arc<Collector>, u64, SocketAddr) {
    fixture_with_redirect(None).await
}

async fn fixture_with_redirect(
    target: Option<SocketAddr>,
) -> (ShoesRuntime, Arc<Collector>, u64, SocketAddr) {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inbound = reserved.local_addr().unwrap();
    let runtime = ShoesRuntime::bootstrap().await.unwrap();
    let collector = Collector::new("web-only-integration".into());
    let epoch = collector.begin_session();
    assert!(collector.configure(epoch, Some(&default_config(true))));
    runtime.set_analysis_collector(collector.clone());
    drop(reserved);
    let mut inbound_config = json!({
        "address": inbound.to_string(),
        "sniff": true,
        "protocol": { "type": "vless", "udp_enabled": true },
    });
    if let Some(target) = target {
        inbound_config["rules"] = json!([{
            "masks": "0.0.0.0/0",
            "action": "allow",
            "override_address": target.to_string(),
        }]);
    }
    runtime
        .apply_config(RuntimeConfig {
            inbounds: vec![CompiledInbound {
                node_id: NODE.into(),
                protocol: "vless".into(),
                spec: InboundSpec {
                    tag: TAG.into(),
                    config: inbound_config,
                    users: Some(vec![
                        serde_json::from_value(json!({ "id": USER, "uuid": UUID })).unwrap(),
                    ]),
                },
            }],
            ..RuntimeConfig::default()
        })
        .await
        .unwrap();
    (runtime, collector, epoch, inbound)
}

fn vless_request(target: SocketAddr, udp: bool) -> Vec<u8> {
    let IpAddr::V4(address) = target.ip() else {
        panic!("loopback fixture must use IPv4");
    };
    let mut bytes = vec![0];
    bytes.extend_from_slice(&UUID_BYTES);
    bytes.extend_from_slice(&[0, if udp { 2 } else { 1 }]);
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&address.octets());
    bytes
}

async fn tcp_roundtrip(inbound: SocketAddr, request: &[u8], response: &[u8]) -> (u64, u64) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let header = vless_request(target.local_addr().unwrap(), false);
    tcp_roundtrip_to(inbound, target, header, request, response).await
}

async fn tcp_roundtrip_to(
    inbound: SocketAddr,
    target: TcpListener,
    header: Vec<u8>,
    request: &[u8],
    response: &[u8],
) -> (u64, u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let header_len = header.len();
        let upstream_request = request.to_vec();
        let upstream_response = response.to_vec();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut received = vec![0; upstream_request.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(
                received, upstream_request,
                "classification must preserve upstream payload"
            );
            stream.write_all(&upstream_response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&header).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0, 0]);
        let mut received = vec![0; response.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(
            received, response,
            "classification must preserve downstream payload"
        );
        client.shutdown().await.unwrap();
        drop(client);
        upstream.await.unwrap();
        (
            (header_len + request.len()) as u64,
            (2 + response.len()) as u64,
        )
    })
    .await
    .expect("TCP fixture must complete through the real proxy")
}

async fn dns_roundtrip(inbound: SocketAddr) -> (u64, u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let header = vless_request(target.local_addr().unwrap(), true);
        let mut question = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        question.extend_from_slice(b"\x03www\x07youtube\x03com\x00\x00\x01\x00\x01");
        let mut response = question.clone();
        response[2] |= 0x80;
        let expected_question = question.clone();
        let response_packet = response.clone();
        let upstream = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (len, source) = target.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..len], expected_question);
            target.send_to(&response_packet, source).await.unwrap();
        });
        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&header).await.unwrap();
        client.write_u16(question.len() as u16).await.unwrap();
        client.write_all(&question).await.unwrap();
        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0, 0]);
        assert_eq!(client.read_u16().await.unwrap() as usize, response.len());
        let mut received = vec![0; response.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, response);
        client.shutdown().await.unwrap();
        drop(client);
        upstream.await.unwrap();
        (
            (header.len() + 2 + question.len()) as u64,
            (2 + 2 + response.len()) as u64,
        )
    })
    .await
    .expect("DNS datagrams must still pass through the real proxy")
}

async fn non_web_roundtrips(inbound: SocketAddr) -> (u64, u64) {
    let mut total = (0, 0);
    for (request, response) in [
        (
            b"SSH-2.0-integration-client\r\n".as_slice(),
            b"SSH-2.0-integration-server\r\n".as_slice(),
        ),
        (
            b"USER anonymous\r\n".as_slice(),
            b"331 Password required\r\n".as_slice(),
        ),
        (
            b"\xff\x00\x81raw-binary\x00".as_slice(),
            b"\xfe\x00raw-reply\x00".as_slice(),
        ),
    ] {
        let (up, down) = tcp_roundtrip(inbound, request, response).await;
        total.0 += up;
        total.1 += down;
    }
    let (up, down) = dns_roundtrip(inbound).await;
    (total.0 + up, total.1 + down)
}

async fn settled_billing(runtime: &ShoesRuntime) -> (u64, u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.connection_stats(NODE).active_connections != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed client connections must release their meters");
    runtime
        .drain_traffic()
        .await
        .unwrap()
        .iter()
        .filter(|row| row.node_id == NODE && row.user_id == USER)
        .fold((0, 0), |(up, down), row| {
            (up + row.uplink_bytes, down + row.downlink_bytes)
        })
}

fn seal_observed_minute(collector: &Collector) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // A historical observation twelve seconds before now has already passed
    // the <=10s send jitter, while retaining eight seconds of queue validity.
    collector.sample(now - 72);
    collector.sample(now - 12);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_web_payload_enters_analytics_and_all_protocols_remain_billable() {
    let (runtime, collector, epoch, inbound) = fixture().await;
    let (other_up, other_down) = non_web_roundtrips(inbound).await;
    let (web_wire_up, web_wire_down) = tcp_roundtrip(inbound, HTTP_REQUEST, HTTP_RESPONSE).await;
    let billing = settled_billing(&runtime).await;
    assert_eq!(
        billing,
        (other_up + web_wire_up, other_down + web_wire_down),
        "billing retains every original VLESS byte, including non-Web traffic"
    );
    seal_observed_minute(&collector);
    assert_eq!(collector.status().queued_batches, 1);
    let cancel = CancellationToken::new();
    let batch = tokio::time::timeout(Duration::from_secs(2), collector.next(&cancel, epoch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.message.user_minutes.len(), 1);
    let user = &batch.message.user_minutes[0];
    assert_eq!(
        (&*user.node_id, &*user.user_id, &*user.network),
        (NODE, USER, "tcp")
    );
    assert_eq!(
        (user.uplink_bytes, user.downlink_bytes),
        (HTTP_REQUEST.len() as u64, HTTP_RESPONSE.len() as u64)
    );
    assert_eq!(user.started_sessions, 1);
    assert_eq!(batch.message.domain_minutes.len(), 1);
    let domain = &batch.message.domain_minutes[0];
    assert_eq!(
        (&*domain.domain, &*domain.app_protocol),
        ("WWW.YouTube.COM.", "http")
    );
    assert!(domain.destination_domain.is_empty());
    assert!(!domain.ech_present);
    assert_eq!(
        (domain.uplink_bytes, domain.downlink_bytes),
        (HTTP_REQUEST.len() as u64, HTTP_RESPONSE.len() as u64)
    );
    collector.complete(&batch, true);
    runtime.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_non_web_traffic_produces_no_analytics_batch() {
    let (runtime, collector, _epoch, inbound) = fixture().await;
    let expected = non_web_roundtrips(inbound).await;
    assert_eq!(settled_billing(&runtime).await, expected);
    assert!(expected.0 > 0 && expected.1 > 0);
    seal_observed_minute(&collector);
    let status = collector.status();
    assert_eq!(
        status.queued_batches, 0,
        "SSH, FTP, raw streams and DNS must not create unknown analytics rows"
    );
    assert_eq!(status.buffered_domain_keys, 0);
    runtime.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requested_domain_survives_sniffing_and_route_override() {
    const REQUESTED_DOMAIN: &str = "Original.Example.";
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (runtime, collector, epoch, inbound) =
        fixture_with_redirect(Some(target.local_addr().unwrap())).await;
    let mut header = vec![0];
    header.extend_from_slice(&UUID_BYTES);
    header.extend_from_slice(&[0, 1]); // No addons, TCP command.
    header.extend_from_slice(&443u16.to_be_bytes());
    header.extend_from_slice(&[2, REQUESTED_DOMAIN.len() as u8]);
    header.extend_from_slice(REQUESTED_DOMAIN.as_bytes());
    let expected = tcp_roundtrip_to(inbound, target, header, HTTP_REQUEST, HTTP_RESPONSE).await;
    assert_eq!(settled_billing(&runtime).await, expected);
    seal_observed_minute(&collector);
    let cancel = CancellationToken::new();
    let batch = tokio::time::timeout(Duration::from_secs(2), collector.next(&cancel, epoch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.message.user_minutes.len(), 1);
    let user = &batch.message.user_minutes[0];
    assert_eq!(user.identified_uplink_bytes, HTTP_REQUEST.len() as u64);
    assert_eq!(user.identified_downlink_bytes, HTTP_RESPONSE.len() as u64);
    assert_eq!(batch.message.domain_minutes.len(), 1);
    let row = &batch.message.domain_minutes[0];
    assert_eq!(row.domain, "WWW.YouTube.COM.");
    assert_eq!(row.destination_domain, REQUESTED_DOMAIN);
    assert_eq!(row.app_protocol, "http");
    assert!(!row.ech_present);
    assert_eq!(row.uplink_bytes, HTTP_REQUEST.len() as u64);
    assert_eq!(row.downlink_bytes, HTTP_RESPONSE.len() as u64);
    collector.complete(&batch, true);
    runtime.close().await.unwrap();
}

fn tls_client_hello(ech_payload: Option<&[u8]>) -> Vec<u8> {
    let name = b"Public.Example.COM.";
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    extensions.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    extensions.push(0);
    extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(name);
    if let Some(payload) = ech_payload {
        // Both real ECH and GREASE use encrypted_client_hello. The observer
        // reports extension presence without claiming access to the inner SNI.
        // Keep it after SNI to catch a parser that returns before scanning it.
        extensions.extend_from_slice(&[0xfe, 0x0d]);
        extensions.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extensions.extend_from_slice(payload);
    }
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
    record.extend_from_slice(&[1, 0, 0, hello.len() as u8]);
    record.extend_from_slice(&hello);
    record
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ech_and_grease_keep_outer_sni_while_tls_forwarding_and_billing_stay_intact() {
    let (runtime, collector, epoch, inbound) = fixture().await;
    let normal = tls_client_hello(None);
    let ech = tls_client_hello(Some(&[0, 0, 1, 0, 1, 7, 0, 2, 0xaa, 0xbb, 0, 2, 1, 2]));
    let grease = tls_client_hello(Some(&[0, 0, 1, 0, 1, 99, 0, 2, 0xcc, 0xdd, 0, 3, 3, 4, 5]));
    let response = b"\x15\x03\x03\x00\x02\x02\x28";
    let normal_bill = tcp_roundtrip(inbound, &normal, response).await;
    let ech_bill = tcp_roundtrip(inbound, &ech, response).await;
    let grease_bill = tcp_roundtrip(inbound, &grease, response).await;
    assert_eq!(
        settled_billing(&runtime).await,
        (
            normal_bill.0 + ech_bill.0 + grease_bill.0,
            normal_bill.1 + ech_bill.1 + grease_bill.1,
        ),
    );
    seal_observed_minute(&collector);
    let cancel = CancellationToken::new();
    let batch = tokio::time::timeout(Duration::from_secs(2), collector.next(&cancel, epoch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.message.user_minutes.len(), 1);
    let user = &batch.message.user_minutes[0];
    assert_eq!(user.started_sessions, 3);
    assert_eq!(
        user.uplink_bytes,
        (normal.len() + ech.len() + grease.len()) as u64
    );
    assert_eq!(user.downlink_bytes, (3 * response.len()) as u64);
    assert_eq!(user.identified_uplink_bytes, user.uplink_bytes);
    assert_eq!(user.identified_downlink_bytes, user.downlink_bytes);
    assert_eq!(batch.message.domain_minutes.len(), 2);
    for (ech_present, expected_up, sessions) in [
        (false, normal.len(), 1),
        (true, ech.len() + grease.len(), 2),
    ] {
        let row = batch
            .message
            .domain_minutes
            .iter()
            .find(|row| row.ech_present == ech_present)
            .unwrap();
        assert_eq!(row.domain, "Public.Example.COM.");
        assert!(row.destination_domain.is_empty());
        assert_eq!(row.app_protocol, "tls");
        assert_eq!(row.target_sessions, sessions);
        assert_eq!(row.uplink_bytes, expected_up as u64);
        assert_eq!(row.downlink_bytes, sessions * response.len() as u64);
    }
    collector.complete(&batch, true);
    runtime.close().await.unwrap();
}
