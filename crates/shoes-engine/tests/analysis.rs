//! Payload analytics shares authenticated identity with billing, while reporting
//! only routed payload bytes and keeping each UDP destination separate.

mod common;

use common::*;
use shoes_engine::{AnalysisFlow, AnalysisMetadata, AnalysisObserver, AnalysisTarget};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Flow {
    upload: AtomicU64,
    download: AtomicU64,
    closed: AtomicU64,
    targets: Mutex<HashMap<AnalysisTarget, (u64, u64)>>,
}

impl AnalysisFlow for Flow {
    fn begin(&self) -> u64 {
        1
    }
    fn finish(&self, _: u64, up: u64, down: u64, target: Option<&AnalysisTarget>) {
        self.upload.fetch_add(up, Ordering::Relaxed);
        self.download.fetch_add(down, Ordering::Relaxed);
        if let Some(target) = target {
            let mut targets = self.targets.lock().unwrap();
            let counts = targets.entry(target.clone()).or_default();
            counts.0 += up;
            counts.1 += down;
        }
    }
    fn cancel(&self, _: u64) {}
    fn close(&self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Observer {
    enabled: AtomicBool,
    flows: Mutex<Vec<(AnalysisMetadata, Arc<Flow>)>>,
}
impl AnalysisObserver for Observer {
    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    fn register(&self, metadata: AnalysisMetadata) -> Option<Arc<dyn AnalysisFlow>> {
        if !self.enabled() {
            return None;
        }
        let flow = Arc::new(Flow::default());
        self.flows.lock().unwrap().push((metadata, flow.clone()));
        Some(flow)
    }
}

/// An encrypted QUIC Initial, so the real passive classifier admits the target
/// before the observer asserts payload accounting on the decoded UDP path.
fn quic_initial(host: &'static str) -> Vec<u8> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Keep the fixture under Hysteria2's datagram limit; post-quantum key
    // shares are unrelated to testing target attribution.
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut client = rustls::quic::ClientConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        host.try_into().unwrap(),
        Vec::new(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_hs(&mut hello);
    let varint = |value: usize, bytes: &mut Vec<u8>| {
        assert!(value < 16384);
        if value < 64 {
            bytes.push(value as u8);
        } else {
            bytes.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        }
    };
    let mut payload = vec![6, 0]; // CRYPTO frame, offset zero
    varint(hello.len(), &mut payload);
    payload.extend_from_slice(&hello);
    let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap();
    let dcid = b"analysis";
    let keys = suite.keys(dcid, rustls::Side::Client, rustls::quic::Version::V1);
    let mut header = vec![0xc3, 0, 0, 0, 1, dcid.len() as u8];
    header.extend_from_slice(dcid);
    header.extend_from_slice(&[0, 0]); // SCID, token
    varint(4 + payload.len() + 16, &mut header);
    let pn_offset = header.len();
    header.extend_from_slice(&0u32.to_be_bytes());
    let tag = keys
        .local
        .packet
        .encrypt_in_place(0, &header, &mut payload)
        .unwrap();
    payload.extend_from_slice(tag.as_ref());
    let (first, rest) = header.split_at_mut(1);
    keys.local
        .header
        .encrypt_in_place(&payload[..16], &mut first[0], &mut rest[pn_offset - 1..])
        .unwrap();
    header.extend_from_slice(&payload);
    header
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routed_tcp_keeps_raw_observations_across_override_and_counts_payload_exactly() {
    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: WWW.YouTube.COM.:8080\r\n\r\n";
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let engine = engine().await;
    let address = free_addr();
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let requested = "192.0.2.1:443".parse().unwrap();
    let mut config = vless_inbound_with_rules(address, true, redirect_to(target_addr));
    config["sniff"] = serde_json::json!(true);
    engine.add_inbound(dynamic("vless", config)).await.unwrap();
    engine.add_user("vless", user("alice", USER)).unwrap();
    let observer = Arc::new(Observer::default());
    observer.enabled.store(true, Ordering::Relaxed);
    // Install after registry/listener creation: existing users must see it too.
    engine.set_analysis_observer(Some(observer.clone()));
    let leg = start_leg(&engine, "leg", vless_chain(address, USER)).await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut bytes = vec![0; REQUEST.len()];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, REQUEST);
        stream.write_all(RESPONSE).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut client = Socks::connect(leg, requested).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, RESPONSE);
    drop(client);
    upstream.await.unwrap();
    assert!(
        wait_for("analytics flow close", || {
            observer
                .flows
                .lock()
                .unwrap()
                .first()
                .is_some_and(|(_, flow)| flow.closed.load(Ordering::Relaxed) == 1)
        })
        .await
    );
    let flows = observer.flows.lock().unwrap();
    assert_eq!(flows.len(), 1);
    let (metadata, flow) = &flows[0];
    assert_eq!(metadata.inbound_tag, "vless");
    assert_eq!(metadata.user_id, "alice");
    assert_eq!(metadata.domain.as_deref(), Some("WWW.YouTube.COM."));
    assert_eq!(metadata.app_protocol, Some("http"));
    assert!(!metadata.ech_present);
    assert_eq!(
        metadata.destination,
        Some(AnalysisTarget {
            host: "192.0.2.1".into(),
            port: 443,
        }),
        "the requested destination must not be replaced by sniff or route override"
    );
    assert_eq!(flow.upload.load(Ordering::Relaxed), REQUEST.len() as u64);
    assert_eq!(flow.download.load(Ordering::Relaxed), RESPONSE.len() as u64);
    let billed = engine.get_user("vless", "alice").unwrap();
    assert!(billed.rx > flow.upload.load(Ordering::Relaxed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria2_udp_targets_share_one_association_without_mixing_bytes() {
    let engine = engine().await;
    let observer = Arc::new(Observer::default());
    observer.enabled.store(true, Ordering::Relaxed);
    engine.set_analysis_observer(Some(observer.clone()));
    let address = free_addr();
    engine
        .add_inbound(dynamic("hy2", hysteria2_inbound(address, true)))
        .await
        .unwrap();
    engine
        .add_user("hy2", password_user("alice", "analysis-password"))
        .unwrap();
    let first = UdpEcho::start().await;
    let second = UdpEcho::start().await;
    let client = common::hysteria2::Hysteria2Client::connect(address, "analysis-password")
        .await
        .unwrap();
    let first_packet = quic_initial("youtube.com");
    let second_packet = quic_initial("github.com");
    client
        .send_udp(7, 1, first.address, &first_packet)
        .await
        .unwrap();
    assert_eq!(
        client.recv_udp(Duration::from_secs(3)).await.unwrap().1,
        first_packet
    );
    client
        .send_udp(7, 2, second.address, &second_packet)
        .await
        .unwrap();
    assert_eq!(
        client.recv_udp(Duration::from_secs(3)).await.unwrap().1,
        second_packet
    );
    let flows = observer.flows.lock().unwrap();
    assert_eq!(
        flows.len(),
        1,
        "targets of one UDP association share a flow"
    );
    let (metadata, flow) = &flows[0];
    assert_eq!(metadata.network, "udp");
    assert_eq!(metadata.user_id, "alice");
    let targets = flow.targets.lock().unwrap();
    assert_eq!(
        targets.get(&AnalysisTarget {
            host: first.address.ip().to_string(),
            port: first.address.port()
        }),
        Some(&(first_packet.len() as u64, first_packet.len() as u64))
    );
    assert_eq!(
        targets.get(&AnalysisTarget {
            host: second.address.ip().to_string(),
            port: second.address.port()
        }),
        Some(&(second_packet.len() as u64, second_packet.len() as u64))
    );
    let total = (first_packet.len() + second_packet.len()) as u64;
    assert_eq!(flow.upload.load(Ordering::Relaxed), total);
    assert_eq!(flow.download.load(Ordering::Relaxed), total);
    let billed = engine.get_user("hy2", "alice").unwrap();
    assert!(billed.rx >= total);
    assert!(billed.tx >= total);
}
