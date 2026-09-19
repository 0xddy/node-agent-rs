//! Empty datagrams remain messages through the production VLESS, billing and
//! optional analysis wrappers. A subsequent TCP EOF still retires the relay.

mod common;

use common::*;
use shoes_engine::{AnalysisFlow, AnalysisMetadata, AnalysisObserver};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const USER: &str = "11111111-1111-4111-8111-111111111111";
const PACKETS: [&[u8]; 4] = [b"", b"after-empty", b"", b"last-packet"];

#[derive(Default)]
struct Observer {
    registered: AtomicUsize,
    closed: Arc<AtomicUsize>,
}

struct Flow(Arc<AtomicUsize>);

impl AnalysisFlow for Flow {
    fn begin(&self) -> u64 {
        1
    }

    fn finish(&self, _: u64, _: u64, _: u64, _: Option<&shoes_engine::AnalysisTarget>) {}

    fn cancel(&self, _: u64) {}

    fn close(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl AnalysisObserver for Observer {
    fn enabled(&self) -> bool {
        true
    }

    fn register(&self, metadata: AnalysisMetadata) -> Option<Arc<dyn AnalysisFlow>> {
        assert_eq!(metadata.inbound_tag, "vless");
        assert_eq!(metadata.user_id, "alice");
        assert_eq!(metadata.network, "udp");
        self.registered.fetch_add(1, Ordering::SeqCst);
        Some(Arc::new(Flow(self.closed.clone())))
    }
}

async fn round_trip_empty_datagrams(analysis: bool) {
    let engine = engine().await;
    let inbound = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(inbound, true)))
        .await
        .unwrap();
    engine.add_user("vless", user("alice", USER)).unwrap();
    let observer = Arc::new(Observer::default());
    if analysis {
        engine.set_analysis_observer(Some(observer.clone()));
    }

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buffer = [0; 128];
        let mut first_peer = None;
        for packet in PACKETS {
            let (len, peer) = target.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..len], packet);
            assert_eq!(*first_peer.get_or_insert(peer), peer);
            target.send_to(packet, peer).await.unwrap();
        }
    });
    let mut client = TcpStream::connect(inbound).await.unwrap();
    let mut header = vec![0]; // VLESS version.
    let mut uuid = [0x11; 16];
    uuid[6] = 0x41;
    uuid[8] = 0x81;
    header.extend_from_slice(&uuid);
    header.extend_from_slice(&[0, 2]); // No addons; fixed-target UDP command.
    header.extend_from_slice(&destination.port().to_be_bytes());
    header.extend_from_slice(&[1, 127, 0, 0, 1]); // IPv4 loopback destination.

    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(&header).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 0]);
        for packet in PACKETS {
            client.write_u16(packet.len() as u16).await.unwrap();
            client.write_all(packet).await.unwrap();
            let len = client.read_u16().await.unwrap() as usize;
            let mut received = vec![0; len];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, packet);
        }
        client.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .expect("empty datagram interrupted the association or true EOF did not close it");
    echo.await.unwrap();

    assert!(
        wait_for("VLESS UDP relay to retire", || {
            engine.get_user("vless", "alice").unwrap().conns == 0
        })
        .await
    );
    let traffic = engine.get_user("vless", "alice").unwrap();
    let framed_bytes = PACKETS.iter().map(|packet| packet.len() + 2).sum::<usize>() as u64;
    assert_eq!(traffic.rx, header.len() as u64 + framed_bytes);
    assert_eq!(traffic.tx, 2 + framed_bytes);
    if analysis {
        assert_eq!(observer.registered.load(Ordering::SeqCst), 1);
        assert_eq!(observer.closed.load(Ordering::SeqCst), 1);
    }
    engine.remove_inbound("vless").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_empty_udp_survives_in_both_directions_and_preserves_billing() {
    round_trip_empty_datagrams(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_empty_udp_survives_analysis_wrapping_and_true_eof() {
    round_trip_empty_datagrams(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_xudp_preserves_first_and_later_empty_datagrams() {
    let encoding = "xudp";
    let engine = engine().await;
    let inbound = free_addr();
    engine
        .add_inbound(dynamic("vless", vless_inbound(inbound, true)))
        .await
        .unwrap();
    engine.add_user("vless", user("alice", USER)).unwrap();
    let proxy = start_leg(
        &engine,
        "socks",
        serde_json::json!({
            "address": inbound.to_string(),
            "protocol": {
                "type": "vless", "user_id": USER,
                "udp_enabled": true, "packet_encoding": encoding,
            },
        }),
    )
    .await;
    let echo = UdpEcho::start().await;
    let (control, relay) = Socks::associate(proxy).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut response = [0; 256];
    for packet in PACKETS {
        client
            .send_to(&udp_wrap(echo.address, packet).unwrap(), relay)
            .await
            .unwrap();
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .unwrap_or_else(|_| panic!("{encoding} lost datagram {packet:?}"))
                .unwrap();
        assert_eq!(udp_unwrap(&response[..len]), Some(packet), "{encoding}");
    }
    drop(control);
    engine.remove_inbound("socks").await.unwrap();
    engine.remove_inbound("vless").await.unwrap();
}
