use super::*;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use acp_proto::{Session, StreamClosed, TELEMETRY_READY_METADATA_KEY};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use crate::session::{PanelClient, SessionAuthenticator, SessionError};

#[test]
fn snapshot_mapping_preserves_validity_counters_and_inventory() {
    let host = HostSnapshot {
        cpu_percent: 12.5,
        cpu_valid: true,
        cpu_brand: "cpu".into(),
        cpu_cores: 4,
        cpu_threads: 8,
        memory_used_bytes: 10,
        memory_total_bytes: 20,
        memory_valid: true,
        network_interfaces_valid: true,
        network_interfaces: vec![NetworkInterface {
            name: "eth0".into(),
            hardware: "00:11:22:33:44:55".into(),
            addresses: vec!["10.0.0.1/24".into()],
            rx_bytes: 1,
            tx_bytes: 2,
            rx_packets: 3,
            tx_packets: 4,
            is_up: true,
            index: 7,
            counters_valid: true,
        }],
        disk_usages: vec![DiskUsage {
            path: "/".into(),
            fs_type: "ext4".into(),
            used_bytes: 30,
            total_bytes: 40,
        }],
        disk_valid: true,
        disk_collected_at: Some(UNIX_EPOCH + Duration::from_millis(123_456)),
        ..Default::default()
    };
    let snapshot = build_snapshot(
        "machine",
        123,
        host,
        ConnectionStats {
            active_connections: 5,
            online_users: 6,
        },
        true,
    );
    assert_eq!(snapshot.machine_id, "machine");
    assert_eq!(snapshot.timestamp_unix, 123);
    assert_eq!(snapshot.cpu_percent, 12.5);
    assert!(
        snapshot.cpu_valid
            && snapshot.memory_valid
            && snapshot.network_interfaces_valid
            && snapshot.disk_valid
    );
    assert_eq!(snapshot.cpu_brand, "cpu");
    assert_eq!((snapshot.cpu_cores, snapshot.cpu_threads), (4, 8));
    assert_eq!(
        (snapshot.memory_used_bytes, snapshot.memory_total_bytes),
        (10, 20)
    );
    assert_eq!((snapshot.active_connections, snapshot.online_users), (5, 6));
    assert_eq!(snapshot.sing_box_state, "maintenance");
    assert_eq!(snapshot.network_interfaces[0].interface_index, 7);
    assert!(snapshot.network_interfaces[0].counters_valid);
    assert_eq!(snapshot.network_interfaces[0].addresses, ["10.0.0.1/24"]);
    assert_eq!(snapshot.disk_usages[0].fstype, "ext4");
    assert_eq!(snapshot.disk_collected_at_unix_ms, 123_456);
}

#[test]
fn latest_only_publication_keeps_identity_sequence_and_invalid_stats() {
    let reporter = reporter();
    for elapsed in 1..=100 {
        reporter.publish(HostSnapshot::default(), 1, elapsed, None);
    }
    let current = reporter.latest.borrow().clone().unwrap();
    assert_eq!(current.sample_seq, 100);
    assert_eq!(current.sample_elapsed_ms, 100);
    assert!(!current.agent_instance_id.is_empty());
    assert!(!current.connection_stats_valid);
    let identity = current.agent_instance_id.clone();
    reporter.publish(
        HostSnapshot::default(),
        2,
        101,
        Some(ConnectionStats::default()),
    );
    let current = reporter.latest.borrow().clone().unwrap();
    assert_eq!(current.sample_seq, 101);
    assert_eq!(current.agent_instance_id, identity);
    assert!(current.connection_stats_valid);
    assert_eq!(current.sing_box_state, "running");
    assert_ne!(
        reporter.instance_id,
        TelemetryReporter::new(
            "machine".into(),
            "node".into(),
            Arc::new(PolicyState::new())
        )
        .instance_id
    );
}

#[test]
fn frozen_host_cache_keeps_heartbeats_without_claiming_fresh_counters() {
    let old = std::time::Instant::now() - Duration::from_secs(7);
    let mut host = HostSnapshot {
        collected_at: Some(old),
        cpu_valid: true,
        cpu_percent: 70.0,
        memory_valid: true,
        memory_used_bytes: 100,
        memory_total_bytes: 200,
        network_interfaces_valid: true,
        network_interfaces: vec![NetworkInterface {
            counters_valid: true,
            rx_bytes: 12,
            ..Default::default()
        }],
        cpu_brand: "hardware cache".into(),
        disk_valid: true,
        disk_collected_at: Some(UNIX_EPOCH + Duration::from_secs(100)),
        ..Default::default()
    };
    let mut previous = Some(old);
    let reporter = reporter();
    for _ in 0..3 {
        let at =
            sample_collection(&mut host, &mut previous).expect("invalid heartbeat still sampled");
        assert!(at > old);
        assert!(!host.cpu_valid && !host.memory_valid && !host.network_interfaces_valid);
        assert!(!host.network_interfaces[0].counters_valid);
        assert_eq!(host.network_interfaces[0].rx_bytes, 0);
        assert_eq!(host.cpu_brand, "hardware cache");
        assert!(host.disk_valid);
        reporter.publish(
            host.clone(),
            1,
            reporter.elapsed_ms(),
            Some(ConnectionStats::default()),
        );
    }
    let snapshot = reporter.latest.borrow().clone().unwrap();
    assert_eq!(snapshot.sample_seq, 3);
    assert!(snapshot.connection_stats_valid);
    assert!(!snapshot.network_interfaces_valid);

    host.collected_at = previous.map(|at| at - Duration::from_millis(1));
    assert!(
        sample_collection(&mut host, &mut previous).is_none(),
        "late cache publication cannot move the last invalid heartbeat's clock backward"
    );
    host.collected_at = Some(std::time::Instant::now());
    assert!(sample_collection(&mut host, &mut previous).is_some());
    assert!(
        sample_collection(&mut host, &mut previous).is_none(),
        "fresh cache cannot be reported twice with new timestamps"
    );
}

fn reporter() -> Arc<TelemetryReporter> {
    Arc::new(TelemetryReporter::new(
        "machine".into(),
        "node".into(),
        Arc::new(PolicyState::new()),
    ))
}

fn publish_now(reporter: &TelemetryReporter) {
    reporter.publish(HostSnapshot::default(), 1, reporter.elapsed_ms(), None);
}

#[derive(Clone)]
struct TestService {
    delay: Duration,
    ready: bool,
    reject_before_header: bool,
    reject_after_header: bool,
    stall_reader: bool,
    headers: Arc<Notify>,
    samples: mpsc::UnboundedSender<TelemetrySnapshot>,
}

impl tonic::server::NamedService for TestService {
    const NAME: &'static str = "acp.v1.TelemetryService";
}

impl Service<http::Request<Body>> for TestService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let method = self.clone();
        Box::pin(async move {
            assert_eq!(
                request.uri().path(),
                "/acp.v1.TelemetryService/TelemetryStream"
            );
            let codec = tonic_prost::ProstCodec::<StreamClosed, TelemetrySnapshot>::default();
            Ok(tonic::server::Grpc::new(codec)
                .streaming(method, request)
                .await)
        })
    }
}

impl tonic::server::StreamingService<TelemetrySnapshot> for TestService {
    type Response = StreamClosed;
    type ResponseStream = TestResponse;
    type Future = Pin<Box<dyn Future<Output = Result<Response<TestResponse>, Status>> + Send>>;

    fn call(&mut self, request: Request<Streaming<TelemetrySnapshot>>) -> Self::Future {
        let behavior = self.clone();
        Box::pin(async move {
            assert_eq!(
                request
                    .metadata()
                    .get(acp_proto::auth::METADATA_MACHINE_ID)
                    .unwrap(),
                "machine"
            );
            tokio::time::sleep(behavior.delay).await;
            if behavior.reject_before_header {
                return Err(Status::unauthenticated("session expired before headers"));
            }
            let mut input = request.into_inner();
            let (sender, receiver) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                if behavior.stall_reader {
                    std::future::pending::<()>().await;
                }
                if behavior.reject_after_header {
                    let _ = sender
                        .send(Err(Status::unauthenticated(
                            "session expired after headers",
                        )))
                        .await;
                    return;
                }
                while let Ok(Some(snapshot)) = input.message().await {
                    let _ = behavior.samples.send(snapshot);
                }
                let _ = sender.send(Ok(StreamClosed::default())).await;
            });
            let mut response = Response::new(TestResponse {
                receiver: ReceiverStream::new(receiver),
                task,
            });
            if behavior.ready {
                response
                    .metadata_mut()
                    .insert(TELEMETRY_READY_METADATA_KEY, "1".parse().unwrap());
            }
            behavior.headers.notify_one();
            Ok(response)
        })
    }
}

struct TestResponse {
    receiver: ReceiverStream<Result<StreamClosed, Status>>,
    task: JoinHandle<()>,
}

impl Stream for TestResponse {
    type Item = Result<StreamClosed, Status>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().receiver).poll_next(cx)
    }
}

impl Drop for TestResponse {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TestPanel {
    panel: PanelClient,
    auth: SessionAuthenticator,
    samples: mpsc::UnboundedReceiver<TelemetrySnapshot>,
    headers: Arc<Notify>,
    cancel: CancellationToken,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl TestPanel {
    async fn start(configure: impl FnOnce(&mut TestService)) -> Self {
        let (samples, receiver) = mpsc::unbounded_channel();
        let headers = Arc::new(Notify::new());
        let mut service = TestService {
            delay: Duration::ZERO,
            ready: true,
            reject_before_header: false,
            reject_after_header: false,
            stall_reader: false,
            headers: headers.clone(),
            samples,
        };
        configure(&mut service);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .initial_stream_window_size(Some(1024))
                .add_service(service)
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    server_cancel.cancelled(),
                )
                .await
        });
        let config = crate::config::parse(&format!(
            "panel_grpc_endpoint = 'grpc://{address}'\nmachine_id = 'machine'\nnode_id = 'node'\nmachine_secret = 'secret'\n"
        )).unwrap();
        let auth = SessionAuthenticator::new(
            &config,
            &Session {
                session_id: "session".into(),
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            panel: PanelClient::new(config, "test", "test"),
            auth,
            samples: receiver,
            headers,
            cancel,
            server,
        }
    }

    fn run(
        &self,
        reporter: Arc<TelemetryReporter>,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), SessionError>> {
        tokio::spawn(reporter.run_stream(cancel, self.panel.clone(), self.auth.clone()))
    }

    async fn sample(&mut self) -> TelemetrySnapshot {
        tokio::time::timeout(Duration::from_secs(3), self.samples.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn wait_headers(&self) {
        tokio::time::timeout(Duration::from_secs(3), self.headers.notified())
            .await
            .unwrap();
    }
}

impl Drop for TestPanel {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.server.abort();
    }
}

#[tokio::test]
async fn slow_header_handshake_has_its_own_budget_and_samples_never_wait_for_ack() {
    let mut panel = TestPanel::start(|service| service.delay = Duration::from_millis(1200)).await;
    let reporter = reporter();
    publish_now(&reporter);
    let cancel = CancellationToken::new();
    let stream = panel.run(reporter.clone(), cancel.clone());
    panel.wait_headers().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        panel.samples.try_recv().is_err(),
        "pre-handshake sample must be discarded"
    );
    publish_now(&reporter);
    let first = panel.sample().await;
    assert!(first.stream_started_elapsed_ms >= 1100);
    assert!(first.sample_elapsed_ms >= first.stream_started_elapsed_ms);
    publish_now(&reporter);
    let second = panel.sample().await;
    assert_eq!(second.sample_seq, first.sample_seq + 1);
    assert_eq!(second.agent_instance_id, first.agent_instance_id);
    assert_eq!(
        second.stream_started_elapsed_ms,
        first.stream_started_elapsed_ms
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), stream)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn reconnect_preserves_instance_and_sequence_but_discards_old_pending_sample() {
    let mut panel = TestPanel::start(|_| {}).await;
    let reporter = reporter();
    let cancel = CancellationToken::new();
    let first_stream = panel.run(reporter.clone(), cancel.clone());
    panel.wait_headers().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    publish_now(&reporter);
    let first = panel.sample().await;
    cancel.cancel();
    first_stream.await.unwrap().unwrap();
    publish_now(&reporter);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let cancel = CancellationToken::new();
    let second_stream = panel.run(reporter.clone(), cancel.clone());
    panel.wait_headers().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(panel.samples.try_recv().is_err());
    publish_now(&reporter);
    let second = panel.sample().await;
    assert_eq!(second.agent_instance_id, first.agent_instance_id);
    assert_eq!(second.sample_seq, first.sample_seq + 2);
    assert!(second.stream_started_elapsed_ms > first.stream_started_elapsed_ms);
    cancel.cancel();
    second_stream.await.unwrap().unwrap();
}

#[tokio::test]
async fn server_rejection_preserves_authentication_status_before_and_after_headers() {
    for before_headers in [true, false] {
        let panel = TestPanel::start(|service| {
            service.reject_before_header = before_headers;
            service.reject_after_header = !before_headers;
        })
        .await;
        let stream = panel.run(reporter(), CancellationToken::new());
        let error = tokio::time::timeout(Duration::from_secs(2), stream)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is_unauthenticated(), "{error}");
    }
}

#[tokio::test]
async fn missing_clock_header_is_rejected_and_handshake_cancellation_is_bounded() {
    let panel = TestPanel::start(|service| service.ready = false).await;
    let error = panel
        .run(reporter(), CancellationToken::new())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, SessionError::Metadata(_)));
    let panel = TestPanel::start(|service| service.delay = Duration::from_secs(60)).await;
    let cancel = CancellationToken::new();
    let stream = panel.run(reporter(), cancel.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(500), stream)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_header_handshake_expires_with_the_ten_second_budget() {
    let panel = TestPanel::start(|service| service.delay = Duration::from_secs(60)).await;
    let error = tokio::time::timeout(
        Duration::from_secs(12),
        panel.run(reporter(), CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(error, SessionError::Timeout { operation: "telemetry clock handshake", duration } if duration == Duration::from_secs(10))
    );
}

#[tokio::test]
async fn flow_control_stall_times_out_without_blocking_latest_publication() {
    let panel = TestPanel::start(|service| service.stall_reader = true).await;
    let reporter = reporter();
    let cancel = CancellationToken::new();
    let mut stream = panel.run(reporter.clone(), cancel.clone());
    panel.wait_headers().await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let publish = async {
        loop {
            reporter.publish(
                HostSnapshot {
                    cpu_brand: "x".repeat(512 * 1024),
                    ..Default::default()
                },
                1,
                reporter.elapsed_ms(),
                None,
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let result = tokio::select! {
        result = &mut stream => result.unwrap(),
        () = publish => unreachable!(),
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            cancel.cancel();
            panic!("telemetry body must respect transport flow control");
        }
    };
    assert!(
        matches!(
            result,
            Err(SessionError::Timeout {
                operation: "send telemetry sample",
                ..
            })
        ),
        "{result:?}"
    );
    assert!(
        reporter.sequence.load(Ordering::Relaxed) > 10,
        "publication must continue while the sender is stalled"
    );
}
