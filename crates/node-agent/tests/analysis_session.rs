//! Real tonic transport checks for analysis configuration and channel lifetime.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acp_proto::auth::{
    HelloFields, METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
    METADATA_TIMESTAMP_UNIX, SessionFields, sign_hello, sign_session,
};
use acp_proto::auth_service_server::{AuthService, AuthServiceServer};
use acp_proto::config_service_server::{ConfigService, ConfigServiceServer};
use acp_proto::control_service_server::{ControlService, ControlServiceServer};
use acp_proto::traffic_analysis_service_server::{
    TrafficAnalysisService, TrafficAnalysisServiceServer,
};
use acp_proto::traffic_service_server::{TrafficService, TrafficServiceServer};
use acp_proto::*;
use async_trait::async_trait;
use node_agent::agent::Agent;
use node_agent::runtime::{
    ConnectionStats, NodeRuntime, ReloadStatus, RuntimeConfig, RuntimeError, TrafficDrain,
};
use node_agent::session::{
    CONTROL_CLIENT_READY_KEY, CONTROL_READY_METADATA_KEY, CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

const MACHINE: &str = "analysis-machine";
const NODE: &str = "analysis-node";
const SECRET: &str = "analysis-session-test-secret";

#[derive(Clone, Default)]
struct Panel(Arc<PanelState>);

#[derive(Default)]
struct PanelState {
    enabled: AtomicBool,
    fail_config: AtomicBool,
    hellos: AtomicUsize,
    configs: AtomicUsize,
    failed_configs: AtomicUsize,
    users: AtomicUsize,
    ready: AtomicUsize,
    analysis_streams: AtomicUsize,
    control_cancel: Mutex<Option<CancellationToken>>,
    analysis_cancel: Mutex<Option<CancellationToken>>,
    control_peer: Mutex<Option<std::net::SocketAddr>>,
    analysis_peers: Mutex<Vec<std::net::SocketAddr>>,
    analysis_sessions: Mutex<Vec<String>>,
    traffic_reports: Mutex<Vec<(String, TrafficReport)>>,
}

impl Panel {
    fn config(&self) -> MachineConfig {
        MachineConfig {
            machine_id: MACHINE.into(),
            revision: 1,
            nodes: vec![NodeConfig {
                node_id: NODE.into(),
                provider_id: "vless-reality-vision@1".into(),
                provider_config_version: 1,
                provider_config_json: br#"{"type":"vless","listen":"127.0.0.1","listen_port":14431,"flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","reality":{"enabled":true,"handshake":{"server":"example.com","server_port":443},"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":["0123456789abcdef"]}}}"#.to_vec(),
                traffic_analysis: Some(acp_proto::analysis::default_config(self.0.enabled.load(Ordering::SeqCst))),
            }],
            ..Default::default()
        }
    }

    fn digest(&self) -> String {
        let topology = node_agent::topology::from_machine_config(MACHINE, Some(&self.config()));
        acp_proto::digest::sum(topology.snapshot.as_ref())
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let value = |key: &'static str| -> Result<String, Status> {
            request
                .metadata()
                .get(key)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| Status::unauthenticated(key))
        };
        let fields = SessionFields {
            machine_id: value(METADATA_MACHINE_ID)?,
            session_id: value(METADATA_SESSION_ID)?,
            timestamp_unix: value(METADATA_TIMESTAMP_UNIX)?
                .parse()
                .map_err(|_| Status::unauthenticated("timestamp"))?,
            nonce: value(METADATA_NONCE)?,
        };
        let expected = sign_session(SECRET, &fields)
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if fields.machine_id != MACHINE || value(METADATA_SIGNATURE)? != expected {
            return Err(Status::unauthenticated("session signature"));
        }
        Ok(fields.session_id)
    }

    fn disconnect_control(&self) {
        self.0
            .control_cancel
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancel();
    }

    fn disconnect_analysis(&self) {
        self.0
            .analysis_cancel
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancel();
    }
}

#[tonic::async_trait]
impl AuthService for Panel {
    async fn hello(&self, request: Request<HelloRequest>) -> Result<Response<Session>, Status> {
        let request = request.into_inner();
        let fields = HelloFields {
            machine_id: request.machine_id,
            node_id: request.node_id,
            agent_version: request.agent_version,
            sing_box_version: request.sing_box_version,
            timestamp_unix: request.timestamp_unix,
            nonce: request.nonce,
            topology_revision: request.topology_revision,
        };
        let signature = sign_hello(SECRET, &fields)
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if fields.machine_id != MACHINE || fields.node_id != NODE || signature != request.signature
        {
            return Err(Status::unauthenticated("hello signature"));
        }
        let sequence = self.0.hellos.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Response::new(Session {
            session_id: format!("analysis-session-{sequence}"),
            topology_revision: 1,
        }))
    }
}

#[tonic::async_trait]
impl ConfigService for Panel {
    async fn get_machine_config(
        &self,
        request: Request<GetMachineConfigRequest>,
    ) -> Result<Response<MachineConfig>, Status> {
        let session = self.authenticate(&request)?;
        assert_eq!(request.get_ref().session_id, session);
        self.0.configs.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_config.load(Ordering::SeqCst) {
            self.0.failed_configs.fetch_add(1, Ordering::SeqCst);
            return Err(Status::unavailable("configuration temporarily unavailable"));
        }
        Ok(Response::new(self.config()))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        self.authenticate(&request)?;
        self.0.users.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(ListUsersResponse::default()))
    }
}

#[tonic::async_trait]
impl ControlService for Panel {
    type ControlStreamStream = ReceiverStream<Result<ControlCommand, Status>>;

    async fn control_stream(
        &self,
        request: Request<tonic::Streaming<ControlAck>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        self.authenticate(&request)?;
        *self.0.control_peer.lock().unwrap() = request.remote_addr();
        let cancel = CancellationToken::new();
        *self.0.control_cancel.lock().unwrap() = Some(cancel.clone());
        let mut acknowledgements = request.into_inner();
        let panel = self.clone();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => {
                        let _ = sender.send(Err(Status::unavailable("panel restart"))).await;
                        break;
                    }
                    ack = acknowledgements.message() => match ack {
                        Ok(Some(ack)) => {
                            assert_eq!(ack.idempotency_key, CONTROL_CLIENT_READY_KEY);
                            assert_eq!(ack.message, panel.digest());
                            panel.0.ready.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => break,
                    }
                }
            }
        });
        let mut response = Response::new(ReceiverStream::new(receiver));
        response
            .metadata_mut()
            .insert(CONTROL_READY_METADATA_KEY, "1".parse().unwrap());
        response.metadata_mut().insert(
            CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
            self.digest().parse().unwrap(),
        );
        Ok(response)
    }
}

#[tonic::async_trait]
impl TrafficAnalysisService for Panel {
    async fn analysis_stream(
        &self,
        request: Request<tonic::Streaming<TrafficAnalysisBatch>>,
    ) -> Result<Response<StreamClosed>, Status> {
        let session = self.authenticate(&request)?;
        self.0.analysis_sessions.lock().unwrap().push(session);
        self.0
            .analysis_peers
            .lock()
            .unwrap()
            .push(request.remote_addr().unwrap());
        let cancel = CancellationToken::new();
        *self.0.analysis_cancel.lock().unwrap() = Some(cancel.clone());
        self.0.analysis_streams.fetch_add(1, Ordering::SeqCst);
        let mut batches = request.into_inner();
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Err(Status::unavailable("analysis-only failure")),
                batch = batches.message() => if batch?.is_none() {
                    return Ok(Response::new(StreamClosed::default()));
                },
            }
        }
    }
}

#[derive(Default)]
struct Runtime {
    applies: AtomicUsize,
    closes: AtomicUsize,
    config: Mutex<Vec<u8>>,
    disable_analysis: AtomicBool,
    collector_installs: AtomicUsize,
    traffic: Mutex<Vec<TrafficDrain>>,
}

#[async_trait]
impl NodeRuntime for Runtime {
    fn set_disable_traffic_analysis(&self, disabled: bool) {
        self.disable_analysis.store(disabled, Ordering::SeqCst);
    }
    fn set_analysis_collector(&self, _: Arc<node_agent::analysis::Collector>) {
        self.collector_installs.fetch_add(1, Ordering::SeqCst);
    }
    async fn apply_config(&self, config: RuntimeConfig) -> Result<(), RuntimeError> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        *self.config.lock().unwrap() = config.diagnostic_yaml;
        Ok(())
    }
    async fn reload_config(&self, config: RuntimeConfig) -> Result<ReloadStatus, RuntimeError> {
        self.apply_config(config).await?;
        Ok(ReloadStatus {
            running: true,
            rolled_back: false,
        })
    }
    fn current_config(&self) -> Vec<u8> {
        self.config.lock().unwrap().clone()
    }
    async fn close(&self) -> Result<(), RuntimeError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn connection_stats(&self, _: &str) -> ConnectionStats {
        ConnectionStats::default()
    }
    async fn close_user_connections(&self, _: &str, _: &str) -> u64 {
        0
    }
    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        Ok(std::mem::take(&mut *self.traffic.lock().unwrap()))
    }
}

#[tonic::async_trait]
impl TrafficService for Panel {
    async fn traffic_stream(
        &self,
        request: Request<tonic::Streaming<TrafficReport>>,
    ) -> Result<Response<StreamClosed>, Status> {
        let session = self.authenticate(&request)?;
        let mut reports = request.into_inner();
        while let Some(report) = reports.message().await? {
            self.0
                .traffic_reports
                .lock()
                .unwrap()
                .push((session.clone(), report));
        }
        Ok(Response::new(StreamClosed::default()))
    }
}

async fn wait_until(description: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_refreshes_analysis_without_reapplying_users_or_proxy_topology() {
    let panel = Panel::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_cancel = CancellationToken::new();
    let cancel = server_cancel.clone();
    let server_panel = panel.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuthServiceServer::new(server_panel.clone()))
            .add_service(ConfigServiceServer::new(server_panel.clone()))
            .add_service(ControlServiceServer::new(server_panel.clone()))
            .add_service(TrafficAnalysisServiceServer::new(server_panel))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                cancel.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    let config = node_agent::config::parse(&format!(
        r#"
panel_grpc_endpoint = "grpc://{address}"
machine_id = "{MACHINE}"
node_id = "{NODE}"
machine_secret = "{SECRET}"
"#
    ))
    .unwrap();
    let runtime = Arc::new(Runtime::default());
    let agent = Agent::with_runtime(config, runtime.clone());
    assert!(!runtime.disable_analysis.load(Ordering::SeqCst));
    assert_eq!(runtime.collector_installs.load(Ordering::SeqCst), 1);
    let agent_cancel = CancellationToken::new();
    let run = tokio::spawn(agent.clone().run(agent_cancel.clone()));

    wait_until("initial disabled session", || {
        panel.0.ready.load(Ordering::SeqCst) == 1
    })
    .await;
    assert!(!agent.analysis().config().enabled);
    assert_eq!(panel.0.analysis_streams.load(Ordering::SeqCst), 0);
    let first_epoch = agent.analysis().status().epoch;

    panel.0.enabled.store(true, Ordering::SeqCst);
    panel.disconnect_control();
    wait_until("enabled session and analysis stream", || {
        agent.analysis().config().enabled && panel.0.analysis_streams.load(Ordering::SeqCst) == 1
    })
    .await;
    let enabled_epoch = agent.analysis().status().epoch;
    assert!(enabled_epoch > first_epoch);
    assert_eq!(panel.0.configs.load(Ordering::SeqCst), 2);
    assert_eq!(panel.0.users.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.applies.load(Ordering::SeqCst), 1);
    assert_ne!(
        panel.0.analysis_peers.lock().unwrap()[0],
        panel.0.control_peer.lock().unwrap().unwrap()
    );

    // Reconnecting only the analysis channel retains the authenticated session
    // and does not fetch configuration or disturb the collection generation.
    panel.disconnect_analysis();
    wait_until("analysis-only reconnect", || {
        panel.0.analysis_streams.load(Ordering::SeqCst) == 2
    })
    .await;
    assert_eq!(panel.0.hellos.load(Ordering::SeqCst), 2);
    assert_eq!(panel.0.configs.load(Ordering::SeqCst), 2);
    assert_eq!(agent.analysis().status().epoch, enabled_epoch);
    let sessions = panel.0.analysis_sessions.lock().unwrap().clone();
    assert_eq!(sessions, vec!["analysis-session-2", "analysis-session-2"]);
    let peers = panel.0.analysis_peers.lock().unwrap().clone();
    assert_ne!(peers[0], peers[1]);

    panel.0.fail_config.store(true, Ordering::SeqCst);
    panel.disconnect_control();
    wait_until("failed new session configuration", || {
        panel.0.failed_configs.load(Ordering::SeqCst) > 0
    })
    .await;
    assert!(!agent.analysis().status().enabled);
    assert_eq!(panel.0.ready.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.applies.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.closes.load(Ordering::SeqCst), 0);

    panel.0.enabled.store(false, Ordering::SeqCst);
    panel.0.fail_config.store(false, Ordering::SeqCst);
    wait_until("disabled reconnect after config recovers", || {
        panel.0.ready.load(Ordering::SeqCst) == 3 && !agent.analysis().config().enabled
    })
    .await;
    assert!(!agent.analysis().config().enabled);
    assert!(!agent.analysis().status().enabled);
    assert_eq!(panel.0.users.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.applies.load(Ordering::SeqCst), 1);
    assert_eq!(panel.0.analysis_streams.load(Ordering::SeqCst), 2);
    assert!(panel.0.configs.load(Ordering::SeqCst) >= 4);

    agent_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(runtime.closes.load(Ordering::SeqCst), 1);
    server_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_analysis_override_survives_reconnects_and_preserves_billing() {
    let panel = Panel::default();
    panel.0.enabled.store(true, Ordering::SeqCst);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_cancel = CancellationToken::new();
    let cancel = server_cancel.clone();
    let server_panel = panel.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuthServiceServer::new(server_panel.clone()))
            .add_service(ConfigServiceServer::new(server_panel.clone()))
            .add_service(ControlServiceServer::new(server_panel.clone()))
            .add_service(TrafficServiceServer::new(server_panel.clone()))
            .add_service(TrafficAnalysisServiceServer::new(server_panel))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                cancel.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    let config = node_agent::config::parse(&format!(
        r#"
panel_grpc_endpoint = "grpc://{address}"
machine_id = "{MACHINE}"
node_id = "{NODE}"
machine_secret = "{SECRET}"
disable_traffic_analysis = true
traffic_report_min_delta_bytes = 1
"#
    ))
    .unwrap();
    let runtime = Arc::new(Runtime::default());
    let agent = Agent::with_runtime(config, runtime.clone());
    assert!(runtime.disable_analysis.load(Ordering::SeqCst));
    assert_eq!(runtime.collector_installs.load(Ordering::SeqCst), 0);
    let agent_cancel = CancellationToken::new();
    let run = tokio::spawn(agent.clone().run(agent_cancel.clone()));

    for (index, panel_enabled) in [true, false, true].into_iter().enumerate() {
        if index != 0 {
            panel.0.enabled.store(panel_enabled, Ordering::SeqCst);
            panel.disconnect_control();
        }
        wait_until("control readiness after panel configuration", || {
            panel.0.ready.load(Ordering::SeqCst) == index + 1
        })
        .await;
        let protocol = ["hysteria2", "vless", "hysteria2"][index];
        runtime.traffic.lock().unwrap().push(TrafficDrain {
            inbound_tag: "billing-inbound".into(),
            node_id: NODE.into(),
            protocol: protocol.into(),
            user_id: "billing-user".into(),
            uplink_bytes: 43,
            downlink_bytes: 256,
            observed_at: Some(std::time::SystemTime::now()),
        });
        // A real billable report proves the session finished Configure; checking
        // the initially disabled collector alone could hide a readiness race.
        wait_until("billing report while local analysis is disabled", || {
            panel.0.traffic_reports.lock().unwrap().len() == index + 1
        })
        .await;
        let (session, report) = panel.0.traffic_reports.lock().unwrap()[index].clone();
        assert_eq!(session, format!("analysis-session-{}", index + 1));
        assert_eq!(report.machine_id, MACHINE);
        assert_eq!(report.node_id, NODE);
        assert_eq!(report.user_id, "billing-user");
        assert_eq!(report.protocol, protocol);
        assert_eq!((report.uplink_bytes, report.downlink_bytes), (43, 256));
        assert!(!agent.analysis().config().enabled);
        assert!(!agent.analysis().status().enabled);
        assert!(
            agent
                .analysis()
                .register(node_agent::analysis::Metadata {
                    node_id: NODE.into(),
                    user_id: "billing-user".into(),
                    proxy_protocol: protocol.into(),
                    network: "tcp".into(),
                    app_protocol: "tls".into(),
                    domain: "example.com".into(),
                    ..Default::default()
                })
                .is_none()
        );
        assert_eq!(panel.0.analysis_streams.load(Ordering::SeqCst), 0);
    }
    assert_eq!(panel.0.configs.load(Ordering::SeqCst), 3);
    assert_eq!(panel.0.hellos.load(Ordering::SeqCst), 3);
    assert_eq!(panel.0.users.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.applies.load(Ordering::SeqCst), 1);

    agent_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(runtime.closes.load(Ordering::SeqCst), 1);
    server_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
