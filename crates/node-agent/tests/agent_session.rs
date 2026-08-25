use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use acp_proto::auth::{
    HelloFields, METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
    METADATA_TIMESTAMP_UNIX, SessionFields, sign_hello, sign_session,
};
use acp_proto::auth_service_server::{AuthService, AuthServiceServer};
use acp_proto::config_service_server::{ConfigService, ConfigServiceServer};
use acp_proto::control_command;
use acp_proto::control_service_server::{ControlService, ControlServiceServer};
use acp_proto::log_service_server::{LogService, LogServiceServer};
use acp_proto::remote_control_request;
use acp_proto::remote_control_response;
use acp_proto::remote_control_service_server::{RemoteControlService, RemoteControlServiceServer};
use acp_proto::telemetry_service_server::{TelemetryService, TelemetryServiceServer};
use acp_proto::traffic_service_server::{TrafficService, TrafficServiceServer};
use acp_proto::{
    ControlAck, ControlAckStatus, ControlCommand, ControlCommandType, DiagnosticsCommand,
    GetMachineConfigRequest, HelloRequest, ListUsersRequest, ListUsersResponse, MachineConfig,
    NodeLogBatch, NodeLogCommand, NodeLogCommandType, RemoteControlRequest, RemoteControlResponse,
    RemoteControlResponseStatus, RemoteControlStatusRequest, Session, StreamClosed,
    TelemetrySnapshot, TopologySnapshot, TrafficReport,
};
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
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const MACHINE_ID: &str = "machine-1";
const NODE_ID: &str = "node-1";
const SESSION_ID: &str = "session-agent-e2e";
const SECRET: &str = "agent-e2e-secret";
const DIAGNOSTICS_COMMAND_ID: &str = "diagnostics-1";
const DIAGNOSTICS_IDEMPOTENCY_KEY: &str = "diagnostics-key-1";
const REMOTE_REQUEST_ID: &str = "remote-status-1";
const LOG_SUBSCRIPTION_ID: &str = "logs-1";
const LOG_MARKER: &str = "agent-session-e2e-log-marker";

#[derive(Debug)]
enum PanelEvent {
    Hello(HelloRequest),
    Authenticated {
        method: &'static str,
        fields: SessionFields,
    },
    Ack(ControlAck),
    Telemetry(TelemetrySnapshot),
    LogBatch(NodeLogBatch),
    RemoteResponse(RemoteControlResponse),
}

#[derive(Clone)]
struct MockPanel {
    digest: Arc<str>,
    events: mpsc::UnboundedSender<PanelEvent>,
}

impl MockPanel {
    fn authenticated(
        &self,
        method: &'static str,
        metadata: &MetadataMap,
    ) -> Result<SessionFields, Status> {
        let fields = verify_session_metadata(metadata)?;
        self.events
            .send(PanelEvent::Authenticated {
                method,
                fields: fields.clone(),
            })
            .map_err(|_| Status::unavailable("test event receiver closed"))?;
        Ok(fields)
    }
}

#[tonic::async_trait]
impl AuthService for MockPanel {
    async fn hello(&self, request: Request<HelloRequest>) -> Result<Response<Session>, Status> {
        let hello = request.into_inner();
        let fields = HelloFields {
            machine_id: hello.machine_id.clone(),
            node_id: hello.node_id.clone(),
            agent_version: hello.agent_version.clone(),
            sing_box_version: hello.sing_box_version.clone(),
            timestamp_unix: hello.timestamp_unix,
            nonce: hello.nonce.clone(),
            topology_revision: hello.topology_revision,
        };
        let expected = sign_hello(SECRET, &fields)
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if hello.signature != expected {
            return Err(Status::unauthenticated("invalid Hello HMAC"));
        }
        self.events
            .send(PanelEvent::Hello(hello))
            .map_err(|_| Status::unavailable("test event receiver closed"))?;
        Ok(Response::new(Session {
            session_id: SESSION_ID.into(),
            topology_revision: 1,
        }))
    }
}

#[tonic::async_trait]
impl ConfigService for MockPanel {
    async fn get_machine_config(
        &self,
        request: Request<GetMachineConfigRequest>,
    ) -> Result<Response<MachineConfig>, Status> {
        self.authenticated("config", request.metadata())?;
        let request = request.into_inner();
        if request.machine_id != MACHINE_ID || request.session_id != SESSION_ID {
            return Err(Status::invalid_argument(
                "unexpected topology fetch identity",
            ));
        }
        Ok(Response::new(MachineConfig {
            machine_id: MACHINE_ID.into(),
            revision: 1,
            ..Default::default()
        }))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        self.authenticated("list_users", request.metadata())?;
        Err(Status::failed_precondition(
            "zero-node topology must not request users",
        ))
    }
}

#[tonic::async_trait]
impl ControlService for MockPanel {
    type ControlStreamStream = ReceiverStream<Result<ControlCommand, Status>>;

    async fn control_stream(
        &self,
        request: Request<tonic::Streaming<ControlAck>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        self.authenticated("control", request.metadata())?;
        let mut acknowledgements = request.into_inner();
        let events = self.events.clone();
        let (commands, command_receiver) = mpsc::channel(2);
        tokio::spawn(async move {
            let Some(ready) = acknowledgements.message().await.ok().flatten() else {
                return;
            };
            let _ = events.send(PanelEvent::Ack(ready));
            if commands
                .send(Ok(ControlCommand {
                    command_id: DIAGNOSTICS_COMMAND_ID.into(),
                    machine_id: MACHINE_ID.into(),
                    node_id: NODE_ID.into(),
                    revision: 1,
                    idempotency_key: DIAGNOSTICS_IDEMPOTENCY_KEY.into(),
                    r#type: ControlCommandType::Diagnostics as i32,
                    operation_id: "diagnostics-operation-1".into(),
                    payload: Some(control_command::Payload::Diagnostics(DiagnosticsCommand {
                        action: "status".into(),
                        include: vec!["runtime".into()],
                    })),
                    ..Default::default()
                }))
                .await
                .is_err()
            {
                return;
            }
            while let Ok(Some(ack)) = acknowledgements.message().await {
                let _ = events.send(PanelEvent::Ack(ack));
            }
        });

        let mut response = Response::new(ReceiverStream::new(command_receiver));
        response
            .metadata_mut()
            .insert(CONTROL_READY_METADATA_KEY, MetadataValue::from_static("1"));
        response.metadata_mut().insert(
            CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
            MetadataValue::try_from(self.digest.as_ref())
                .map_err(|error| Status::internal(error.to_string()))?,
        );
        Ok(response)
    }
}

#[tonic::async_trait]
impl TrafficService for MockPanel {
    async fn traffic_stream(
        &self,
        request: Request<tonic::Streaming<TrafficReport>>,
    ) -> Result<Response<StreamClosed>, Status> {
        self.authenticated("traffic", request.metadata())?;
        let mut reports = request.into_inner();
        while reports.message().await?.is_some() {}
        Ok(Response::new(StreamClosed {
            message: "traffic drained".into(),
        }))
    }
}

#[tonic::async_trait]
impl TelemetryService for MockPanel {
    async fn telemetry_stream(
        &self,
        request: Request<tonic::Streaming<TelemetrySnapshot>>,
    ) -> Result<Response<StreamClosed>, Status> {
        self.authenticated("telemetry", request.metadata())?;
        let mut snapshots = request.into_inner();
        if let Some(snapshot) = snapshots.message().await? {
            let _ = self.events.send(PanelEvent::Telemetry(snapshot));
        }
        while snapshots.message().await?.is_some() {}
        Ok(Response::new(StreamClosed {
            message: "telemetry drained".into(),
        }))
    }
}

#[tonic::async_trait]
impl LogService for MockPanel {
    type LogStreamStream = ReceiverStream<Result<NodeLogCommand, Status>>;

    async fn log_stream(
        &self,
        request: Request<tonic::Streaming<NodeLogBatch>>,
    ) -> Result<Response<Self::LogStreamStream>, Status> {
        self.authenticated("log", request.metadata())?;
        let mut batches = request.into_inner();
        let events = self.events.clone();
        let (commands, command_receiver) = mpsc::channel(2);
        tokio::spawn(async move {
            if commands
                .send(Ok(NodeLogCommand {
                    subscription_id: LOG_SUBSCRIPTION_ID.into(),
                    r#type: NodeLogCommandType::Start as i32,
                }))
                .await
                .is_err()
            {
                return;
            }
            while let Ok(Some(batch)) = batches.message().await {
                let _ = events.send(PanelEvent::LogBatch(batch));
            }
        });
        Ok(Response::new(ReceiverStream::new(command_receiver)))
    }
}

#[tonic::async_trait]
impl RemoteControlService for MockPanel {
    type RemoteControlStreamStream = ReceiverStream<Result<RemoteControlRequest, Status>>;

    async fn remote_control_stream(
        &self,
        request: Request<tonic::Streaming<RemoteControlResponse>>,
    ) -> Result<Response<Self::RemoteControlStreamStream>, Status> {
        self.authenticated("remote", request.metadata())?;
        let mut responses = request.into_inner();
        let events = self.events.clone();
        let (requests, request_receiver) = mpsc::channel(2);
        tokio::spawn(async move {
            if requests
                .send(Ok(RemoteControlRequest {
                    request_id: REMOTE_REQUEST_ID.into(),
                    command: Some(remote_control_request::Command::Status(
                        RemoteControlStatusRequest {},
                    )),
                }))
                .await
                .is_err()
            {
                return;
            }
            while let Ok(Some(response)) = responses.message().await {
                let _ = events.send(PanelEvent::RemoteResponse(response));
            }
        });
        Ok(Response::new(ReceiverStream::new(request_receiver)))
    }
}

#[derive(Default)]
struct FakeRuntime {
    applied: Mutex<Vec<RuntimeConfig>>,
    close_calls: AtomicUsize,
    drain_calls: AtomicUsize,
}

impl FakeRuntime {
    fn applied(&self) -> Vec<RuntimeConfig> {
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl NodeRuntime for FakeRuntime {
    async fn apply_config(&self, config: RuntimeConfig) -> Result<(), RuntimeError> {
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(config);
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
        self.applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .last()
            .map(|config| config.diagnostic_yaml.clone())
            .unwrap_or_default()
    }

    async fn close(&self) -> Result<(), RuntimeError> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn connection_stats(&self, node_id: &str) -> ConnectionStats {
        assert_eq!(node_id, NODE_ID);
        ConnectionStats::default()
    }

    async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
        0
    }

    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        self.drain_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

fn verify_session_metadata(metadata: &MetadataMap) -> Result<SessionFields, Status> {
    let value = |key| {
        exactly_one(metadata, key)
            .map(str::to_string)
            .map_err(Status::unauthenticated)
    };
    let fields = SessionFields {
        machine_id: value(METADATA_MACHINE_ID)?,
        session_id: value(METADATA_SESSION_ID)?,
        timestamp_unix: value(METADATA_TIMESTAMP_UNIX)?
            .parse()
            .map_err(|error| Status::unauthenticated(format!("invalid timestamp: {error}")))?,
        nonce: value(METADATA_NONCE)?,
    };
    if fields.machine_id != MACHINE_ID || fields.session_id != SESSION_ID {
        return Err(Status::unauthenticated("unexpected session identity"));
    }
    let signature = value(METADATA_SIGNATURE)?;
    let expected = sign_session(SECRET, &fields)
        .map_err(|error| Status::unauthenticated(error.to_string()))?;
    if signature != expected {
        return Err(Status::unauthenticated("invalid session HMAC"));
    }
    Ok(fields)
}

fn exactly_one<'a>(metadata: &'a MetadataMap, key: &'static str) -> Result<&'a str, String> {
    let mut values = metadata.get_all(key).iter();
    let value = values.next().ok_or_else(|| format!("missing {key}"))?;
    if values.next().is_some() {
        return Err(format!("duplicate {key}"));
    }
    value
        .to_str()
        .map_err(|error| format!("invalid {key}: {error}"))
}

fn test_config(address: std::net::SocketAddr) -> node_agent::config::Config {
    node_agent::config::parse(&format!(
        r#"panel_grpc_endpoint = "grpc://{address}"
machine_id = "{MACHINE_ID}"
node_id = "{NODE_ID}"
machine_secret = "{SECRET}"
traffic_report_min_delta_bytes = 1
"#,
    ))
    .expect("valid test configuration")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_agent_session_authenticates_converges_runs_all_streams_and_shuts_down() {
    let snapshot = TopologySnapshot {
        machine_id: MACHINE_ID.into(),
        revision: 1,
        ..Default::default()
    };
    let digest: Arc<str> = Arc::from(acp_proto::digest::sum(Some(&snapshot)));
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let panel = MockPanel {
        digest: digest.clone(),
        events: event_sender,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock panel");
    let address = listener.local_addr().expect("mock panel address");
    let incoming = TcpListenerStream::new(listener);
    let panel_shutdown = CancellationToken::new();
    let panel_token = panel_shutdown.clone();
    let panel_task = tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServiceServer::new(panel.clone()))
            .add_service(ConfigServiceServer::new(panel.clone()))
            .add_service(ControlServiceServer::new(panel.clone()))
            .add_service(TrafficServiceServer::new(panel.clone()))
            .add_service(TelemetryServiceServer::new(panel.clone()))
            .add_service(LogServiceServer::new(panel.clone()))
            .add_service(RemoteControlServiceServer::new(panel))
            .serve_with_incoming_shutdown(incoming, panel_token.cancelled_owned())
            .await
            .expect("mock panel server");
    });

    let runtime = Arc::new(FakeRuntime::default());
    let runtime_for_agent: Arc<dyn NodeRuntime> = runtime.clone();
    let agent = Agent::with_runtime(test_config(address), runtime_for_agent);
    let agent_shutdown = CancellationToken::new();
    let agent_token = agent_shutdown.clone();
    let agent_task = tokio::spawn(agent.run(agent_token));

    let mut hello_seen = false;
    let mut methods = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut ready_seen = false;
    let mut diagnostics_statuses = Vec::new();
    let mut telemetry_seen = false;
    let mut log_seen = false;
    let mut remote_seen = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut log_publish = tokio::time::interval(Duration::from_millis(25));

    while !(hello_seen
        && methods.len() == 6
        && ready_seen
        && diagnostics_statuses.len() == 2
        && telemetry_seen
        && log_seen
        && remote_seen)
    {
        tokio::select! {
            _ = log_publish.tick() => {
                node_agent::logging::publish_remote("agent-session-e2e", LOG_MARKER);
            }
            event = events.recv() => {
                match event.expect("mock panel event stream closed") {
                    PanelEvent::Hello(hello) => {
                        assert_eq!(hello.machine_id, MACHINE_ID);
                        assert_eq!(hello.node_id, NODE_ID);
                        assert_eq!(hello.topology_revision, 0);
                        assert!(!hello.agent_version.is_empty());
                        assert!(!hello.sing_box_version.is_empty());
                        assert_eq!(hello.nonce.len(), 32);
                        hello_seen = true;
                    }
                    PanelEvent::Authenticated { method, fields } => {
                        assert!(methods.insert(method), "duplicate authenticated RPC {method}");
                        assert!(nonces.insert(fields.nonce), "session nonce was reused");
                    }
                    PanelEvent::Ack(ack) if ack.idempotency_key == CONTROL_CLIENT_READY_KEY => {
                        assert_eq!(ack.status, ControlAckStatus::Applied as i32);
                        assert_eq!(ack.revision, 1);
                        assert_eq!(ack.message, digest.as_ref());
                        ready_seen = true;
                    }
                    PanelEvent::Ack(ack) => {
                        assert_eq!(ack.command_id, DIAGNOSTICS_COMMAND_ID);
                        assert_eq!(ack.idempotency_key, DIAGNOSTICS_IDEMPOTENCY_KEY);
                        diagnostics_statuses.push(ack.status);
                    }
                    PanelEvent::Telemetry(snapshot) => {
                        assert_eq!(snapshot.machine_id, MACHINE_ID);
                        assert!(snapshot.timestamp_unix > 0);
                        assert_eq!(snapshot.active_connections, 0);
                        assert_eq!(snapshot.online_users, 0);
                        assert_eq!(snapshot.sing_box_state, "running");
                        telemetry_seen = true;
                    }
                    PanelEvent::LogBatch(batch) => {
                        assert_eq!(batch.subscription_id, LOG_SUBSCRIPTION_ID);
                        if batch.lines.iter().any(|line| line.text.contains(LOG_MARKER)) {
                            log_seen = true;
                        }
                    }
                    PanelEvent::RemoteResponse(response) => {
                        assert_eq!(response.request_id, REMOTE_REQUEST_ID);
                        assert_eq!(response.status, RemoteControlResponseStatus::Completed as i32);
                        assert!(matches!(
                            response.payload,
                            Some(remote_control_response::Payload::ControlState(_))
                        ));
                        remote_seen = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!(
                    "agent session timed out: hello={hello_seen} methods={methods:?} ready={ready_seen} diagnostics={diagnostics_statuses:?} telemetry={telemetry_seen} log={log_seen} remote={remote_seen}"
                );
            }
        }
    }

    assert_eq!(
        methods,
        BTreeSet::from(["config", "control", "log", "remote", "telemetry", "traffic"])
    );
    assert_eq!(nonces.len(), methods.len());
    assert_eq!(
        diagnostics_statuses,
        [
            ControlAckStatus::Accepted as i32,
            ControlAckStatus::Applied as i32
        ]
    );

    let applied = runtime.applied();
    assert_eq!(applied.len(), 1, "initial convergence applies exactly once");
    assert!(applied[0].inbounds.is_empty());
    assert!(!applied[0].diagnostic_yaml.is_empty());

    agent_shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(8), agent_task)
        .await
        .expect("agent shutdown exceeded its bound")
        .expect("agent task panicked")
        .expect("agent returned an error");
    assert_eq!(runtime.close_calls.load(Ordering::SeqCst), 1);
    assert!(runtime.drain_calls.load(Ordering::SeqCst) >= 1);

    panel_shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), panel_task)
        .await
        .expect("mock panel did not stop")
        .expect("mock panel task panicked");
}
