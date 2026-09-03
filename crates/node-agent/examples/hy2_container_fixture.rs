//! Local-only ACP panel and bounded transfer target for testing the real daemon.
//!
//! Run this process first, then run `node-agent STATE_DIR/agent.toml` separately.
//! Publish only the configured HY2 UDP port from the test container. This fixture
//! never constructs an Engine and never contacts a production control plane.
//! The target speaks the protocol in tests/interop/sing-quic-switch/README.md.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::auth::{
    HelloFields, METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
    METADATA_TIMESTAMP_UNIX, SessionFields, sign_hello, sign_session,
};
use acp_proto::auth_service_server::{AuthService, AuthServiceServer};
use acp_proto::config_service_server::{ConfigService, ConfigServiceServer};
use acp_proto::control_service_server::{ControlService, ControlServiceServer};
use acp_proto::log_service_server::{LogService, LogServiceServer};
use acp_proto::remote_control_service_server::{RemoteControlService, RemoteControlServiceServer};
use acp_proto::telemetry_service_server::{TelemetryService, TelemetryServiceServer};
use acp_proto::traffic_service_server::{TrafficService, TrafficServiceServer};
use acp_proto::*;
use node_agent::session::{
    CONTROL_CLIENT_READY_KEY, CONTROL_READY_METADATA_KEY, CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
};
use node_agent::topology::provider::{
    CURRENT_CONFIG_VERSION, HYSTERIA2_SALAMANDER_ID, Hysteria2SalamanderConfig, Hysteria2TlsConfig,
};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};

type Error = Box<dyn std::error::Error + Send + Sync>;
const MACHINE: &str = "hy2-container-machine";
const NODE: &str = "hy2-container-node";
const SESSION: &str = "hy2-container-session";
const SECRET: &str = "local-container-fixture-secret";
const CHUNK: usize = 64 * 1024;
const MAX_TRANSFER: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

struct Options {
    state_dir: PathBuf,
    panel: SocketAddr,
    target: SocketAddr,
    hy2_port: u16,
    transfer_timeout: Duration,
}

impl Options {
    fn parse() -> Result<Self, Error> {
        let mut options = Self {
            state_dir: PathBuf::from("/fixture"),
            panel: "127.0.0.1:19090".parse()?,
            target: "127.0.0.1:19091".parse()?,
            hy2_port: 18443,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let value = args.next().ok_or_else(|| {
                io::Error::other("usage: hy2_container_fixture [--state-dir DIR] [--panel IP:PORT] [--target IP:PORT] [--hy2-port PORT] [--transfer-timeout-secs SECONDS]")
            })?;
            match arg.as_str() {
                "--state-dir" => options.state_dir = value.into(),
                "--panel" => options.panel = value.parse()?,
                "--target" => options.target = value.parse()?,
                "--hy2-port" => options.hy2_port = value.parse()?,
                "--transfer-timeout-secs" => {
                    options.transfer_timeout = Duration::from_secs(value.parse()?)
                }
                _ => return Err(io::Error::other(format!("unknown argument {arg}")).into()),
            }
        }
        if options.hy2_port == 0 || options.panel.port() == 0 || options.target.port() == 0 {
            return Err(io::Error::other("fixture ports must be nonzero").into());
        }
        if options.transfer_timeout.is_zero()
            || options.transfer_timeout > Duration::from_secs(3600)
        {
            return Err(io::Error::other("transfer timeout must be 1 to 3600 seconds").into());
        }
        for address in [options.panel, options.target] {
            if !address.ip().is_loopback() && !address.ip().is_unspecified() {
                return Err(
                    io::Error::other("fixture listeners must bind loopback or wildcard").into(),
                );
            }
        }
        Ok(options)
    }
}

#[derive(Default, Serialize)]
struct UserTraffic {
    reports: u64,
    uplink_bytes: u64,
    downlink_bytes: u64,
}

#[derive(Default, Serialize)]
struct PanelStats {
    hello_count: u64,
    config_fetches: u64,
    user_fetches: u64,
    control_ready_count: u64,
    control_connected: bool,
    control_ready: bool,
    agent_version: String,
    data_plane_version: String,
    telemetry_count: u64,
    agent_state: String,
    agent_active_connections: u64,
    agent_online_users: u64,
    // ACP reports HostCollector/System::used_memory(), not daemon RSS. Read
    // /proc/<agent-pid>/status or the container observer for process memory.
    system_memory_used_bytes: u64,
    log_batches: u64,
    traffic: BTreeMap<String, UserTraffic>,
}

#[derive(Default)]
struct TargetStats {
    accepted: AtomicU64,
    active: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    rejected: AtomicU64,
    probes: AtomicU64,
    uplink_bytes: AtomicU64,
    downlink_bytes: AtomicU64,
}

#[derive(Clone)]
struct Panel {
    config: MachineConfig,
    users: Vec<UserCredential>,
    digest: String,
    stats: Arc<Mutex<PanelStats>>,
}

fn metadata_value(metadata: &MetadataMap, name: &'static str) -> Result<String, Status> {
    let mut values = metadata.get_all(name).iter();
    let value = values.next().ok_or_else(|| Status::unauthenticated(name))?;
    if values.next().is_some() {
        return Err(Status::unauthenticated("duplicate authentication metadata"));
    }
    Ok(value
        .to_str()
        .map_err(|_| Status::unauthenticated(name))?
        .to_owned())
}

impl Panel {
    fn authenticate(&self, metadata: &MetadataMap) -> Result<(), Status> {
        let fields = SessionFields {
            machine_id: metadata_value(metadata, METADATA_MACHINE_ID)?,
            session_id: metadata_value(metadata, METADATA_SESSION_ID)?,
            timestamp_unix: metadata_value(metadata, METADATA_TIMESTAMP_UNIX)?
                .parse()
                .map_err(|_| Status::unauthenticated("invalid timestamp"))?,
            nonce: metadata_value(metadata, METADATA_NONCE)?,
        };
        if fields.machine_id != MACHINE || fields.session_id != SESSION {
            return Err(Status::unauthenticated("not the local test session"));
        }
        let expected = sign_session(SECRET, &fields)
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if metadata_value(metadata, METADATA_SIGNATURE)? != expected {
            return Err(Status::unauthenticated("invalid test session HMAC"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl AuthService for Panel {
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
        let signature = sign_hello(SECRET, &fields)
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        if hello.machine_id != MACHINE || hello.node_id != NODE || signature != hello.signature {
            return Err(Status::unauthenticated("invalid local test Hello"));
        }
        let mut stats = self.stats.lock().unwrap();
        stats.hello_count += 1;
        stats.agent_version = hello.agent_version;
        stats.data_plane_version = hello.sing_box_version;
        stats.control_ready = false;
        println!(
            "agent registered: version={} core={}",
            stats.agent_version, stats.data_plane_version
        );
        Ok(Response::new(Session {
            session_id: SESSION.into(),
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
        self.authenticate(request.metadata())?;
        let request = request.into_inner();
        if request.machine_id != MACHINE || request.session_id != SESSION {
            return Err(Status::invalid_argument("wrong test machine/session"));
        }
        self.stats.lock().unwrap().config_fetches += 1;
        Ok(Response::new(self.config.clone()))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        self.authenticate(request.metadata())?;
        let request = request.into_inner();
        if request.machine_id != MACHINE
            || request.node_id != NODE
            || request.session_id != SESSION
            || !request.page_token.is_empty()
        {
            return Err(Status::invalid_argument("wrong test user-list request"));
        }
        self.stats.lock().unwrap().user_fetches += 1;
        Ok(Response::new(ListUsersResponse {
            users: self.users.clone(),
            total_size: self.users.len() as u32,
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl ControlService for Panel {
    type ControlStreamStream = ReceiverStream<Result<ControlCommand, Status>>;
    async fn control_stream(
        &self,
        request: Request<tonic::Streaming<ControlAck>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        self.authenticate(request.metadata())?;
        let mut stream = request.into_inner();
        let panel = self.clone();
        let (sender, receiver) = mpsc::channel(1);
        self.stats.lock().unwrap().control_connected = true;
        tokio::spawn(async move {
            while let Ok(Some(ack)) = stream.message().await {
                if ack.idempotency_key == CONTROL_CLIENT_READY_KEY {
                    let valid = ack.status == ControlAckStatus::Applied as i32
                        && ack.revision == 1
                        && ack.message == panel.digest;
                    let mut stats = panel.stats.lock().unwrap();
                    stats.control_ready = valid;
                    stats.control_ready_count += u64::from(valid);
                    println!(
                        "agent control-ready: valid={valid} revision={} digest={}",
                        ack.revision, ack.message
                    );
                }
            }
            let mut stats = panel.stats.lock().unwrap();
            stats.control_connected = false;
            stats.control_ready = false;
            drop(sender); // Keep the server stream open for the lifetime of ACP.
        });
        let mut response = Response::new(ReceiverStream::new(receiver));
        response
            .metadata_mut()
            .insert(CONTROL_READY_METADATA_KEY, MetadataValue::from_static("1"));
        response.metadata_mut().insert(
            CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
            MetadataValue::try_from(self.digest.as_str())
                .map_err(|error| Status::internal(error.to_string()))?,
        );
        Ok(response)
    }
}

#[tonic::async_trait]
impl TrafficService for Panel {
    async fn traffic_stream(
        &self,
        request: Request<tonic::Streaming<TrafficReport>>,
    ) -> Result<Response<StreamClosed>, Status> {
        self.authenticate(request.metadata())?;
        let mut stream = request.into_inner();
        while let Some(report) = stream.message().await? {
            if report.machine_id != MACHINE || report.node_id != NODE {
                return Err(Status::invalid_argument("wrong traffic identity"));
            }
            let mut stats = self.stats.lock().unwrap();
            let user = stats
                .traffic
                .get_mut(&report.user_id)
                .ok_or_else(|| Status::invalid_argument("unknown test user"))?;
            user.reports += 1;
            user.uplink_bytes = user.uplink_bytes.saturating_add(report.uplink_bytes);
            user.downlink_bytes = user.downlink_bytes.saturating_add(report.downlink_bytes);
        }
        Ok(Response::new(StreamClosed {
            message: "traffic drained".into(),
        }))
    }
}

#[tonic::async_trait]
impl TelemetryService for Panel {
    async fn telemetry_stream(
        &self,
        request: Request<tonic::Streaming<TelemetrySnapshot>>,
    ) -> Result<Response<StreamClosed>, Status> {
        self.authenticate(request.metadata())?;
        let mut stream = request.into_inner();
        while let Some(snapshot) = stream.message().await? {
            let mut stats = self.stats.lock().unwrap();
            stats.telemetry_count += 1;
            stats.agent_state = snapshot.sing_box_state;
            stats.agent_active_connections = snapshot.active_connections;
            stats.agent_online_users = snapshot.online_users;
            stats.system_memory_used_bytes = snapshot.memory_used_bytes;
        }
        Ok(Response::new(StreamClosed {
            message: "telemetry drained".into(),
        }))
    }
}

#[tonic::async_trait]
impl LogService for Panel {
    type LogStreamStream = ReceiverStream<Result<NodeLogCommand, Status>>;
    async fn log_stream(
        &self,
        request: Request<tonic::Streaming<NodeLogBatch>>,
    ) -> Result<Response<Self::LogStreamStream>, Status> {
        self.authenticate(request.metadata())?;
        let mut stream = request.into_inner();
        let stats = self.stats.clone();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            // agent.toml directs full real-daemon logs to agent.log. The ACP log
            // stream remains available without duplicating large logs in memory.
            while let Ok(Some(_batch)) = stream.message().await {
                stats.lock().unwrap().log_batches += 1;
            }
            drop(sender);
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

#[tonic::async_trait]
impl RemoteControlService for Panel {
    type RemoteControlStreamStream = ReceiverStream<Result<RemoteControlRequest, Status>>;
    async fn remote_control_stream(
        &self,
        request: Request<tonic::Streaming<RemoteControlResponse>>,
    ) -> Result<Response<Self::RemoteControlStreamStream>, Status> {
        self.authenticate(request.metadata())?;
        let mut stream = request.into_inner();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Ok(Some(_)) = stream.message().await {}
            drop(sender);
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

struct ActiveTarget(Arc<TargetStats>);
impl Drop for ActiveTarget {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn transfer(mut stream: TcpStream, stats: &TargetStats) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut header = Vec::with_capacity(64);
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if header.len() == 127 {
            return Err(io::Error::other("target request header too long"));
        }
        header.push(byte);
    }
    if header == b"who" {
        stream.write_all(b"bounded-peer\n").await?;
        stream.shutdown().await?;
        stats.probes.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    let header = std::str::from_utf8(&header).map_err(io::Error::other)?;
    let fields: Vec<_> = header.split_whitespace().collect();
    if fields.len() != 2 {
        return Err(io::Error::other("expected UPLOAD_BYTES DOWNLOAD_BYTES"));
    }
    let upload: u64 = fields[0].parse().map_err(io::Error::other)?;
    let download: u64 = fields[1].parse().map_err(io::Error::other)?;
    if upload > MAX_TRANSFER || download > MAX_TRANSFER {
        return Err(io::Error::other("transfer exceeds 8 GiB direction limit"));
    }
    let mut buffer = vec![b'y'; CHUNK];
    let mut remaining = upload;
    while remaining > 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        stream.read_exact(&mut buffer[..count]).await?;
        if buffer[..count].iter().any(|byte| *byte != b'x') {
            return Err(io::Error::other("upload payload mismatch"));
        }
        stats
            .uplink_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        remaining -= count as u64;
    }
    buffer.fill(b'y');
    remaining = download;
    while remaining > 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        stream.write_all(&buffer[..count]).await?;
        stats
            .downlink_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        remaining -= count as u64;
    }
    stream.shutdown().await?;
    stats.completed.fetch_add(1, Ordering::Relaxed);
    println!("target transfer complete: up={upload} down={download}");
    Ok(())
}

async fn serve_target(
    listener: TcpListener,
    stats: Arc<TargetStats>,
    transfer_timeout: Duration,
    stop: CancellationToken,
) -> Result<(), Error> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined { eprintln!("target task: {error}"); }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                // Include completed tasks awaiting collection in the cap, so
                // the JoinSet itself cannot grow under rapid short requests.
                if tasks.len() >= MAX_CONNECTIONS {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
                stats.accepted.fetch_add(1, Ordering::Relaxed);
                stats.active.fetch_add(1, Ordering::Relaxed);
                let active = ActiveTarget(stats.clone());
                tasks.spawn(async move {
                    let outcome = tokio::time::timeout(transfer_timeout, transfer(stream, &active.0)).await;
                    if !matches!(outcome, Ok(Ok(()))) {
                        active.0.failed.fetch_add(1, Ordering::Relaxed);
                        if outcome.is_err() { active.0.timed_out.fetch_add(1, Ordering::Relaxed); }
                        eprintln!("target transfer failed: peer={peer} outcome={outcome:?}");
                    }
                });
            }
        }
    }
    tasks.shutdown().await;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), Error> {
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn snapshot(
    options: &Options,
    panel: &Panel,
    target: &TargetStats,
    listening: bool,
) -> Result<(), Error> {
    let stats = panel.stats.lock().unwrap();
    let agent_ready = listening
        && stats.hello_count > 0
        && stats.config_fetches > 0
        && stats.user_fetches > 0
        && stats.control_connected
        && stats.control_ready;
    write_json(
        &options.state_dir.join("ready.json"),
        &json!({
            "fixture_listening": listening, "agent_ready": agent_ready,
            "agent_registered": stats.hello_count > 0,
            "config_and_users_served": stats.config_fetches > 0 && stats.user_fetches > 0,
            "control_ready": stats.control_ready, "control_connected": stats.control_connected,
            "panel": options.panel.to_string(), "target": options.target.to_string(),
            "hy2_port": options.hy2_port, "timestamp_unix": unix_now(), "topology_digest": panel.digest,
        }),
    )?;
    write_json(
        &options.state_dir.join("stats.json"),
        &json!({
            "timestamp_unix": unix_now(), "agent_ready": agent_ready, "acp": *stats,
            "target": {
                "accepted": target.accepted.load(Ordering::Relaxed),
                "active": target.active.load(Ordering::Relaxed),
                "completed": target.completed.load(Ordering::Relaxed),
                "failed": target.failed.load(Ordering::Relaxed),
                "timed_out": target.timed_out.load(Ordering::Relaxed),
                "rejected": target.rejected.load(Ordering::Relaxed),
                "probes": target.probes.load(Ordering::Relaxed),
                "uplink_bytes": target.uplink_bytes.load(Ordering::Relaxed),
                "downlink_bytes": target.downlink_bytes.load(Ordering::Relaxed),
                "max_connections": MAX_CONNECTIONS, "max_direction_bytes": MAX_TRANSFER,
                "buffer_bytes_per_connection": CHUNK,
                "transfer_timeout_secs": options.transfer_timeout.as_secs(),
            },
        }),
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = Options::parse()?;
    std::fs::create_dir_all(&options.state_dir)?;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let provider = Hysteria2SalamanderConfig {
        kind: "hysteria2".into(),
        tag: NODE.into(),
        listen: "0.0.0.0".into(),
        listen_port: options.hy2_port,
        up_mbps: 0,
        down_mbps: 0,
        ignore_client_bandwidth: true,
        tls: Hysteria2TlsConfig {
            enabled: true,
            server_name: "localhost".into(),
            certificate_pem: cert.pem(),
            private_key_pem: signing_key.serialize_pem(),
            ..Default::default()
        },
        ..Default::default()
    };
    std::fs::write(options.state_dir.join("hy2-test-cert.pem"), cert.pem())?;
    // Include zeros explicitly in the wire fixture even though the provider
    // serializer normally omits these default-valued configuration fields.
    let mut provider_json = serde_json::to_value(&provider)?;
    provider_json["up_mbps"] = json!(0);
    provider_json["down_mbps"] = json!(0);
    let config = MachineConfig {
        machine_id: MACHINE.into(),
        revision: 1,
        nodes: vec![NodeConfig {
            node_id: NODE.into(),
            provider_id: HYSTERIA2_SALAMANDER_ID.into(),
            provider_config_version: CURRENT_CONFIG_VERSION,
            provider_config_json: serde_json::to_vec(&provider_json)?,
        }],
        ..Default::default()
    };
    let users: Vec<_> = ["alice", "bob"]
        .into_iter()
        .map(|name| UserCredential {
            user_id: name.into(),
            name: name.into(),
            credential: format!("fixture-{name}"),
            status: UserStatus::Active as i32,
            ..Default::default()
        })
        .collect();
    let topology = TopologySnapshot {
        machine_id: MACHINE.into(),
        revision: 1,
        nodes: vec![NodeTopology {
            node_id: NODE.into(),
            provider_id: HYSTERIA2_SALAMANDER_ID.into(),
            provider_config_version: CURRENT_CONFIG_VERSION,
            provider_config_json: config.nodes[0].provider_config_json.clone(),
            users: users.clone(),
        }],
        ..Default::default()
    };
    let stats = PanelStats {
        traffic: users
            .iter()
            .map(|user| (user.user_id.clone(), UserTraffic::default()))
            .collect(),
        ..Default::default()
    };
    let panel = Panel {
        config,
        users,
        digest: acp_proto::digest::sum(Some(&topology)),
        stats: Arc::new(Mutex::new(stats)),
    };
    let target_stats = Arc::new(TargetStats::default());
    let mut panel_address = options.panel;
    if panel_address.ip().is_unspecified() {
        panel_address.set_ip("127.0.0.1".parse()?);
    }
    let log_path = options
        .state_dir
        .join("agent.log")
        .to_string_lossy()
        .into_owned();
    let agent_config = format!(
        "panel_grpc_endpoint = \"grpc://{panel_address}\"\nmachine_id = \"{MACHINE}\"\nnode_id = \"{NODE}\"\nmachine_secret = \"{SECRET}\"\ndebug = false\nlog_file_path = {}\ntraffic_report_min_delta_bytes = 1\n",
        toml::Value::String(log_path),
    );
    node_agent::config::parse(&agent_config)?;
    std::fs::write(options.state_dir.join("agent.toml"), agent_config)?;
    snapshot(&options, &panel, &target_stats, false)?;
    let panel_listener = TcpListener::bind(options.panel).await?;
    let target_listener = TcpListener::bind(options.target).await?;
    snapshot(&options, &panel, &target_stats, true)?;
    println!(
        "fixture listening: panel={} target={} HY2=0.0.0.0:{} users=alice,bob; run node-agent {}",
        options.panel,
        options.target,
        options.hy2_port,
        options.state_dir.join("agent.toml").display()
    );
    let stop = node_agent::shutdown::cancellation_token();
    let serve_panel = tonic::transport::Server::builder()
        .add_service(AuthServiceServer::new(panel.clone()))
        .add_service(ConfigServiceServer::new(panel.clone()))
        .add_service(ControlServiceServer::new(panel.clone()))
        .add_service(TrafficServiceServer::new(panel.clone()))
        .add_service(TelemetryServiceServer::new(panel.clone()))
        .add_service(LogServiceServer::new(panel.clone()))
        .add_service(RemoteControlServiceServer::new(panel.clone()))
        .serve_with_incoming_shutdown(
            TcpListenerStream::new(panel_listener),
            stop.clone().cancelled_owned(),
        );
    let target = serve_target(
        target_listener,
        target_stats.clone(),
        options.transfer_timeout,
        stop.clone(),
    );
    let writer = async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = interval.tick() => snapshot(&options, &panel, &target_stats, true)?,
            }
        }
        snapshot(&options, &panel, &target_stats, false)?;
        Ok::<(), Error>(())
    };
    tokio::try_join!(
        async { serve_panel.await.map_err(Error::from) },
        target,
        writer
    )?;
    Ok(())
}
