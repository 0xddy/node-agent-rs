//! ACP transport, authentication, control-stream registration, and stream lifetime.
//!
//! This module deliberately stops at the control stream's ready acknowledgement.
//! Command execution belongs to `control`; traffic aggregation, telemetry and log
//! production likewise remain in their own modules.  What is centralised here is
//! the security-sensitive part every one of those streams must share: one fresh
//! five-field session HMAC on every RPC, bounded connection/registration waits,
//! and one cancellation domain for the whole authenticated session.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use acp_proto::auth::{
    HelloFields, NONCE_BYTES, SessionFields, new_nonce, session_metadata, sign_hello,
};
use acp_proto::control_service_client::ControlServiceClient;
use acp_proto::{ControlAck, ControlAckStatus, ControlCommand, HelloRequest, Session};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime, pem::PemObject as _};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinSet};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status};

use crate::backoff::ExponentialBackoff;
use crate::config::{Config, PANEL_GRPC_SCHEME_PLAINTEXT, PANEL_GRPC_SCHEME_TLS};

pub const PANEL_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
pub const PANEL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const SESSION_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const SESSION_BACKOFF_MAX: Duration = Duration::from_secs(30);
pub const STABLE_SESSION_RESET_AFTER: Duration = Duration::from_secs(60);
pub const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

pub const CONTROL_READY_METADATA_KEY: &str = "x-acp-control-ready";
pub const CONTROL_TOPOLOGY_DIGEST_METADATA_KEY: &str = "x-acp-topology-digest";
pub const CONTROL_CLIENT_READY_KEY: &str = "control-stream-ready-v1";

const CONTROL_ACK_QUEUE_SIZE: usize = 256;

#[derive(Debug)]
pub enum SessionError {
    InvalidConfig(String),
    ReadCa {
        path: String,
        source: std::io::Error,
    },
    InvalidCa {
        path: String,
        message: String,
    },
    Transport(tonic::transport::Error),
    Rpc(Status),
    Timeout {
        operation: &'static str,
        duration: Duration,
    },
    Authentication(String),
    Metadata(String),
    ControlRegistration(String),
    ControlStreamClosed,
    CriticalStreamEnded(String),
    Stream {
        name: String,
        source: Box<SessionError>,
    },
    Task {
        name: String,
        message: String,
    },
}

impl SessionError {
    pub fn is_unauthenticated(&self) -> bool {
        match self {
            Self::Rpc(status) => status.code() == Code::Unauthenticated,
            Self::Stream { source, .. } => source.is_unauthenticated(),
            _ => false,
        }
    }

    fn stream(name: impl Into<String>, source: SessionError) -> Self {
        Self::Stream {
            name: name.into(),
            source: Box::new(source),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid panel configuration: {message}"),
            Self::ReadCa { path, source } => {
                write!(f, "read panel CA certificate {path:?}: {source}")
            }
            Self::InvalidCa { path, message } => {
                write!(f, "parse panel CA certificate {path:?}: {message}")
            }
            Self::Transport(error) => write!(f, "panel transport: {error}"),
            Self::Rpc(status) => write!(f, "panel RPC: {status}"),
            Self::Timeout {
                operation,
                duration,
            } => write!(f, "{operation} timed out after {duration:?}"),
            Self::Authentication(message) => write!(f, "panel authentication: {message}"),
            Self::Metadata(message) => write!(f, "session metadata: {message}"),
            Self::ControlRegistration(message) => {
                write!(f, "control stream registration: {message}")
            }
            Self::ControlStreamClosed => f.write_str("control stream acknowledgement side closed"),
            Self::CriticalStreamEnded(name) => {
                write!(f, "session-critical {name} exited")
            }
            Self::Stream { name, source } => write!(f, "{name}: {source}"),
            Self::Task { name, message } => write!(f, "{name} task failed: {message}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadCa { source, .. } => Some(source),
            Self::Transport(error) => Some(error),
            Self::Rpc(status) => Some(status),
            Self::Stream { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<Status> for SessionError {
    fn from(status: Status) -> Self {
        Self::Rpc(status)
    }
}

/// Connection and unsigned-Hello settings that remain stable across sessions.
#[derive(Clone)]
pub struct PanelClient {
    config: Arc<Config>,
    agent_version: Arc<str>,
    data_plane_version: Arc<str>,
}

impl PanelClient {
    pub fn new(
        config: Config,
        agent_version: impl Into<Arc<str>>,
        data_plane_version: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            agent_version: agent_version.into(),
            data_plane_version: data_plane_version.into(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Resolves, connects, completes TLS when requested, and waits for an HTTP/2
    /// channel to become ready. Both endpoint connection work and the outer future
    /// are bounded so DNS or a connector implementation cannot bypass the 10s limit.
    pub async fn dial(&self) -> Result<Channel, SessionError> {
        let endpoint = self.endpoint()?;
        match tokio::time::timeout(PANEL_DIAL_TIMEOUT, endpoint.connect()).await {
            Ok(Ok(channel)) => Ok(channel),
            Ok(Err(error)) => Err(SessionError::Transport(error)),
            Err(_) => Err(SessionError::Timeout {
                operation: "panel dial",
                duration: PANEL_DIAL_TIMEOUT,
            }),
        }
    }

    fn endpoint(&self) -> Result<Endpoint, SessionError> {
        let scheme = match self.config.panel_grpc_scheme.as_str() {
            PANEL_GRPC_SCHEME_PLAINTEXT => "http",
            PANEL_GRPC_SCHEME_TLS => "https",
            other => {
                return Err(SessionError::InvalidConfig(format!(
                    "unsupported panel gRPC scheme {other:?}"
                )));
            }
        };
        let uri = format!("{scheme}://{}", self.config.panel_grpc_address);
        let mut endpoint = Endpoint::from_shared(uri)
            .map_err(SessionError::Transport)?
            .connect_timeout(PANEL_DIAL_TIMEOUT)
            .tcp_nodelay(true);

        // Do not install a channel-wide request timeout here. Traffic and
        // telemetry are long-lived client-streaming RPCs whose unary response is
        // intentionally delayed until shutdown; a tower timeout would tear them
        // down every ten seconds. Bounded unary calls and control registration
        // use explicit `tokio::time::timeout` at their call sites instead.

        if self.config.panel_grpc_scheme == PANEL_GRPC_SCHEME_TLS {
            endpoint = self.configure_tls(endpoint)?;
        }
        Ok(endpoint)
    }

    fn configure_tls(&self, endpoint: Endpoint) -> Result<Endpoint, SessionError> {
        // The workspace can enable both rustls providers through independent
        // crates. In that feature combination rustls deliberately refuses to
        // guess and panics unless the application selects one first.
        install_crypto_provider();
        let ca = load_optional_ca(&self.config.ca_cert_path)?;
        let mut tls = ClientTlsConfig::new()
            // A scope identifier selects a local interface; it is not part of
            // the certificate identity. Go's crypto/tls likewise removes the
            // `%zone` before producing SNI.
            .domain_name(tls_server_name(&self.config.panel_grpc_server_name))
            .timeout(PANEL_DIAL_TIMEOUT);

        if self.config.tls_insecure_skip_verify {
            // CA files are still parsed above. This matches Go: a broken explicit
            // path is an operator error even when verification is temporarily off.
            endpoint
                .tls_config_with_verifier(tls, Arc::new(InsecureVerifier::new()))
                .map_err(SessionError::Transport)
        } else {
            // Load native certificates ourselves instead of using tonic's
            // `with_native_roots`: tonic rejects an empty native store before it
            // considers an explicit CA, while Go falls back to an empty pool and
            // then appends the configured private CA.
            let native = rustls_native_certs::load_native_certs();
            if !native.errors.is_empty() {
                log::debug!(
                    "errors occurred while loading native panel CA certificates: {:?}",
                    native.errors
                );
            }
            tls = tls.trust_anchors(trust_anchors(native.certs));
            if let Some(ca) = ca {
                tls = tls.trust_anchors(ca);
            }
            endpoint.tls_config(tls).map_err(SessionError::Transport)
        }
    }

    pub fn hello_request(&self, topology_revision: u64) -> Result<HelloRequest, SessionError> {
        let timestamp_unix = unix_now()?;
        let nonce = new_nonce(NONCE_BYTES);
        build_hello_request_at(
            &self.config,
            &self.agent_version,
            &self.data_plane_version,
            topology_revision,
            timestamp_unix,
            nonce,
        )
    }

    pub async fn authenticate(
        &self,
        channel: Channel,
        topology_revision: u64,
    ) -> Result<AuthenticatedSession, SessionError> {
        let request = Request::new(self.hello_request(topology_revision)?);
        let mut client = acp_proto::auth_service_client::AuthServiceClient::new(channel.clone());
        let response =
            match tokio::time::timeout(PANEL_REQUEST_TIMEOUT, client.hello(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(status)) => return Err(SessionError::Rpc(status)),
                Err(_) => {
                    return Err(SessionError::Timeout {
                        operation: "auth hello",
                        duration: PANEL_REQUEST_TIMEOUT,
                    });
                }
            };
        AuthenticatedSession::new(&self.config, channel, response.into_inner())
    }
}

fn tls_server_name(server_name: &str) -> String {
    if let Some((address, _zone)) = server_name.rsplit_once('%')
        && address.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return address.to_owned();
    }
    server_name.to_owned()
}

fn build_hello_request_at(
    config: &Config,
    agent_version: &str,
    data_plane_version: &str,
    topology_revision: u64,
    timestamp_unix: i64,
    nonce: String,
) -> Result<HelloRequest, SessionError> {
    let fields = HelloFields {
        machine_id: config.machine_id.clone(),
        node_id: config.node_id.clone(),
        agent_version: agent_version.to_string(),
        // The proto field keeps its historical sing-box name, but the value is
        // deliberately the shoes data-plane version.
        sing_box_version: data_plane_version.to_string(),
        timestamp_unix,
        nonce,
        topology_revision,
    };
    let signature = sign_hello(&config.machine_secret, &fields)
        .map_err(|error| SessionError::Authentication(error.to_string()))?;
    Ok(HelloRequest {
        machine_id: fields.machine_id,
        node_id: fields.node_id,
        agent_version: fields.agent_version,
        sing_box_version: fields.sing_box_version,
        timestamp_unix: fields.timestamp_unix,
        nonce: fields.nonce,
        signature,
        topology_revision: fields.topology_revision,
    })
}

fn unix_now() -> Result<i64, SessionError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            SessionError::Authentication(format!("system clock before Unix epoch: {error}"))
        })?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| SessionError::Authentication("Unix timestamp exceeds i64".into()))
}

fn load_optional_ca(path: &str) -> Result<Option<Vec<TrustAnchor<'static>>>, SessionError> {
    if path.is_empty() {
        return Ok(None);
    }
    let pem = std::fs::read(path).map_err(|source| SessionError::ReadCa {
        path: path.to_string(),
        source,
    })?;

    // AppendCertsFromPEM in Go is deliberately best-effort: malformed blocks
    // are skipped and the operation succeeds when at least one X.509
    // certificate parses. Build trust anchors here both to match that contract
    // and to prevent tonic from silently ignoring a PEM-wrapped invalid DER.
    let anchors = trust_anchors(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
    if anchors.is_empty() {
        return Err(SessionError::InvalidCa {
            path: path.to_string(),
            message: "PEM contains no valid X.509 certificates".into(),
        });
    }
    Ok(Some(anchors))
}

fn trust_anchors<'a>(
    certificates: impl IntoIterator<Item = CertificateDer<'a>>,
) -> Vec<TrustAnchor<'static>> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certificates);
    roots.roots
}

/// Rustls verifier used only for the explicit `tls_insecure_skip_verify` escape
/// hatch. Certificate-chain and hostname checks are skipped, while CertificateVerify
/// signatures are still cryptographically checked with the same AWS-LC provider as
/// tonic and shoes.
#[derive(Debug)]
struct InsecureVerifier(CryptoProvider);

impl InsecureVerifier {
    fn new() -> Self {
        Self(process_crypto_provider())
    }
}

fn install_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        // Losing this race is harmless: the winner's process-wide provider is
        // exactly the provider rustls will subsequently use.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn process_crypto_provider() -> CryptoProvider {
    install_crypto_provider();
    CryptoProvider::get_default()
        .expect("a rustls crypto provider was installed above")
        .as_ref()
        .clone()
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Clone)]
pub struct SessionAuthenticator {
    machine_id: Arc<str>,
    session_id: Arc<str>,
    machine_secret: Arc<str>,
}

impl SessionAuthenticator {
    pub fn new(config: &Config, session: &Session) -> Result<Self, SessionError> {
        if config.machine_id.is_empty() {
            return Err(SessionError::Authentication(
                "machine id is required".into(),
            ));
        }
        if config.machine_secret.is_empty() {
            return Err(SessionError::Authentication(
                "machine secret is required".into(),
            ));
        }
        if session.session_id.is_empty() {
            return Err(SessionError::Authentication(
                "session id is required".into(),
            ));
        }
        Ok(Self {
            machine_id: Arc::from(config.machine_id.as_str()),
            session_id: Arc::from(session.session_id.as_str()),
            machine_secret: Arc::from(config.machine_secret.as_str()),
        })
    }

    pub fn interceptor(&self) -> SessionInterceptor {
        SessionInterceptor { auth: self.clone() }
    }

    pub fn intercepted_channel(
        &self,
        channel: Channel,
    ) -> InterceptedService<Channel, SessionInterceptor> {
        InterceptedService::new(channel, self.interceptor())
    }

    fn attach<T>(&self, request: &mut Request<T>) -> Result<(), SessionError> {
        self.attach_at(request, unix_now()?, new_nonce(NONCE_BYTES))
    }

    fn attach_at<T>(
        &self,
        request: &mut Request<T>,
        timestamp_unix: i64,
        nonce: String,
    ) -> Result<(), SessionError> {
        let fields = SessionFields {
            machine_id: self.machine_id.to_string(),
            session_id: self.session_id.to_string(),
            timestamp_unix,
            nonce,
        };
        let metadata = session_metadata(&self.machine_secret, &fields)
            .map_err(|error| SessionError::Authentication(error.to_string()))?;
        for (key, value) in metadata {
            let parsed = MetadataValue::<Ascii>::try_from(value.as_str()).map_err(|error| {
                SessionError::Metadata(format!("invalid value for {key}: {error}"))
            })?;
            // `insert` replaces any caller-supplied stale value, so the request has
            // exactly one copy of each security field when it leaves this layer.
            request.metadata_mut().insert(key, parsed);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SessionInterceptor {
    auth: SessionAuthenticator,
}

impl Interceptor for SessionInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        self.auth
            .attach(&mut request)
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(request)
    }
}

#[derive(Clone)]
pub struct AuthenticatedSession {
    channel: Channel,
    descriptor: Session,
    authenticator: SessionAuthenticator,
}

impl AuthenticatedSession {
    fn new(config: &Config, channel: Channel, descriptor: Session) -> Result<Self, SessionError> {
        let authenticator = SessionAuthenticator::new(config, &descriptor)?;
        Ok(Self {
            channel,
            descriptor,
            authenticator,
        })
    }

    pub fn descriptor(&self) -> &Session {
        &self.descriptor
    }

    pub fn authenticator(&self) -> &SessionAuthenticator {
        &self.authenticator
    }

    /// A cheap handle clone for stream runners that accept the transport and
    /// [`SessionAuthenticator`] separately.
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }

    /// Preferred entry point for additional generated ACP clients. The
    /// interceptor creates a new nonce/signature every time tonic invokes it.
    pub fn authenticated_channel(&self) -> InterceptedService<Channel, SessionInterceptor> {
        self.authenticator.intercepted_channel(self.channel.clone())
    }

    pub async fn open_control_stream(&self) -> Result<OpenedControlStream, SessionError> {
        let (ack_sender, ack_receiver) = mpsc::channel(CONTROL_ACK_QUEUE_SIZE);
        let outgoing = ReceiverStream::new(ack_receiver);
        let mut client = ControlServiceClient::new(self.authenticated_channel());
        let response = match tokio::time::timeout(
            PANEL_REQUEST_TIMEOUT,
            client.control_stream(Request::new(outgoing)),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(status)) => return Err(SessionError::Rpc(status)),
            Err(_) => {
                return Err(SessionError::Timeout {
                    operation: "control stream registration",
                    duration: PANEL_REQUEST_TIMEOUT,
                });
            }
        };
        let panel_digest = validate_control_metadata(response.metadata())?;
        Ok(OpenedControlStream {
            ack_sender,
            commands: response.into_inner(),
            panel_digest,
        })
    }
}

pub struct OpenedControlStream {
    ack_sender: mpsc::Sender<ControlAck>,
    commands: tonic::Streaming<ControlCommand>,
    panel_digest: String,
}

impl OpenedControlStream {
    pub fn panel_digest(&self) -> &str {
        &self.panel_digest
    }

    pub fn ack_sender(&self) -> mpsc::Sender<ControlAck> {
        self.ack_sender.clone()
    }

    pub async fn confirm_ready(
        &self,
        current_digest: &str,
        revision: u64,
    ) -> Result<(), SessionError> {
        self.send_ack(control_ready_ack(current_digest, revision)?)
            .await
    }

    pub async fn send_ack(&self, ack: ControlAck) -> Result<(), SessionError> {
        self.ack_sender
            .send(ack)
            .await
            .map_err(|_| SessionError::ControlStreamClosed)
    }

    pub async fn message(&mut self) -> Result<Option<ControlCommand>, SessionError> {
        self.commands.message().await.map_err(SessionError::Rpc)
    }

    pub fn into_parts(
        self,
    ) -> (
        mpsc::Sender<ControlAck>,
        tonic::Streaming<ControlCommand>,
        String,
    ) {
        (self.ack_sender, self.commands, self.panel_digest)
    }
}

pub fn control_ready_ack(digest: &str, revision: u64) -> Result<ControlAck, SessionError> {
    validate_digest(digest).map_err(SessionError::ControlRegistration)?;
    if revision == 0 {
        return Err(SessionError::ControlRegistration(
            "topology revision is required".into(),
        ));
    }
    Ok(ControlAck {
        command_id: String::new(),
        machine_id: String::new(),
        node_id: String::new(),
        revision,
        idempotency_key: CONTROL_CLIENT_READY_KEY.to_string(),
        status: ControlAckStatus::Applied as i32,
        message: digest.to_string(),
        operation_id: String::new(),
    })
}

fn validate_control_metadata(metadata: &MetadataMap) -> Result<String, SessionError> {
    let ready = single_ascii_metadata(metadata, CONTROL_READY_METADATA_KEY)
        .map_err(|message| SessionError::ControlRegistration(format!("ready marker: {message}")))?;
    if ready != "1" {
        return Err(SessionError::ControlRegistration(
            "server did not confirm registration with x-acp-control-ready=1".into(),
        ));
    }
    let digest = single_ascii_metadata(metadata, CONTROL_TOPOLOGY_DIGEST_METADATA_KEY).map_err(
        |message| SessionError::ControlRegistration(format!("topology digest: {message}")),
    )?;
    validate_digest(digest).map_err(SessionError::ControlRegistration)?;
    Ok(digest.to_string())
}

fn single_ascii_metadata<'a>(
    metadata: &'a MetadataMap,
    key: &'static str,
) -> Result<&'a str, String> {
    let mut values = metadata.get_all(key).iter();
    let value = values.next().ok_or_else(|| format!("missing {key}"))?;
    if values.next().is_some() {
        return Err(format!("{key} must occur exactly once"));
    }
    value
        .to_str()
        .map_err(|error| format!("{key} is not ASCII: {error}"))
}

fn validate_digest(digest: &str) -> Result<(), String> {
    if digest.len() != 64 || acp_proto::hex::decode(digest).is_none_or(|bytes| bytes.len() != 32) {
        return Err(format!(
            "invalid topology digest {digest:?}; expected 64 hex characters"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RetryPolicy {
    initial: Duration,
    max: Duration,
    stable_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial: SESSION_BACKOFF_INITIAL,
            max: SESSION_BACKOFF_MAX,
            stable_after: STABLE_SESSION_RESET_AFTER,
        }
    }
}

/// Repeatedly establishes a complete authenticated panel session. The attempt
/// callback owns dial/Hello/topology-ready/streams for one generation; any error
/// tears that generation down and is retried with the Go-compatible equal-jitter
/// curve. A healthy generation lasting over one minute resets the curve.
pub async fn run_panel_sessions<F, Fut>(
    shutdown: CancellationToken,
    attempt: F,
) -> Result<(), SessionError>
where
    F: FnMut(CancellationToken) -> Fut,
    Fut: Future<Output = Result<(), SessionError>>,
{
    run_panel_sessions_with_policy(shutdown, attempt, RetryPolicy::default()).await
}

async fn run_panel_sessions_with_policy<F, Fut>(
    shutdown: CancellationToken,
    mut attempt: F,
    policy: RetryPolicy,
) -> Result<(), SessionError>
where
    F: FnMut(CancellationToken) -> Fut,
    Fut: Future<Output = Result<(), SessionError>>,
{
    let mut backoff = ExponentialBackoff::new(policy.initial, policy.max);
    while !shutdown.is_cancelled() {
        let started_at = Instant::now();
        let attempt_cancel = shutdown.child_token();
        let mut future = Box::pin(attempt(attempt_cancel.clone()));
        let result = tokio::select! {
            biased;
            result = &mut future => result,
            () = shutdown.cancelled() => {
                attempt_cancel.cancel();
                let _ = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, &mut future).await;
                return Ok(());
            }
        };
        attempt_cancel.cancel();

        if shutdown.is_cancelled() {
            return Ok(());
        }
        if result.is_ok() {
            backoff.reset();
            continue;
        }
        if started_at.elapsed() > policy.stable_after {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = shutdown.cancelled() => return Ok(()),
        }
    }
    Ok(())
}

/// One authenticated session's cancellation domain. Auxiliary streams reconnect
/// independently, but `Unauthenticated` invalidates the shared session; the control
/// stream is critical and any exit invalidates it.
pub struct StreamGroup {
    cancel: CancellationToken,
    tasks: JoinSet<Result<(), SessionError>>,
    policy: RetryPolicy,
    shutdown_grace: Duration,
}

impl StreamGroup {
    pub fn new(parent: &CancellationToken) -> Self {
        Self::with_policy(parent, RetryPolicy::default(), SHUTDOWN_GRACE_PERIOD)
    }

    fn with_policy(
        parent: &CancellationToken,
        policy: RetryPolicy,
        shutdown_grace: Duration,
    ) -> Self {
        Self {
            cancel: parent.child_token(),
            tasks: JoinSet::new(),
            policy,
            shutdown_grace,
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn start_auxiliary<F, Fut>(&mut self, name: impl Into<String>, runner: F)
    where
        F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), SessionError>> + Send + 'static,
    {
        let name = name.into();
        let cancel = self.cancel.clone();
        let policy = self.policy;
        self.tasks.spawn(async move {
            run_auxiliary_stream(cancel, runner, policy)
                .await
                .map_err(|error| SessionError::stream(name, error))
        });
    }

    pub fn start_session_critical<F, Fut>(&mut self, name: impl Into<String>, runner: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), SessionError>> + Send + 'static,
    {
        let name = name.into();
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            let result = runner(cancel.clone()).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            match result {
                Ok(()) => Err(SessionError::CriticalStreamEnded(name)),
                Err(error) => Err(SessionError::stream(name, error)),
            }
        });
    }

    pub async fn wait(mut self) -> Result<(), SessionError> {
        loop {
            if self.tasks.is_empty() {
                return Ok(());
            }
            tokio::select! {
                biased;
                joined = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    match joined {
                        Some(Ok(Ok(()))) => continue,
                        Some(Ok(Err(error))) => {
                            self.cancel.cancel();
                            self.drain().await;
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            let failure = task_error("session stream", error);
                            self.cancel.cancel();
                            self.drain().await;
                            return Err(failure);
                        }
                        None => return Ok(()),
                    }
                }
                () = self.cancel.cancelled() => {
                    let error = self.drain().await;
                    return error.map_or(Ok(()), Err);
                }
            }
        }
    }

    async fn drain(&mut self) -> Option<SessionError> {
        let mut first_error = None;
        let drain = async {
            while let Some(joined) = self.tasks.join_next().await {
                match joined {
                    Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                    Err(error) if first_error.is_none() => {
                        first_error = Some(task_error("session stream", error));
                    }
                    _ => {}
                }
            }
        };
        if tokio::time::timeout(self.shutdown_grace, drain)
            .await
            .is_err()
        {
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
        first_error
    }
}

impl Drop for StreamGroup {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.abort_all();
    }
}

async fn run_auxiliary_stream<F, Fut>(
    cancel: CancellationToken,
    runner: F,
    policy: RetryPolicy,
) -> Result<(), SessionError>
where
    F: Fn(CancellationToken) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), SessionError>> + Send,
{
    let mut backoff = ExponentialBackoff::new(policy.initial, policy.max);
    while !cancel.is_cancelled() {
        let started_at = Instant::now();
        let result = runner(cancel.clone()).await;
        if cancel.is_cancelled() || result.is_ok() {
            return Ok(());
        }
        let error = result.expect_err("checked above");
        if error.is_unauthenticated() {
            return Err(error);
        }
        if started_at.elapsed() > policy.stable_after {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = cancel.cancelled() => return Ok(()),
        }
    }
    Ok(())
}

fn task_error(name: &str, error: JoinError) -> SessionError {
    SessionError::Task {
        name: name.to_string(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
