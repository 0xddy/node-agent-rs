use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use acp_proto::auth::{
    METADATA_MACHINE_ID, METADATA_NONCE, METADATA_SESSION_ID, METADATA_SIGNATURE,
    METADATA_TIMESTAMP_UNIX, SessionFields, sign_hello, sign_session,
};
use acp_proto::auth_service_server::{AuthService, AuthServiceServer};
use acp_proto::config_service_client::ConfigServiceClient;
use acp_proto::config_service_server::{ConfigService, ConfigServiceServer};
use acp_proto::control_service_server::{ControlService, ControlServiceServer};
use acp_proto::{
    ControlAck, ControlCommand, GetMachineConfigRequest, HelloRequest, ListUsersRequest,
    ListUsersResponse, MachineConfig, Session,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Code, Request, Response, Status};

use super::*;
use crate::config;

const SECRET: &str = "s3cr3t";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UPPERCASE_DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn test_config(endpoint: &str) -> Config {
    config::parse(&format!(
        r#"panel_grpc_endpoint = "{endpoint}"
machine_id = "machine-1"
node_id = "node-1"
machine_secret = "{SECRET}"
"#,
    ))
    .unwrap()
}

fn descriptor() -> Session {
    Session {
        session_id: "session-abc".into(),
        topology_revision: 41,
    }
}

#[test]
fn hello_covers_every_wire_field_in_go_order() {
    let config = test_config("grpc://127.0.0.1:9090");
    let request = build_hello_request_at(
        &config,
        "0.1.0-dev",
        "shoes-0.2.8",
        41,
        1_700_000_000,
        "Zm9vYmFyLXRlc3Qtbm9uY2UtMjQ".into(),
    )
    .unwrap();

    assert_eq!(request.machine_id, "machine-1");
    assert_eq!(request.node_id, "node-1");
    assert_eq!(request.agent_version, "0.1.0-dev");
    assert_eq!(request.sing_box_version, "shoes-0.2.8");
    assert_eq!(request.timestamp_unix, 1_700_000_000);
    assert_eq!(request.topology_revision, 41);
    assert_eq!(
        request.signature,
        sign_hello(
            SECRET,
            &HelloFields {
                machine_id: request.machine_id.clone(),
                node_id: request.node_id.clone(),
                agent_version: request.agent_version.clone(),
                sing_box_version: request.sing_box_version.clone(),
                timestamp_unix: request.timestamp_unix,
                nonce: request.nonce.clone(),
                topology_revision: request.topology_revision,
            },
        )
        .unwrap()
    );
}

#[test]
fn every_authenticated_request_has_exactly_five_fresh_hmac_fields() {
    let config = test_config("grpc://127.0.0.1:9090");
    let authenticator = SessionAuthenticator::new(&config, &descriptor()).unwrap();

    let mut deterministic = Request::new(());
    authenticator
        .attach_at(&mut deterministic, 1_700_000_000, "fixed-nonce".into())
        .unwrap();
    assert_session_metadata(
        deterministic.metadata(),
        &SessionFields {
            machine_id: "machine-1".into(),
            session_id: "session-abc".into(),
            timestamp_unix: 1_700_000_000,
            nonce: "fixed-nonce".into(),
        },
    );

    let mut interceptor = authenticator.interceptor();
    let first = interceptor.call(Request::new(())).unwrap();
    let second = interceptor.call(Request::new(())).unwrap();
    for metadata in [first.metadata(), second.metadata()] {
        for key in AUTH_METADATA_KEYS {
            assert_eq!(metadata.get_all(key).iter().count(), 1, "{key}");
        }
    }
    assert_ne!(
        single(first.metadata(), METADATA_NONCE),
        single(second.metadata(), METADATA_NONCE),
        "a replayable nonce was reused across two RPCs"
    );
}

const AUTH_METADATA_KEYS: [&str; 5] = [
    METADATA_MACHINE_ID,
    METADATA_SESSION_ID,
    METADATA_TIMESTAMP_UNIX,
    METADATA_NONCE,
    METADATA_SIGNATURE,
];

fn assert_session_metadata(metadata: &MetadataMap, expected: &SessionFields) {
    assert_eq!(single(metadata, METADATA_MACHINE_ID), expected.machine_id);
    assert_eq!(single(metadata, METADATA_SESSION_ID), expected.session_id);
    assert_eq!(
        single(metadata, METADATA_TIMESTAMP_UNIX),
        expected.timestamp_unix.to_string()
    );
    assert_eq!(single(metadata, METADATA_NONCE), expected.nonce);
    assert_eq!(
        single(metadata, METADATA_SIGNATURE),
        sign_session(SECRET, expected).unwrap()
    );
}

fn single<'a>(metadata: &'a MetadataMap, key: &'static str) -> &'a str {
    let mut values = metadata.get_all(key).iter();
    let value = values.next().unwrap().to_str().unwrap();
    assert!(values.next().is_none(), "duplicate {key}");
    value
}

fn control_metadata(entries: &[(&'static str, &'static str)]) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    for (key, value) in entries {
        metadata.append(*key, MetadataValue::try_from(*value).unwrap());
    }
    metadata
}

#[test]
fn control_registration_headers_are_strict_and_digest_accepts_go_hex_syntax() {
    let valid = control_metadata(&[
        (CONTROL_READY_METADATA_KEY, "1"),
        (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST),
    ]);
    assert_eq!(validate_control_metadata(&valid).unwrap(), DIGEST);
    let uppercase = control_metadata(&[
        (CONTROL_READY_METADATA_KEY, "1"),
        (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, UPPERCASE_DIGEST),
    ]);
    assert_eq!(
        validate_control_metadata(&uppercase).unwrap(),
        UPPERCASE_DIGEST
    );

    let invalid_cases = [
        control_metadata(&[(CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST)]),
        control_metadata(&[
            (CONTROL_READY_METADATA_KEY, "0"),
            (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST),
        ]),
        control_metadata(&[
            (CONTROL_READY_METADATA_KEY, "1"),
            (CONTROL_READY_METADATA_KEY, "1"),
            (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST),
        ]),
        control_metadata(&[(CONTROL_READY_METADATA_KEY, "1")]),
        control_metadata(&[
            (CONTROL_READY_METADATA_KEY, "1"),
            (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, "AAAA"),
        ]),
        control_metadata(&[
            (CONTROL_READY_METADATA_KEY, "1"),
            (
                CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
                "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            ),
        ]),
        control_metadata(&[
            (CONTROL_READY_METADATA_KEY, "1"),
            (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST),
            (CONTROL_TOPOLOGY_DIGEST_METADATA_KEY, DIGEST),
        ]),
    ];
    for metadata in invalid_cases {
        assert!(validate_control_metadata(&metadata).is_err());
    }
}

#[test]
fn ready_ack_has_the_fixed_wire_identity_and_requires_converged_state() {
    let ack = control_ready_ack(DIGEST, 41).unwrap();
    assert_eq!(ack.command_id, "");
    assert_eq!(ack.machine_id, "");
    assert_eq!(ack.node_id, "");
    assert_eq!(ack.operation_id, "");
    assert_eq!(ack.idempotency_key, CONTROL_CLIENT_READY_KEY);
    assert_eq!(ack.status, ControlAckStatus::Applied as i32);
    assert_eq!(ack.message, DIGEST);
    assert_eq!(ack.revision, 41);

    assert!(control_ready_ack(DIGEST, 0).is_err());
    assert!(control_ready_ack("not-a-digest", 41).is_err());
}

#[derive(Debug)]
enum PanelEvent {
    Hello(HelloRequest),
    AuthenticatedRpc {
        method: &'static str,
        fields: SessionFields,
    },
    ControlMetadata(SessionFields),
    Ready(ControlAck),
}

#[derive(Clone)]
struct MockPanel {
    events: mpsc::UnboundedSender<PanelEvent>,
    digest: Arc<str>,
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
            .map_err(|error| Status::unauthenticated(format!("invalid hello fields: {error}")))?;
        if hello.signature != expected {
            return Err(Status::unauthenticated("invalid hello signature"));
        }
        self.events.send(PanelEvent::Hello(hello)).unwrap();
        Ok(Response::new(descriptor()))
    }
}

#[tonic::async_trait]
impl ControlService for MockPanel {
    type ControlStreamStream = ReceiverStream<Result<ControlCommand, Status>>;

    async fn control_stream(
        &self,
        request: Request<tonic::Streaming<ControlAck>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let fields = verify_incoming_session_metadata(request.metadata())?;
        self.events
            .send(PanelEvent::ControlMetadata(fields))
            .unwrap();

        let events = self.events.clone();
        let mut acknowledgements = request.into_inner();
        let (command_sender, command_receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            if let Ok(Some(ack)) = acknowledgements.message().await {
                let _ = events.send(PanelEvent::Ready(ack));
            }
            drop(command_sender);
        });

        let mut response = Response::new(ReceiverStream::new(command_receiver));
        response
            .metadata_mut()
            .insert(CONTROL_READY_METADATA_KEY, MetadataValue::from_static("1"));
        response.metadata_mut().insert(
            CONTROL_TOPOLOGY_DIGEST_METADATA_KEY,
            MetadataValue::try_from(self.digest.as_ref()).unwrap(),
        );
        Ok(response)
    }
}

#[tonic::async_trait]
impl ConfigService for MockPanel {
    async fn get_machine_config(
        &self,
        request: Request<GetMachineConfigRequest>,
    ) -> Result<Response<MachineConfig>, Status> {
        let fields = verify_incoming_session_metadata(request.metadata())?;
        self.events
            .send(PanelEvent::AuthenticatedRpc {
                method: "GetMachineConfig",
                fields,
            })
            .unwrap();
        Ok(Response::new(MachineConfig::default()))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let fields = verify_incoming_session_metadata(request.metadata())?;
        self.events
            .send(PanelEvent::AuthenticatedRpc {
                method: "ListUsers",
                fields,
            })
            .unwrap();
        Ok(Response::new(ListUsersResponse::default()))
    }
}

fn verify_incoming_session_metadata(metadata: &MetadataMap) -> Result<SessionFields, Status> {
    let value = |key| {
        single_ascii_metadata(metadata, key)
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
    let signature = value(METADATA_SIGNATURE)?;
    if signature != sign_session(SECRET, &fields).unwrap() {
        return Err(Status::unauthenticated("invalid session signature"));
    }
    Ok(fields)
}

struct RunningPanel {
    address: std::net::SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl RunningPanel {
    async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), self.task)
            .await
            .expect("mock panel did not stop")
            .expect("mock panel task panicked");
    }
}

async fn spawn_panel(panel: MockPanel, identity: Option<Identity>) -> RunningPanel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let shutdown = CancellationToken::new();
    let shutdown_task = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut server = Server::builder();
        if let Some(identity) = identity {
            server = server
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap();
        }
        server
            .add_service(AuthServiceServer::new(panel.clone()))
            .add_service(ConfigServiceServer::new(panel.clone()))
            .add_service(ControlServiceServer::new(panel))
            .serve_with_incoming_shutdown(incoming, shutdown_task.cancelled_owned())
            .await
            .unwrap();
    });
    RunningPanel {
        address,
        shutdown,
        task,
    }
}

fn mock_panel() -> (MockPanel, mpsc::UnboundedReceiver<PanelEvent>) {
    let (events, receiver) = mpsc::unbounded_channel();
    (
        MockPanel {
            events,
            digest: Arc::from(DIGEST),
        },
        receiver,
    )
}

async fn next_event(events: &mut mpsc::UnboundedReceiver<PanelEvent>) -> PanelEvent {
    tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .expect("panel event timed out")
        .expect("panel event channel closed")
}

#[tokio::test]
async fn plaintext_tonic_mock_verifies_hello_stream_metadata_and_ready_ack() {
    let (panel, mut events) = mock_panel();
    let running = spawn_panel(panel, None).await;
    let client = PanelClient::new(
        test_config(&format!("grpc://{}", running.address)),
        "0.1.0-dev",
        "shoes-0.2.8",
    );

    let channel = client.dial().await.unwrap();
    let session = client.authenticate(channel, 41).await.unwrap();
    let mut config_client = ConfigServiceClient::new(session.authenticated_channel());
    config_client
        .get_machine_config(GetMachineConfigRequest {
            machine_id: "machine-1".into(),
            session_id: "session-abc".into(),
        })
        .await
        .unwrap();
    config_client
        .list_users(ListUsersRequest {
            machine_id: "machine-1".into(),
            session_id: "session-abc".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let control = session.open_control_stream().await.unwrap();
    assert_eq!(control.panel_digest(), DIGEST);
    control.confirm_ready(DIGEST, 41).await.unwrap();

    match next_event(&mut events).await {
        PanelEvent::Hello(hello) => {
            assert_eq!(hello.machine_id, "machine-1");
            assert_eq!(hello.node_id, "node-1");
            assert_eq!(hello.topology_revision, 41);
            assert_eq!(hello.nonce.len(), 32);
        }
        event => panic!("unexpected first event: {event:?}"),
    }
    let first_rpc_nonce = match next_event(&mut events).await {
        PanelEvent::AuthenticatedRpc { method, fields } => {
            assert_eq!(method, "GetMachineConfig");
            assert_eq!(fields.machine_id, "machine-1");
            assert_eq!(fields.session_id, "session-abc");
            fields.nonce
        }
        event => panic!("unexpected second event: {event:?}"),
    };
    let second_rpc_nonce = match next_event(&mut events).await {
        PanelEvent::AuthenticatedRpc { method, fields } => {
            assert_eq!(method, "ListUsers");
            assert_eq!(fields.machine_id, "machine-1");
            assert_eq!(fields.session_id, "session-abc");
            fields.nonce
        }
        event => panic!("unexpected third event: {event:?}"),
    };
    assert_ne!(first_rpc_nonce, second_rpc_nonce);

    match next_event(&mut events).await {
        PanelEvent::ControlMetadata(fields) => {
            assert_eq!(fields.machine_id, "machine-1");
            assert_eq!(fields.session_id, "session-abc");
            assert_eq!(fields.nonce.len(), 32);
            assert_ne!(fields.nonce, first_rpc_nonce);
            assert_ne!(fields.nonce, second_rpc_nonce);
        }
        event => panic!("unexpected fourth event: {event:?}"),
    }
    match next_event(&mut events).await {
        PanelEvent::Ready(ack) => {
            assert_eq!(ack.idempotency_key, CONTROL_CLIENT_READY_KEY);
            assert_eq!(ack.status, ControlAckStatus::Applied as i32);
            assert_eq!(ack.message, DIGEST);
            assert_eq!(ack.revision, 41);
        }
        event => panic!("unexpected fifth event: {event:?}"),
    }

    drop(control);
    running.stop().await;
}

#[tokio::test]
async fn tls_supports_explicit_ca_server_name_and_insecure_escape_hatch() {
    install_crypto_provider();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["panel.test".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let (panel, _events) = mock_panel();
    let running = spawn_panel(panel, Some(Identity::from_pem(cert_pem.clone(), key_pem))).await;

    let temporary = tempfile::tempdir().unwrap();
    let ca_path = temporary.path().join("panel-ca.pem");
    std::fs::write(&ca_path, &cert_pem).unwrap();

    let mut verified = test_config(&format!("grpcs://{}", running.address));
    verified.panel_grpc_server_name = "panel.test".into();
    verified.ca_cert_path = ca_path.to_string_lossy().into_owned();
    let verified = PanelClient::new(verified, "agent", "shoes");
    let channel = verified.dial().await.unwrap();
    verified.authenticate(channel, 41).await.unwrap();

    let mut insecure = test_config(&format!("grpcs://{}", running.address));
    insecure.panel_grpc_server_name = "untrusted-name.invalid".into();
    insecure.tls_insecure_skip_verify = true;
    let insecure = PanelClient::new(insecure, "agent", "shoes");
    let channel = insecure.dial().await.unwrap();
    insecure.authenticate(channel, 41).await.unwrap();

    running.stop().await;
}

fn fast_policy() -> RetryPolicy {
    RetryPolicy {
        initial: Duration::from_millis(2),
        max: Duration::from_millis(4),
        stable_after: Duration::from_millis(50),
    }
}

#[tokio::test]
async fn auxiliary_stream_retries_transient_failures_then_stops_on_success() {
    let parent = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut group = StreamGroup::with_policy(&parent, fast_policy(), Duration::from_millis(20));
    let attempts_task = attempts.clone();
    group.start_auxiliary("traffic", move |_| {
        let attempts = attempts_task.clone();
        async move {
            if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(SessionError::Rpc(Status::unavailable("retry")))
            } else {
                Ok(())
            }
        }
    });

    tokio::time::timeout(Duration::from_millis(100), group.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn auxiliary_unauthenticated_and_any_control_exit_end_the_session() {
    let parent = CancellationToken::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut auxiliary = StreamGroup::with_policy(&parent, fast_policy(), Duration::from_millis(20));
    let calls_task = calls.clone();
    auxiliary.start_auxiliary("telemetry", move |_| {
        calls_task.fetch_add(1, Ordering::SeqCst);
        async { Err(SessionError::Rpc(Status::unauthenticated("expired"))) }
    });
    let error = auxiliary.wait().await.unwrap_err();
    assert!(error.is_unauthenticated());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "must not retry auth failure"
    );

    let parent = CancellationToken::new();
    let mut control = StreamGroup::with_policy(&parent, fast_policy(), Duration::from_millis(20));
    control.start_session_critical("control", |_| async { Ok(()) });
    assert!(matches!(
        control.wait().await.unwrap_err(),
        SessionError::CriticalStreamEnded(name) if name == "control"
    ));
}

#[tokio::test]
async fn cancellation_is_bounded_even_when_a_stream_ignores_its_token() {
    let parent = CancellationToken::new();
    let mut group = StreamGroup::with_policy(&parent, fast_policy(), Duration::from_millis(10));
    group.start_session_critical("stuck", |_| async {
        std::future::pending::<Result<(), SessionError>>().await
    });
    parent.cancel();

    tokio::time::timeout(Duration::from_millis(100), group.wait())
        .await
        .expect("shutdown grace was not bounded")
        .unwrap();
}

#[tokio::test]
async fn complete_session_attempts_reconnect_with_the_same_cancellation_domain() {
    let shutdown = CancellationToken::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_task = attempts.clone();
    let shutdown_task = shutdown.clone();
    run_panel_sessions_with_policy(
        shutdown,
        move |attempt_cancel| {
            let attempts = attempts_task.clone();
            let shutdown = shutdown_task.clone();
            async move {
                assert!(!attempt_cancel.is_cancelled());
                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt == 3 {
                    shutdown.cancel();
                }
                Err(SessionError::Rpc(Status::unavailable("reconnect")))
            }
        },
        fast_policy(),
    )
    .await
    .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[test]
fn configured_timeouts_and_backoff_match_the_go_contract() {
    assert_eq!(PANEL_DIAL_TIMEOUT, Duration::from_secs(10));
    assert_eq!(PANEL_REQUEST_TIMEOUT, Duration::from_secs(10));
    assert_eq!(SESSION_BACKOFF_INITIAL, Duration::from_secs(1));
    assert_eq!(SESSION_BACKOFF_MAX, Duration::from_secs(30));
    assert_eq!(STABLE_SESSION_RESET_AFTER, Duration::from_secs(60));
    assert_eq!(SHUTDOWN_GRACE_PERIOD, Duration::from_secs(5));
}

#[test]
fn invalid_explicit_ca_fails_before_dial_even_when_verification_is_disabled() {
    let temporary = tempfile::tempdir().unwrap();
    let ca_path = temporary.path().join("bad.pem");
    std::fs::write(&ca_path, b"definitely not a certificate").unwrap();
    let mut config = test_config("grpcs://127.0.0.1:12345");
    config.ca_cert_path = ca_path.to_string_lossy().into_owned();
    config.tls_insecure_skip_verify = true;
    let error = PanelClient::new(config, "agent", "shoes")
        .endpoint()
        .unwrap_err();
    assert!(matches!(error, SessionError::InvalidCa { .. }));
}

#[test]
fn pem_wrapped_invalid_der_is_rejected_but_valid_blocks_are_kept_best_effort() {
    install_crypto_provider();
    const INVALID_DER_PEM: &str = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let temporary = tempfile::tempdir().unwrap();
    let invalid_path = temporary.path().join("invalid-der.pem");
    std::fs::write(&invalid_path, INVALID_DER_PEM).unwrap();
    assert!(matches!(
        load_optional_ca(invalid_path.to_str().unwrap()),
        Err(SessionError::InvalidCa { .. })
    ));

    let CertifiedKey { cert, .. } = generate_simple_self_signed(vec!["panel.test".into()]).unwrap();
    let mixed_path = temporary.path().join("mixed.pem");
    std::fs::write(&mixed_path, format!("{INVALID_DER_PEM}{}", cert.pem())).unwrap();
    let anchors = load_optional_ca(mixed_path.to_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(anchors.len(), 1);
}

#[test]
fn explicit_private_ca_remains_usable_when_native_root_set_is_empty() {
    install_crypto_provider();
    let CertifiedKey { cert, .. } = generate_simple_self_signed(vec!["panel.test".into()]).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let ca_path = temporary.path().join("private-ca.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();
    let ca = load_optional_ca(ca_path.to_str().unwrap())
        .unwrap()
        .unwrap();

    let native = trust_anchors(Vec::<CertificateDer<'static>>::new());
    assert!(native.is_empty());
    let tls = ClientTlsConfig::new()
        .domain_name("panel.test")
        .trust_anchors(native)
        .trust_anchors(ca);
    Endpoint::from_static("https://127.0.0.1:443")
        .tls_config(tls)
        .expect("an explicit CA must not require native roots");
}

#[test]
fn error_classification_finds_unauthenticated_through_stream_context() {
    let error = SessionError::stream(
        "traffic",
        SessionError::Rpc(Status::new(Code::Unauthenticated, "expired")),
    );
    assert!(error.is_unauthenticated());
    assert!(!SessionError::Rpc(Status::unavailable("retry")).is_unauthenticated());
}

#[test]
fn panel_config_is_shared_immutably_by_client() {
    let config = test_config("grpc://127.0.0.1:9090");
    let client = PanelClient::new(config.clone(), "agent", "shoes");
    assert_eq!(client.config(), &config);
    let cloned = client.clone();
    assert!(Arc::ptr_eq(&client.config, &cloned.config));
}

#[test]
fn scoped_ipv6_panel_address_can_be_lowered_to_a_tonic_endpoint() {
    for (endpoint, address) in [
        ("grpc://[fe80::1%25eth0]:9090", "[fe80::1%eth0]:9090"),
        ("grpc://[fe80::1%253]:9090", "[fe80::1%3]:9090"),
        ("grpcs://[fe80::1%25eth0]:9443", "[fe80::1%eth0]:9443"),
    ] {
        let config = test_config(endpoint);
        assert_eq!(config.panel_grpc_address, address);
        PanelClient::new(config, "agent", "shoes")
            .endpoint()
            .expect("a Go-compatible scoped IPv6 address must form a tonic endpoint");
    }
}
