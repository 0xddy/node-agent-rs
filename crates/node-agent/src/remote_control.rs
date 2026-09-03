//! Remote operations carried over ACP's bidirectional remote-control stream.
//!
//! The controller is process-scoped, not session-scoped: reload exclusion,
//! the last reload result, and periodic-pull settings survive a gRPC reconnect.
//! Concrete topology/fetch/runtime wiring is injected through three small traits
//! so this protocol state machine does not depend on a particular topology
//! manager implementation.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use acp_proto::remote_control_request::Command;
use acp_proto::remote_control_response::Payload;
use acp_proto::remote_control_service_client::RemoteControlServiceClient;
use acp_proto::{
    LoadedUsersPage, ReloadSingBoxOutcome, ReloadSingBoxResult, RemoteControlRequest,
    RemoteControlResponse, RemoteControlResponseStatus, RemoteControlState, SingBoxConfigChunk,
    SyncUsersResult, UserCredential as ProtoUserCredential, UserStatus,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Notify, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use tonic::transport::Channel;

use crate::runtime::NodeRuntime;
use crate::session::{SessionAuthenticator, SessionError};
use crate::topology::UserCredential;

mod adapter;

pub use adapter::{PanelRemoteFetcher, RuntimeRemoteView};

pub const REMOTE_RESPONSE_QUEUE_SIZE: usize = 64;
const MAX_CONCURRENT_REMOTE_REQUESTS: usize = 16;
const RELOAD_PROGRESS_SEND_TIMEOUT: Duration = Duration::from_secs(1);
pub const REMOTE_CONFIG_CHUNK_SIZE: usize = 64 * 1024;
pub const REMOTE_RELOAD_TIMEOUT: Duration = Duration::from_secs(2 * 60);
pub const REMOTE_SYNC_USERS_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_LOADED_USERS_PAGE_SIZE: u32 = 100;
pub const MAX_LOADED_USERS_PAGE_SIZE: u32 = 500;

pub const RELOAD_STAGE_PULL_CONFIGURATION: &str = "pull_configuration";
pub const RELOAD_STAGE_PULL_USERS: &str = "pull_users";
pub const RELOAD_STAGE_BUILD_CONFIGURATION: &str = "build_configuration";
pub const RELOAD_STAGE_CONFIGURE_PORT_HOPPING: &str = "configure_port_hopping";
pub const RELOAD_STAGE_START_INSTANCE: &str = "start_instance";
pub const RELOAD_STAGE_COMPLETED: &str = "completed";
pub const RELOAD_STAGE_ROLLBACK: &str = "rollback";
pub const RELOAD_STAGE_BUSY: &str = "busy";

const CONTEXT_DEADLINE_EXCEEDED: &str = "context deadline exceeded";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOperationError(String);

impl RemoteOperationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for RemoteOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RemoteOperationError {}

impl From<String> for RemoteOperationError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<&str> for RemoteOperationError {
    fn from(message: &str) -> Self {
        Self(message.to_string())
    }
}

/// Read-only topology state needed by STATUS, LOADED_USERS and SYNC_USERS.
#[async_trait]
pub trait RemoteTopology: Send + Sync {
    async fn loaded_users(
        &self,
        node_id: &str,
    ) -> Result<Vec<UserCredential>, RemoteOperationError>;

    /// Returns the total user count and a page. Implementations with shared
    /// storage can override this to copy only the requested credentials.
    async fn loaded_users_page(
        &self,
        node_id: &str,
        offset: u64,
        limit: usize,
    ) -> Result<(usize, Vec<UserCredential>), RemoteOperationError> {
        let users = self.loaded_users(node_id).await?;
        let total = users.len();
        let start = offset.min(total as u64) as usize;
        Ok((total, users.into_iter().skip(start).take(limit).collect()))
    }
}

#[async_trait]
impl RemoteTopology for crate::topology::manager::TopologyManager {
    async fn loaded_users(
        &self,
        node_id: &str,
    ) -> Result<Vec<UserCredential>, RemoteOperationError> {
        crate::topology::manager::TopologyManager::loaded_users(self, node_id)
            .await
            .map_err(|error| RemoteOperationError::new(error.to_string()))
    }

    async fn loaded_users_page(
        &self,
        node_id: &str,
        offset: u64,
        limit: usize,
    ) -> Result<(usize, Vec<UserCredential>), RemoteOperationError> {
        crate::topology::manager::TopologyManager::loaded_users_page(self, node_id, offset, limit)
            .await
            .map_err(|error| RemoteOperationError::new(error.to_string()))
    }
}

/// The diagnostic snapshot returned by SING_BOX_CONFIG.
pub trait RemoteRuntime: Send + Sync {
    fn current_config(&self) -> Vec<u8>;
}

impl<T> RemoteRuntime for T
where
    T: NodeRuntime + ?Sized,
{
    fn current_config(&self) -> Vec<u8> {
        NodeRuntime::current_config(self)
    }
}

/// Result of one authoritative panel user refresh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserSyncChanges {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub applied: bool,
}

/// Topology/runtime result of a forced reload. The adapter is responsible for
/// the same rollback classification as the topology transaction layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReloadResult {
    pub outcome: ReloadSingBoxOutcome,
    pub stage: String,
    pub message: String,
    pub topology_revision: u64,
    pub config_sha256: String,
    pub loaded_user_count: usize,
}

/// The five non-terminal stages emitted by the Go reload pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadProgressStage {
    PullConfiguration,
    PullUsers,
    BuildConfiguration,
    ConfigurePortHopping,
    StartInstance,
}

impl ReloadProgressStage {
    pub const ALL: [Self; 5] = [
        Self::PullConfiguration,
        Self::PullUsers,
        Self::BuildConfiguration,
        Self::ConfigurePortHopping,
        Self::StartInstance,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PullConfiguration => RELOAD_STAGE_PULL_CONFIGURATION,
            Self::PullUsers => RELOAD_STAGE_PULL_USERS,
            Self::BuildConfiguration => RELOAD_STAGE_BUILD_CONFIGURATION,
            Self::ConfigurePortHopping => RELOAD_STAGE_CONFIGURE_PORT_HOPPING,
            Self::StartInstance => RELOAD_STAGE_START_INSTANCE,
        }
    }
}

/// Fetch/application boundary. Implementations may own the panel ConfigService,
/// topology transaction manager and port-hopping adapter. The supplied token
/// cancels panel reads only. Once an implementation starts a local topology
/// transaction it must ignore that token and drive the transaction to a
/// terminal result; callers likewise keep awaiting the future after signalling
/// cancellation.
#[async_trait]
pub trait RemoteFetcher: Send + Sync {
    async fn reload(
        &self,
        cancel: CancellationToken,
        progress: ReloadProgressReporter,
    ) -> Result<RemoteReloadResult, RemoteOperationError>;

    async fn sync_users(
        &self,
        cancel: CancellationToken,
        node_id: &str,
    ) -> Result<UserSyncChanges, RemoteOperationError>;
}

#[derive(Clone)]
pub struct RemoteControlDependencies {
    topology: Arc<dyn RemoteTopology>,
    runtime: Arc<dyn RemoteRuntime>,
    fetcher: Arc<dyn RemoteFetcher>,
}

impl RemoteControlDependencies {
    pub fn new(
        topology: Arc<dyn RemoteTopology>,
        runtime: Arc<dyn RemoteRuntime>,
        fetcher: Arc<dyn RemoteFetcher>,
    ) -> Self {
        Self {
            topology,
            runtime,
            fetcher,
        }
    }

    pub fn topology(&self) -> &Arc<dyn RemoteTopology> {
        &self.topology
    }

    pub fn runtime(&self) -> &Arc<dyn RemoteRuntime> {
        &self.runtime
    }

    pub fn fetcher(&self) -> &Arc<dyn RemoteFetcher> {
        &self.fetcher
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteControlTarget {
    pub machine_id: String,
    pub node_id: String,
}

#[derive(Clone)]
pub struct RemoteController {
    inner: Arc<ControllerInner>,
}

struct ControllerInner {
    state: Mutex<ControllerState>,
    reload_gate: Arc<tokio::sync::Mutex<()>>,
    request_slots: Arc<Semaphore>,
    periodic_wake: Notify,
}

#[derive(Default)]
struct ControllerState {
    reload_in_progress: bool,
    reload_operation: String,
    reload_stage: String,
    last_reload: Option<ReloadSingBoxResult>,
    periodic_enabled: bool,
    periodic_interval: Duration,
    periodic_last_attempt: Option<SystemTime>,
    periodic_last_success: Option<SystemTime>,
    periodic_next_attempt: Option<SystemTime>,
    periodic_last_error: String,
    periodic_attempt: Option<CancellationToken>,
}

impl Default for RemoteController {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                state: Mutex::new(ControllerState::default()),
                reload_gate: Arc::new(tokio::sync::Mutex::new(())),
                request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_REMOTE_REQUESTS)),
                periodic_wake: Notify::new(),
            }),
        }
    }

    pub fn snapshot(&self) -> RemoteControlState {
        snapshot_state(&self.inner.state.lock().expect("remote state poisoned"))
    }

    fn begin_reload(&self, operation_id: &str) -> Option<ReloadLease> {
        let guard = self.inner.reload_gate.clone().try_lock_owned().ok()?;
        let mut state = self.inner.state.lock().expect("remote state poisoned");
        state.reload_in_progress = true;
        state.reload_operation = operation_id.to_string();
        state.reload_stage = RELOAD_STAGE_PULL_CONFIGURATION.to_string();
        drop(state);
        Some(ReloadLease {
            controller: self.clone(),
            guard: Some(guard),
            finished: false,
        })
    }

    fn set_reload_stage(&self, stage: &str) {
        self.inner
            .state
            .lock()
            .expect("remote state poisoned")
            .reload_stage = stage.to_string();
    }

    fn reload_stage(&self) -> String {
        self.inner
            .state
            .lock()
            .expect("remote state poisoned")
            .reload_stage
            .clone()
    }

    pub fn set_periodic(&self, enabled: bool, interval: Duration) -> RemoteControlState {
        let mut state = self.inner.state.lock().expect("remote state poisoned");
        if let Some(attempt) = &state.periodic_attempt {
            attempt.cancel();
        }
        state.periodic_enabled = enabled;
        if enabled {
            state.periodic_interval = interval;
            state.periodic_next_attempt = Some(SystemTime::now());
            state.periodic_last_error.clear();
        } else {
            state.periodic_interval = Duration::ZERO;
            state.periodic_next_attempt = None;
        }
        let snapshot = snapshot_state(&state);
        drop(state);
        self.inner.periodic_wake.notify_waiters();
        snapshot
    }

    fn periodic_schedule(&self) -> PeriodicSchedule {
        let state = self.inner.state.lock().expect("remote state poisoned");
        PeriodicSchedule {
            enabled: state.periodic_enabled,
            next: state.periodic_next_attempt,
        }
    }

    fn begin_periodic_attempt(&self, parent: &CancellationToken) -> Option<PeriodicAttempt> {
        let mut state = self.inner.state.lock().expect("remote state poisoned");
        if !state.periodic_enabled || state.periodic_attempt.is_some() {
            return None;
        }
        let attempt = parent.child_token();
        state.periodic_attempt = Some(attempt.clone());
        state.periodic_last_attempt = Some(SystemTime::now());
        state.periodic_next_attempt = None;
        Some(PeriodicAttempt {
            controller: self.clone(),
            cancel: attempt,
            finished: false,
        })
    }

    fn finish_periodic_attempt(&self, error: Option<&RemoteOperationError>, was_cancelled: bool) {
        let mut state = self.inner.state.lock().expect("remote state poisoned");
        state.periodic_attempt = None;
        if error.is_none() {
            state.periodic_last_success = Some(SystemTime::now());
            state.periodic_last_error.clear();
        } else if !state.periodic_enabled || was_cancelled {
            state.periodic_last_error.clear();
        } else if let Some(error) = error {
            state.periodic_last_error = error.to_string();
        }
        if state.periodic_enabled {
            state.periodic_next_attempt = Some(SystemTime::now() + state.periodic_interval);
        }
        drop(state);
        self.inner.periodic_wake.notify_waiters();
    }
}

/// A retired stream may still be completing its local transaction. Keep its
/// attempt registered until that owner finishes, and wake replacement streams
/// without polling. Unwinding must not leave the process-scoped slot occupied.
struct PeriodicAttempt {
    controller: RemoteController,
    cancel: CancellationToken,
    finished: bool,
}

impl PeriodicAttempt {
    fn finish(mut self, error: Option<&RemoteOperationError>, was_cancelled: bool) {
        self.controller
            .finish_periodic_attempt(error, was_cancelled);
        self.finished = true;
    }
}

impl Drop for PeriodicAttempt {
    fn drop(&mut self) {
        if !self.finished {
            self.cancel.cancel();
            self.controller.finish_periodic_attempt(
                Some(&RemoteOperationError::new(
                    "periodic user pull task stopped",
                )),
                true,
            );
        }
    }
}

fn snapshot_state(state: &ControllerState) -> RemoteControlState {
    RemoteControlState {
        reload_in_progress: state.reload_in_progress,
        reload_operation_id: state.reload_operation.clone(),
        reload_stage: state.reload_stage.clone(),
        last_reload: state.last_reload.clone(),
        periodic_user_pull_enabled: state.periodic_enabled,
        periodic_user_pull_interval_minutes: duration_minutes(state.periodic_interval),
        periodic_user_pull_last_attempt_at_unix_milli: unix_millis(state.periodic_last_attempt),
        periodic_user_pull_last_success_at_unix_milli: unix_millis(state.periodic_last_success),
        periodic_user_pull_next_attempt_at_unix_milli: unix_millis(state.periodic_next_attempt),
        periodic_user_pull_last_error: state.periodic_last_error.clone(),
    }
}

fn duration_minutes(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs() / 60).unwrap_or(u32::MAX)
}

fn unix_millis(value: Option<SystemTime>) -> i64 {
    let Some(value) = value else {
        return 0;
    };
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

struct ReloadLease {
    controller: RemoteController,
    guard: Option<OwnedMutexGuard<()>>,
    finished: bool,
}

impl ReloadLease {
    fn finish(mut self, result: &ReloadSingBoxResult) {
        let mut state = self
            .controller
            .inner
            .state
            .lock()
            .expect("remote state poisoned");
        state.reload_in_progress = false;
        state.reload_operation.clear();
        state.reload_stage.clear();
        state.last_reload = Some(result.clone());
        drop(state);
        self.finished = true;
        self.guard.take();
    }
}

impl Drop for ReloadLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = self
            .controller
            .inner
            .state
            .lock()
            .expect("remote state poisoned");
        state.reload_in_progress = false;
        state.reload_operation.clear();
        state.reload_stage.clear();
    }
}

#[derive(Clone)]
struct ResponseSink {
    sender: mpsc::Sender<RemoteControlResponse>,
    stream_cancel: CancellationToken,
}

impl ResponseSink {
    async fn send(&self, request_id: &str, mut response: RemoteControlResponse) -> bool {
        response.request_id = request_id.to_string();
        tokio::select! {
            result = self.sender.send(response) => {
                result.is_ok()
            }
            () = self.stream_cancel.cancelled() => false,
        }
    }
}

#[derive(Clone)]
pub struct ReloadProgressReporter {
    controller: RemoteController,
    sink: ResponseSink,
    request_id: Arc<str>,
}

impl ReloadProgressReporter {
    pub async fn report(&self, stage: ReloadProgressStage) -> bool {
        let stage = stage.as_str();
        self.controller.set_reload_stage(stage);
        // The topology transaction awaits progress while holding its operation
        // lock. A slow response consumer must not retain that lock indefinitely,
        // including between port configuration and instance replacement. Retire
        // only this remote stream; its owned transaction still reaches a terminal
        // state and publishes the result through the process-scoped controller.
        match tokio::time::timeout(
            RELOAD_PROGRESS_SEND_TIMEOUT,
            self.sink.send(
                &self.request_id,
                response(RemoteControlResponseStatus::Progress, stage, stage, None),
            ),
        )
        .await
        {
            Ok(sent) => sent,
            Err(_) => {
                self.sink.stream_cancel.cancel();
                false
            }
        }
    }
}

#[derive(Clone, Copy)]
struct PeriodicSchedule {
    enabled: bool,
    next: Option<SystemTime>,
}

/// Handles one decoded request. Calls for different request IDs may execute
/// concurrently; each call preserves ordering among its own progress/chunk/final
/// responses by awaiting the shared bounded queue.
pub async fn handle_remote_control_request(
    stream_cancel: CancellationToken,
    target: RemoteControlTarget,
    dependencies: RemoteControlDependencies,
    controller: RemoteController,
    request: RemoteControlRequest,
    responses: mpsc::Sender<RemoteControlResponse>,
) {
    if request.request_id.is_empty() {
        return;
    }
    let request_id = request.request_id;
    let sink = ResponseSink {
        sender: responses,
        stream_cancel: stream_cancel.clone(),
    };

    match request.command {
        Some(Command::Status(_)) => {
            sink.send(
                &request_id,
                response(
                    RemoteControlResponseStatus::Completed,
                    "",
                    "remote control state loaded",
                    Some(Payload::ControlState(controller.snapshot())),
                ),
            )
            .await;
        }
        Some(Command::ReloadSingBox(_)) => {
            handle_reload(request_id, dependencies, controller, sink).await;
        }
        Some(Command::LoadedUsers(page)) => {
            handle_loaded_users(
                &request_id,
                &target,
                &dependencies,
                page.page,
                page.page_size,
                &sink,
            )
            .await;
        }
        Some(Command::SyncUsers(_)) => {
            handle_sync_users(&request_id, stream_cancel, &target, &dependencies, &sink).await;
        }
        Some(Command::SingBoxConfig(_)) => {
            handle_current_config(&request_id, &dependencies, &sink).await;
        }
        Some(Command::PeriodicUserPull(setting)) => {
            if setting.enabled && !(1..=60).contains(&setting.interval_minutes) {
                send_failure(
                    &sink,
                    &request_id,
                    "periodic_user_pull",
                    "interval_minutes must be between 1 and 60",
                )
                .await;
                return;
            }
            let state = controller.set_periodic(
                setting.enabled,
                Duration::from_secs(u64::from(setting.interval_minutes) * 60),
            );
            sink.send(
                &request_id,
                response(
                    RemoteControlResponseStatus::Completed,
                    "",
                    "periodic user pull setting updated",
                    Some(Payload::ControlState(state)),
                ),
            )
            .await;
        }
        None => {
            send_failure(
                &sink,
                &request_id,
                "request",
                "remote control command is required",
            )
            .await;
        }
    }
}

async fn handle_loaded_users(
    request_id: &str,
    target: &RemoteControlTarget,
    dependencies: &RemoteControlDependencies,
    requested_page: u32,
    requested_page_size: u32,
    sink: &ResponseSink,
) {
    let page = requested_page.max(1);
    let page_size = if (1..=MAX_LOADED_USERS_PAGE_SIZE).contains(&requested_page_size) {
        requested_page_size
    } else {
        DEFAULT_LOADED_USERS_PAGE_SIZE
    };
    let offset = u64::from(page - 1).saturating_mul(u64::from(page_size));
    let (total, users) = match dependencies
        .topology
        .loaded_users_page(&target.node_id, offset, page_size as usize)
        .await
    {
        Ok(page) => page,
        Err(error) => {
            send_failure(sink, request_id, "loaded_users", &error.to_string()).await;
            return;
        }
    };
    let items = users.into_iter().map(remote_user_credential).collect();
    sink.send(
        request_id,
        response(
            RemoteControlResponseStatus::Completed,
            "",
            "loaded users returned",
            Some(Payload::LoadedUsers(LoadedUsersPage {
                users: items,
                page,
                page_size,
                total_size: total as u32,
            })),
        ),
    )
    .await;
}

async fn handle_current_config(
    request_id: &str,
    dependencies: &RemoteControlDependencies,
    sink: &ResponseSink,
) {
    let config = dependencies.runtime.current_config();
    if config.is_empty() {
        send_failure(
            sink,
            request_id,
            "sing_box_config",
            "sing-box runtime has no active configuration",
        )
        .await;
        return;
    }
    let checksum = lower_hex(&Sha256::digest(&config));
    let mut sequence = 0u32;
    for chunk in config.chunks(REMOTE_CONFIG_CHUNK_SIZE) {
        if !sink
            .send(
                request_id,
                response(
                    RemoteControlResponseStatus::Progress,
                    "sing_box_config",
                    "",
                    Some(Payload::SingBoxConfig(SingBoxConfigChunk {
                        sequence,
                        data: chunk.to_vec(),
                        eof: false,
                        total_bytes: 0,
                        sha256: String::new(),
                    })),
                ),
            )
            .await
        {
            return;
        }
        sequence = sequence.saturating_add(1);
    }
    sink.send(
        request_id,
        response(
            RemoteControlResponseStatus::Completed,
            "sing_box_config",
            "current sing-box configuration returned",
            Some(Payload::SingBoxConfig(SingBoxConfigChunk {
                sequence,
                data: Vec::new(),
                eof: true,
                total_bytes: config.len() as u64,
                sha256: checksum,
            })),
        ),
    )
    .await;
}

async fn handle_sync_users(
    request_id: &str,
    stream_cancel: CancellationToken,
    target: &RemoteControlTarget,
    dependencies: &RemoteControlDependencies,
    sink: &ResponseSink,
) {
    let operation_cancel = stream_cancel.child_token();
    let operation = dependencies
        .fetcher
        .sync_users(operation_cancel.clone(), &target.node_id);
    tokio::pin!(operation);
    let result = tokio::select! {
        () = stream_cancel.cancelled() => {
            operation_cancel.cancel();
            // A panel read should now return promptly. If the fetcher already
            // crossed into its owned local transaction, keep this request task
            // alive until runtime and published topology have converged.
            let _ = operation.await;
            return;
        }
        () = tokio::time::sleep(REMOTE_SYNC_USERS_TIMEOUT) => {
            operation_cancel.cancel();
            deadline_result(operation.await)
        }
        result = &mut operation => result,
    };
    let changes = match result {
        Ok(changes) => changes,
        Err(error) => {
            send_failure(sink, request_id, "sync_users", &error.to_string()).await;
            return;
        }
    };
    let users = match dependencies.topology.loaded_users(&target.node_id).await {
        Ok(users) => users,
        Err(error) => {
            send_failure(sink, request_id, "sync_users", &error.to_string()).await;
            return;
        }
    };
    sink.send(
        request_id,
        response(
            RemoteControlResponseStatus::Completed,
            "sync_users",
            "node users synchronized from panel",
            Some(Payload::SyncUsersResult(SyncUsersResult {
                added_count: changes.added as u32,
                updated_count: changes.updated as u32,
                deleted_count: changes.deleted as u32,
                applied: changes.applied,
                loaded_user_count: users.len() as u32,
                completed_at_unix_milli: unix_millis(Some(SystemTime::now())),
            })),
        ),
    )
    .await;
}

async fn handle_reload(
    operation_id: String,
    dependencies: RemoteControlDependencies,
    controller: RemoteController,
    sink: ResponseSink,
) {
    let started_at = Instant::now();
    let Some(lease) = controller.begin_reload(&operation_id) else {
        let result = ReloadSingBoxResult {
            operation_id: operation_id.clone(),
            outcome: ReloadSingBoxOutcome::RejectedBusy as i32,
            stage: RELOAD_STAGE_BUSY.to_string(),
            message: "another sing-box reload is already running".to_string(),
            topology_revision: 0,
            config_sha256: String::new(),
            loaded_user_count: 0,
            duration_millis: 0,
            completed_at_unix_milli: unix_millis(Some(SystemTime::now())),
        };
        let message = result.message.clone();
        sink.send(
            &operation_id,
            response(
                RemoteControlResponseStatus::Failed,
                RELOAD_STAGE_BUSY,
                &message,
                Some(Payload::ReloadResult(result)),
            ),
        )
        .await;
        return;
    };

    // Go uses context.WithoutCancel here: a stream reconnect must not abandon a
    // half-completed replacement. The 2m deadline only cancels panel reads. We
    // deliberately continue polling the same future afterward so an already
    // started local transaction reaches its real terminal state while this
    // lease remains held.
    let operation_cancel = CancellationToken::new();
    let reporter = ReloadProgressReporter {
        controller: controller.clone(),
        sink: sink.clone(),
        request_id: Arc::from(operation_id.as_str()),
    };
    let operation = dependencies
        .fetcher
        .reload(operation_cancel.clone(), reporter);
    tokio::pin!(operation);
    let backend_result = tokio::select! {
        () = tokio::time::sleep(REMOTE_RELOAD_TIMEOUT) => {
            operation_cancel.cancel();
            deadline_result(operation.await)
        }
        result = &mut operation => result,
    };
    let backend_result = backend_result.unwrap_or_else(|error| RemoteReloadResult {
        outcome: ReloadSingBoxOutcome::FailedUnchanged,
        stage: controller.reload_stage(),
        message: error.to_string(),
        topology_revision: 0,
        config_sha256: String::new(),
        loaded_user_count: 0,
    });
    let completed_at = SystemTime::now();
    let proto_result = ReloadSingBoxResult {
        operation_id: operation_id.clone(),
        outcome: backend_result.outcome as i32,
        stage: backend_result.stage,
        message: backend_result.message,
        topology_revision: backend_result.topology_revision,
        config_sha256: backend_result.config_sha256,
        loaded_user_count: backend_result.loaded_user_count as u32,
        duration_millis: i64::try_from(started_at.elapsed().as_millis()).unwrap_or(i64::MAX),
        completed_at_unix_milli: unix_millis(Some(completed_at)),
    };
    lease.finish(&proto_result);
    let stage = proto_result.stage.clone();
    let message = proto_result.message.clone();
    sink.send(
        &operation_id,
        response(
            RemoteControlResponseStatus::Completed,
            &stage,
            &message,
            Some(Payload::ReloadResult(proto_result)),
        ),
    )
    .await;
}

async fn send_failure(sink: &ResponseSink, request_id: &str, stage: &str, message: &str) {
    sink.send(
        request_id,
        response(RemoteControlResponseStatus::Failed, stage, message, None),
    )
    .await;
}

fn response(
    status: RemoteControlResponseStatus,
    stage: &str,
    message: &str,
    payload: Option<Payload>,
) -> RemoteControlResponse {
    RemoteControlResponse {
        request_id: String::new(),
        status: status as i32,
        stage: stage.to_string(),
        message: message.to_string(),
        payload,
    }
}

fn remote_user_credential(user: UserCredential) -> ProtoUserCredential {
    ProtoUserCredential {
        user_id: user.user_id,
        name: user.name,
        credential: user.credential,
        status: if user.status == "disabled" {
            UserStatus::Disabled as i32
        } else {
            UserStatus::Active as i32
        },
        upload_speed_limit_bps: user.upload_speed_limit_bps,
        download_speed_limit_bps: user.download_speed_limit_bps,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn deadline_result<T>(result: Result<T, RemoteOperationError>) -> Result<T, RemoteOperationError> {
    match result {
        Err(error) if error.to_string() == "context canceled" => {
            Err(RemoteOperationError::new(CONTEXT_DEADLINE_EXCEEDED))
        }
        result => result,
    }
}

async fn run_periodic_user_pull(
    stream_cancel: CancellationToken,
    target: RemoteControlTarget,
    dependencies: RemoteControlDependencies,
    controller: RemoteController,
) {
    while !stream_cancel.is_cancelled() {
        // Register before inspecting state so a concurrent attempt completion or
        // setting change cannot be lost between the check and the wait.
        let wake = controller.inner.periodic_wake.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        let schedule = controller.periodic_schedule();
        if !schedule.enabled {
            tokio::select! {
                () = &mut wake => continue,
                () = stream_cancel.cancelled() => return,
            }
        }
        if let Some(next) = schedule.next {
            let delay = next
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);
            if !delay.is_zero() {
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = &mut wake => continue,
                    () = stream_cancel.cancelled() => return,
                }
            }
        }

        let Some(attempt) = controller.begin_periodic_attempt(&stream_cancel) else {
            tokio::select! {
                () = &mut wake => {}
                () = stream_cancel.cancelled() => return,
            }
            continue;
        };
        // The attempt token is a child of the stream token (and is also
        // signalled when the setting changes). The fetcher observes it while
        // reading the panel, but a local transaction is always awaited to
        // completion before the attempt state is released.
        let result = dependencies
            .fetcher
            .sync_users(attempt.cancel.clone(), &target.node_id)
            .await;
        let cancelled = attempt.cancel.is_cancelled() || stream_cancel.is_cancelled();
        attempt.finish(result.as_ref().err(), cancelled);
    }
}

/// Opens the authenticated bidirectional stream, dispatches each request in its
/// own task, serialises all responses through a bounded queue, and runs the
/// process-scoped periodic pull scheduler for this session generation.
pub async fn run_remote_control_stream(
    shutdown: CancellationToken,
    channel: Channel,
    authenticator: SessionAuthenticator,
    target: RemoteControlTarget,
    dependencies: RemoteControlDependencies,
    controller: RemoteController,
) -> Result<(), SessionError> {
    let stream_cancel = shutdown.child_token();
    // Dropping/aborting the outer stream must also stop detached request panel
    // reads and response waits. Cancellation never aborts an owned transaction.
    let _stream_cancel_on_drop = stream_cancel.clone().drop_guard();
    let (response_sender, response_receiver) = mpsc::channel(REMOTE_RESPONSE_QUEUE_SIZE);
    let outgoing = ReceiverStream::new(response_receiver);
    let mut client = RemoteControlServiceClient::new(authenticator.intercepted_channel(channel));
    let response = tokio::select! {
        result = client.remote_control_stream(Request::new(outgoing)) => {
            result.map_err(SessionError::Rpc)?
        }
        () = shutdown.cancelled() => return Ok(()),
    };
    let mut requests = response.into_inner();
    let mut periodic = tokio::spawn(run_periodic_user_pull(
        stream_cancel.clone(),
        target.clone(),
        dependencies.clone(),
        controller.clone(),
    ));

    let outcome = loop {
        // Admit before reading/spawning another request, so neither suspended
        // task stacks nor full configuration snapshots can grow without bound.
        // Slots belong to the controller and remain bounded across reconnects.
        let request_permit = tokio::select! {
            permit = acquire_request_slot(&controller, &stream_cancel) => permit,
            () = response_sender.closed() => {
                break Err(SessionError::Rpc(tonic::Status::unavailable(
                    "remote control response stream closed",
                )));
            }
        };
        let Some(request_permit) = request_permit else {
            break if shutdown.is_cancelled() {
                Ok(())
            } else {
                Err(SessionError::Rpc(tonic::Status::unavailable(
                    "remote control response stream closed",
                )))
            };
        };
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break Ok(()),
            () = stream_cancel.cancelled() => {
                break Err(SessionError::Rpc(tonic::Status::unavailable(
                    "remote control response stream closed",
                )));
            }
            message = requests.message() => match message {
                Ok(Some(request)) => {
                    let request_cancel = stream_cancel.clone();
                    let request_target = target.clone();
                    let request_dependencies = dependencies.clone();
                    let request_controller = controller.clone();
                    let request_responses = response_sender.clone();
                    let task = tokio::spawn(async move {
                        let _request_permit = request_permit;
                        handle_remote_control_request(
                            request_cancel,
                            request_target,
                            request_dependencies,
                            request_controller,
                            request,
                            request_responses,
                        )
                        .await;
                    });
                    monitor_request_task(task);
                }
                Ok(None) => break Err(SessionError::Rpc(tonic::Status::unavailable(
                    "remote control stream closed by panel",
                ))),
                Err(_status) if shutdown.is_cancelled() => break Ok(()),
                Err(status) => break Err(SessionError::Rpc(status)),
            },
            () = response_sender.closed() => {
                break Err(SessionError::Rpc(tonic::Status::unavailable(
                    "remote control response stream closed",
                )));
            }
        }
    };

    stream_cancel.cancel();
    drop(response_sender);
    // Cancellation stops panel I/O; an in-flight local topology transaction
    // remains owned by the periodic task and must not be aborted midway.
    let _ = (&mut periodic).await;
    outcome
}

async fn acquire_request_slot(
    controller: &RemoteController,
    stream_cancel: &CancellationToken,
) -> Option<OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        () = stream_cancel.cancelled() => None,
        permit = controller.inner.request_slots.clone().acquire_owned() => permit.ok(),
    }
}

fn monitor_request_task(task: JoinHandle<()>) {
    tokio::spawn(async move {
        if let Err(error) = task.await {
            log::error!("remote control request task failed: {error}");
        }
    });
}

#[cfg(test)]
mod tests;
