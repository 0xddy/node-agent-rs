//! Dual-lane ACP control execution with terminal ACK guarantees.

use std::fmt;
use std::sync::Arc;

use acp_proto::control_command::Payload;
use acp_proto::{ControlAck, ControlAckStatus, ControlCommand, ControlCommandType, TopologyDelta};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{Ack, AckStatus, AckStore, Command, TopologyFetcher};
use crate::policy::PolicyState;
use crate::topology::MachineTopology;
use crate::topology::manager::{
    PublicationToken, TopologyError, TopologyErrorKind, TopologyManager,
};

pub const MAX_QUEUED_CONTROL_COMMANDS: usize = 256;
pub const MAX_QUEUED_USER_REFRESH_COMMANDS: usize = 256;
/// Bounds ACKs waiting between command execution and tonic's already-bounded
/// outgoing stream. This is intentionally smaller than the command queues:
/// when the panel stops reading, execution should backpressure rather than
/// retain an unbounded number of cloned command identifiers and messages.
pub const MAX_QUEUED_CONTROL_ACKS: usize = 64;
const MAX_USER_REFRESH_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalResult {
    pub status: AckStatus,
    pub message: String,
}

impl TerminalResult {
    pub fn applied(message: impl Into<String>) -> Self {
        Self {
            status: AckStatus::Applied,
            message: message.into(),
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            status: AckStatus::Failed,
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait CommandExecutor: Send + Sync + 'static {
    async fn execute(&self, command: ControlCommand) -> TerminalResult;

    /// Executes one dequeued command with the lifetime of its panel session.
    /// Generic executors retain the historical non-cancellable behavior; the
    /// production topology executor overrides this to cancel only panel reads.
    async fn execute_with_cancel(
        &self,
        command: ControlCommand,
        _cancellation: CancellationToken,
    ) -> TerminalResult {
        self.execute(command).await
    }
}

/// Topology-aware executor including authoritative resynchronization.
pub struct TopologyCommandExecutor {
    manager: Arc<TopologyManager>,
    fetcher: Arc<dyn TopologyFetcher>,
    policy: Arc<PolicyState>,
}

struct AuthoritativeFetch {
    topology: MachineTopology,
    expected_publication: PublicationToken,
}

impl TopologyCommandExecutor {
    pub fn new(manager: Arc<TopologyManager>, fetcher: Arc<dyn TopologyFetcher>) -> Self {
        Self {
            manager,
            fetcher,
            policy: Arc::new(PolicyState::new()),
        }
    }

    pub fn with_policy(
        manager: Arc<TopologyManager>,
        fetcher: Arc<dyn TopologyFetcher>,
        policy: Arc<PolicyState>,
    ) -> Self {
        Self {
            manager,
            fetcher,
            policy,
        }
    }

    /// Fetches and applies the initial authoritative topology.
    ///
    /// # Errors
    ///
    /// Returns a contextual message when the panel fetch fails or another
    /// publication wins before the fetched snapshot can be committed.
    pub async fn sync_initial(&self) -> Result<String, String> {
        let expected_publication = self.manager.publication_token();
        let topology = self
            .fetcher
            .fetch_machine_topology()
            .await
            .map_err(|error| format!("initial topology fetch: {error}"))?;
        self.manager
            .apply_authoritative_if_unchanged(topology, expected_publication)
            .await
            .map_err(|error| format!("initial topology apply: {error}"))
    }

    async fn execute_regular(
        &self,
        command: &ControlCommand,
        cancellation: &CancellationToken,
    ) -> TerminalResult {
        match self.apply_with_recovery(command, cancellation).await {
            Ok(message) => TerminalResult::applied(message),
            Err(error) => TerminalResult {
                status: if error.rolled_back {
                    AckStatus::RolledBack
                } else {
                    AckStatus::Failed
                },
                message: error.message,
            },
        }
    }

    async fn apply_with_recovery(
        &self,
        command: &ControlCommand,
        cancellation: &CancellationToken,
    ) -> Result<String, ApplyFailure> {
        match self.apply_command(command, cancellation).await {
            Ok(message) => Ok(message),
            Err(error) if !error.revision_recovery => Err(error),
            Err(error) => {
                let cause = error.message;
                let (resync_message, current_revision) =
                    self.resync(cancellation).await.map_err(|resync| {
                        ApplyFailure::plain(format!(
                            "revision resync failed after {cause}: {}",
                            resync.message
                        ))
                    })?;
                if !revision_fenced_command(command.r#type) || current_revision > command.revision {
                    return Ok(format!("revision mismatch, {resync_message}"));
                }

                let rebased = rebase_control_command(command, current_revision);
                ensure_active(cancellation)?;
                let replayed = self.apply_command(&rebased, cancellation).await.map_err(
                    |error| ApplyFailure {
                        message: format!(
                            "revision resync replay from base {current_revision} to target {}: {}",
                            command.revision, error.message
                        ),
                        ..error
                    },
                )?;
                Ok(format!(
                    "revision mismatch, {resync_message}; replayed: {replayed}"
                ))
            }
        }
    }

    async fn apply_command(
        &self,
        command: &ControlCommand,
        cancellation: &CancellationToken,
    ) -> Result<String, ApplyFailure> {
        // This check is the hand-off boundary: cancellation before it prevents
        // any local mutation. Once a manager future is called below, it is
        // deliberately awaited to a consistent terminal state.
        ensure_active(cancellation)?;
        let command_type = ControlCommandType::try_from(command.r#type).map_err(|_| {
            ApplyFailure::plain(format!(
                "unsupported control command type {}",
                command.r#type
            ))
        })?;
        match command_type {
            ControlCommandType::TopologySnapshot => {
                let Some(Payload::TopologySnapshot(snapshot)) = command.payload.as_ref() else {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} snapshot revision=0",
                        command.revision
                    )));
                };
                if command.revision != snapshot.revision {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} snapshot revision={}",
                        command.revision, snapshot.revision
                    )));
                }
                self.manager
                    .apply_snapshot(Some(snapshot))
                    .await
                    .map_err(Into::into)
            }
            ControlCommandType::TopologyDelta => {
                let Some(Payload::TopologyDelta(delta)) = command.payload.as_ref() else {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command base={} target={} delta base=0 target=0",
                        command.base_revision, command.revision
                    )));
                };
                let command_revisions = (command.base_revision, command.revision);
                let delta_revisions = (delta.base_revision, delta.target_revision);
                if command_revisions != delta_revisions {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command base={} target={} delta base={} target={}",
                        command.base_revision,
                        command.revision,
                        delta.base_revision,
                        delta.target_revision
                    )));
                }
                self.manager
                    .apply_delta(Some(delta))
                    .await
                    .map_err(Into::into)
            }
            ControlCommandType::RoutePatch => {
                let Some(Payload::TopologyRoutePatch(patch)) = command.payload.as_ref() else {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} route patch revision=0",
                        command.revision
                    )));
                };
                if command.revision != patch.revision {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} route patch revision={}",
                        command.revision, patch.revision
                    )));
                }
                self.manager
                    .apply_route_patch(Some(patch), command.base_revision)
                    .await
                    .map_err(Into::into)
            }
            ControlCommandType::UserMutation => {
                let Some(Payload::UserMutation(mutation)) = command.payload.as_ref() else {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} user mutation revision=0",
                        command.revision
                    )));
                };
                if command.revision != mutation.revision {
                    return Err(ApplyFailure::revision(format!(
                        "topology revision mismatch: command revision={} user mutation revision={}",
                        command.revision, mutation.revision
                    )));
                }
                self.manager
                    .apply_user_mutation(Some(mutation), command.base_revision)
                    .await
                    .map_err(Into::into)
            }
            ControlCommandType::UserRefresh => self.execute_refresh(command, cancellation).await,
            _ => self
                .policy
                .apply(command)
                .map_err(|error| ApplyFailure::plain(error.to_string())),
        }
    }

    async fn execute_refresh(
        &self,
        command: &ControlCommand,
        cancellation: &CancellationToken,
    ) -> Result<String, ApplyFailure> {
        if let Err(error) = self
            .manager
            .guard_revision_fence(command.base_revision, command.revision)
        {
            if error.revision_recovery_required() {
                return self
                    .recover_refresh_revision(command, &error, cancellation)
                    .await;
            }
            return Err(error.into());
        }

        for _ in 0..MAX_USER_REFRESH_ATTEMPTS {
            let current = self
                .manager
                .loaded_users(&command.node_id)
                .await
                .map_err(ApplyFailure::from)?;
            let desired = self
                .fetcher
                .fetch_node_users_cancellable(cancellation, &command.node_id)
                .await
                .map_err(|error| {
                    ApplyFailure::plain(format!(
                        "user refresh failed: command_id={} node={}: fetch users: {error}",
                        command.command_id,
                        dash_if_empty(&command.node_id)
                    ))
                })?;
            ensure_active(cancellation)?;
            match self
                .manager
                .refresh_node_users_if_current_at_revision_fence(
                    &command.node_id,
                    desired,
                    current,
                    command.base_revision,
                    command.revision,
                )
                .await
            {
                Ok(changes) => {
                    return Ok(format!(
                        "user refresh applied: added={} updated={} deleted={} applied={}",
                        changes.added, changes.updated, changes.deleted, changes.applied
                    ));
                }
                Err(error) if error.kind() == TopologyErrorKind::UsersChangedDuringRefresh => {}
                Err(error) if error.revision_recovery_required() => {
                    return self
                        .recover_refresh_revision(command, &error, cancellation)
                        .await;
                }
                Err(error) => {
                    return Err(ApplyFailure {
                        rolled_back: error.rolled_back(),
                        revision_recovery: false,
                        message: format!(
                            "user refresh failed: command_id={} node={}: {error}",
                            command.command_id,
                            dash_if_empty(&command.node_id)
                        ),
                    });
                }
            }
        }
        Err(ApplyFailure::plain(format!(
            "refresh users for node {} did not stabilize after {} attempts: node users changed during refresh",
            command.node_id, MAX_USER_REFRESH_ATTEMPTS
        )))
    }

    async fn recover_refresh_revision(
        &self,
        command: &ControlCommand,
        cause: &TopologyError,
        cancellation: &CancellationToken,
    ) -> Result<String, ApplyFailure> {
        let topology = self.fetch_resync(cancellation).await.map_err(|error| {
            ApplyFailure::plain(format!(
                "user refresh revision resync failed after {cause}: {}",
                error.message
            ))
        })?;
        if topology.topology.revision < command.revision {
            return Err(ApplyFailure::plain(format!(
                "user refresh cannot be replayed from an older authoritative snapshot: snapshot={} target={}",
                topology.topology.revision, command.revision
            )));
        }
        let (message, _) = self.apply_resync(topology).await.map_err(|error| {
            ApplyFailure::plain(format!(
                "user refresh revision resync failed after {cause}: {}",
                error.message
            ))
        })?;
        Ok(format!("user refresh revision mismatch, {message}"))
    }

    async fn fetch_resync(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<AuthoritativeFetch, ApplyFailure> {
        // Capture immediately before the fetch. The fetched snapshot may have
        // the same revision as a command applied by the other worker lane, so
        // revision alone cannot prevent a delayed response from rolling it
        // back.
        let expected_publication = self.manager.publication_token();
        let topology = self
            .fetcher
            .fetch_machine_topology_cancellable(cancellation)
            .await
            .map_err(|error| ApplyFailure::plain(format!("revision resync fetch: {error}")))?;
        ensure_active(cancellation)?;
        Ok(AuthoritativeFetch {
            topology,
            expected_publication,
        })
    }

    async fn apply_resync(
        &self,
        fetched: AuthoritativeFetch,
    ) -> Result<(String, u64), ApplyFailure> {
        let message = self
            .manager
            .apply_authoritative_if_unchanged(fetched.topology, fetched.expected_publication)
            .await
            .map_err(|error| ApplyFailure {
                message: format!("revision resync apply: {error}"),
                rolled_back: error.rolled_back(),
                revision_recovery: false,
            })?;
        let revision = self
            .manager
            .current_revision()
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                ApplyFailure::plain("revision resync returned an unversioned topology")
            })?;
        Ok((format!("resynced: {message}"), revision))
    }

    async fn resync(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(String, u64), ApplyFailure> {
        let topology = self.fetch_resync(cancellation).await?;
        self.apply_resync(topology).await
    }
}

#[async_trait]
impl CommandExecutor for TopologyCommandExecutor {
    async fn execute(&self, command: ControlCommand) -> TerminalResult {
        self.execute_regular(&command, &CancellationToken::new())
            .await
    }

    async fn execute_with_cancel(
        &self,
        command: ControlCommand,
        cancellation: CancellationToken,
    ) -> TerminalResult {
        self.execute_regular(&command, &cancellation).await
    }
}

#[derive(Debug)]
struct ApplyFailure {
    message: String,
    revision_recovery: bool,
    rolled_back: bool,
}

impl ApplyFailure {
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            revision_recovery: false,
            rolled_back: false,
        }
    }

    fn revision(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            revision_recovery: true,
            rolled_back: false,
        }
    }
}

fn ensure_active(cancellation: &CancellationToken) -> Result<(), ApplyFailure> {
    if cancellation.is_cancelled() {
        Err(ApplyFailure::plain("control command execution canceled"))
    } else {
        Ok(())
    }
}

impl From<TopologyError> for ApplyFailure {
    fn from(error: TopologyError) -> Self {
        Self {
            revision_recovery: error.revision_recovery_required(),
            rolled_back: error.rolled_back(),
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerClosed;

impl fmt::Display for WorkerClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("control command worker is closed")
    }
}

impl std::error::Error for WorkerClosed {}

/// Submit side of the two serial command lanes.
///
/// Regular submission awaits queue capacity and therefore pushes back on the
/// upstream gRPC reader. Refresh submission never blocks the regular lane: when
/// its bounded queue is full it emits an explicit FAILED terminal ACK.
#[derive(Clone)]
pub struct ControlCommandWorker {
    regular: mpsc::Sender<ControlCommand>,
    refresh: mpsc::Sender<ControlCommand>,
    acknowledgements: mpsc::Sender<ControlAck>,
    lifecycle: Arc<WorkerLifecycle>,
}

struct WorkerLifecycle {
    cancellation: CancellationToken,
}

struct WorkerSpawnOptions {
    regular_capacity: usize,
    refresh_capacity: usize,
    parent_cancellation: CancellationToken,
}

#[derive(Clone)]
struct LaneContext {
    executor: Arc<dyn CommandExecutor>,
    acknowledgements: Arc<AckStore>,
    output: mpsc::Sender<ControlAck>,
    cancellation: CancellationToken,
}

impl Drop for WorkerLifecycle {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl ControlCommandWorker {
    pub fn spawn(
        executor: Arc<dyn CommandExecutor>,
        acknowledgements: Arc<AckStore>,
    ) -> (Self, mpsc::Receiver<ControlAck>) {
        Self::spawn_configured(
            executor,
            acknowledgements,
            WorkerSpawnOptions {
                regular_capacity: MAX_QUEUED_CONTROL_COMMANDS,
                refresh_capacity: MAX_QUEUED_USER_REFRESH_COMMANDS,
                parent_cancellation: CancellationToken::new(),
            },
        )
    }

    pub fn spawn_with_cancel(
        executor: Arc<dyn CommandExecutor>,
        acknowledgements: Arc<AckStore>,
        cancellation: CancellationToken,
    ) -> (Self, mpsc::Receiver<ControlAck>) {
        Self::spawn_configured(
            executor,
            acknowledgements,
            WorkerSpawnOptions {
                regular_capacity: MAX_QUEUED_CONTROL_COMMANDS,
                refresh_capacity: MAX_QUEUED_USER_REFRESH_COMMANDS,
                parent_cancellation: cancellation,
            },
        )
    }

    pub fn spawn_with_capacity(
        executor: Arc<dyn CommandExecutor>,
        acknowledgements: Arc<AckStore>,
        regular_capacity: usize,
        refresh_capacity: usize,
    ) -> (Self, mpsc::Receiver<ControlAck>) {
        Self::spawn_configured(
            executor,
            acknowledgements,
            WorkerSpawnOptions {
                regular_capacity,
                refresh_capacity,
                parent_cancellation: CancellationToken::new(),
            },
        )
    }

    pub fn spawn_with_capacity_and_cancel(
        executor: Arc<dyn CommandExecutor>,
        acknowledgements: Arc<AckStore>,
        regular_capacity: usize,
        refresh_capacity: usize,
        parent_cancellation: CancellationToken,
    ) -> (Self, mpsc::Receiver<ControlAck>) {
        Self::spawn_configured(
            executor,
            acknowledgements,
            WorkerSpawnOptions {
                regular_capacity,
                refresh_capacity,
                parent_cancellation,
            },
        )
    }

    fn spawn_configured(
        executor: Arc<dyn CommandExecutor>,
        acknowledgements: Arc<AckStore>,
        options: WorkerSpawnOptions,
    ) -> (Self, mpsc::Receiver<ControlAck>) {
        let WorkerSpawnOptions {
            regular_capacity,
            refresh_capacity,
            parent_cancellation,
        } = options;
        assert!(regular_capacity > 0, "regular capacity must be non-zero");
        assert!(refresh_capacity > 0, "refresh capacity must be non-zero");
        let cancellation = parent_cancellation.child_token();
        let lifecycle = Arc::new(WorkerLifecycle {
            cancellation: cancellation.clone(),
        });
        let (regular_tx, regular_rx) = mpsc::channel(regular_capacity);
        let (refresh_tx, refresh_rx) = mpsc::channel(refresh_capacity);
        let (ack_tx, ack_rx) = mpsc::channel(MAX_QUEUED_CONTROL_ACKS);
        let lane = LaneContext {
            executor,
            acknowledgements,
            output: ack_tx.clone(),
            cancellation,
        };
        spawn_lane(regular_rx, lane.clone());
        spawn_lane(refresh_rx, lane);
        (
            Self {
                regular: regular_tx,
                refresh: refresh_tx,
                acknowledgements: ack_tx,
                lifecycle,
            },
            ack_rx,
        )
    }

    /// # Errors
    ///
    /// Returns [`WorkerClosed`] when cancellation or a closed command/ACK
    /// channel prevents the command from being accepted.
    pub async fn submit(&self, command: ControlCommand) -> Result<(), WorkerClosed> {
        if self.lifecycle.cancellation.is_cancelled() {
            return Err(WorkerClosed);
        }
        if uses_refresh_lane(command.r#type) {
            self.send_ack(proto_ack(
                &command,
                AckStatus::Accepted,
                "accepted for execution",
            ))
            .await?;
            match self.refresh.try_send(command) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(command)) => {
                    self.send_ack(proto_ack(
                        &command,
                        AckStatus::Failed,
                        "user refresh queue is full",
                    ))
                    .await
                }
                Err(mpsc::error::TrySendError::Closed(command)) => {
                    self.send_ack(proto_ack(
                        &command,
                        AckStatus::Failed,
                        "control command worker is closed",
                    ))
                    .await
                }
            }
        } else {
            // Reserve backlog space before accepting. When all 256 slots are
            // occupied this await stops the upstream receive loop, allowing
            // HTTP/2 flow control to push back on the panel exactly as in Go.
            let permit = self.regular.reserve().await.map_err(|_| WorkerClosed)?;
            self.send_ack(proto_ack(
                &command,
                AckStatus::Accepted,
                "accepted for execution",
            ))
            .await?;
            permit.send(command);
            Ok(())
        }
    }

    async fn send_ack(&self, acknowledgement: ControlAck) -> Result<(), WorkerClosed> {
        tokio::select! {
            biased;
            () = self.lifecycle.cancellation.cancelled() => Err(WorkerClosed),
            result = self.acknowledgements.send(acknowledgement) => {
                result.map_err(|_| WorkerClosed)
            }
        }
    }

    pub fn cancel(&self) {
        self.lifecycle.cancellation.cancel();
    }
}

fn spawn_lane(mut commands: mpsc::Receiver<ControlCommand>, lane: LaneContext) {
    tokio::spawn(async move {
        let LaneContext {
            executor,
            acknowledgements,
            output,
            cancellation,
        } = lane;
        loop {
            let command = tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                command = commands.recv() => match command {
                    Some(command) => command,
                    None => break,
                },
            };
            if cancellation.is_cancelled() {
                break;
            }
            let generic = ack_command_from_proto(&command);
            if !generic.idempotency_key.is_empty()
                && let Ok(Some(replay)) = acknowledgements.replay(&generic)
            {
                if send_lane_ack(
                    &output,
                    &cancellation,
                    proto_ack(&command, replay.status, replay.message),
                )
                .await
                .is_err()
                {
                    break;
                }
                continue;
            }

            let executor = executor.clone();
            // The lane only needs the reply envelope after execution. Transfer
            // the topology/delta payload to its task instead of retaining a copy.
            let mut acknowledgement = proto_ack(&command, AckStatus::Accepted, String::new());
            let execution_cancellation = cancellation.clone();
            let joined = tokio::spawn(async move {
                executor
                    .execute_with_cancel(command, execution_cancellation)
                    .await
            })
            .await;
            let mut result = match joined {
                Ok(result) => result,
                Err(error) if error.is_panic() => {
                    let payload = error.into_panic();
                    TerminalResult::failed(format!(
                        "control command execution panicked: {}",
                        panic_message(payload.as_ref())
                    ))
                }
                Err(error) => TerminalResult::failed(format!(
                    "control command execution task failed: {error}"
                )),
            };
            // An already-started topology transaction must run to a consistent
            // conclusion, but its disconnected session no longer receives an
            // ACK and no queued successor may execute.
            if cancellation.is_cancelled() {
                break;
            }
            if result.status == AckStatus::Accepted {
                result =
                    TerminalResult::failed("control command completed without a terminal result");
            }

            let terminal = if generic.idempotency_key.is_empty() {
                Ack {
                    status: result.status,
                    message: result.message,
                    ..Ack::default()
                }
            } else {
                acknowledgements
                    .complete(
                        &generic,
                        Ack {
                            status: result.status,
                            message: result.message,
                            ..Ack::default()
                        },
                    )
                    .unwrap_or_else(|error| Ack {
                        status: AckStatus::Failed,
                        message: error.to_string(),
                        ..Ack::default()
                    })
            };
            acknowledgement.status = proto_ack_status(terminal.status);
            acknowledgement.message = terminal.message;
            if send_lane_ack(&output, &cancellation, acknowledgement)
                .await
                .is_err()
            {
                break;
            }
        }
    });
}

async fn send_lane_ack(
    output: &mpsc::Sender<ControlAck>,
    cancellation: &CancellationToken,
    acknowledgement: ControlAck,
) -> Result<(), WorkerClosed> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(WorkerClosed),
        result = output.send(acknowledgement) => result.map_err(|_| WorkerClosed),
    }
}

// AckStore only uses delivery metadata, never the command payload or type.
fn ack_command_from_proto(command: &ControlCommand) -> Command {
    Command {
        command_id: command.command_id.clone(),
        operation_id: command.operation_id.clone(),
        machine_id: command.machine_id.clone(),
        node_id: command.node_id.clone(),
        revision: command.revision,
        idempotency_key: command.idempotency_key.clone(),
        ..Command::default()
    }
}

fn proto_ack(
    command: &ControlCommand,
    status: AckStatus,
    message: impl Into<String>,
) -> ControlAck {
    ControlAck {
        command_id: command.command_id.clone(),
        operation_id: command.operation_id.clone(),
        machine_id: command.machine_id.clone(),
        node_id: command.node_id.clone(),
        revision: command.revision,
        idempotency_key: command.idempotency_key.clone(),
        status: proto_ack_status(status),
        message: message.into(),
    }
}

fn proto_ack_status(status: AckStatus) -> i32 {
    (match status {
        AckStatus::Accepted => ControlAckStatus::Accepted,
        AckStatus::Applied => ControlAckStatus::Applied,
        AckStatus::Failed => ControlAckStatus::Failed,
        AckStatus::RolledBack => ControlAckStatus::RolledBack,
    }) as i32
}

const fn uses_refresh_lane(command_type: i32) -> bool {
    command_type == ControlCommandType::UserRefresh as i32
}

fn revision_fenced_command(command_type: i32) -> bool {
    matches!(
        ControlCommandType::try_from(command_type),
        Ok(ControlCommandType::TopologyDelta
            | ControlCommandType::RoutePatch
            | ControlCommandType::UserMutation
            | ControlCommandType::UserRefresh)
    )
}

fn rebase_control_command(command: &ControlCommand, base_revision: u64) -> ControlCommand {
    let mut rebased = command.clone();
    rebased.base_revision = base_revision;
    if let Some(Payload::TopologyDelta(TopologyDelta {
        base_revision: base,
        ..
    })) = rebased.payload.as_mut()
    {
        *base = base_revision;
    }
    rebased
}

fn panic_message(payload: &(dyn std::any::Any + Send + 'static)) -> String {
    match (
        payload.downcast_ref::<&str>(),
        payload.downcast_ref::<String>(),
    ) {
        (Some(message), _) => (*message).to_string(),
        (_, Some(message)) => message.clone(),
        (None, None) => "non-string panic payload".to_string(),
    }
}

const fn dash_if_empty(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}
