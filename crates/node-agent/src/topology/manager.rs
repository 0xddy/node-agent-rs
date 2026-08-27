//! Serialized, revision-fenced topology state transitions.
//!
//! This is a direct Rust counterpart of the Go agent's `topology_manager.go`.
//! The manager deliberately knows nothing about the control transport: it owns
//! only the optimistic revision fence, immutable candidate construction, and
//! the publish-after-success boundary around the data-plane runtime.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use acp_proto as pb;
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use crate::porthopping::{Manager as PortHoppingManager, Plan as PortHoppingPlan};
use crate::runtime::{NodeRuntime, ReloadStatus, RuntimeConfig, RuntimeError};

use super::{
    MachineTopology, NodeInstance, UserCredential, apply_node_mutation_to_snapshot,
    apply_route_patch_to_snapshot, apply_user_mutation_to_snapshot, digest, from_snapshot,
    replace_node_users,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyErrorKind {
    StaleRevision,
    RevisionMismatch,
    UsersChangedDuringRefresh,
    InvalidMutation,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyError {
    kind: TopologyErrorKind,
    message: String,
    rolled_back: bool,
    running: bool,
    rollback_stage: bool,
}

impl TopologyError {
    fn new(kind: TopologyErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            rolled_back: false,
            running: true,
            rollback_stage: false,
        }
    }

    pub fn runtime(message: impl Into<String>, rolled_back: bool) -> Self {
        Self {
            kind: TopologyErrorKind::Runtime,
            message: message.into(),
            rolled_back,
            running: true,
            rollback_stage: rolled_back,
        }
    }

    pub fn runtime_state(message: impl Into<String>, rolled_back: bool, running: bool) -> Self {
        Self {
            kind: TopologyErrorKind::Runtime,
            message: message.into(),
            rolled_back,
            running,
            rollback_stage: rolled_back,
        }
    }

    pub fn kind(&self) -> TopologyErrorKind {
        self.kind
    }

    pub fn revision_recovery_required(&self) -> bool {
        matches!(
            self.kind,
            TopologyErrorKind::StaleRevision | TopologyErrorKind::RevisionMismatch
        )
    }

    pub fn rolled_back(&self) -> bool {
        self.rolled_back
    }

    pub fn running(&self) -> bool {
        self.running
    }

    fn with_rollback_stage(mut self) -> Self {
        self.rollback_stage = true;
        self
    }
}

impl fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TopologyError {}

/// Minimal injectable boundary used by the state machine.
///
/// Production uses [`NodeRuntimeTopologyAdapter`]. Tests can inject a recorder
/// without implementing unrelated traffic and connection-stat APIs.
#[async_trait]
pub trait TopologyRuntime: Send + Sync {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError>;
    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64;
    fn current_config(&self) -> Vec<u8>;

    /// Deterministically ordered warnings for the last successfully published
    /// candidate. Failed candidates must never replace this list.
    fn warnings(&self) -> Vec<String> {
        Vec::new()
    }

    /// Rebuilds/verifies platform-owned state for an already published
    /// topology. A digest hit must still call this hook to repair drift.
    async fn reconcile_current(&self, _topology: &MachineTopology) -> Result<(), TopologyError> {
        Ok(())
    }

    /// Composite implementations close platform-owned routing first and the
    /// data-plane runtime second, joining both errors before returning.
    async fn close(&self) -> Result<(), TopologyError> {
        Ok(())
    }

    /// Pure build step for a forced reload. Implementations may override this
    /// to validate/compile without touching the live runtime.
    fn prepare_reload(&self, _topology: &MachineTopology) -> Result<RuntimeConfig, TopologyError> {
        Ok(RuntimeConfig::default())
    }

    /// Transaction hook reserved for platform-owned forwarding/masquerade
    /// state. Implementations that mutate external state must restore it before
    /// returning an error and classify that error via `rolled_back/running`.
    async fn configure_reload(&self, _topology: &MachineTopology) -> Result<(), TopologyError> {
        Ok(())
    }

    /// Starts the prepared replacement exactly once. The default is useful for
    /// injected test runtimes; production overrides it with `reload_config`.
    async fn reload_prepared(
        &self,
        topology: &MachineTopology,
        _prepared: RuntimeConfig,
    ) -> Result<ReloadStatus, TopologyError> {
        self.apply(topology).await?;
        Ok(ReloadStatus {
            running: true,
            rolled_back: false,
        })
    }
}

type PortRouterError = Box<dyn std::error::Error + Send + Sync + 'static>;

trait PortRouter: Send + Sync {
    fn reconcile(&self, desired: &PortHoppingPlan) -> Result<(), PortRouterError>;
    fn close(&self) -> Result<(), PortRouterError>;
}

impl PortRouter for PortHoppingManager {
    fn reconcile(&self, desired: &PortHoppingPlan) -> Result<(), PortRouterError> {
        PortHoppingManager::reconcile(self, desired)
    }

    fn close(&self) -> Result<(), PortRouterError> {
        PortHoppingManager::close(self)
    }
}

#[derive(Clone)]
struct PreparedReload {
    candidate: MachineTopology,
    desired_plan: PortHoppingPlan,
    previous_plan: PortHoppingPlan,
    previous_config: Option<RuntimeConfig>,
    previous_had_topology: bool,
    warnings: Vec<String>,
    configured: bool,
}

#[derive(Default)]
struct AdapterState {
    active_topology: MachineTopology,
    active_plan: PortHoppingPlan,
    active_warnings: Vec<String>,
    pending_reload: Option<PreparedReload>,
}

struct AdapterInner {
    runtime: Arc<dyn NodeRuntime>,
    port_router: Arc<dyn PortRouter>,
    operation: tokio::sync::Mutex<()>,
    state: Mutex<AdapterState>,
}

/// Compiles topology, reconciles port hopping, and delegates the data-plane
/// side of the same transaction to `NodeRuntime`.
///
/// Every live mutation runs in an owned task behind `operation`. Dropping a
/// caller therefore cannot strand the forwarding plan between the previous and
/// candidate runtime configurations.
#[derive(Clone)]
pub struct NodeRuntimeTopologyAdapter {
    inner: Arc<AdapterInner>,
}

impl NodeRuntimeTopologyAdapter {
    /// Backwards-compatible constructor. Production should use
    /// [`Self::for_machine`] so platform ownership markers include machine ID.
    pub fn new(runtime: Arc<dyn NodeRuntime>) -> Self {
        Self::for_machine("", runtime)
    }

    pub fn for_machine(machine_id: &str, runtime: Arc<dyn NodeRuntime>) -> Self {
        Self::with_port_router(runtime, Arc::new(PortHoppingManager::new(machine_id)))
    }

    pub fn with_port_router(
        runtime: Arc<dyn NodeRuntime>,
        port_router: Arc<PortHoppingManager>,
    ) -> Self {
        Self::with_router(runtime, port_router)
    }

    fn with_router(runtime: Arc<dyn NodeRuntime>, port_router: Arc<dyn PortRouter>) -> Self {
        Self {
            inner: Arc::new(AdapterInner {
                runtime,
                port_router,
                operation: tokio::sync::Mutex::new(()),
                state: Mutex::new(AdapterState::default()),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, AdapterState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn run_owned<T, F>(&self, operation: &'static str, future: F) -> Result<T, TopologyError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, TopologyError>> + Send + 'static,
    {
        tokio::spawn(future).await.map_err(|error| {
            TopologyError::runtime_state(
                format!("{operation} transaction task failed: {error}"),
                false,
                false,
            )
        })?
    }
}

#[async_trait]
impl TopologyRuntime for NodeRuntimeTopologyAdapter {
    async fn apply(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        let inner = Arc::clone(&self.inner);
        let candidate = topology.clone();
        self.run_owned("topology apply", async move {
            let _operation = inner.operation.lock().await;
            let output = crate::compile::compile_with_warnings(&candidate).map_err(|error| {
                TopologyError::runtime(format!("compile topology: {error}"), false)
            })?;
            let desired_plan = crate::porthopping::build_plan(&candidate).map_err(|error| {
                TopologyError::runtime(
                    format!("build port hopping forwarding configuration: {error}"),
                    false,
                )
            })?;
            let (previous_plan, previous_config, previous_had_topology) = {
                let state = inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let previous_plan = crate::porthopping::build_plan(&state.active_topology)
                    .map_err(|error| {
                        TopologyError::runtime(
                            format!(
                                "build previous port hopping forwarding configuration: {error}"
                            ),
                            false,
                        )
                    })?;
                debug_assert_eq!(previous_plan, state.active_plan);
                let previous_had_topology = !state.active_topology.machine_id.is_empty();
                let previous_config = previous_had_topology
                    .then(|| crate::compile::compile_with_warnings(&state.active_topology))
                    .transpose()
                    .map_err(|error| {
                        TopologyError::runtime(
                            format!("compile previous shoes configuration for rollback: {error}"),
                            false,
                        )
                    })?
                    .map(|output| output.runtime);
                (previous_plan, previous_config, previous_had_topology)
            };

            if let Err(error) = inner.port_router.reconcile(&desired_plan) {
                return Err(port_configuration_failure(
                    &inner,
                    error,
                    &previous_plan,
                    previous_had_topology,
                ));
            }

            if let Err(error) = inner.runtime.apply_config(output.runtime).await {
                return Err(runtime_transaction_failure(
                    &inner,
                    error,
                    &previous_plan,
                    previous_config,
                    previous_had_topology,
                    RuntimeFailureMode::OrdinaryApply,
                )
                .await);
            }

            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.active_topology = candidate;
            state.active_plan = desired_plan;
            state.active_warnings = output.warnings;
            state.pending_reload = None;
            Ok(())
        })
        .await
    }

    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64 {
        self.inner
            .runtime
            .close_user_connections(node_id, user_id)
            .await
    }

    fn current_config(&self) -> Vec<u8> {
        self.inner.runtime.current_config()
    }

    fn warnings(&self) -> Vec<String> {
        self.state().active_warnings.clone()
    }

    async fn reconcile_current(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        let inner = Arc::clone(&self.inner);
        let current = topology.clone();
        self.run_owned("port hopping reconciliation", async move {
            let _operation = inner.operation.lock().await;
            let plan = crate::porthopping::build_plan(&current).map_err(|error| {
                TopologyError::runtime(
                    format!("build current port hopping forwarding state: {error}"),
                    false,
                )
            })?;
            inner.port_router.reconcile(&plan).map_err(|error| {
                TopologyError::runtime(
                    format!("reconcile current port hopping forwarding state: {error}"),
                    false,
                )
            })?;
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.active_topology = current;
            state.active_plan = plan;
            Ok(())
        })
        .await
    }

    async fn close(&self) -> Result<(), TopologyError> {
        let inner = Arc::clone(&self.inner);
        self.run_owned("topology close", async move {
            let _operation = inner.operation.lock().await;
            let port_error = match inner.port_router.close() {
                Ok(()) => {
                    let mut state = inner
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.active_plan = PortHoppingPlan::default();
                    state.pending_reload = None;
                    None
                }
                Err(error) => Some(error.to_string()),
            };
            let runtime_error = inner.runtime.close().await.err();
            match (port_error, runtime_error) {
                (None, None) => Ok(()),
                (port_error, runtime_error) => {
                    let running = runtime_error.as_ref().is_some_and(RuntimeError::running);
                    let mut messages = Vec::with_capacity(2);
                    if let Some(error) = port_error {
                        messages.push(format!("close port hopping forwarding: {error}"));
                    }
                    if let Some(error) = runtime_error {
                        messages.push(format!("close shoes runtime: {error}"));
                    }
                    Err(TopologyError::runtime_state(
                        messages.join("; "),
                        false,
                        running,
                    ))
                }
            }
        })
        .await
    }

    fn prepare_reload(&self, topology: &MachineTopology) -> Result<RuntimeConfig, TopologyError> {
        let output = crate::compile::compile_with_warnings(topology)
            .map_err(|error| TopologyError::runtime(format!("compile topology: {error}"), false))?;
        let desired_plan = crate::porthopping::build_plan(topology).map_err(|error| {
            TopologyError::runtime(
                format!("build port hopping forwarding configuration: {error}"),
                false,
            )
        })?;
        let mut state = self.state();
        if state
            .pending_reload
            .as_ref()
            .is_some_and(|pending| pending.configured)
        {
            return Err(TopologyError::runtime(
                "a configured forced reload transaction is already pending",
                false,
            ));
        }
        state.pending_reload = None;
        let previous_plan =
            crate::porthopping::build_plan(&state.active_topology).map_err(|error| {
                TopologyError::runtime(
                    format!("build previous port hopping forwarding configuration: {error}"),
                    false,
                )
            })?;
        debug_assert_eq!(previous_plan, state.active_plan);
        let previous_had_topology = !state.active_topology.machine_id.is_empty();
        let previous_config = previous_had_topology
            .then(|| crate::compile::compile_with_warnings(&state.active_topology))
            .transpose()
            .map_err(|error| {
                TopologyError::runtime(
                    format!("compile previous shoes configuration for rollback: {error}"),
                    false,
                )
            })?
            .map(|output| output.runtime);
        state.pending_reload = Some(PreparedReload {
            candidate: topology.clone(),
            desired_plan,
            previous_plan,
            previous_config,
            previous_had_topology,
            warnings: output.warnings,
            configured: false,
        });
        Ok(output.runtime)
    }

    async fn configure_reload(&self, topology: &MachineTopology) -> Result<(), TopologyError> {
        let inner = Arc::clone(&self.inner);
        let candidate = topology.clone();
        self.run_owned("configure reload port hopping", async move {
            let _operation = inner.operation.lock().await;
            let pending = {
                let state = inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.pending_reload.clone()
            }
            .ok_or_else(|| {
                TopologyError::runtime("forced reload has no prepared transaction", false)
            })?;
            if pending.candidate != candidate {
                inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pending_reload = None;
                return Err(TopologyError::runtime(
                    "forced reload candidate changed after preparation",
                    false,
                ));
            }
            if let Err(error) = inner.port_router.reconcile(&pending.desired_plan) {
                inner
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pending_reload = None;
                return Err(port_configuration_failure(
                    &inner,
                    error,
                    &pending.previous_plan,
                    pending.previous_had_topology,
                ));
            }
            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let pending = state.pending_reload.as_mut().ok_or_else(|| {
                TopologyError::runtime("forced reload transaction disappeared", false)
            })?;
            pending.configured = true;
            Ok(())
        })
        .await
    }

    async fn reload_prepared(
        &self,
        topology: &MachineTopology,
        prepared: RuntimeConfig,
    ) -> Result<ReloadStatus, TopologyError> {
        let inner = Arc::clone(&self.inner);
        let candidate = topology.clone();
        self.run_owned("start prepared reload", async move {
            let _operation = inner.operation.lock().await;
            let pending = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pending_reload
                .take()
                .ok_or_else(|| {
                    TopologyError::runtime("forced reload has no prepared transaction", false)
                })?;
            if pending.candidate != candidate {
                return Err(prepared_reload_protocol_failure(
                    &inner,
                    "forced reload candidate changed after port configuration",
                    &pending,
                ));
            }
            if !pending.configured {
                return Err(TopologyError::runtime(
                    "forced reload port hopping was not configured",
                    false,
                ));
            }

            let status = match inner.runtime.reload_config(prepared).await {
                Ok(status) if status.running => status,
                Ok(_) => {
                    return Err(runtime_transaction_failure_parts(
                        &inner,
                        RuntimeFailureState {
                            operation: "forced reload completed without a running shoes instance"
                                .into(),
                            rolled_back: false,
                            unchanged: false,
                            running: false,
                        },
                        RuntimeRollbackTarget {
                            port_hopping: &pending.previous_plan,
                            config: pending.previous_config,
                            had_topology: pending.previous_had_topology,
                        },
                        RuntimeFailureMode::ForcedReload,
                    )
                    .await);
                }
                Err(error) => {
                    return Err(runtime_transaction_failure(
                        &inner,
                        error,
                        &pending.previous_plan,
                        pending.previous_config,
                        pending.previous_had_topology,
                        RuntimeFailureMode::ForcedReload,
                    )
                    .await);
                }
            };

            let mut state = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.active_topology = candidate;
            state.active_plan = pending.desired_plan;
            state.active_warnings = pending.warnings;
            Ok(status)
        })
        .await
    }
}

fn port_configuration_failure(
    inner: &AdapterInner,
    error: PortRouterError,
    previous_plan: &PortHoppingPlan,
    previous_had_topology: bool,
) -> TopologyError {
    let message = format!("configure port hopping forwarding: {error}");
    if !crate::porthopping::is_state_uncertain(error.as_ref()) {
        return TopologyError::runtime(message, false);
    }
    match inner.port_router.reconcile(previous_plan) {
        Ok(()) if previous_had_topology => TopologyError::runtime_state(
            format!("{message}; previous forwarding state restored"),
            true,
            true,
        ),
        Ok(()) => TopologyError::runtime(message, false),
        Err(rollback) => TopologyError::runtime_state(
            format!(
                "{message}; rollback incomplete: restore previous port hopping forwarding state: {rollback}"
            ),
            false,
            true,
        )
        .with_rollback_stage(),
    }
}

fn prepared_reload_protocol_failure(
    inner: &AdapterInner,
    message: &str,
    pending: &PreparedReload,
) -> TopologyError {
    if !pending.configured {
        return TopologyError::runtime(message, false);
    }
    match inner.port_router.reconcile(&pending.previous_plan) {
        Ok(()) if pending.previous_had_topology => TopologyError::runtime_state(
            format!("{message}; previous forwarding state restored"),
            true,
            true,
        ),
        Ok(()) => TopologyError::runtime(message, false),
        Err(error) => TopologyError::runtime_state(
            format!(
                "{message}; rollback incomplete: restore previous port hopping forwarding state: {error}"
            ),
            false,
            true,
        )
        .with_rollback_stage(),
    }
}

#[derive(Clone, Copy)]
enum RuntimeFailureMode {
    OrdinaryApply,
    ForcedReload,
}

struct RuntimeFailureState {
    operation: String,
    rolled_back: bool,
    unchanged: bool,
    running: bool,
}

impl From<&RuntimeError> for RuntimeFailureState {
    fn from(error: &RuntimeError) -> Self {
        Self {
            operation: error.to_string(),
            rolled_back: error.rolled_back(),
            unchanged: error.state_unchanged(),
            running: error.running(),
        }
    }
}

struct RuntimeRollbackTarget<'a> {
    port_hopping: &'a PortHoppingPlan,
    config: Option<RuntimeConfig>,
    had_topology: bool,
}

async fn runtime_transaction_failure(
    inner: &AdapterInner,
    error: RuntimeError,
    previous_plan: &PortHoppingPlan,
    previous_config: Option<RuntimeConfig>,
    previous_had_topology: bool,
    mode: RuntimeFailureMode,
) -> TopologyError {
    runtime_transaction_failure_parts(
        inner,
        RuntimeFailureState::from(&error),
        RuntimeRollbackTarget {
            port_hopping: previous_plan,
            config: previous_config,
            had_topology: previous_had_topology,
        },
        mode,
    )
    .await
}

async fn runtime_transaction_failure_parts(
    inner: &AdapterInner,
    failure: RuntimeFailureState,
    previous: RuntimeRollbackTarget<'_>,
    mode: RuntimeFailureMode,
) -> TopologyError {
    let mut rollback_errors = Vec::with_capacity(2);
    if let Err(error) = inner.port_router.reconcile(previous.port_hopping) {
        rollback_errors.push(format!(
            "restore previous port hopping forwarding state: {error}"
        ));
    }

    let should_restore_runtime = previous.config.is_some()
        && match mode {
            RuntimeFailureMode::OrdinaryApply => true,
            // `running` is only a liveness hint: a failed per-inbound rollback can
            // leave one listener alive while the topology is incoherent. Only the
            // explicit transaction classifications prove that the published Box
            // survived intact or was completely restored.
            RuntimeFailureMode::ForcedReload => !(failure.rolled_back || failure.unchanged),
        };
    let mut restored_runtime = false;
    let mut running = failure.running;
    if should_restore_runtime && let Some(previous_config) = previous.config {
        match inner.runtime.apply_config(previous_config).await {
            Ok(()) => {
                restored_runtime = true;
                running = true;
            }
            Err(error) => {
                // A failed restore does not establish that the previous topology
                // is serving coherently, even if a fragment of the candidate still
                // owns a listener.
                running = false;
                rollback_errors.push(format!("restore previous shoes configuration: {error}"));
            }
        }
    }

    let runtime_restored = restored_runtime
        || failure.rolled_back
        || (matches!(mode, RuntimeFailureMode::OrdinaryApply) && failure.unchanged);
    let restored =
        rollback_errors.is_empty() && previous.had_topology && running && runtime_restored;
    let mut message = format!("start/apply shoes runtime: {}", failure.operation);
    if !rollback_errors.is_empty() {
        write!(
            message,
            "; rollback incomplete: {}",
            rollback_errors.join("; ")
        )
        .expect("writing into String cannot fail");
    } else if restored {
        message.push_str("; previous topology restored");
    }
    let mut error = TopologyError::runtime_state(message, restored, running);
    if !rollback_errors.is_empty() || restored {
        error = error.with_rollback_stage();
    }
    error
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserRefreshChanges {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub applied: bool,
}

#[derive(Clone, Copy)]
enum UserRefreshRevision {
    None,
    AdvanceTo(u64),
    Fence { base: u64, target: u64 },
}

impl UserRefreshRevision {
    const fn target(self) -> u64 {
        match self {
            Self::None => 0,
            Self::AdvanceTo(target) | Self::Fence { target, .. } => target,
        }
    }
}

struct UserRefreshRequest {
    node_id: String,
    users: Vec<UserCredential>,
    expected_current: Option<Vec<UserCredential>>,
    revision: UserRefreshRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    Succeeded,
    FailedUnchanged,
    FailedRolledBack,
    FailedStopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadStage {
    PullConfiguration,
    PullUsers,
    BuildConfiguration,
    ConfigurePortHopping,
    StartInstance,
    Rollback,
    Completed,
}

impl ReloadStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PullConfiguration => "pull_configuration",
            Self::PullUsers => "pull_users",
            Self::BuildConfiguration => "build_configuration",
            Self::ConfigurePortHopping => "configure_port_hopping",
            Self::StartInstance => "start_instance",
            Self::Rollback => "rollback",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyReloadResult {
    pub outcome: ReloadOutcome,
    pub stage: ReloadStage,
    pub message: String,
    pub topology_revision: u64,
    pub config_sha256: String,
    pub loaded_user_count: usize,
}

#[async_trait]
pub trait ReloadProgress: Send + Sync {
    async fn report(&self, stage: ReloadStage);
}

/// Cloneable progress handle passed into the fetch closure. Reporting
/// `PullUsers` after GetMachineConfig and before the first ListUsers call lets
/// the manager classify a fetch failure at the exact Go stage.
#[derive(Clone)]
pub struct ReloadReporter {
    progress: Option<Arc<dyn ReloadProgress>>,
    current: Arc<RwLock<ReloadStage>>,
}

impl ReloadReporter {
    fn new(progress: Option<Arc<dyn ReloadProgress>>) -> Self {
        Self {
            progress,
            current: Arc::new(RwLock::new(ReloadStage::PullConfiguration)),
        }
    }

    pub async fn report(&self, stage: ReloadStage) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = stage;
        if let Some(progress) = &self.progress {
            progress.report(stage).await;
        }
    }

    pub fn current_stage(&self) -> ReloadStage {
        *self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One machine's currently published topology.
#[derive(Default)]
struct PublishedTopology {
    topology: MachineTopology,
    generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct PublicationToken(u64);

#[derive(Clone)]
pub struct TopologyManager {
    machine_id: String,
    runtime: Arc<dyn TopologyRuntime>,
    operation: Arc<tokio::sync::Mutex<()>>,
    published: Arc<RwLock<PublishedTopology>>,
}

impl TopologyManager {
    pub fn new(machine_id: impl Into<String>, runtime: Arc<dyn TopologyRuntime>) -> Self {
        Self {
            machine_id: machine_id.into(),
            runtime,
            operation: Arc::new(tokio::sync::Mutex::new(())),
            published: Arc::new(RwLock::new(PublishedTopology::default())),
        }
    }

    pub fn from_node_runtime(machine_id: impl Into<String>, runtime: Arc<dyn NodeRuntime>) -> Self {
        let machine_id = machine_id.into();
        Self::new(
            machine_id.clone(),
            Arc::new(NodeRuntimeTopologyAdapter::for_machine(
                &machine_id,
                runtime,
            )),
        )
    }

    pub fn from_node_runtime_with_port_router(
        machine_id: impl Into<String>,
        runtime: Arc<dyn NodeRuntime>,
        port_router: Arc<PortHoppingManager>,
    ) -> Self {
        Self::new(
            machine_id,
            Arc::new(NodeRuntimeTopologyAdapter::with_port_router(
                runtime,
                port_router,
            )),
        )
    }

    fn read_published(&self) -> RwLockReadGuard<'_, PublishedTopology> {
        self.published
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_published(&self) -> RwLockWriteGuard<'_, PublishedTopology> {
        self.published
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish(&self, topology: MachineTopology) {
        let mut published = self.write_published();
        published.topology = topology;
        published.generation = published.generation.wrapping_add(1);
    }

    /// Returns a compare-and-swap token for an authoritative panel fetch.
    /// Every successful topology publication advances this value, including
    /// publications which intentionally retain the same panel revision.
    pub(crate) fn publication_token(&self) -> PublicationToken {
        PublicationToken(self.read_published().generation)
    }

    pub fn current_revision(&self) -> Option<u64> {
        let published = self.read_published();
        let current = &published.topology;
        (!current.machine_id.is_empty()).then_some(current.revision)
    }

    pub fn current_digest(&self) -> Option<String> {
        digest(&self.read_published().topology)
    }

    pub fn current_topology(&self) -> MachineTopology {
        self.read_published().topology.clone()
    }

    pub fn current_config(&self) -> Result<Vec<u8>, TopologyError> {
        let config = self.runtime.current_config();
        if config.is_empty() {
            return Err(TopologyError::new(
                TopologyErrorKind::Runtime,
                "shoes runtime has no active configuration",
            ));
        }
        Ok(config)
    }

    pub async fn reconcile_current(&self) -> Result<(), TopologyError> {
        let _operation = self.operation.lock().await;
        let current = self.read_published().topology.clone();
        if current.machine_id.is_empty() {
            return Ok(());
        }
        self.runtime.reconcile_current(&current).await
    }

    pub async fn close(&self) -> Result<(), TopologyError> {
        let _operation = self.operation.lock().await;
        self.runtime.close().await
    }

    pub fn guard_revision(&self, incoming: u64) -> Result<(), TopologyError> {
        if incoming == 0 {
            return Err(TopologyError::new(
                TopologyErrorKind::RevisionMismatch,
                "topology revision mismatch: incoming revision is zero",
            ));
        }
        let current = self.read_published().topology.revision;
        if incoming < current {
            return Err(TopologyError::new(
                TopologyErrorKind::StaleRevision,
                format!("stale revision: incoming={incoming} current={current}"),
            ));
        }
        Ok(())
    }

    /// Rejects an authoritative full snapshot that is older than the topology
    /// already published by another operation. This must be called while the
    /// operation lock is held because panel fetches happen outside that lock.
    fn guard_authoritative_revision(&self, incoming: u64) -> Result<(), TopologyError> {
        let published = self.read_published();
        let current = &published.topology;
        if current.machine_id.is_empty() || current.revision == 0 || incoming >= current.revision {
            return Ok(());
        }
        Err(TopologyError::new(
            TopologyErrorKind::StaleRevision,
            format!(
                "stale authoritative topology: incoming={incoming} current={}",
                current.revision
            ),
        ))
    }

    /// Requires a partial command to name the exact currently loaded base.
    /// Equal base/target revisions are valid because one logical panel update
    /// may emit several commands at the same revision.
    pub fn guard_revision_fence(&self, base: u64, target: u64) -> Result<(), TopologyError> {
        if base == 0 || target == 0 {
            return Err(TopologyError::new(
                TopologyErrorKind::RevisionMismatch,
                format!("topology revision mismatch: base={base} target={target}"),
            ));
        }
        let current = self.read_published().topology.revision;
        if base != current {
            return Err(TopologyError::new(
                TopologyErrorKind::RevisionMismatch,
                format!(
                    "topology revision mismatch: base={base} current={current} target={target}"
                ),
            ));
        }
        if target < base {
            return Err(TopologyError::new(
                TopologyErrorKind::StaleRevision,
                format!("stale revision: incoming={target} current={current}"),
            ));
        }
        Ok(())
    }

    pub async fn apply_initial(&self, topology: MachineTopology) -> Result<String, TopologyError> {
        let manager = self.clone();
        tokio::spawn(async move {
            let _operation = manager.operation.lock().await;
            manager.guard_authoritative_revision(topology.revision)?;
            manager.apply(topology).await
        })
        .await
        .map_err(|error| {
            TopologyError::runtime_state(
                format!("initial topology transaction task failed: {error}"),
                false,
                false,
            )
        })?
    }

    /// Applies an authoritative topology only if no topology publication has
    /// completed since the caller captured its [`PublicationToken`] immediately
    /// before its panel fetch. Revision equality alone is not a valid fence:
    /// one panel update may legitimately publish multiple commands at the same
    /// revision.
    pub(crate) async fn apply_authoritative_if_unchanged(
        &self,
        topology: MachineTopology,
        expected: PublicationToken,
    ) -> Result<String, TopologyError> {
        let manager = self.clone();
        tokio::spawn(async move {
            let _operation = manager.operation.lock().await;
            manager.guard_authoritative_revision(topology.revision)?;
            let current = manager.publication_token();
            if current.0 != expected.0 {
                return Err(TopologyError::new(
                    TopologyErrorKind::StaleRevision,
                    format!(
                        "authoritative topology changed during fetch: expected_generation={} current_generation={}",
                        expected.0, current.0
                    ),
                ));
            }
            manager.apply(topology).await
        })
        .await
        .map_err(|error| {
            TopologyError::runtime_state(
                format!("authoritative topology transaction task failed: {error}"),
                false,
                false,
            )
        })?
    }

    /// Fetches, builds, configures and force-reloads one candidate under the
    /// same operation lock. The candidate is published only after the single
    /// `reload_prepared` call succeeds; this intentionally never follows reload
    /// with a second ordinary apply.
    pub async fn reload_from<F, Fut, E>(
        self: &Arc<Self>,
        fetch: F,
        progress: Option<Arc<dyn ReloadProgress>>,
    ) -> TopologyReloadResult
    where
        F: FnOnce(ReloadReporter) -> Fut + Send + 'static,
        Fut: Future<Output = Result<MachineTopology, E>> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        let manager = Arc::clone(self);
        let reporter = ReloadReporter::new(progress);
        match tokio::spawn(async move { manager.reload_from_owned(fetch, reporter).await }).await {
            Ok(result) => result,
            Err(error) => TopologyReloadResult {
                outcome: ReloadOutcome::FailedStopped,
                stage: ReloadStage::Rollback,
                message: format!("forced reload transaction task failed: {error}"),
                topology_revision: 0,
                config_sha256: String::new(),
                loaded_user_count: 0,
            },
        }
    }

    async fn reload_from_owned<F, Fut, E>(
        &self,
        fetch: F,
        reporter: ReloadReporter,
    ) -> TopologyReloadResult
    where
        F: FnOnce(ReloadReporter) -> Fut + Send,
        Fut: Future<Output = Result<MachineTopology, E>> + Send,
        E: fmt::Display,
    {
        let _operation = self.operation.lock().await;
        reporter.report(ReloadStage::PullConfiguration).await;
        let mut candidate = match fetch(reporter.clone()).await {
            Ok(candidate) => candidate,
            Err(error) => {
                return TopologyReloadResult {
                    outcome: ReloadOutcome::FailedUnchanged,
                    stage: reporter.current_stage(),
                    message: format!("reload data from panel: {error}"),
                    topology_revision: 0,
                    config_sha256: String::new(),
                    loaded_user_count: 0,
                };
            }
        };
        if candidate.machine_id.is_empty() {
            candidate.machine_id.clone_from(&self.machine_id);
        }

        reporter.report(ReloadStage::BuildConfiguration).await;
        let prepared = match self.runtime.prepare_reload(&candidate) {
            Ok(prepared) => prepared,
            Err(error) => {
                return reload_failure(ReloadStage::BuildConfiguration, error);
            }
        };
        let config_sha256 = sha256_hex(&prepared.diagnostic_yaml);

        reporter.report(ReloadStage::ConfigurePortHopping).await;
        if let Err(error) = self.runtime.configure_reload(&candidate).await {
            return reload_failure(ReloadStage::ConfigurePortHopping, error);
        }

        reporter.report(ReloadStage::StartInstance).await;
        let status = match self.runtime.reload_prepared(&candidate, prepared).await {
            Ok(status) => status,
            Err(error) => return reload_failure(ReloadStage::StartInstance, error),
        };
        if !status.running {
            return TopologyReloadResult {
                outcome: ReloadOutcome::FailedStopped,
                stage: ReloadStage::StartInstance,
                message: "forced reload completed without a running shoes instance".into(),
                topology_revision: 0,
                config_sha256: String::new(),
                loaded_user_count: 0,
            };
        }

        let previous = self.read_published().topology.clone();
        self.publish(candidate.clone());
        self.close_stale_users(&previous, &candidate).await;
        reporter.report(ReloadStage::Completed).await;
        let warnings = self.runtime.warnings();
        report_compile_warnings(&warnings);
        TopologyReloadResult {
            outcome: ReloadOutcome::Succeeded,
            stage: ReloadStage::Completed,
            message: append_warning_summary(
                "shoes reloaded with fresh panel configuration and users".into(),
                &warnings,
            ),
            topology_revision: candidate.revision,
            config_sha256,
            loaded_user_count: topology_user_count(&candidate),
        }
    }

    pub async fn apply_snapshot(
        &self,
        snapshot: Option<&pb::TopologySnapshot>,
    ) -> Result<String, TopologyError> {
        let _operation = self.operation.lock().await;
        let snapshot = snapshot.ok_or_else(|| {
            TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                "topology_snapshot payload is required",
            )
        })?;
        self.guard_revision(snapshot.revision)?;
        self.apply(from_snapshot(self.machine_id.clone(), Some(snapshot)))
            .await
    }

    pub async fn apply_delta(
        &self,
        delta: Option<&pb::TopologyDelta>,
    ) -> Result<String, TopologyError> {
        let _operation = self.operation.lock().await;
        let delta = delta.ok_or_else(|| {
            TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                "topology_delta payload is required",
            )
        })?;
        self.guard_revision_fence(delta.base_revision, delta.target_revision)?;

        let mut next = self.read_published().topology.clone();
        if next.machine_id.is_empty() {
            next.machine_id.clone_from(&self.machine_id);
        }
        for mutation in &delta.node_mutations {
            apply_node_mutation(&mut next, mutation);
            apply_node_mutation_to_snapshot(&mut next, mutation);
        }
        for mutation in &delta.user_mutations {
            apply_user_mutation(&mut next, mutation)?;
            apply_user_mutation_to_snapshot(&mut next, mutation);
        }
        next.revision = delta.target_revision;
        if let Some(snapshot) = next.snapshot.as_mut() {
            snapshot.revision = delta.target_revision;
        }

        let message = self.apply(next).await?;
        self.close_explicitly_requested_users(&delta.user_mutations)
            .await;
        Ok(message)
    }

    pub async fn apply_route_patch(
        &self,
        patch: Option<&pb::TopologyRoutePatch>,
        base_revision: u64,
    ) -> Result<String, TopologyError> {
        let _operation = self.operation.lock().await;
        let patch = patch.ok_or_else(|| {
            TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                "topology_route_patch payload is required",
            )
        })?;
        self.guard_revision_fence(base_revision, patch.revision)?;

        let mut next = self.read_published().topology.clone();
        if next.machine_id.is_empty() {
            next.machine_id.clone_from(&self.machine_id);
        }
        if !patch.machine_id.is_empty() {
            next.machine_id.clone_from(&patch.machine_id);
        }
        next.outbounds = patch.outbounds.iter().map(Into::into).collect();
        next.route = patch.route.as_ref().map(Into::into);
        next.dns = patch.dns.as_ref().map(Into::into);
        apply_route_patch_to_snapshot(&mut next, patch);
        next.revision = patch.revision;
        self.apply(next).await
    }

    pub async fn apply_user_mutation(
        &self,
        mutation: Option<&pb::UserMutation>,
        base_revision: u64,
    ) -> Result<String, TopologyError> {
        let _operation = self.operation.lock().await;
        let mutation = mutation.ok_or_else(|| {
            TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                "user_mutation payload is required",
            )
        })?;
        self.guard_revision_fence(base_revision, mutation.revision)?;

        let mut next = self.read_published().topology.clone();
        if next.machine_id.is_empty() {
            next.machine_id.clone_from(&self.machine_id);
        }
        apply_user_mutation(&mut next, mutation)?;
        apply_user_mutation_to_snapshot(&mut next, mutation);
        next.revision = mutation.revision;
        if let Some(snapshot) = next.snapshot.as_mut() {
            snapshot.revision = mutation.revision;
        }
        let message = self.apply(next).await?;
        self.close_explicitly_requested_users(std::slice::from_ref(mutation))
            .await;
        Ok(message)
    }

    pub async fn refresh_node_users(
        &self,
        node_id: &str,
        users: Vec<UserCredential>,
    ) -> Result<UserRefreshChanges, TopologyError> {
        self.refresh(UserRefreshRequest {
            node_id: node_id.to_string(),
            users,
            expected_current: None,
            revision: UserRefreshRevision::None,
        })
        .await
    }

    pub async fn refresh_node_users_if_current_at_revision(
        &self,
        node_id: &str,
        users: Vec<UserCredential>,
        expected_current: Vec<UserCredential>,
        target_revision: u64,
    ) -> Result<UserRefreshChanges, TopologyError> {
        self.refresh(UserRefreshRequest {
            node_id: node_id.to_string(),
            users,
            expected_current: Some(expected_current),
            revision: UserRefreshRevision::AdvanceTo(target_revision),
        })
        .await
    }

    pub async fn refresh_node_users_if_current_at_revision_fence(
        &self,
        node_id: &str,
        users: Vec<UserCredential>,
        expected_current: Vec<UserCredential>,
        base_revision: u64,
        target_revision: u64,
    ) -> Result<UserRefreshChanges, TopologyError> {
        self.refresh(UserRefreshRequest {
            node_id: node_id.to_string(),
            users,
            expected_current: Some(expected_current),
            revision: UserRefreshRevision::Fence {
                base: base_revision,
                target: target_revision,
            },
        })
        .await
    }

    async fn refresh(
        &self,
        request: UserRefreshRequest,
    ) -> Result<UserRefreshChanges, TopologyError> {
        let manager = self.clone();
        tokio::spawn(async move { manager.refresh_owned(request).await })
            .await
            .map_err(|error| {
                TopologyError::runtime_state(
                    format!("user refresh transaction task failed: {error}"),
                    false,
                    false,
                )
            })?
    }

    /// Runs the complete data-plane apply and manager publication in one owned
    /// task. Dropping an RPC/periodic caller can therefore no longer leave the
    /// runtime on the candidate while `current` still describes the previous
    /// users.
    async fn refresh_owned(
        &self,
        request: UserRefreshRequest,
    ) -> Result<UserRefreshChanges, TopologyError> {
        let UserRefreshRequest {
            node_id,
            users,
            expected_current,
            revision,
        } = request;
        let _operation = self.operation.lock().await;
        if node_id.is_empty() {
            return Err(TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                "user refresh requires node_id",
            ));
        }
        if let UserRefreshRevision::Fence { base, target } = revision {
            self.guard_revision_fence(base, target)?;
        }
        let target_revision = revision.target();
        let mut next = self.read_published().topology.clone();
        let node_index = next
            .nodes
            .iter()
            .position(|node| node.node_id == node_id)
            .ok_or_else(|| {
                TopologyError::new(
                    TopologyErrorKind::InvalidMutation,
                    format!("node {node_id} not found for user refresh"),
                )
            })?;

        if let Some(expected) = expected_current.as_deref() {
            let current_changes = compare_node_users(expected, &next.nodes[node_index].users)?;
            if current_changes.added != 0
                || current_changes.updated != 0
                || current_changes.deleted != 0
            {
                return Err(TopologyError::new(
                    TopologyErrorKind::UsersChangedDuringRefresh,
                    format!("node users changed during refresh: node={node_id}"),
                ));
            }
        }

        let mut changes = compare_node_users(&next.nodes[node_index].users, &users)?;
        if target_revision > next.revision {
            next.revision = target_revision;
            if let Some(snapshot) = next.snapshot.as_mut() {
                snapshot.revision = target_revision;
            }
        }
        if changes.added == 0 && changes.updated == 0 && changes.deleted == 0 {
            if target_revision > 0 {
                let mut published = self.write_published();
                if target_revision > published.topology.revision {
                    published.topology.revision = target_revision;
                    if let Some(snapshot) = published.topology.snapshot.as_mut() {
                        snapshot.revision = target_revision;
                    }
                    published.generation = published.generation.wrapping_add(1);
                }
            }
            return Ok(changes);
        }

        next.nodes[node_index].users.clone_from(&users);
        replace_node_users(&mut next, &node_id, &users);
        self.apply(next).await.map_err(|error| TopologyError {
            message: format!("apply refreshed users for node {node_id}: {error}"),
            ..error
        })?;
        changes.applied = true;
        Ok(changes)
    }

    pub async fn loaded_users(&self, node_id: &str) -> Result<Vec<UserCredential>, TopologyError> {
        // Match Go's `LoadedUsers`: serialize against mutations so a fetch/CAS
        // loop observes a complete manager operation, never an intermediate one.
        let _operation = self.operation.lock().await;
        self.read_published()
            .topology
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .map(|node| node.users.clone())
            .ok_or_else(|| {
                TopologyError::new(
                    TopologyErrorKind::InvalidMutation,
                    format!("node {node_id} not found in loaded topology"),
                )
            })
    }

    async fn apply(&self, mut topology: MachineTopology) -> Result<String, TopologyError> {
        if topology.machine_id.is_empty() {
            topology.machine_id.clone_from(&self.machine_id);
        }
        let previous = self.read_published().topology.clone();
        self.runtime.apply(&topology).await?;
        self.publish(topology.clone());
        self.close_stale_users(&previous, &topology).await;
        let warnings = self.runtime.warnings();
        report_compile_warnings(&warnings);
        Ok(append_warning_summary(
            format!(
                "shoes configuration applied: topology revision={}, nodes={}, users={}",
                topology.revision,
                topology.nodes.len(),
                topology_user_count(&topology)
            ),
            &warnings,
        ))
    }

    async fn close_stale_users(&self, previous: &MachineTopology, next: &MachineTopology) {
        for (node_id, user_ids) in stale_credential_topology_users(previous, next) {
            for user_id in user_ids {
                self.runtime
                    .close_user_connections(&node_id, &user_id)
                    .await;
            }
        }
    }

    async fn close_explicitly_requested_users(&self, mutations: &[pb::UserMutation]) {
        for mutation in mutations {
            if !mutation.kick_existing_connections {
                continue;
            }
            let Some(user) = mutation.user.as_ref() else {
                continue;
            };
            if mutation.node_id.is_empty() || user.user_id.is_empty() {
                continue;
            }
            if !topology_authorizes_user(
                &self.read_published().topology,
                &mutation.node_id,
                &user.user_id,
            ) {
                // Generic old/new diff already closed removed/disabled users.
                continue;
            }
            self.runtime
                .close_user_connections(&mutation.node_id, &user.user_id)
                .await;
        }
    }
}

fn reload_failure(stage: ReloadStage, error: TopologyError) -> TopologyReloadResult {
    let (outcome, stage) = if error.rolled_back() {
        (ReloadOutcome::FailedRolledBack, ReloadStage::Rollback)
    } else if error.running() {
        (
            ReloadOutcome::FailedUnchanged,
            if error.rollback_stage {
                ReloadStage::Rollback
            } else {
                stage
            },
        )
    } else {
        (
            ReloadOutcome::FailedStopped,
            if error.rollback_stage {
                ReloadStage::Rollback
            } else {
                stage
            },
        )
    };
    TopologyReloadResult {
        outcome,
        stage,
        message: error.to_string(),
        topology_revision: 0,
        config_sha256: String::new(),
        loaded_user_count: 0,
    }
}

fn report_compile_warnings(warnings: &[String]) {
    for warning in warnings {
        log::warn!("topology compile warning: {warning}");
    }
}

fn append_warning_summary(mut message: String, warnings: &[String]) -> String {
    if !warnings.is_empty() {
        message.push_str("; warnings: ");
        message.push_str(&warnings.join(" | "));
    }
    message
}

fn apply_node_mutation(topology: &mut MachineTopology, mutation: &pb::NodeMutation) {
    let node_id = if mutation.node_id.is_empty() {
        mutation
            .node
            .as_ref()
            .map(|node| node.node_id.as_str())
            .unwrap_or_default()
    } else {
        &mutation.node_id
    };
    if node_id.is_empty() {
        return;
    }
    match pb::MutationOperation::try_from(mutation.operation)
        .unwrap_or(pb::MutationOperation::Unspecified)
    {
        pb::MutationOperation::Delete | pb::MutationOperation::Disable => {
            topology.nodes.retain(|node| node.node_id != node_id);
        }
        pb::MutationOperation::Unspecified | pb::MutationOperation::Upsert => {
            let mut replacement = mutation
                .node
                .as_ref()
                .map(NodeInstance::from)
                .unwrap_or_default();
            if replacement.node_id.is_empty() {
                replacement.node_id = node_id.to_string();
            }
            if let Some(existing) = topology
                .nodes
                .iter_mut()
                .find(|node| node.node_id == node_id)
            {
                *existing = replacement;
            } else {
                topology.nodes.push(replacement);
            }
        }
    }
}

fn apply_user_mutation(
    topology: &mut MachineTopology,
    mutation: &pb::UserMutation,
) -> Result<(), TopologyError> {
    if mutation.node_id.is_empty() {
        return Err(TopologyError::new(
            TopologyErrorKind::InvalidMutation,
            "user mutation requires node_id",
        ));
    }
    let user = mutation.user.as_ref().ok_or_else(|| {
        TopologyError::new(
            TopologyErrorKind::InvalidMutation,
            "user mutation requires user.user_id",
        )
    })?;
    if user.user_id.is_empty() {
        return Err(TopologyError::new(
            TopologyErrorKind::InvalidMutation,
            "user mutation requires user.user_id",
        ));
    }
    let node = topology
        .nodes
        .iter_mut()
        .find(|node| node.node_id == mutation.node_id)
        .ok_or_else(|| {
            TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                format!("node {} not found for user mutation", mutation.node_id),
            )
        })?;
    let operation = pb::MutationOperation::try_from(mutation.operation)
        .unwrap_or(pb::MutationOperation::Unspecified);
    let replacement = UserCredential::from(user);
    if matches!(
        operation,
        pb::MutationOperation::Delete | pb::MutationOperation::Disable
    ) || replacement.status == "disabled"
    {
        node.users
            .retain(|candidate| candidate.user_id != user.user_id);
    } else if let Some(existing) = node
        .users
        .iter_mut()
        .find(|candidate| candidate.user_id == user.user_id)
    {
        *existing = replacement;
    } else {
        node.users.push(replacement);
    }
    Ok(())
}

pub fn compare_node_users(
    current: &[UserCredential],
    desired: &[UserCredential],
) -> Result<UserRefreshChanges, TopologyError> {
    let current = index_node_users(current, "current")?;
    let desired = index_node_users(desired, "desired")?;
    let mut changes = UserRefreshChanges::default();
    for (user_id, desired_user) in &desired {
        match current.get(user_id) {
            None => changes.added += 1,
            Some(current_user) if current_user != desired_user => changes.updated += 1,
            Some(_) => {}
        }
    }
    for user_id in current.keys() {
        if !desired.contains_key(user_id) {
            changes.deleted += 1;
        }
    }
    Ok(changes)
}

fn index_node_users<'a>(
    users: &'a [UserCredential],
    source: &str,
) -> Result<BTreeMap<&'a str, &'a UserCredential>, TopologyError> {
    let mut indexed = BTreeMap::new();
    for user in users {
        if user.user_id.is_empty() {
            return Err(TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                format!("{source} user list contains an empty user_id"),
            ));
        }
        if indexed.insert(user.user_id.as_str(), user).is_some() {
            return Err(TopologyError::new(
                TopologyErrorKind::InvalidMutation,
                format!(
                    "{source} user list contains duplicate user_id {}",
                    user.user_id
                ),
            ));
        }
    }
    Ok(indexed)
}

fn stale_credential_topology_users(
    current: &MachineTopology,
    desired: &MachineTopology,
) -> BTreeMap<String, Vec<String>> {
    let desired_by_node: BTreeMap<&str, &[UserCredential]> = desired
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.users.as_slice()))
        .collect();
    current
        .nodes
        .iter()
        .filter_map(|node| {
            let desired = desired_by_node
                .get(node.node_id.as_str())
                .copied()
                .unwrap_or_default();
            let stale = stale_credential_user_ids(&node.users, desired);
            (!stale.is_empty()).then(|| (node.node_id.clone(), stale))
        })
        .collect()
}

fn stale_credential_user_ids(
    current: &[UserCredential],
    desired: &[UserCredential],
) -> Vec<String> {
    let desired_active: BTreeMap<&str, &UserCredential> = desired
        .iter()
        .filter(|user| !user.user_id.is_empty() && user.status != "disabled")
        .map(|user| (user.user_id.as_str(), user))
        .collect();
    current
        .iter()
        .filter(|user| !user.user_id.is_empty() && user.status != "disabled")
        .filter(|user| {
            desired_active
                .get(user.user_id.as_str())
                .is_none_or(|desired| desired.credential != user.credential)
        })
        .map(|user| user.user_id.clone())
        .collect()
}

fn topology_authorizes_user(topology: &MachineTopology, node_id: &str, user_id: &str) -> bool {
    topology
        .nodes
        .iter()
        .find(|node| node.node_id == node_id)
        .is_some_and(|node| {
            node.users
                .iter()
                .any(|user| user.user_id == user_id && user.status != "disabled")
        })
}

fn topology_user_count(topology: &MachineTopology) -> usize {
    topology.nodes.iter().map(|node| node.users.len()).sum()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing into String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod transaction_tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use serde_json::json;
    use tokio::sync::{Notify, Semaphore};

    use super::*;
    use crate::porthopping::{PortRange, Redirect, StateUncertainError};
    use crate::runtime::{ConnectionStats, TrafficDrain};
    use crate::topology::RawJson;
    use crate::topology::provider::{CURRENT_CONFIG_VERSION, HYSTERIA2_SALAMANDER_ID};

    #[derive(Clone, Copy)]
    enum RouterOutcome {
        Pass,
        Ordinary,
        Uncertain,
    }

    #[derive(Default)]
    struct RouterState {
        plans: Vec<PortHoppingPlan>,
        outcomes: VecDeque<RouterOutcome>,
        committed: PortHoppingPlan,
    }

    #[derive(Default)]
    struct FakeRouter {
        state: Mutex<RouterState>,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl FakeRouter {
        fn queue(&self, outcomes: impl IntoIterator<Item = RouterOutcome>) {
            self.state.lock().unwrap().outcomes.extend(outcomes);
        }

        fn plans(&self) -> Vec<PortHoppingPlan> {
            self.state.lock().unwrap().plans.clone()
        }

        fn committed(&self) -> PortHoppingPlan {
            self.state.lock().unwrap().committed.clone()
        }

        fn reconcile_inner(&self, desired: &PortHoppingPlan) -> Result<(), PortRouterError> {
            let mut state = self.state.lock().unwrap();
            state.plans.push(desired.clone());
            match state.outcomes.pop_front().unwrap_or(RouterOutcome::Pass) {
                RouterOutcome::Pass => {
                    state.committed = desired.clone();
                    Ok(())
                }
                RouterOutcome::Ordinary => {
                    Err(Box::new(std::io::Error::other("port forwarding rejected")))
                }
                RouterOutcome::Uncertain => Err(Box::new(StateUncertainError::new(
                    std::io::Error::other("netlink acknowledgement lost"),
                ))),
            }
        }
    }

    impl PortRouter for FakeRouter {
        fn reconcile(&self, desired: &PortHoppingPlan) -> Result<(), PortRouterError> {
            self.reconcile_inner(desired)
        }

        fn close(&self) -> Result<(), PortRouterError> {
            if let Some(events) = &self.events {
                events.lock().unwrap().push("port-close");
            }
            self.reconcile_inner(&PortHoppingPlan::default())
        }
    }

    #[derive(Default)]
    struct RuntimeState {
        apply_calls: usize,
        successful_applies: Vec<Vec<u8>>,
        reload_calls: usize,
        apply_errors: VecDeque<RuntimeError>,
        reload_errors: VecDeque<RuntimeError>,
        current: Vec<u8>,
    }

    struct ApplyGate {
        entered: Notify,
        permit: Semaphore,
    }

    #[derive(Default)]
    struct FakeRuntime {
        state: Mutex<RuntimeState>,
        gate: Option<Arc<ApplyGate>>,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
        close_calls: AtomicUsize,
    }

    impl FakeRuntime {
        fn queue_apply_error(&self, error: RuntimeError) {
            self.state.lock().unwrap().apply_errors.push_back(error);
        }

        fn queue_reload_error(&self, error: RuntimeError) {
            self.state.lock().unwrap().reload_errors.push_back(error);
        }

        fn apply_calls(&self) -> usize {
            self.state.lock().unwrap().apply_calls
        }

        fn reload_calls(&self) -> usize {
            self.state.lock().unwrap().reload_calls
        }
    }

    #[async_trait]
    impl NodeRuntime for FakeRuntime {
        async fn apply_config(&self, config: RuntimeConfig) -> Result<(), RuntimeError> {
            {
                let mut state = self.state.lock().unwrap();
                state.apply_calls += 1;
                if let Some(error) = state.apply_errors.pop_front() {
                    return Err(error);
                }
            }
            if let Some(gate) = &self.gate {
                gate.entered.notify_one();
                gate.permit.acquire().await.unwrap().forget();
            }
            let mut state = self.state.lock().unwrap();
            state.current = config.diagnostic_yaml.clone();
            state.successful_applies.push(config.diagnostic_yaml);
            Ok(())
        }

        async fn reload_config(&self, config: RuntimeConfig) -> Result<ReloadStatus, RuntimeError> {
            let mut state = self.state.lock().unwrap();
            state.reload_calls += 1;
            if let Some(error) = state.reload_errors.pop_front() {
                return Err(error);
            }
            state.current = config.diagnostic_yaml;
            Ok(ReloadStatus {
                running: true,
                rolled_back: false,
            })
        }

        fn current_config(&self) -> Vec<u8> {
            self.state.lock().unwrap().current.clone()
        }

        async fn close(&self) -> Result<(), RuntimeError> {
            if let Some(events) = &self.events {
                events.lock().unwrap().push("runtime-close");
            }
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn connection_stats(&self, _node_id: &str) -> ConnectionStats {
            ConnectionStats::default()
        }

        async fn close_user_connections(&self, _node_id: &str, _user_id: &str) -> u64 {
            0
        }

        async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
            Ok(Vec::new())
        }
    }

    fn topology(revision: u64, hopping: &str) -> MachineTopology {
        MachineTopology {
            machine_id: "machine-1".into(),
            revision,
            nodes: vec![NodeInstance {
                node_id: "node-hysteria".into(),
                provider_id: HYSTERIA2_SALAMANDER_ID.into(),
                provider_config_version: CURRENT_CONFIG_VERSION,
                provider_config: RawJson::from(json!({
                    "type": "hysteria2",
                    "tag": "node-hysteria",
                    "listen": "127.0.0.1",
                    "listen_port": 8443,
                    "port_hopping": hopping,
                    "obfs": {"type": "salamander", "password": "secret"},
                    "tls": {
                        "enabled": true,
                        "server_name": "example.com",
                        "certificate_pem": "certificate",
                        "private_key_pem": "private-key"
                    }
                })),
                users: vec![UserCredential {
                    user_id: "user-1".into(),
                    credential: "password".into(),
                    ..UserCredential::default()
                }],
            }],
            ..MachineTopology::default()
        }
    }

    fn expected_plan(hopping: u16) -> PortHoppingPlan {
        PortHoppingPlan {
            redirects: vec![Redirect {
                node_id: "node-hysteria".into(),
                listen_port: 8443,
                ports: vec![PortRange::new(hopping, hopping)],
            }],
        }
    }

    fn fixture() -> (
        Arc<TopologyManager>,
        Arc<NodeRuntimeTopologyAdapter>,
        Arc<FakeRuntime>,
        Arc<FakeRouter>,
    ) {
        let runtime = Arc::new(FakeRuntime::default());
        let router = Arc::new(FakeRouter::default());
        let adapter = Arc::new(NodeRuntimeTopologyAdapter::with_router(
            runtime.clone(),
            router.clone(),
        ));
        let manager = Arc::new(TopologyManager::new("machine-1", adapter.clone()));
        (manager, adapter, runtime, router)
    }

    #[tokio::test]
    async fn ordinary_and_uncertain_port_failures_preserve_previous_transaction() {
        let (manager, _adapter, runtime, router) = fixture();
        manager.apply_initial(topology(1, "20000")).await.unwrap();

        router.queue([RouterOutcome::Ordinary]);
        let ordinary = manager
            .apply_initial(topology(2, "30000"))
            .await
            .unwrap_err();
        assert!(!ordinary.rolled_back());
        assert_eq!(runtime.apply_calls(), 1);
        assert_eq!(manager.current_revision(), Some(1));
        assert_eq!(router.committed(), expected_plan(20000));

        router.queue([RouterOutcome::Uncertain, RouterOutcome::Pass]);
        let uncertain = manager
            .apply_initial(topology(3, "40000"))
            .await
            .unwrap_err();
        assert!(uncertain.rolled_back(), "{uncertain}");
        assert_eq!(runtime.apply_calls(), 1);
        assert_eq!(manager.current_revision(), Some(1));
        assert_eq!(router.committed(), expected_plan(20000));
        let plans = router.plans();
        assert_eq!(plans[plans.len() - 2], expected_plan(40000));
        assert_eq!(plans[plans.len() - 1], expected_plan(20000));
    }

    #[tokio::test]
    async fn runtime_failure_restores_runtime_and_reports_port_rollback_failure() {
        let (manager, adapter, runtime, router) = fixture();
        manager.apply_initial(topology(1, "20000")).await.unwrap();
        let warnings = adapter.warnings();
        runtime.queue_apply_error(RuntimeError::external(
            "candidate runtime rejected",
            false,
            false,
            true,
        ));
        router.queue([RouterOutcome::Pass, RouterOutcome::Ordinary]);

        let error = manager
            .apply_initial(topology(2, "30000"))
            .await
            .unwrap_err();
        assert!(!error.rolled_back());
        assert!(error.running());
        assert!(error.to_string().contains("rollback incomplete"));
        assert_eq!(runtime.apply_calls(), 3, "initial, candidate, restore");
        assert_eq!(manager.current_revision(), Some(1));
        assert_eq!(adapter.warnings(), warnings, "failed warnings leaked");
    }

    async fn reload_with(
        runtime_error: RuntimeError,
        restore_error: Option<RuntimeError>,
    ) -> (TopologyReloadResult, Arc<FakeRuntime>, Arc<FakeRouter>) {
        let (manager, _adapter, runtime, router) = fixture();
        manager.apply_initial(topology(1, "20000")).await.unwrap();
        runtime.queue_reload_error(runtime_error);
        if let Some(error) = restore_error {
            runtime.queue_apply_error(error);
        }
        let result = manager
            .reload_from(
                |_reporter| async { Ok::<_, String>(topology(2, "30000")) },
                None,
            )
            .await;
        assert_eq!(manager.current_revision(), Some(1));
        (result, runtime, router)
    }

    #[tokio::test]
    async fn forced_reload_classifies_unchanged_rolled_back_and_stopped_without_double_apply() {
        let (unchanged, runtime, _) = reload_with(
            RuntimeError::external("replacement rejected", false, true, true),
            None,
        )
        .await;
        assert_eq!(unchanged.outcome, ReloadOutcome::FailedUnchanged);
        assert_eq!(unchanged.stage, ReloadStage::StartInstance);
        assert_eq!(runtime.reload_calls(), 1);
        assert_eq!(
            runtime.apply_calls(),
            1,
            "reload must not call ordinary apply"
        );

        let (rolled_back, runtime, _) = reload_with(
            RuntimeError::external("replacement failed", true, false, true),
            None,
        )
        .await;
        assert_eq!(rolled_back.outcome, ReloadOutcome::FailedRolledBack);
        assert_eq!(rolled_back.stage, ReloadStage::Rollback);
        assert_eq!(runtime.reload_calls(), 1);

        let (partial_candidate, runtime, _) = reload_with(
            RuntimeError::external("replacement left a partial topology", false, false, true),
            None,
        )
        .await;
        assert_eq!(partial_candidate.outcome, ReloadOutcome::FailedRolledBack);
        assert_eq!(partial_candidate.stage, ReloadStage::Rollback);
        assert_eq!(runtime.reload_calls(), 1);
        assert_eq!(
            runtime.apply_calls(),
            2,
            "a live fragment is not proof that the previous topology was restored"
        );

        let (stopped, runtime, _) = reload_with(
            RuntimeError::external("replacement stopped", false, false, false),
            Some(RuntimeError::external(
                "previous runtime would not start",
                false,
                false,
                false,
            )),
        )
        .await;
        assert_eq!(stopped.outcome, ReloadOutcome::FailedStopped);
        assert_eq!(stopped.stage, ReloadStage::Rollback);
        assert!(stopped.message.contains("previous runtime would not start"));
        assert_eq!(runtime.reload_calls(), 1);
    }

    #[tokio::test]
    async fn successful_reload_commits_once_and_warning_is_visible_in_ack_message() {
        let (manager, adapter, runtime, router) = fixture();
        let initial = manager.apply_initial(topology(1, "20000")).await.unwrap();
        assert!(initial.contains("warnings:"), "{initial}");
        assert!(initial.contains("port_hopping"), "{initial}");

        let result = manager
            .reload_from(
                |_reporter| async { Ok::<_, String>(topology(2, "30000")) },
                None,
            )
            .await;
        assert_eq!(result.outcome, ReloadOutcome::Succeeded);
        assert!(result.message.contains("warnings:"), "{}", result.message);
        assert_eq!(runtime.reload_calls(), 1);
        assert_eq!(runtime.apply_calls(), 1, "successful reload applied twice");
        assert_eq!(manager.current_revision(), Some(2));
        assert_eq!(router.committed(), expected_plan(30000));
        assert!(adapter.warnings()[0].contains("30000"));
    }

    #[tokio::test]
    async fn digest_hit_reconciles_current_plan_without_restarting_runtime() {
        let (manager, _adapter, runtime, router) = fixture();
        manager.apply_initial(topology(1, "20000")).await.unwrap();
        manager.reconcile_current().await.unwrap();
        assert_eq!(runtime.apply_calls(), 1);
        let plans = router.plans();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0], plans[1]);
    }

    #[tokio::test]
    async fn close_orders_port_cleanup_before_runtime_close() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = Arc::new(FakeRuntime {
            events: Some(events.clone()),
            ..FakeRuntime::default()
        });
        let router = Arc::new(FakeRouter {
            events: Some(events.clone()),
            ..FakeRouter::default()
        });
        let adapter = Arc::new(NodeRuntimeTopologyAdapter::with_router(runtime, router));
        let manager = TopologyManager::new("machine-1", adapter);
        manager.close().await.unwrap();
        assert_eq!(*events.lock().unwrap(), ["port-close", "runtime-close"]);
    }

    #[tokio::test]
    async fn dropping_apply_caller_does_not_strand_port_and_runtime_states() {
        let gate = Arc::new(ApplyGate {
            entered: Notify::new(),
            permit: Semaphore::new(0),
        });
        let runtime = Arc::new(FakeRuntime {
            gate: Some(gate.clone()),
            ..FakeRuntime::default()
        });
        let router = Arc::new(FakeRouter::default());
        let adapter = Arc::new(NodeRuntimeTopologyAdapter::with_router(
            runtime.clone(),
            router.clone(),
        ));
        let manager = Arc::new(TopologyManager::new("machine-1", adapter.clone()));
        let entered = gate.entered.notified();
        let apply_manager = manager.clone();
        let caller =
            tokio::spawn(async move { apply_manager.apply_initial(topology(1, "20000")).await });
        entered.await;
        assert_eq!(router.committed(), expected_plan(20000));
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        gate.permit.add_permits(1);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager.current_revision() == Some(1) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned composite apply did not finish");
        assert_eq!(runtime.apply_calls(), 1);
        assert_eq!(manager.current_revision(), Some(1));
        assert_eq!(adapter.state().active_plan, expected_plan(20000));
        assert_eq!(router.committed(), expected_plan(20000));
    }

    #[tokio::test]
    async fn dropping_user_refresh_caller_still_publishes_the_applied_runtime() {
        let gate = Arc::new(ApplyGate {
            entered: Notify::new(),
            permit: Semaphore::new(0),
        });
        let runtime = Arc::new(FakeRuntime {
            gate: Some(gate.clone()),
            ..FakeRuntime::default()
        });
        let router = Arc::new(FakeRouter::default());
        let adapter = Arc::new(NodeRuntimeTopologyAdapter::with_router(
            runtime.clone(),
            router.clone(),
        ));
        let manager = Arc::new(TopologyManager::new("machine-1", adapter.clone()));

        let initial_entered = gate.entered.notified();
        let initial_manager = manager.clone();
        let initial =
            tokio::spawn(async move { initial_manager.apply_initial(topology(1, "20000")).await });
        initial_entered.await;
        gate.permit.add_permits(1);
        initial.await.unwrap().unwrap();

        let expected = manager.loaded_users("node-hysteria").await.unwrap();
        let mut desired = expected.clone();
        desired[0].credential = "replacement-password".into();
        let refresh_entered = gate.entered.notified();
        let refresh_manager = manager.clone();
        let caller = tokio::spawn(async move {
            refresh_manager
                .refresh_node_users_if_current_at_revision("node-hysteria", desired, expected, 0)
                .await
        });
        refresh_entered.await;
        assert_eq!(
            adapter.state().active_topology.nodes[0].users[0].credential,
            "password",
            "adapter publication must wait for the gated runtime"
        );
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        gate.permit.add_permits(1);

        let users = tokio::time::timeout(
            Duration::from_secs(1),
            manager.loaded_users("node-hysteria"),
        )
        .await
        .expect("owned user refresh did not finish")
        .unwrap();
        assert_eq!(users[0].credential, "replacement-password");
        assert_eq!(
            adapter.state().active_topology,
            manager.current_topology(),
            "runtime adapter and manager publication diverged"
        );
        let expected_config = crate::compile::compile(&manager.current_topology())
            .unwrap()
            .diagnostic_yaml;
        assert_eq!(runtime.current_config(), expected_config);
        assert_eq!(router.committed(), expected_plan(20000));
    }
}
