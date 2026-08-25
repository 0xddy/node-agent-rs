//! Transactional glue between compiled ACP topology and [`shoes_engine::Engine`].
//!
//! `Engine` deliberately exposes small, individually atomic operations.  A panel
//! topology is larger than one such operation, so this module owns the missing
//! transaction boundary: it serialises applies, retains every credential needed
//! for rollback, journals inverse operations, and does not publish a new diagnostic
//! snapshot until the whole change has committed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use shoes_api::{InboundSpec, UserInfo, UserSpec};
use shoes_engine::{Engine, EngineError};
use tokio_util::sync::CancellationToken;

use crate::rule_set::{RuleSetLoader, RuleSetResource, RuleSetSource};

/// One shoes inbound produced by the topology compiler.
///
/// `spec` is retained in full, including user credentials.  The engine quite
/// correctly never echoes credentials through `UserInfo`, so a runtime that kept
/// only engine status would be unable to roll a failed transaction back.
#[derive(Debug, Clone)]
pub struct CompiledInbound {
    pub node_id: String,
    pub protocol: String,
    pub spec: InboundSpec,
}

/// A complete candidate for the running data plane.
#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    pub inbounds: Vec<CompiledInbound>,
    /// Local/remote rule-set files that must exist before the candidate is
    /// handed to shoes for validation.
    pub rule_sets: Vec<RuleSetResource>,
    /// The equivalent shoes YAML shown by `SingBoxConfigRequest`.
    pub diagnostic_yaml: Vec<u8>,
}

/// Current connection counts for one panel node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    pub active_connections: u64,
    pub online_users: u64,
}

/// Outcome of a successful forced reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReloadStatus {
    pub running: bool,
    pub rolled_back: bool,
}

/// Traffic atomically removed from an engine user counter.
///
/// Engine directions are from the proxy's point of view (`rx`/`tx`); ACP names
/// them from the client's point of view, hence the explicit mapping below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficDrain {
    pub inbound_tag: String,
    pub node_id: String,
    pub protocol: String,
    pub user_id: String,
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    /// Time of the last actual byte observation represented by the engine
    /// counter. `None` is reserved for a generation that never carried bytes.
    pub observed_at: Option<SystemTime>,
}

/// A failed runtime operation and, independently, any failure while restoring the
/// previously published state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError {
    operation: String,
    rollback: Option<String>,
    rolled_back: bool,
    state_unchanged: bool,
    running: bool,
}

impl RuntimeError {
    /// Classification constructor for alternate [`NodeRuntime`]
    /// implementations and transaction adapters.
    pub fn external(
        operation: impl Into<String>,
        rolled_back: bool,
        state_unchanged: bool,
        running: bool,
    ) -> Self {
        Self {
            operation: operation.into(),
            rollback: None,
            rolled_back,
            state_unchanged,
            running,
        }
    }

    fn unchanged(operation: impl Into<String>, running: bool) -> Self {
        Self {
            operation: operation.into(),
            rollback: None,
            rolled_back: false,
            state_unchanged: true,
            running,
        }
    }

    fn failed(
        operation: impl Into<String>,
        rollback: Vec<String>,
        rolled_back: bool,
        state_unchanged: bool,
        running: bool,
    ) -> Self {
        Self {
            operation: operation.into(),
            rollback: (!rollback.is_empty()).then(|| rollback.join("; ")),
            rolled_back,
            state_unchanged,
            running,
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn rollback_error(&self) -> Option<&str> {
        self.rollback.as_deref()
    }

    /// True only when a non-empty topology published before the operation had to
    /// be restored.  Restoring an empty initial state remains a plain failure, in
    /// line with the ACP/Go acknowledgement semantics.
    pub fn rolled_back(&self) -> bool {
        self.rolled_back
    }

    /// True for validation and other preflight failures that made no live change.
    pub fn state_unchanged(&self) -> bool {
        self.state_unchanged
    }

    pub fn running(&self) -> bool {
        self.running
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.operation)?;
        if let Some(rollback) = &self.rollback {
            write!(f, "; rollback failed: {rollback}")?;
        } else if self.rolled_back {
            write!(f, "; previous runtime state restored")?;
        }
        Ok(())
    }
}

impl std::error::Error for RuntimeError {}

/// The data-plane operations consumed by the topology and remote-control layers.
///
/// Mutating methods are async because removing a user waits until its connections
/// have closed.  Implementations must remain cancellation safe: dropping the caller's
/// future must not strand half a topology.  [`ShoesRuntime`] accomplishes that by
/// running each mutation in an owned task behind one apply mutex.
#[async_trait]
pub trait NodeRuntime: Send + Sync {
    async fn apply_config(&self, config: RuntimeConfig) -> Result<(), RuntimeError>;
    async fn reload_config(&self, config: RuntimeConfig) -> Result<ReloadStatus, RuntimeError>;
    fn current_config(&self) -> Vec<u8>;
    async fn close(&self) -> Result<(), RuntimeError>;
    fn connection_stats(&self, node_id: &str) -> ConnectionStats;
    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64;

    /// Takes both queued tail counters and every live user's current counters.
    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError>;
}

#[derive(Clone)]
pub struct ShoesRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    engine: Engine,
    rule_sets: RuleSetLoader,
    apply: tokio::sync::Mutex<()>,
    rule_set_watcher: Mutex<RuleSetWatcherState>,
    state: RwLock<AppliedState>,
    /// Final counters from users whose registry entry no longer exists.  Keeping
    /// them here until `drain_traffic` takes them closes the remove-vs-flush hole.
    pending_traffic: Mutex<Vec<TrafficDrain>>,
}

#[derive(Default)]
struct RuleSetWatcherState {
    generation: u64,
    cancel: Option<CancellationToken>,
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        let watcher = self
            .rule_set_watcher
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cancel) = watcher.cancel.take() {
            cancel.cancel();
        }
    }
}

#[derive(Clone)]
struct NormalizedInbound {
    compiled: CompiledInbound,
    users: BTreeMap<String, UserSpec>,
    dynamic_users: bool,
}

#[derive(Clone, Default)]
struct NormalizedConfig {
    inbounds: BTreeMap<String, NormalizedInbound>,
    /// Digest of the prepared rule-set bytes, independent of their stable
    /// cache paths. A content refresh must rebuild selectors even when the ACP
    /// topology JSON itself is byte-for-byte unchanged.
    rule_set_digest: [u8; 32],
    diagnostic_yaml: Vec<u8>,
}

struct AppliedState {
    /// `None` means a rollback failed and the live engine must be reconciled from
    /// `recovery` before another topology can be applied.
    current: Option<NormalizedConfig>,
    recovery: Option<NormalizedConfig>,
    closed: bool,
}

impl Default for AppliedState {
    fn default() -> Self {
        Self {
            current: Some(NormalizedConfig::default()),
            recovery: None,
            closed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigDiff {
    removed: Vec<String>,
    added: Vec<String>,
    changed: Vec<InboundDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InboundDelta {
    tag: String,
    config_changed: bool,
    user_mode_changed: bool,
    removed_users: Vec<String>,
    upsert_users: Vec<UserDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UserDelta {
    id: String,
    added: bool,
    credential_changed: bool,
}

enum Undo {
    AddInbound(NormalizedInbound),
    RemoveInbound(NormalizedInbound),
    RestoreHotConfig {
        current: NormalizedInbound,
        previous: NormalizedInbound,
    },
    ReplaceBack {
        current: NormalizedInbound,
        previous: NormalizedInbound,
    },
    AddUser {
        inbound: NormalizedInbound,
        user: UserSpec,
    },
    RemoveUser {
        inbound: NormalizedInbound,
        user_id: String,
    },
    RestoreUser {
        inbound: NormalizedInbound,
        user: UserSpec,
        kick: bool,
    },
}

struct StepFailure {
    operation: String,
    rollback: Vec<String>,
    /// Whether this step changed live state before attempting its local restore.
    changed: bool,
    restored: bool,
}

impl StepFailure {
    fn unchanged(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            rollback: Vec::new(),
            changed: false,
            restored: true,
        }
    }
}

impl ShoesRuntime {
    pub async fn bootstrap() -> Result<Self, RuntimeError> {
        let engine = Engine::bootstrap()
            .await
            .map_err(|error| RuntimeError::unchanged(format!("bootstrap shoes: {error}"), false))?;
        Ok(Self::from_engine(engine))
    }

    pub fn from_engine(engine: Engine) -> Self {
        let rule_sets = RuleSetLoader::new()
            .expect("the fixed node-agent rule-set HTTP client configuration is valid");
        Self {
            inner: Arc::new(RuntimeInner {
                engine,
                rule_sets,
                apply: tokio::sync::Mutex::new(()),
                rule_set_watcher: Mutex::new(RuleSetWatcherState::default()),
                state: RwLock::new(AppliedState::default()),
                pending_traffic: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Exposed for status/diagnostic wiring, not for topology mutations.
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }

    /// Apply a control-plane candidate and, only after it commits, replace the
    /// remote rule-set refresh generation. Holding the apply mutex across both
    /// steps prevents a retiring watcher from reacquiring it in the commit-to-
    /// watcher handoff window and publishing its older topology.
    async fn apply_external_owned(
        &self,
        config: RuntimeConfig,
        force_reload: bool,
    ) -> Result<(), RuntimeError> {
        let watcher_config = config.clone();
        let _apply = self.inner.apply.lock().await;
        let result = self.apply_transaction_locked(config, force_reload).await;
        if result.is_ok() {
            self.install_rule_set_watcher_locked(watcher_config);
        }
        result
    }

    /// The topology transaction itself. Callers must hold `inner.apply`.
    ///
    /// This method never installs or replaces a watcher. In particular the
    /// watcher can call it without constructing an asynchronously recursive
    /// apply -> schedule -> apply future.
    async fn apply_transaction_locked(
        &self,
        mut config: RuntimeConfig,
        force_reload: bool,
    ) -> Result<(), RuntimeError> {
        let resources = config.rule_sets.clone();
        if self.read_state().closed {
            return Err(RuntimeError::unchanged("runtime is closed", false));
        }

        let prepared = self
            .inner
            .rule_sets
            .prepare(&resources)
            .await
            .map_err(|error| {
                RuntimeError::unchanged(
                    format!("prepare route rule-set resources: {error}"),
                    !self.inner.engine.list_inbounds().is_empty(),
                )
            })?;
        for inbound in &mut config.inbounds {
            prepared.rewrite_config(&mut inbound.spec.config);
        }
        let mut desired = normalize(config).map_err(|error| {
            RuntimeError::unchanged(
                format!("normalize runtime config: {error}"),
                !self.inner.engine.list_inbounds().is_empty(),
            )
        })?;
        desired.rule_set_digest = prepared.digest;

        self.recover_if_needed().await?;
        let previous = self
            .read_state()
            .current
            .clone()
            .expect("recovery publishes a known state");

        // Validate every complete desired inbound before the first destructive
        // operation.  Address conflicts remain a start-time concern, but schema,
        // certificate and dynamic-user failures cannot take a healthy listener down.
        for inbound in desired.inbounds.values() {
            if let Err(error) = self
                .inner
                .engine
                .validate_inbound(&inbound.compiled.spec)
                .await
            {
                return Err(RuntimeError::unchanged(
                    format!("validate inbound {}: {error}", inbound.compiled.spec.tag),
                    !self.inner.engine.list_inbounds().is_empty(),
                ));
            }
        }

        let transaction = if force_reload {
            self.execute_reload(&previous, &desired).await
        } else {
            self.execute_apply(&previous, &desired).await
        };

        match transaction {
            Ok(()) => {
                // Candidate selectors already point at immutable snapshots. Only
                // now, after shoes preflight and the live transaction both
                // succeeded, advance the restart-time stable last-good cache.
                // A durability failure must not roll back an otherwise healthy
                // live topology; the previous stable cache remains usable and
                // the watcher will retry the stale resource.
                if let Err(error) = prepared.commit().await {
                    log::error!("commit route rule-set last-good cache: {error}");
                }
                let mut state = self.write_state();
                state.current = Some(desired);
                state.recovery = None;
                Ok(())
            }
            Err((failure, journal)) => Err(self
                .finish_failed_transaction(previous, failure, journal)
                .await),
        }
    }

    fn rule_set_watcher(&self) -> MutexGuard<'_, RuleSetWatcherState> {
        self.inner
            .rule_set_watcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Replace the watcher generation after a successful external transaction.
    /// The caller holds `inner.apply`, making generation publication atomic with
    /// respect to watcher refresh transactions.
    fn install_rule_set_watcher_locked(&self, config: RuntimeConfig) {
        let interval = config
            .rule_sets
            .iter()
            .filter_map(|resource| {
                matches!(resource.source, RuleSetSource::Remote { .. })
                    .then_some(resource.update_interval)
            })
            .min();

        let (generation, cancel, interval) = {
            let mut watcher = self.rule_set_watcher();
            watcher.generation = watcher.generation.wrapping_add(1);
            if let Some(previous) = watcher.cancel.take() {
                previous.cancel();
            }
            let Some(interval) = interval else {
                return;
            };
            if interval.is_zero() {
                log::error!("remote route rule-set update interval cannot be zero");
                return;
            }
            let cancel = CancellationToken::new();
            watcher.cancel = Some(cancel.clone());
            (watcher.generation, cancel, interval)
        };

        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(run_rule_set_watcher(
            weak, generation, cancel, interval, config,
        ));
    }

    fn cancel_rule_set_watcher_locked(&self) {
        let mut watcher = self.rule_set_watcher();
        watcher.generation = watcher.generation.wrapping_add(1);
        if let Some(cancel) = watcher.cancel.take() {
            cancel.cancel();
        }
    }

    fn rule_set_watcher_is_active(&self, generation: u64) -> bool {
        let watcher = self.rule_set_watcher();
        watcher.generation == generation
            && watcher
                .cancel
                .as_ref()
                .is_some_and(|cancel| !cancel.is_cancelled())
    }

    /// Run one watcher refresh without changing watcher scheduling. `None`
    /// means this generation retired while it was sleeping or waiting for the
    /// apply mutex; `Some` is the outcome of the refresh transaction itself.
    async fn refresh_rule_sets_owned(
        &self,
        generation: u64,
        config: RuntimeConfig,
    ) -> Option<Result<(), RuntimeError>> {
        let _apply = self.inner.apply.lock().await;
        if !self.rule_set_watcher_is_active(generation) || self.read_state().closed {
            return None;
        }
        Some(self.apply_transaction_locked(config, false).await)
    }

    fn read_state(&self) -> RwLockReadGuard<'_, AppliedState> {
        self.inner
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, AppliedState> {
        self.inner
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn pending_traffic(&self) -> MutexGuard<'_, Vec<TrafficDrain>> {
        self.inner
            .pending_traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn queue_traffic(&self, inbound: &NormalizedInbound, info: UserInfo) {
        self.pending_traffic().push(traffic_drain(inbound, info));
    }

    async fn execute_apply(
        &self,
        current: &NormalizedConfig,
        desired: &NormalizedConfig,
    ) -> Result<(), (StepFailure, Vec<Undo>)> {
        let diff = diff_configs(current, desired);
        let mut journal = Vec::new();

        // Deletions go first so an added or moved inbound may legitimately claim
        // one of their ports.  Every deletion is journalled before the next starts.
        for tag in &diff.removed {
            let old = current.inbounds.get(tag).expect("diff tag exists").clone();
            if let Err(failure) = self.stop_inbound(&old).await {
                return Err((failure, journal));
            }
            journal.push(Undo::AddInbound(old));
        }

        for delta in &diff.changed {
            let old = current
                .inbounds
                .get(&delta.tag)
                .expect("diff tag exists")
                .clone();
            let new = desired
                .inbounds
                .get(&delta.tag)
                .expect("diff tag exists")
                .clone();

            let mut replaced = false;
            if delta.user_mode_changed {
                if let Err(failure) = self.replace_inbound(&old, &new).await {
                    return Err((failure, journal));
                }
                journal.push(Undo::ReplaceBack {
                    current: new.clone(),
                    previous: old.clone(),
                });
                replaced = true;
            } else if delta.config_changed {
                match self.inner.engine.update_inbound(update_spec(&new)).await {
                    Ok(_) => journal.push(Undo::RestoreHotConfig {
                        current: new.clone(),
                        previous: old.clone(),
                    }),
                    Err(EngineError::ReloadRequired(_)) => {
                        // The complete candidate was already validated before the
                        // transaction began; only binding can now fail.
                        if let Err(failure) = self.replace_inbound(&old, &new).await {
                            return Err((failure, journal));
                        }
                        journal.push(Undo::ReplaceBack {
                            current: new.clone(),
                            previous: old.clone(),
                        });
                        replaced = true;
                    }
                    Err(error) => {
                        return Err((
                            StepFailure::unchanged(format!(
                                "update inbound {}: {error}",
                                delta.tag
                            )),
                            journal,
                        ));
                    }
                }
            }

            // A replacement was created from the complete desired InboundSpec, so
            // its registry already contains the desired user set.
            if replaced {
                continue;
            }

            // Retire first.  Besides making revocation immediate, this frees a
            // credential that the same transaction may intentionally assign to a
            // newly added user.
            for id in &delta.removed_users {
                let old_user = old.users.get(id).expect("diff user exists").clone();
                match self.inner.engine.remove_user(&delta.tag, id).await {
                    Ok(info) => {
                        self.queue_traffic(&old, info);
                        journal.push(Undo::AddUser {
                            inbound: old.clone(),
                            user: old_user,
                        });
                    }
                    Err(error) => {
                        return Err((
                            StepFailure::unchanged(format!(
                                "remove user {id} from {}: {error}",
                                delta.tag
                            )),
                            journal,
                        ));
                    }
                }
            }

            for change in &delta.upsert_users {
                let new_user = new.users.get(&change.id).expect("diff user exists").clone();
                if let Err(error) = self.inner.engine.add_user(&delta.tag, new_user) {
                    return Err((
                        StepFailure::unchanged(format!(
                            "upsert user {} on {}: {error}",
                            change.id, delta.tag
                        )),
                        journal,
                    ));
                }

                if change.added {
                    journal.push(Undo::RemoveUser {
                        inbound: new.clone(),
                        user_id: change.id.clone(),
                    });
                } else {
                    journal.push(Undo::RestoreUser {
                        inbound: old.clone(),
                        user: old
                            .users
                            .get(&change.id)
                            .expect("updated user existed")
                            .clone(),
                        // Rolling the credential back must also evict sessions that
                        // authenticated during the candidate window.
                        kick: change.credential_changed,
                    });
                }

                if change.credential_changed
                    && let Err(error) = self.inner.engine.kick_user(&delta.tag, &change.id)
                {
                    return Err((
                        StepFailure::unchanged(format!(
                            "kick stale sessions for user {} on {}: {error}",
                            change.id, delta.tag
                        )),
                        journal,
                    ));
                }
            }
        }

        for tag in &diff.added {
            let new = desired.inbounds.get(tag).expect("diff tag exists").clone();
            if let Err(error) = self
                .inner
                .engine
                .add_inbound(new.compiled.spec.clone())
                .await
            {
                return Err((
                    StepFailure::unchanged(format!("add inbound {tag}: {error}")),
                    journal,
                ));
            }
            journal.push(Undo::RemoveInbound(new));
        }

        Ok(())
    }

    async fn execute_reload(
        &self,
        current: &NormalizedConfig,
        desired: &NormalizedConfig,
    ) -> Result<(), (StepFailure, Vec<Undo>)> {
        let mut journal = Vec::new();

        // A forced reload rebuilds listeners even when the compiled values compare
        // equal.  This is the semantic used by the remote reload operation.
        for old in current.inbounds.values() {
            if let Err(failure) = self.stop_inbound(old).await {
                return Err((failure, journal));
            }
            journal.push(Undo::AddInbound(old.clone()));
        }
        for new in desired.inbounds.values() {
            if let Err(error) = self
                .inner
                .engine
                .add_inbound(new.compiled.spec.clone())
                .await
            {
                return Err((
                    StepFailure::unchanged(format!(
                        "start reloaded inbound {}: {error}",
                        new.compiled.spec.tag
                    )),
                    journal,
                ));
            }
            journal.push(Undo::RemoveInbound(new.clone()));
        }
        Ok(())
    }

    async fn replace_inbound(
        &self,
        old: &NormalizedInbound,
        new: &NormalizedInbound,
    ) -> Result<(), StepFailure> {
        self.stop_inbound(old).await?;
        match self
            .inner
            .engine
            .add_inbound(new.compiled.spec.clone())
            .await
        {
            Ok(_) => Ok(()),
            Err(operation) => match self
                .inner
                .engine
                .add_inbound(old.compiled.spec.clone())
                .await
            {
                Ok(_) => Err(StepFailure {
                    operation: format!(
                        "start replacement inbound {}: {operation}",
                        new.compiled.spec.tag
                    ),
                    rollback: Vec::new(),
                    changed: true,
                    restored: true,
                }),
                Err(rollback) => Err(StepFailure {
                    operation: format!(
                        "start replacement inbound {}: {operation}",
                        new.compiled.spec.tag
                    ),
                    rollback: vec![format!(
                        "restore inbound {}: {rollback}",
                        old.compiled.spec.tag
                    )],
                    changed: true,
                    restored: false,
                }),
            },
        }
    }

    /// Removes every live user before removing the listener, preserving their final
    /// counters and making the operation locally reversible if listener shutdown
    /// itself fails.
    async fn stop_inbound(&self, inbound: &NormalizedInbound) -> Result<(), StepFailure> {
        let tag = &inbound.compiled.spec.tag;
        let live_users = match self.inner.engine.list_users(tag) {
            Ok(users) => users,
            Err(EngineError::Unsupported(_)) => Vec::new(),
            Err(error) => {
                return Err(StepFailure::unchanged(format!(
                    "list users before removing inbound {tag}: {error}"
                )));
            }
        };

        let mut removed = Vec::new();
        for live in live_users {
            let Some(spec) = inbound.users.get(&live.id).cloned() else {
                let rollback = self.restore_users(tag, &removed);
                return Err(StepFailure {
                    operation: format!(
                        "cannot remove inbound {tag}: live user {} is absent from AppliedState",
                        live.id
                    ),
                    changed: !removed.is_empty(),
                    restored: rollback.is_empty(),
                    rollback,
                });
            };
            match self.inner.engine.remove_user(tag, &live.id).await {
                Ok(info) => {
                    self.queue_traffic(inbound, info);
                    removed.push(spec);
                }
                Err(error) => {
                    let rollback = self.restore_users(tag, &removed);
                    return Err(StepFailure {
                        operation: format!(
                            "remove user {} before stopping inbound {tag}: {error}",
                            live.id
                        ),
                        changed: !removed.is_empty(),
                        restored: rollback.is_empty(),
                        rollback,
                    });
                }
            }
        }

        if let Err(error) = self.inner.engine.remove_inbound(tag).await {
            let rollback = self.restore_users(tag, &removed);
            return Err(StepFailure {
                operation: format!("remove inbound {tag}: {error}"),
                changed: !removed.is_empty(),
                restored: rollback.is_empty(),
                rollback,
            });
        }
        Ok(())
    }

    fn restore_users(&self, tag: &str, users: &[UserSpec]) -> Vec<String> {
        let mut errors = Vec::new();
        for user in users.iter().rev() {
            let id = user.resolved_id().unwrap_or("<unknown>");
            if let Err(error) = self.inner.engine.add_user(tag, user.clone()) {
                errors.push(format!("restore user {id} on {tag}: {error}"));
            }
        }
        errors
    }

    async fn finish_failed_transaction(
        &self,
        previous: NormalizedConfig,
        failure: StepFailure,
        mut journal: Vec<Undo>,
    ) -> RuntimeError {
        let restoration_attempted = failure.changed || !journal.is_empty();
        let had_previous_topology = !previous.inbounds.is_empty();
        let mut rollback = failure.rollback;
        rollback.extend(self.rollback_journal(&mut journal).await);
        let fully_restored = failure.restored && rollback.is_empty();
        let rolled_back = fully_restored && restoration_attempted && had_previous_topology;
        let state_unchanged = fully_restored && !restoration_attempted;

        let mut state = self.write_state();
        // `rolled_back` follows the ACP/Go wire meaning and is only true when a
        // non-empty published topology had to be restored.  State bookkeeping is
        // broader: a preflight/first-step failure and a transaction that restored
        // an empty topology are both fully known as well.
        if fully_restored {
            state.current = Some(previous);
            state.recovery = None;
        } else {
            state.current = None;
            state.recovery = Some(previous);
        }
        drop(state);

        RuntimeError::failed(
            failure.operation,
            rollback,
            rolled_back,
            state_unchanged,
            !self.inner.engine.list_inbounds().is_empty(),
        )
    }

    async fn rollback_journal(&self, journal: &mut Vec<Undo>) -> Vec<String> {
        let mut errors = Vec::new();
        while let Some(undo) = journal.pop() {
            let result = match undo {
                Undo::AddInbound(inbound) => self
                    .inner
                    .engine
                    .add_inbound(inbound.compiled.spec.clone())
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!("restore inbound {}: {error}", inbound.compiled.spec.tag)
                    }),
                Undo::RemoveInbound(inbound) => {
                    self.stop_inbound(&inbound).await.map_err(|failure| {
                        format!("remove candidate: {}", describe_step_failure(failure))
                    })
                }
                Undo::RestoreHotConfig { current, previous } => {
                    match self
                        .inner
                        .engine
                        .update_inbound(update_spec(&previous))
                        .await
                    {
                        Ok(_) => Ok(()),
                        Err(EngineError::ReloadRequired(_)) => self
                            .replace_inbound(&current, &previous)
                            .await
                            .map_err(describe_step_failure),
                        Err(error) => Err(format!(
                            "restore config for {}: {error}",
                            previous.compiled.spec.tag
                        )),
                    }
                }
                Undo::ReplaceBack { current, previous } => self
                    .replace_inbound(&current, &previous)
                    .await
                    .map_err(describe_step_failure),
                Undo::AddUser { inbound, user } => {
                    let id = user.resolved_id().unwrap_or("<unknown>").to_string();
                    self.inner
                        .engine
                        .add_user(&inbound.compiled.spec.tag, user)
                        .map(|_| ())
                        .map_err(|error| {
                            format!(
                                "restore user {id} on {}: {error}",
                                inbound.compiled.spec.tag
                            )
                        })
                }
                Undo::RemoveUser { inbound, user_id } => {
                    match self
                        .inner
                        .engine
                        .remove_user(&inbound.compiled.spec.tag, &user_id)
                        .await
                    {
                        Ok(info) => {
                            self.queue_traffic(&inbound, info);
                            Ok(())
                        }
                        Err(error) => Err(format!(
                            "remove candidate user {user_id} from {}: {error}",
                            inbound.compiled.spec.tag
                        )),
                    }
                }
                Undo::RestoreUser {
                    inbound,
                    user,
                    kick,
                } => {
                    let id = user.resolved_id().unwrap_or("<unknown>").to_string();
                    match self.inner.engine.add_user(&inbound.compiled.spec.tag, user) {
                        Err(error) => Err(format!(
                            "restore user {id} on {}: {error}",
                            inbound.compiled.spec.tag
                        )),
                        Ok(_) if kick => self
                            .inner
                            .engine
                            .kick_user(&inbound.compiled.spec.tag, &id)
                            .map(|_| ())
                            .map_err(|error| {
                                format!(
                                    "kick candidate sessions for {id} on {}: {error}",
                                    inbound.compiled.spec.tag
                                )
                            }),
                        Ok(_) => Ok(()),
                    }
                }
            };
            if let Err(error) = result {
                errors.push(error);
            }
        }
        errors
    }

    async fn recover_if_needed(&self) -> Result<(), RuntimeError> {
        let recovery = {
            let state = self.read_state();
            if state.current.is_some() {
                return Ok(());
            }
            state.recovery.clone().unwrap_or_default()
        };

        // A failed rollback leaves no trustworthy per-tag model.  Converge through
        // the one state we do know: stop everything the engine reports, then rebuild
        // the retained recovery configuration from complete specs.
        let mut errors = Vec::new();
        for info in self.inner.engine.list_inbounds() {
            let known = recovery.inbounds.get(&info.tag);
            if let Err(error) = self.force_stop_tag(&info.tag, known, &info.protocol).await {
                errors.push(error);
            }
        }
        if !errors.is_empty() {
            return Err(RuntimeError::failed(
                "clean up an indeterminate runtime before recovery",
                errors,
                false,
                false,
                !self.inner.engine.list_inbounds().is_empty(),
            ));
        }

        for inbound in recovery.inbounds.values() {
            if let Err(error) = self
                .inner
                .engine
                .add_inbound(inbound.compiled.spec.clone())
                .await
            {
                return Err(RuntimeError::failed(
                    format!(
                        "restore recovery inbound {}: {error}",
                        inbound.compiled.spec.tag
                    ),
                    Vec::new(),
                    false,
                    false,
                    !self.inner.engine.list_inbounds().is_empty(),
                ));
            }
        }

        let mut state = self.write_state();
        state.current = Some(recovery);
        state.recovery = None;
        Ok(())
    }

    async fn force_stop_tag(
        &self,
        tag: &str,
        known: Option<&NormalizedInbound>,
        fallback_protocol: &str,
    ) -> Result<(), String> {
        match self.inner.engine.list_users(tag) {
            Ok(users) => {
                for user in users {
                    let info =
                        self.inner
                            .engine
                            .remove_user(tag, &user.id)
                            .await
                            .map_err(|error| {
                                format!("remove user {} while stopping {tag}: {error}", user.id)
                            })?;
                    match known {
                        Some(inbound) => self.queue_traffic(inbound, info),
                        None => {
                            let observed_at = traffic_observed_at(&info);
                            self.pending_traffic().push(TrafficDrain {
                                inbound_tag: tag.to_string(),
                                node_id: tag.to_string(),
                                protocol: fallback_protocol.to_string(),
                                user_id: info.id,
                                uplink_bytes: info.rx,
                                downlink_bytes: info.tx,
                                observed_at,
                            });
                        }
                    }
                }
            }
            Err(EngineError::Unsupported(_)) => {}
            Err(error) => return Err(format!("list users while stopping {tag}: {error}")),
        }
        self.inner
            .engine
            .remove_inbound(tag)
            .await
            .map(|_| ())
            .map_err(|error| format!("remove inbound {tag}: {error}"))
    }

    async fn close_owned(&self) -> Result<(), RuntimeError> {
        let _apply = self.inner.apply.lock().await;
        self.cancel_rule_set_watcher_locked();
        let already_closed = self.read_state().closed;
        if already_closed && self.inner.engine.list_inbounds().is_empty() {
            let mut state = self.write_state();
            state.current = Some(NormalizedConfig::default());
            state.recovery = None;
            return Ok(());
        }

        let known = {
            let state = self.read_state();
            state.current.clone().or_else(|| state.recovery.clone())
        };
        let mut errors = Vec::new();
        for info in self.inner.engine.list_inbounds() {
            let inbound = known
                .as_ref()
                .and_then(|config| config.inbounds.get(&info.tag));
            if let Err(error) = self
                .force_stop_tag(&info.tag, inbound, &info.protocol)
                .await
            {
                errors.push(error);
            }
        }

        let mut state = self.write_state();
        state.closed = true;
        if errors.is_empty() {
            state.current = Some(NormalizedConfig::default());
            state.recovery = None;
        } else {
            // Applying is permanently forbidden once close begins, but a second
            // close must still be able to retry listeners that failed to stop.  Do
            // not publish an empty snapshot while any of them remain live.
            state.current = None;
            state.recovery = known;
        }
        drop(state);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(RuntimeError::failed(
                "close shoes runtime",
                errors,
                false,
                false,
                !self.inner.engine.list_inbounds().is_empty(),
            ))
        }
    }

    fn connection_stats_owned(&self, node_id: &str) -> ConnectionStats {
        if node_id.is_empty() {
            return ConnectionStats::default();
        }
        let state = self.read_state();
        let Some(current) = &state.current else {
            return ConnectionStats::default();
        };

        let mut active_connections = 0u64;
        let mut online = BTreeSet::new();
        for (tag, inbound) in &current.inbounds {
            if inbound.compiled.node_id != node_id {
                continue;
            }
            let Ok(users) = self.inner.engine.list_users(tag) else {
                continue;
            };
            for user in users {
                active_connections = active_connections.saturating_add(user.conns);
                if user.conns > 0 {
                    online.insert(user.id);
                }
            }
        }
        ConnectionStats {
            active_connections,
            online_users: online.len() as u64,
        }
    }

    async fn close_user_connections_owned(&self, node_id: &str, user_id: &str) -> u64 {
        if node_id.is_empty() || user_id.is_empty() {
            return 0;
        }
        let _apply = self.inner.apply.lock().await;
        let tags: Vec<String> = {
            let state = self.read_state();
            state
                .current
                .as_ref()
                .into_iter()
                .flat_map(|current| current.inbounds.iter())
                .filter(|(_, inbound)| inbound.compiled.node_id == node_id)
                .map(|(tag, _)| tag.clone())
                .collect()
        };
        tags.into_iter()
            .filter_map(|tag| self.inner.engine.kick_user(&tag, user_id).ok())
            .fold(0u64, u64::saturating_add)
    }

    async fn drain_traffic_owned(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        let _apply = self.inner.apply.lock().await;
        let current = self.read_state().current.clone();
        let mut live = Vec::new();
        if let Some(current) = current {
            for (tag, inbound) in &current.inbounds {
                match self.inner.engine.take_inbound_traffic(tag) {
                    Ok(users) => {
                        live.extend(users.into_iter().map(|info| traffic_drain(inbound, info)));
                    }
                    Err(EngineError::Unsupported(_)) | Err(EngineError::UnknownTag(_)) => {}
                    Err(error) => {
                        // Earlier tags were already atomically zeroed.  Queue them
                        // before returning the error so a retry cannot lose them.
                        self.pending_traffic().extend(live);
                        return Err(RuntimeError::failed(
                            format!("take traffic for inbound {tag}: {error}"),
                            Vec::new(),
                            false,
                            false,
                            !self.inner.engine.list_inbounds().is_empty(),
                        ));
                    }
                }
            }
        }

        let mut pending = self.pending_traffic();
        let mut drained = std::mem::take(&mut *pending);
        drained.extend(live);
        Ok(drained)
    }
}

async fn run_rule_set_watcher(
    weak: Weak<RuntimeInner>,
    generation: u64,
    cancel: CancellationToken,
    interval: Duration,
    config: RuntimeConfig,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(interval) => {}
        }
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let runtime = ShoesRuntime { inner };
        match runtime
            .refresh_rule_sets_owned(generation, config.clone())
            .await
        {
            None => return,
            Some(Ok(())) => {}
            Some(Err(error)) => {
                log::warn!("refresh remote route rule-set generation {generation}: {error}");
            }
        }
        // `runtime` (and therefore the upgraded Arc) drops here, before the next
        // potentially day-long sleep. The sleeping task retains only `weak`.
    }
}

#[async_trait]
impl NodeRuntime for ShoesRuntime {
    async fn apply_config(&self, config: RuntimeConfig) -> Result<(), RuntimeError> {
        let runtime = self.clone();
        tokio::spawn(async move { runtime.apply_external_owned(config, false).await })
            .await
            .map_err(|error| self.join_error("apply runtime config", error))?
    }

    async fn reload_config(&self, config: RuntimeConfig) -> Result<ReloadStatus, RuntimeError> {
        let runtime = self.clone();
        tokio::spawn(async move { runtime.apply_external_owned(config, true).await })
            .await
            .map_err(|error| self.join_error("reload runtime config", error))??;
        Ok(ReloadStatus {
            running: true,
            rolled_back: false,
        })
    }

    fn current_config(&self) -> Vec<u8> {
        self.read_state()
            .current
            .as_ref()
            .map(|config| config.diagnostic_yaml.clone())
            .unwrap_or_default()
    }

    async fn close(&self) -> Result<(), RuntimeError> {
        let runtime = self.clone();
        tokio::spawn(async move { runtime.close_owned().await })
            .await
            .map_err(|error| self.join_error("close runtime", error))?
    }

    fn connection_stats(&self, node_id: &str) -> ConnectionStats {
        self.connection_stats_owned(node_id)
    }

    async fn close_user_connections(&self, node_id: &str, user_id: &str) -> u64 {
        let runtime = self.clone();
        let node_id = node_id.to_string();
        let user_id = user_id.to_string();
        tokio::spawn(async move {
            runtime
                .close_user_connections_owned(&node_id, &user_id)
                .await
        })
        .await
        .unwrap_or(0)
    }

    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        let runtime = self.clone();
        tokio::spawn(async move { runtime.drain_traffic_owned().await })
            .await
            .map_err(|error| self.join_error("drain runtime traffic", error))?
    }
}

impl ShoesRuntime {
    fn join_error(&self, operation: &str, error: tokio::task::JoinError) -> RuntimeError {
        RuntimeError::failed(
            format!("{operation} task failed: {error}"),
            Vec::new(),
            false,
            false,
            !self.inner.engine.list_inbounds().is_empty(),
        )
    }
}

fn normalize(config: RuntimeConfig) -> Result<NormalizedConfig, String> {
    let mut inbounds = BTreeMap::new();
    for mut compiled in config.inbounds {
        let tag = compiled.spec.tag.trim().to_string();
        if tag.is_empty() {
            return Err("inbound tag is required".into());
        }
        if compiled.node_id.trim().is_empty() {
            return Err(format!("inbound {tag} has no node_id"));
        }
        if compiled.protocol.trim().is_empty() {
            return Err(format!("inbound {tag} has no protocol label"));
        }
        // The map key and the tag sent to Engine must be identical.  Engine trims
        // only to validate emptiness and otherwise preserves the caller's string;
        // leaving whitespace here would make every later operation address a tag
        // that was never registered.
        compiled.spec.tag = tag.clone();

        let dynamic_users = compiled.spec.users.is_some();
        let mut users = BTreeMap::new();
        if let Some(specs) = &compiled.spec.users {
            for user in specs {
                let id = user
                    .resolved_id()
                    .filter(|id| !id.trim().is_empty())
                    .ok_or_else(|| format!("inbound {tag} contains a user with no id"))?
                    .to_string();
                if users.insert(id.clone(), user.clone()).is_some() {
                    return Err(format!("inbound {tag} lists user {id} twice"));
                }
            }
        }

        let normalized = NormalizedInbound {
            compiled,
            users,
            dynamic_users,
        };
        if inbounds.insert(tag.to_string(), normalized).is_some() {
            return Err(format!("inbound tag {tag} is listed twice"));
        }
    }
    Ok(NormalizedConfig {
        inbounds,
        rule_set_digest: [0; 32],
        diagnostic_yaml: config.diagnostic_yaml,
    })
}

fn diff_configs(current: &NormalizedConfig, desired: &NormalizedConfig) -> ConfigDiff {
    let removed = current
        .inbounds
        .keys()
        .filter(|tag| !desired.inbounds.contains_key(*tag))
        .cloned()
        .collect();
    let added = desired
        .inbounds
        .keys()
        .filter(|tag| !current.inbounds.contains_key(*tag))
        .cloned()
        .collect();

    let rule_sets_changed = current.rule_set_digest != desired.rule_set_digest;
    let mut changed = Vec::new();
    for (tag, before) in &current.inbounds {
        let Some(after) = desired.inbounds.get(tag) else {
            continue;
        };
        let user_mode_changed = before.dynamic_users != after.dynamic_users;
        let removed_users: Vec<String> = before
            .users
            .keys()
            .filter(|id| !after.users.contains_key(*id))
            .cloned()
            .collect();
        let upsert_users: Vec<UserDelta> = after
            .users
            .iter()
            .filter_map(|(id, user)| match before.users.get(id) {
                None => Some(UserDelta {
                    id: id.clone(),
                    added: true,
                    credential_changed: false,
                }),
                Some(old) if !same_user(old, user) => Some(UserDelta {
                    id: id.clone(),
                    added: false,
                    credential_changed: credential_changed(old, user),
                }),
                Some(_) => None,
            })
            .collect();
        let config_changed =
            rule_sets_changed || before.compiled.spec.config != after.compiled.spec.config;
        if config_changed
            || user_mode_changed
            || !removed_users.is_empty()
            || !upsert_users.is_empty()
        {
            changed.push(InboundDelta {
                tag: tag.clone(),
                config_changed,
                user_mode_changed,
                removed_users,
                upsert_users,
            });
        }
    }

    ConfigDiff {
        removed,
        added,
        changed,
    }
}

fn same_user(left: &UserSpec, right: &UserSpec) -> bool {
    left.id == right.id
        && left.uuid == right.uuid
        && left.password == right.password
        && left.enabled == right.enabled
        && left.max_conns == right.max_conns
        && left.upload_limit_bps == right.upload_limit_bps
        && left.download_limit_bps == right.download_limit_bps
}

fn credential_changed(left: &UserSpec, right: &UserSpec) -> bool {
    // `id` is the username half of NaiveProxy and is also the map key, so two
    // records reaching this comparison already have the same id.
    left.uuid != right.uuid || left.password != right.password
}

fn update_spec(inbound: &NormalizedInbound) -> InboundSpec {
    let mut spec = inbound.compiled.spec.clone();
    // Users are reconciled through their atomic endpoints.  Passing them to
    // update_inbound is intentionally rejected by shoes-engine.
    spec.users = None;
    spec
}

fn traffic_drain(inbound: &NormalizedInbound, info: UserInfo) -> TrafficDrain {
    let observed_at = traffic_observed_at(&info);
    TrafficDrain {
        inbound_tag: inbound.compiled.spec.tag.clone(),
        node_id: inbound.compiled.node_id.clone(),
        protocol: inbound.compiled.protocol.clone(),
        user_id: info.id,
        uplink_bytes: info.rx,
        downlink_bytes: info.tx,
        observed_at,
    }
}

fn traffic_observed_at(info: &UserInfo) -> Option<SystemTime> {
    (info.last_traffic_observed_at_unix_millis != 0).then(|| {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(
                info.last_traffic_observed_at_unix_millis,
            ))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    })
}

fn describe_step_failure(failure: StepFailure) -> String {
    if failure.rollback.is_empty() {
        failure.operation
    } else {
        format!(
            "{}; local rollback failed: {}",
            failure.operation,
            failure.rollback.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};
    use shoes::dynamic::{ConnContext, UserRegistry};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;

    use super::*;

    const ALICE_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const ALICE_ROTATED_UUID: &str = "22222222-2222-4222-8222-222222222222";
    const BOB_UUID: &str = "33333333-3333-4333-8333-333333333333";
    const CAROL_UUID: &str = "44444444-4444-4444-8444-444444444444";

    struct MutableRuleSetResponse {
        body: Vec<u8>,
        fail: bool,
        requests: usize,
    }

    async fn start_rule_set_server(
        initial_body: Vec<u8>,
    ) -> (
        String,
        Arc<Mutex<MutableRuleSetResponse>>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mutable rule-set server");
        let address = listener.local_addr().expect("rule-set server address");
        let state = Arc::new(Mutex::new(MutableRuleSetResponse {
            body: initial_body,
            fail: false,
            requests: 0,
        }));
        let server_state = Arc::clone(&state);
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = server_cancel.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut socket, _)) = accepted else {
                    return;
                };
                let mut request = [0u8; 4096];
                if socket.read(&mut request).await.is_err() {
                    continue;
                }
                let (fail, body) = {
                    let mut state = server_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.requests += 1;
                    (state.fail, state.body.clone())
                };
                let (status, body) = if fail {
                    ("500 Internal Server Error", b"temporary failure".to_vec())
                } else {
                    ("200 OK", body)
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if socket.write_all(header.as_bytes()).await.is_ok() {
                    let _ = socket.write_all(&body).await;
                    let _ = socket.shutdown().await;
                }
            }
        });
        (format!("http://{address}/rules.json"), state, cancel, task)
    }

    fn source_rule_set(domain: &str) -> Vec<u8> {
        format!(r#"{{"version":4,"rules":[{{"domain":["{domain}"]}}]}}"#).into_bytes()
    }

    async fn wait_for_revision(runtime: &ShoesRuntime, tag: &str, previous: u64) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let revision = runtime
                    .engine()
                    .get_inbound(tag)
                    .expect("watched inbound remains live")
                    .revision();
                if revision > previous {
                    return revision;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rule-set watcher reloads the inbound")
    }

    async fn wait_for_request_after(state: &Arc<Mutex<MutableRuleSetResponse>>, previous: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let requests = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .requests;
                if requests > previous {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rule-set watcher retries the HTTP request");
    }

    async fn wait_for_cache(path: &std::path::Path, expected: &[u8]) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::fs::read(path)
                    .await
                    .is_ok_and(|bytes| bytes == expected)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("rule-set last-good cache is committed");
    }

    fn free_addrs(count: usize) -> Vec<SocketAddr> {
        // Keep every probe open until all addresses have been collected.  This
        // prevents Windows from immediately handing the same ephemeral port to a
        // second probe in this test.
        let listeners: Vec<TcpListener> = (0..count)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port"))
            .collect();
        listeners
            .iter()
            .map(|listener| listener.local_addr().expect("read ephemeral port"))
            .collect()
    }

    fn user(id: &str, uuid: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: Some(uuid.to_string()),
            password: None,
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn uuid_bytes(uuid: &str) -> [u8; 16] {
        let hex: String = uuid.chars().filter(|character| *character != '-').collect();
        assert_eq!(hex.len(), 32, "test UUID must have 32 hex digits");
        let mut parsed = [0; 16];
        for (index, byte) in parsed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .expect("test UUID contains only hex digits");
        }
        parsed
    }

    fn vless(address: SocketAddr) -> Value {
        json!({
            "address": address.to_string(),
            "protocol": {"type": "vless", "udp_enabled": false},
        })
    }

    fn compiled(
        tag: &str,
        node_id: &str,
        config: Value,
        users: Option<Vec<UserSpec>>,
    ) -> CompiledInbound {
        CompiledInbound {
            node_id: node_id.to_string(),
            protocol: "vless".to_string(),
            spec: InboundSpec {
                tag: tag.to_string(),
                config,
                users,
            },
        }
    }

    fn config(snapshot: &[u8], inbounds: Vec<CompiledInbound>) -> RuntimeConfig {
        RuntimeConfig {
            inbounds,
            rule_sets: Vec::new(),
            diagnostic_yaml: snapshot.to_vec(),
        }
    }

    async fn runtime() -> ShoesRuntime {
        ShoesRuntime::from_engine(Engine::bootstrap().await.expect("bootstrap engine"))
    }

    #[test]
    fn diff_separates_listener_user_and_credential_changes() {
        let addresses = free_addrs(3);
        let before = normalize(config(
            b"before",
            vec![
                compiled(
                    "edge",
                    "node-a",
                    vless(addresses[0]),
                    Some(vec![user("alice", ALICE_UUID), user("bob", BOB_UUID)]),
                ),
                compiled("retired", "node-b", vless(addresses[1]), Some(vec![])),
            ],
        ))
        .expect("normalize old config");
        let after = normalize(config(
            b"after",
            vec![
                compiled(
                    "edge",
                    "node-a",
                    vless(addresses[2]),
                    Some(vec![
                        user("alice", ALICE_ROTATED_UUID),
                        user("carol", CAROL_UUID),
                    ]),
                ),
                compiled("new", "node-c", vless(addresses[1]), Some(vec![])),
            ],
        ))
        .expect("normalize new config");

        assert_eq!(
            diff_configs(&before, &after),
            ConfigDiff {
                removed: vec!["retired".into()],
                added: vec!["new".into()],
                changed: vec![InboundDelta {
                    tag: "edge".into(),
                    config_changed: true,
                    user_mode_changed: false,
                    removed_users: vec!["bob".into()],
                    upsert_users: vec![
                        UserDelta {
                            id: "alice".into(),
                            added: false,
                            credential_changed: true,
                        },
                        UserDelta {
                            id: "carol".into(),
                            added: true,
                            credential_changed: false,
                        },
                    ],
                }],
            }
        );
    }

    #[test]
    fn diff_marks_dynamic_user_mode_changes_for_replacement() {
        let address = free_addrs(1)[0];
        let dynamic = normalize(config(
            b"dynamic",
            vec![compiled(
                "edge",
                "node-a",
                vless(address),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        ))
        .expect("normalize dynamic config");
        let classic = normalize(config(
            b"classic",
            vec![compiled("edge", "node-a", vless(address), None)],
        ))
        .expect("normalize classic config");

        let diff = diff_configs(&dynamic, &classic);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0].user_mode_changed);
    }

    #[test]
    fn diff_rebuilds_selectors_when_rule_set_bytes_change_at_same_path() {
        let address = free_addrs(1)[0];
        let before = normalize(config(
            b"same topology",
            vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
        ))
        .expect("normalize config");
        let mut after = before.clone();
        after.rule_set_digest = [7; 32];

        let diff = diff_configs(&before, &after);
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed[0].config_changed);
        assert!(!diff.changed[0].user_mode_changed);
    }

    #[test]
    fn normalization_canonicalizes_the_engine_tag_with_the_state_key() {
        let address = free_addrs(1)[0];
        let normalized = normalize(config(
            b"canonical",
            vec![compiled("  edge  ", "node-a", vless(address), Some(vec![]))],
        ))
        .expect("normalize config");
        let inbound = normalized.inbounds.get("edge").expect("canonical key");
        assert_eq!(inbound.compiled.spec.tag, "edge");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_multi_operation_apply_rolls_back_in_reverse_order() {
        let addresses = free_addrs(3);
        let runtime = runtime().await;
        let old = config(
            b"old",
            vec![
                compiled(
                    "a",
                    "node-a",
                    vless(addresses[0]),
                    Some(vec![user("alice", ALICE_UUID)]),
                ),
                compiled("b", "node-b", vless(addresses[1]), Some(vec![])),
            ],
        );
        runtime
            .apply_config(old.clone())
            .await
            .expect("start old topology");

        // Moving a succeeds via ReloadRequired -> replace.  Adding c then fails
        // because b owns its address, so the journal must move a back.
        let candidate = config(
            b"candidate",
            vec![
                compiled(
                    "a",
                    "node-a",
                    vless(addresses[2]),
                    Some(vec![user("alice", ALICE_UUID)]),
                ),
                compiled("b", "node-b", vless(addresses[1]), Some(vec![])),
                compiled("c", "node-c", vless(addresses[1]), Some(vec![])),
            ],
        );
        let error = runtime
            .apply_config(candidate)
            .await
            .expect_err("c must conflict with b");

        assert!(error.rolled_back(), "{error}");
        assert!(!error.state_unchanged());
        assert!(error.rollback_error().is_none(), "{error}");
        assert_eq!(runtime.current_config(), b"old");
        let infos = runtime.engine().list_inbounds();
        assert_eq!(infos.len(), 2);
        assert!(infos.iter().any(|info| {
            info.tag == "a"
                && info
                    .bind
                    .iter()
                    .any(|bind| bind == &addresses[0].to_string())
        }));
        assert!(infos.iter().any(|info| info.tag == "b"));
        assert!(runtime.engine().get_inbound("c").is_none());

        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_step_failure_keeps_known_state_without_claiming_rollback() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let old = config(
            b"old",
            vec![compiled("b", "node-b", vless(address), Some(vec![]))],
        );
        runtime
            .apply_config(old.clone())
            .await
            .expect("start old topology");

        let conflict = config(
            b"conflict",
            vec![
                old.inbounds[0].clone(),
                compiled("c", "node-c", vless(address), Some(vec![])),
            ],
        );
        let error = runtime
            .apply_config(conflict)
            .await
            .expect_err("first add must conflict");
        assert!(!error.rolled_back());
        assert!(error.state_unchanged());
        assert_eq!(runtime.current_config(), b"old");

        let mut republished = old;
        republished.diagnostic_yaml = b"republished".to_vec();
        runtime
            .apply_config(republished)
            .await
            .expect("known state must accept the next apply");
        assert_eq!(runtime.current_config(), b"republished");
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preflight_failure_preserves_snapshot_and_next_apply() {
        let addresses = free_addrs(2);
        let runtime = runtime().await;
        let old = config(
            b"old",
            vec![compiled(
                "edge",
                "node-a",
                vless(addresses[0]),
                Some(vec![]),
            )],
        );
        runtime
            .apply_config(old.clone())
            .await
            .expect("start old topology");

        let invalid = config(
            b"invalid",
            vec![compiled(
                "broken",
                "node-b",
                json!({
                    "address": addresses[1].to_string(),
                    "protocol": {"type": "not-a-real-protocol"},
                }),
                Some(vec![]),
            )],
        );
        let error = runtime
            .apply_config(invalid)
            .await
            .expect_err("invalid protocol must fail preflight");
        assert!(!error.rolled_back());
        assert!(error.state_unchanged());
        assert_eq!(runtime.current_config(), b"old");

        let mut republished = old;
        republished.diagnostic_yaml = b"after-preflight".to_vec();
        runtime
            .apply_config(republished)
            .await
            .expect("preflight failure must not poison state");
        assert_eq!(runtime.current_config(), b"after-preflight");
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forced_reload_rebuilds_an_identical_inbound() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let initial = config(
            b"initial",
            vec![compiled(
                "edge",
                "node-a",
                vless(address),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        );
        runtime
            .apply_config(initial.clone())
            .await
            .expect("start topology");
        let before = runtime
            .engine()
            .get_inbound("edge")
            .expect("old inbound slot");

        let status = runtime
            .reload_config(initial)
            .await
            .expect("force reload identical topology");
        let after = runtime
            .engine()
            .get_inbound("edge")
            .expect("new inbound slot");
        assert_eq!(
            status,
            ReloadStatus {
                running: true,
                rolled_back: false
            }
        );
        assert!(!Arc::ptr_eq(&before, &after));
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removed_user_tail_keeps_direction_and_actual_observation_time() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"with-alice",
                vec![compiled(
                    "edge",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .expect("start topology");

        let registry = runtime
            .engine()
            .get_inbound("edge")
            .expect("inbound slot")
            .users()
            .expect("dynamic registry")
            .clone();
        let alice = registry
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .expect("alice resolves");
        alice.add_rx(11);
        alice.add_tx(22);
        let observed_at_millis = alice.last_traffic_observed_at_unix_millis();
        assert_ne!(observed_at_millis, 0);

        runtime
            .apply_config(config(
                b"without-alice",
                vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
            ))
            .await
            .expect("remove alice");
        let mut drained = runtime.drain_traffic().await.expect("drain traffic");
        assert_eq!(drained.len(), 1);
        let tail = drained.pop().expect("alice tail");
        assert_eq!(tail.inbound_tag, "edge");
        assert_eq!(tail.node_id, "node-a");
        assert_eq!(tail.protocol, "vless");
        assert_eq!(tail.user_id, "alice");
        // Shoes rx is bytes from the client (ACP uplink); tx is bytes sent back
        // to the client (ACP downlink).
        assert_eq!((tail.uplink_bytes, tail.downlink_bytes), (11, 22));
        assert_eq!(
            tail.observed_at
                .expect("non-zero tail has an observation time")
                .duration_since(UNIX_EPOCH)
                .expect("current wall clock is after the epoch")
                .as_millis(),
            u128::from(observed_at_millis)
        );
        assert!(
            runtime
                .drain_traffic()
                .await
                .expect("second drain")
                .is_empty()
        );
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn credential_rotation_kicks_stale_session_and_admits_new_credential() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"old-credential",
                vec![compiled(
                    "edge",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .expect("start topology");

        let registry = runtime
            .engine()
            .get_inbound("edge")
            .expect("inbound slot")
            .users()
            .expect("dynamic registry")
            .clone();
        let old_user = registry
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .expect("old credential resolves before rotation");
        let stale = ConnContext::new();
        assert!(stale.bind_authenticated(old_user.clone()));
        assert_eq!(old_user.conns(), 1);

        runtime
            .apply_config(config(
                b"new-credential",
                vec![compiled(
                    "edge",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_ROTATED_UUID)]),
                )],
            ))
            .await
            .expect("rotate credential");

        assert!(registry.find_uuid(&uuid_bytes(ALICE_UUID)).is_none());
        let rotated_user = registry
            .find_uuid(&uuid_bytes(ALICE_ROTATED_UUID))
            .expect("new credential resolves immediately");
        assert!(Arc::ptr_eq(&old_user, &rotated_user));
        tokio::time::timeout(Duration::from_secs(1), stale.cancelled())
            .await
            .expect("the stale connection token must be kicked");
        drop(stale);

        let fresh = ConnContext::new();
        assert!(fresh.bind_authenticated(rotated_user));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), fresh.cancelled())
                .await
                .is_err(),
            "kick is a snapshot and must not cancel a fresh session"
        );
        drop(fresh);
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connection_stats_and_remote_kick_span_every_tag_for_a_node() {
        let addresses = free_addrs(2);
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"two-tags",
                vec![
                    compiled(
                        "edge-a",
                        "node-a",
                        vless(addresses[0]),
                        Some(vec![user("alice", ALICE_UUID)]),
                    ),
                    compiled(
                        "edge-b",
                        "node-a",
                        vless(addresses[1]),
                        Some(vec![user("alice", ALICE_UUID)]),
                    ),
                ],
            ))
            .await
            .expect("start topology");

        let registry_a = runtime
            .engine()
            .get_inbound("edge-a")
            .expect("edge-a")
            .users()
            .expect("edge-a registry")
            .clone();
        let registry_b = runtime
            .engine()
            .get_inbound("edge-b")
            .expect("edge-b")
            .users()
            .expect("edge-b registry")
            .clone();
        let uuid = uuid_bytes(ALICE_UUID);
        let user_a = registry_a.find_uuid(&uuid).expect("alice on edge-a");
        let user_b = registry_b.find_uuid(&uuid).expect("alice on edge-b");
        let connection_a = ConnContext::new();
        let connection_b1 = ConnContext::new();
        let connection_b2 = ConnContext::new();
        assert!(connection_a.bind_authenticated(user_a));
        assert!(connection_b1.bind_authenticated(user_b.clone()));
        assert!(connection_b2.bind_authenticated(user_b));

        assert_eq!(
            runtime.connection_stats("node-a"),
            ConnectionStats {
                active_connections: 3,
                online_users: 1,
            }
        );
        assert_eq!(
            runtime.connection_stats("missing"),
            ConnectionStats::default()
        );
        assert_eq!(runtime.close_user_connections("node-a", "alice").await, 3);
        for connection in [&connection_a, &connection_b1, &connection_b2] {
            tokio::time::timeout(Duration::from_secs(1), connection.cancelled())
                .await
                .expect("remote kick must signal every matching connection");
        }
        drop(connection_a);
        drop(connection_b1);
        drop(connection_b2);
        assert_eq!(
            runtime.connection_stats("node-a"),
            ConnectionStats::default()
        );

        let fresh_user = registry_a
            .find_uuid(&uuid)
            .expect("kick keeps alice authorized");
        let fresh = ConnContext::new();
        assert!(fresh.bind_authenticated(fresh_user));
        drop(fresh);
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_to_empty_is_known_but_not_reported_as_rolled_back() {
        let free = free_addrs(1)[0];
        let blocker = TcpListener::bind("127.0.0.1:0").expect("hold conflict port");
        let blocked = blocker.local_addr().expect("read conflict port");
        let runtime = runtime().await;
        let candidate = config(
            b"candidate",
            vec![
                compiled("a", "node-a", vless(free), Some(vec![])),
                compiled("b", "node-b", vless(blocked), Some(vec![])),
            ],
        );

        // a starts, b fails, and the journal removes a again.  The exact empty
        // topology is known, but Go/ACP reserves ROLLED_BACK for restoring a
        // non-empty previous topology.
        let error = runtime
            .apply_config(candidate.clone())
            .await
            .expect_err("b cannot bind while the probe listener is held");
        assert!(!error.rolled_back());
        assert!(!error.state_unchanged());
        assert!(runtime.engine().list_inbounds().is_empty());
        assert!(runtime.current_config().is_empty());

        drop(blocker);
        runtime
            .apply_config(candidate)
            .await
            .expect("known empty state accepts a later apply");
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_rule_set_watcher_refreshes_retries_and_is_generation_safe() {
        let interval = Duration::from_millis(60);
        let (url, server_state, server_cancel, server_task) =
            start_rule_set_server(source_rule_set("first.example")).await;
        let temporary = tempfile::tempdir().expect("create rule-set cache directory");
        let cache_path = temporary.path().join("mutable-rules.json");
        let address = free_addrs(1)[0];
        let resource = RuleSetResource {
            tag: "mutable".into(),
            format: "source".into(),
            path: cache_path.clone(),
            source: RuleSetSource::Remote { url },
            update_interval: interval,
        };
        let inbound_config = json!({
            "address": address.to_string(),
            "protocol": {"type": "vless", "udp_enabled": false},
            "rules": [{
                "masks": "0.0.0.0/0",
                "match": {
                    "rule_set": [{
                        "format": "source",
                        "path": cache_path.to_string_lossy(),
                    }]
                },
                "action": "block",
            }],
        });
        let watched = RuntimeConfig {
            inbounds: vec![compiled("edge", "node-a", inbound_config, Some(vec![]))],
            rule_sets: vec![resource.clone()],
            diagnostic_yaml: b"watched-v1".to_vec(),
        };
        let runtime = runtime().await;
        runtime
            .apply_config(watched.clone())
            .await
            .expect("start watched topology");
        let initial_revision = runtime
            .engine()
            .get_inbound("edge")
            .expect("watched inbound")
            .revision();
        let (initial_generation, initial_cancel) = {
            let watcher = runtime.rule_set_watcher();
            (
                watcher.generation,
                watcher.cancel.clone().expect("remote watcher installed"),
            )
        };

        // An envelope-valid download can still be semantically unparsable by
        // shoes. It is used only through its immutable candidate snapshot; a
        // failed preflight must not poison the durable cache used on restart.
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("initial last-good cache"),
            source_rule_set("first.example")
        );
        let requests_before_invalid = {
            let mut state = server_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.body = br#"{"version":4,"rules":[{"domain":5}]}"#.to_vec();
            state.requests
        };
        wait_for_request_after(&server_state, requests_before_invalid).await;
        tokio::time::sleep(interval + interval).await;
        assert_eq!(
            runtime
                .engine()
                .get_inbound("edge")
                .expect("old inbound survives candidate parse failure")
                .revision(),
            initial_revision
        );
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("old cache survives candidate parse failure"),
            source_rule_set("first.example")
        );

        // Simulate process restart: a new loader sees the still-fresh stable
        // file, not the rejected candidate snapshot.
        let mut restart_resource = resource.clone();
        restart_resource.update_interval = Duration::from_nanos(1);
        RuleSetLoader::new()
            .expect("create restarted loader")
            .prepare(&[restart_resource])
            .await
            .expect("restart prepares old last-good cache");
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("restart reads old cache"),
            source_rule_set("first.example")
        );

        // A failed external candidate must not retire the successful topology's
        // watcher. The subsequent body change is applied without another ACP
        // topology delivery, proving that the old generation kept running.
        let invalid = config(
            b"invalid",
            vec![compiled(
                "broken",
                "node-b",
                json!({
                    "address": free_addrs(1)[0].to_string(),
                    "protocol": {"type": "not-a-real-protocol"},
                }),
                Some(vec![]),
            )],
        );
        runtime
            .apply_config(invalid)
            .await
            .expect_err("invalid external candidate must fail");
        {
            let watcher = runtime.rule_set_watcher();
            assert_eq!(watcher.generation, initial_generation);
            assert!(!initial_cancel.is_cancelled());
        }
        server_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .body = source_rule_set("second.example");
        let second_revision = wait_for_revision(&runtime, "edge", initial_revision).await;
        wait_for_cache(&cache_path, &source_rule_set("second.example")).await;
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("second candidate becomes last-good after commit"),
            source_rule_set("second.example")
        );
        assert_eq!(runtime.current_config(), b"watched-v1");

        // A transient download failure keeps the already-running selector and
        // immutable snapshot. The stale cache timestamp makes the next interval
        // retry instead of suppressing future attempts.
        let requests_before_failure = {
            let mut state = server_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.fail = true;
            state.requests
        };
        wait_for_request_after(&server_state, requests_before_failure).await;
        tokio::time::sleep(interval + interval).await;
        assert_eq!(
            runtime
                .engine()
                .get_inbound("edge")
                .expect("old inbound survives download failure")
                .revision(),
            second_revision
        );
        assert_eq!(runtime.current_config(), b"watched-v1");

        {
            let mut state = server_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.body = source_rule_set("third.example");
            state.fail = false;
        }
        let third_revision = wait_for_revision(&runtime, "edge", second_revision).await;
        assert!(third_revision > second_revision);
        wait_for_cache(&cache_path, &source_rule_set("third.example")).await;
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("third candidate becomes last-good after commit"),
            source_rule_set("third.example")
        );

        // A later successful topology atomically publishes a new generation and
        // cancels the old one. Failed applies above deliberately did neither.
        let mut replacement = watched;
        replacement.diagnostic_yaml = b"watched-v2".to_vec();
        runtime
            .apply_config(replacement)
            .await
            .expect("replace watcher generation");
        let replacement_cancel = {
            let watcher = runtime.rule_set_watcher();
            assert_ne!(watcher.generation, initial_generation);
            watcher
                .cancel
                .clone()
                .expect("replacement watcher installed")
        };
        assert!(initial_cancel.is_cancelled());

        runtime.close().await.expect("close watched runtime");
        assert!(replacement_cancel.is_cancelled());
        let requests_after_close = server_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .requests;
        tokio::time::sleep(interval + interval).await;
        assert_eq!(
            server_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .requests,
            requests_after_close,
            "close must stop future watcher downloads"
        );

        server_cancel.cancel();
        server_task.await.expect("join rule-set HTTP server");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn close_is_idempotent_and_rejects_future_applies() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let initial = config(
            b"running",
            vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
        );
        runtime
            .apply_config(initial.clone())
            .await
            .expect("start topology");
        runtime.close().await.expect("first close");
        runtime.close().await.expect("idempotent close");
        assert!(runtime.engine().list_inbounds().is_empty());
        assert!(runtime.current_config().is_empty());

        let error = runtime
            .apply_config(initial)
            .await
            .expect_err("closed runtime cannot restart");
        assert!(!error.rolled_back());
        assert!(error.state_unchanged());
        assert!(!error.running());
    }
}
