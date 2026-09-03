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
use shoes_engine::{Engine, EngineError, InboundReplayLease};
use tokio_util::sync::CancellationToken;

use crate::rule_set::{PreparedRuleSets, RuleSetLoader, RuleSetResource, RuleSetSource};

const MAX_PENDING_TRAFFIC_KEYS: usize = 65_536;

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
    /// Stable digest of the global DNS client/data-plane surface (DNS, route,
    /// outbounds). Inbound/user-only changes deliberately retain the current
    /// Go-compatible DNS client generation.
    pub dns_client_fingerprint: [u8; 32],
    /// One generation-global DNS graph for URLTest background probes. Unlike
    /// ordinary inbound DNS projections, this contains no inbound context.
    pub urltest_probe_dns: Option<serde_json::Value>,
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

    /// Stop admitting/preparing new configurations before a caller waits for an
    /// outer transaction lock. This only requests shutdown: an already-started
    /// mutation must still finish, and `close` owns resource and traffic cleanup.
    fn begin_close(&self) {}

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
    /// Order configuration preparation and last-good cache publication without
    /// blocking traffic drains, connection kicks or shutdown on remote I/O.
    configuration: tokio::sync::Mutex<()>,
    closing: CancellationToken,
    apply: tokio::sync::Mutex<()>,
    rule_set_watcher: Mutex<RuleSetWatcherState>,
    state: RwLock<AppliedState>,
    /// Replay namespaces retained only while an indeterminate transaction may
    /// need to reconstruct the last published topology.
    recovery_replay: Mutex<BTreeMap<String, InboundReplayLease>>,
    /// Final counters from users whose registry entry no longer exists.  Keeping
    /// them here until `drain_traffic` takes them closes the remove-vs-flush hole.
    pending_traffic: Mutex<PendingTraffic>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TrafficDrainKey {
    inbound_tag: String,
    node_id: String,
    protocol: String,
    user_id: String,
}

#[derive(Debug)]
struct UserConnectionTarget {
    node_id: String,
    user_id: String,
}

impl UserConnectionTarget {
    fn new(node_id: &str, user_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            user_id: user_id.to_string(),
        }
    }
}

impl From<&TrafficDrain> for TrafficDrainKey {
    fn from(value: &TrafficDrain) -> Self {
        Self {
            inbound_tag: value.inbound_tag.clone(),
            node_id: value.node_id.clone(),
            protocol: value.protocol.clone(),
            user_id: value.user_id.clone(),
        }
    }
}

struct PendingTraffic {
    entries: BTreeMap<TrafficDrainKey, TrafficDrain>,
    reserved: BTreeSet<TrafficDrainKey>,
    max_keys: usize,
}

impl PendingTraffic {
    fn new(max_keys: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            reserved: BTreeSet::new(),
            max_keys,
        }
    }

    fn reserve(&mut self, key: &TrafficDrainKey) -> Result<bool, String> {
        if self.entries.contains_key(key) {
            return Ok(false);
        }
        if self.reserved.contains(key) {
            return Err(format!(
                "traffic key for inbound {} user {} is already reserved",
                key.inbound_tag, key.user_id
            ));
        }
        if self.entries.len().saturating_add(self.reserved.len()) >= self.max_keys {
            return Err(format!(
                "pending traffic key limit {} is full; drain traffic before changing users or inbounds",
                self.max_keys
            ));
        }
        self.reserved.insert(key.clone());
        Ok(true)
    }

    fn release(&mut self, key: &TrafficDrainKey) {
        self.reserved.remove(key);
    }

    fn merge_reserved(&mut self, drain: TrafficDrain, owns_reservation: bool) {
        let key = TrafficDrainKey::from(&drain);
        if owns_reservation {
            assert!(
                self.reserved.remove(&key),
                "traffic reservation disappeared before its receipt committed"
            );
        }
        if drain.uplink_bytes == 0 && drain.downlink_bytes == 0 {
            return;
        }
        merge_traffic_entry(&mut self.entries, drain);
        debug_assert!(self.entries.len().saturating_add(self.reserved.len()) <= self.max_keys);
    }

    #[cfg(test)]
    fn merge(&mut self, drain: TrafficDrain) -> Result<(), String> {
        if drain.uplink_bytes == 0 && drain.downlink_bytes == 0 {
            return Ok(());
        }
        let key = TrafficDrainKey::from(&drain);
        if !self.entries.contains_key(&key)
            && self.entries.len().saturating_add(self.reserved.len()) >= self.max_keys
        {
            return Err(format!(
                "pending traffic key limit {} is full; drain traffic before changing users or inbounds",
                self.max_keys
            ));
        }
        merge_traffic_entry(&mut self.entries, drain);
        Ok(())
    }

    fn drain(&mut self) -> Vec<TrafficDrain> {
        std::mem::take(&mut self.entries).into_values().collect()
    }
}

fn merge_traffic_entry(entries: &mut BTreeMap<TrafficDrainKey, TrafficDrain>, drain: TrafficDrain) {
    if drain.uplink_bytes == 0 && drain.downlink_bytes == 0 {
        return;
    }
    let key = TrafficDrainKey::from(&drain);
    if let Some(existing) = entries.get_mut(&key) {
        existing.uplink_bytes = existing.uplink_bytes.saturating_add(drain.uplink_bytes);
        existing.downlink_bytes = existing.downlink_bytes.saturating_add(drain.downlink_bytes);
        existing.observed_at = match (existing.observed_at, drain.observed_at) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
    } else {
        entries.insert(key, drain);
    }
}

struct PendingTrafficReservation {
    inner: Arc<RuntimeInner>,
    key: TrafficDrainKey,
    owns_reservation: bool,
}

impl PendingTrafficReservation {
    fn commit(mut self, drain: TrafficDrain) {
        assert_eq!(
            self.key,
            TrafficDrainKey::from(&drain),
            "traffic receipt metadata differs from its reservation"
        );
        let mut pending = self
            .inner
            .pending_traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.merge_reserved(drain, self.owns_reservation);
        self.owns_reservation = false;
    }
}

impl Drop for PendingTrafficReservation {
    fn drop(&mut self) {
        if !self.owns_reservation {
            return;
        }
        self.inner
            .pending_traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release(&self.key);
    }
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

#[derive(Clone)]
struct RetiringInbound {
    /// The listener/user generation that is actually present in Engine.
    live: NormalizedInbound,
    /// The published owner to which bytes produced before transaction commit
    /// belong. This deliberately differs from `live` for an uncommitted
    /// replacement candidate.
    accounting: NormalizedInbound,
}

#[derive(Clone, Default)]
struct NormalizedConfig {
    inbounds: BTreeMap<String, NormalizedInbound>,
    /// Digest of the prepared rule-set bytes, independent of their stable
    /// cache paths. A content refresh must rebuild selectors even when the ACP
    /// topology JSON itself is byte-for-byte unchanged.
    rule_set_digest: [u8; 32],
    dns_client_fingerprint: [u8; 32],
    urltest_probe_dns: Option<serde_json::Value>,
    diagnostic_yaml: Vec<u8>,
}

struct AppliedState {
    /// `None` means a rollback failed and the live engine must be reconciled from
    /// `recovery` before another topology can be applied.
    current: Option<NormalizedConfig>,
    recovery: Option<NormalizedConfig>,
    /// Listener generations that survived a failed rollback, together with the
    /// still-published accounting owner for their pre-commit tail traffic.
    recovery_live: BTreeMap<String, RetiringInbound>,
    /// Distinguishes the process bootstrap placeholder from an intentionally
    /// committed empty topology. Go constructs a fresh DNS client for every
    /// subsequent Box even when the previous Box had no inbounds.
    committed: bool,
    closed: bool,
}

impl Default for AppliedState {
    fn default() -> Self {
        Self {
            current: Some(NormalizedConfig::default()),
            recovery: None,
            recovery_live: BTreeMap::new(),
            committed: false,
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
    AddInbound {
        inbound: NormalizedInbound,
        replay: InboundReplayLease,
    },
    RemoveInbound {
        live: NormalizedInbound,
        accounting: NormalizedInbound,
    },
    RestoreHotConfig {
        current: NormalizedInbound,
        previous: NormalizedInbound,
        replay: InboundReplayLease,
    },
    AddUser {
        inbound: NormalizedInbound,
        user: UserSpec,
    },
    RemoveUser {
        live: NormalizedInbound,
        accounting: NormalizedInbound,
        user_id: String,
    },
    RestoreUser {
        inbound: NormalizedInbound,
        user: UserSpec,
        kick: bool,
    },
}

#[derive(Debug)]
struct StepFailure {
    operation: String,
    rollback: Vec<String>,
    /// Whether this step changed live state before attempting its local restore.
    changed: bool,
    restored: bool,
}

#[derive(Debug, Clone, Copy)]
struct DnsReloadContext {
    client_rotated: bool,
    full_reload: bool,
}

struct FailedTransaction {
    previous: NormalizedConfig,
    previous_replay: BTreeMap<String, InboundReplayLease>,
    failure: StepFailure,
    journal: Vec<Undo>,
    dns: DnsReloadContext,
}

#[derive(Debug)]
struct UserRemovalFailure {
    message: String,
    changed: bool,
    missing: bool,
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
                configuration: tokio::sync::Mutex::new(()),
                closing: CancellationToken::new(),
                apply: tokio::sync::Mutex::new(()),
                rule_set_watcher: Mutex::new(RuleSetWatcherState::default()),
                state: RwLock::new(AppliedState::default()),
                recovery_replay: Mutex::new(BTreeMap::new()),
                pending_traffic: Mutex::new(PendingTraffic::new(MAX_PENDING_TRAFFIC_KEYS)),
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
        let _configuration = tokio::select! {
            biased;
            () = self.inner.closing.cancelled() => {
                return Err(RuntimeError::unchanged(
                    "runtime is closed",
                    !self.inner.engine.list_inbounds().is_empty(),
                ));
            }
            guard = self.inner.configuration.lock() => guard,
        };
        let prepared = self.prepare_rule_sets(&config, &self.inner.closing).await?;
        let watcher_config = config
            .rule_sets
            .iter()
            .any(|resource| matches!(resource.source, RuleSetSource::Remote { .. }))
            .then(|| config.clone());
        let _apply = self.inner.apply.lock().await;
        // Topology changes are infrequent control-plane operations. Boxing the
        // large transaction future here keeps its state machine from being
        // embedded in every caller (including the public async-trait boundary).
        let result = Box::pin(self.apply_transaction_locked(config, prepared, force_reload)).await;
        if result.is_ok() {
            match watcher_config {
                Some(config) => self.install_rule_set_watcher_locked(config),
                // A successful local-only configuration must also retire an
                // older remote watcher, without keeping a duplicate config.
                None => self.cancel_rule_set_watcher_locked(),
            }
        }
        result
    }

    async fn prepare_rule_sets(
        &self,
        config: &RuntimeConfig,
        cancel: &CancellationToken,
    ) -> Result<PreparedRuleSets, RuntimeError> {
        self.inner
            .rule_sets
            .prepare_with_cancel(&config.rule_sets, cancel)
            .await
            .map_err(|error| {
                RuntimeError::unchanged(
                    format!("prepare route rule-set resources: {error}"),
                    !self.inner.engine.list_inbounds().is_empty(),
                )
            })
    }

    /// The topology transaction itself. Callers must hold `inner.apply`.
    ///
    /// This method never installs or replaces a watcher. In particular the
    /// watcher can call it without constructing an asynchronously recursive
    /// apply -> schedule -> apply future.
    async fn apply_transaction_locked(
        &self,
        mut config: RuntimeConfig,
        prepared: PreparedRuleSets,
        force_reload: bool,
    ) -> Result<(), RuntimeError> {
        // Close can overtake slow preparation. Never revive a closed runtime
        // with a candidate that was downloaded before its shutdown boundary.
        if self.inner.closing.is_cancelled() || self.read_state().closed {
            return Err(RuntimeError::unchanged(
                "runtime is closed",
                !self.inner.engine.list_inbounds().is_empty(),
            ));
        }
        for inbound in &mut config.inbounds {
            prepared.rewrite_config(&mut inbound.spec.config);
        }
        if let Some(probe_dns) = &mut config.urltest_probe_dns {
            prepared.rewrite_config(probe_dns);
        }
        let mut desired = normalize(config).map_err(|error| {
            RuntimeError::unchanged(
                format!("normalize runtime config: {error}"),
                !self.inner.engine.list_inbounds().is_empty(),
            )
        })?;
        desired.rule_set_digest = prepared.digest;

        Box::pin(self.recover_if_needed()).await?;
        let (previous, previous_committed) = {
            let state = self.read_state();
            (
                state
                    .current
                    .clone()
                    .expect("recovery publishes a known state"),
                state.committed,
            )
        };

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
        if let Err(error) = self
            .inner
            .engine
            .validate_urltest_probe_dns(desired.urltest_probe_dns.as_ref())
            .await
        {
            return Err(RuntimeError::unchanged(
                format!("validate generation-global URLTest probe DNS: {error}"),
                !self.inner.engine.list_inbounds().is_empty(),
            ));
        }

        // A failed rollback may temporarily remove every listener that owned these
        // Arcs. Retain one opaque lease per published inbound until the transaction
        // either commits or recovery has reconstructed the previous topology.
        let previous_replay = self.capture_replay_state(&previous)?;

        let full_dns_client_reload = force_reload
            || previous.dns_client_fingerprint != desired.dns_client_fingerprint
            || previous.rule_set_digest != desired.rule_set_digest;
        // Go validates before replacing Box. Rotate only after every preflight
        // succeeded and immediately before the first full-reload mutation, so
        // candidate bootstrap cannot read the old generation. Only the process
        // bootstrap placeholder has no prior client; an intentionally committed
        // empty topology is still a Box/DNS-client generation.
        let dns_client_rotated = full_dns_client_reload && previous_committed;
        let dns = DnsReloadContext {
            client_rotated: dns_client_rotated,
            full_reload: full_dns_client_reload,
        };
        if dns_client_rotated {
            let generation = self.inner.engine.rotate_dns_client_generation().await;
            log::debug!(
                "rotated DNS client state to generation {generation} before full topology candidate"
            );
        }

        if (full_dns_client_reload || !previous_committed)
            && let Err(error) = self
                .inner
                .engine
                .configure_urltest_probe_dns(desired.urltest_probe_dns.as_ref())
                .await
        {
            return Err(Box::pin(self.finish_failed_transaction(FailedTransaction {
                previous,
                previous_replay,
                failure: StepFailure::unchanged(format!(
                    "configure generation-global URLTest probe DNS: {error}"
                )),
                journal: Vec::new(),
                dns,
            }))
            .await);
        }

        let transaction =
            Box::pin(self.execute_apply(&previous, &desired, full_dns_client_reload)).await;

        match transaction {
            Ok(()) => {
                // Publish the ownership boundary before any fallible durability
                // work. `execute_apply` atomically took every pre-boundary byte
                // under the old metadata immediately before returning.
                {
                    let mut state = self.write_state();
                    state.current = Some(desired);
                    state.recovery = None;
                    state.recovery_live.clear();
                    state.committed = true;
                }
                self.recovery_replay().clear();
                self.inner
                    .engine
                    .commit_client_chain_group_generation()
                    .await;

                // Candidate selectors already point at immutable snapshots. Only
                // now, after shoes preflight and the live transaction both
                // succeeded, advance the restart-time stable last-good cache.
                // A durability failure must not roll back an otherwise healthy
                // live topology; the previous stable cache remains usable and
                // the watcher will retry the stale resource.
                if let Err(error) = prepared.commit().await {
                    log::error!("commit route rule-set last-good cache: {error}");
                }
                Ok(())
            }
            Err((failure, journal)) => {
                Err(Box::pin(self.finish_failed_transaction(FailedTransaction {
                    previous,
                    previous_replay,
                    failure,
                    journal,
                    dns,
                }))
                .await)
            }
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
            let cancel = self.inner.closing.child_token();
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
        let cancel = {
            let watcher = self.rule_set_watcher();
            if watcher.generation != generation {
                return None;
            }
            watcher.cancel.clone()?
        };
        let _configuration = tokio::select! {
            biased;
            () = cancel.cancelled() => return None,
            guard = self.inner.configuration.lock() => guard,
        };
        if !self.rule_set_watcher_is_active(generation) || self.read_state().closed {
            return None;
        }
        let prepared = self.prepare_rule_sets(&config, &cancel).await;
        let _apply = self.inner.apply.lock().await;
        // A successful external apply or close may retire this watcher while
        // it prepares. Discard its immutable snapshot instead of publishing it.
        if !self.rule_set_watcher_is_active(generation) || self.read_state().closed {
            return None;
        }
        Some(match prepared {
            Ok(prepared) => self.apply_transaction_locked(config, prepared, false).await,
            Err(error) => Err(error),
        })
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

    fn pending_traffic(&self) -> MutexGuard<'_, PendingTraffic> {
        self.inner
            .pending_traffic
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn recovery_replay(&self) -> MutexGuard<'_, BTreeMap<String, InboundReplayLease>> {
        self.inner
            .recovery_replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn capture_replay_state(
        &self,
        config: &NormalizedConfig,
    ) -> Result<BTreeMap<String, InboundReplayLease>, RuntimeError> {
        let mut replay = BTreeMap::new();
        for tag in config.inbounds.keys() {
            let lease = self
                .inner
                .engine
                .preserve_inbound_replay(tag)
                .map_err(|error| {
                    RuntimeError::unchanged(
                        format!("preserve replay state for inbound {tag}: {error}"),
                        !config.inbounds.is_empty(),
                    )
                })?;
            replay.insert(tag.clone(), lease);
        }
        Ok(replay)
    }

    fn traffic_key(inbound: &NormalizedInbound, user_id: &str) -> TrafficDrainKey {
        TrafficDrainKey {
            inbound_tag: inbound.compiled.spec.tag.clone(),
            node_id: inbound.compiled.node_id.clone(),
            protocol: inbound.compiled.protocol.clone(),
            user_id: user_id.to_string(),
        }
    }

    fn uncommitted_accounting_owner(
        published: Option<&NormalizedInbound>,
        candidate: &NormalizedInbound,
    ) -> NormalizedInbound {
        if let Some(published) = published {
            return published.clone();
        }

        // Go publishes topology traffic metadata only after Apply/Reload returns.
        // A brand-new tag that carries bytes during a failed transaction therefore
        // follows trafficTracker's missing-metadata fallback: node id is the inbound
        // tag and protocol is the actual inbound type.
        let mut fallback = candidate.clone();
        fallback.compiled.node_id = candidate.compiled.spec.tag.clone();
        fallback
    }

    fn reserve_traffic(
        &self,
        inbound: &NormalizedInbound,
        user_id: &str,
    ) -> Result<PendingTrafficReservation, String> {
        let key = Self::traffic_key(inbound, user_id);
        let owns_reservation = self.pending_traffic().reserve(&key)?;
        Ok(PendingTrafficReservation {
            inner: Arc::clone(&self.inner),
            key,
            owns_reservation,
        })
    }

    fn queue_traffic(
        &self,
        reservation: PendingTrafficReservation,
        inbound: &NormalizedInbound,
        info: UserInfo,
    ) {
        reservation.commit(traffic_drain(inbound, info));
    }

    async fn remove_user_with_retry(
        &self,
        tag: &str,
        user_id: &str,
    ) -> Result<UserInfo, UserRemovalFailure> {
        match self.inner.engine.remove_user(tag, user_id).await {
            Ok(info) => Ok(info),
            Err(EngineError::Io(first)) => {
                // MemoryUserRegistry removes the user and installs its draining
                // tombstone before awaiting a detached finalizer. A JoinError is
                // therefore an uncertain receipt, not proof that nothing changed;
                // the documented retry path attaches to that tombstone and collects
                // the same final counters.
                self.inner
                    .engine
                    .remove_user(tag, user_id)
                    .await
                    .map_err(|retry| UserRemovalFailure {
                        message: format!(
                            "user removal finalizer failed: {first}; retry final receipt: {retry}"
                        ),
                        changed: true,
                        missing: false,
                    })
            }
            Err(error) => {
                let missing = matches!(error, EngineError::UnknownUser { .. });
                Err(UserRemovalFailure {
                    message: error.to_string(),
                    changed: false,
                    missing,
                })
            }
        }
    }

    fn flush_changed_traffic_metadata(
        &self,
        previous: &NormalizedConfig,
        desired: &NormalizedConfig,
        replaced: &BTreeSet<String>,
    ) -> Result<(), StepFailure> {
        for (tag, old) in &previous.inbounds {
            // Hard replacement already collected the old generation's final
            // counters in `stop_inbound`; anything now reachable under this tag
            // belongs to the candidate generation and its metadata.
            if replaced.contains(tag) {
                continue;
            }
            let Some(new) = desired.inbounds.get(tag) else {
                continue;
            };
            if old.compiled.node_id == new.compiled.node_id
                && old.compiled.protocol == new.compiled.protocol
            {
                continue;
            }
            let users = match self.inner.engine.list_users(tag) {
                Ok(users) => users,
                Err(EngineError::Unsupported(_)) => continue,
                Err(error) => {
                    return Err(StepFailure::unchanged(format!(
                        "list users before changing ownership metadata for inbound {tag}: {error}"
                    )));
                }
            };
            // Reserve and take one receipt at a time. A topology with more than
            // MAX_PENDING_TRAFFIC_KEYS zero-traffic users therefore remains legal,
            // while every non-zero receipt is still guaranteed bounded storage
            // before its counter is zeroed.
            for user in users {
                let reservation = self.reserve_traffic(old, &user.id).map_err(|error| {
                    StepFailure::unchanged(format!(
                        "reserve old traffic for user {} before changing ownership metadata for inbound {tag}: {error}",
                        user.id
                    ))
                })?;
                let info = self
                    .inner
                    .engine
                    .take_user_traffic(tag, &user.id)
                    .map_err(|error| {
                        StepFailure::unchanged(format!(
                            "take old traffic for user {} before changing ownership metadata for inbound {tag}: {error}",
                            user.id
                        ))
                    })?;
                self.queue_traffic(reservation, old, info);
            }
        }
        Ok(())
    }

    async fn execute_apply(
        &self,
        current: &NormalizedConfig,
        desired: &NormalizedConfig,
        force_config_reload: bool,
    ) -> Result<(), (StepFailure, Vec<Undo>)> {
        if force_config_reload {
            return Box::pin(self.execute_full_reload(current, desired)).await;
        }

        let diff = diff_configs(current, desired);
        let mut journal = Vec::new();

        // Deletions go first so an added or moved inbound may legitimately claim
        // one of their ports.  Every deletion is journalled before the next starts.
        for tag in &diff.removed {
            let old = current.inbounds.get(tag).expect("diff tag exists").clone();
            let replay = match self.inner.engine.preserve_inbound_replay(tag) {
                Ok(replay) => replay,
                Err(error) => {
                    return Err((
                        StepFailure::unchanged(format!(
                            "preserve replay state for inbound {tag}: {error}"
                        )),
                        journal,
                    ));
                }
            };
            if let Err(failure) = self.stop_inbound(&old).await {
                return Err((failure, journal));
            }
            journal.push(Undo::AddInbound {
                inbound: old,
                replay,
            });
        }

        // First distinguish true listener replacements from handler-only RCU
        // updates. `update_inbound` is the engine's authoritative classifier: a
        // `ReloadRequired` result is non-mutating, while success is journalled for
        // rollback. No replacement listener is stopped during this phase.
        let mut replacements = Vec::new();
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

            if delta.user_mode_changed {
                let replay = match self.inner.engine.preserve_inbound_replay(&delta.tag) {
                    Ok(replay) => replay,
                    Err(error) => {
                        return Err((
                            StepFailure::unchanged(format!(
                                "preserve replay state before replacing inbound {}: {error}",
                                delta.tag
                            )),
                            journal,
                        ));
                    }
                };
                replacements.push((delta.tag.clone(), old, new, replay));
            } else if delta.config_changed {
                let replay = match self.inner.engine.preserve_inbound_replay(&delta.tag) {
                    Ok(replay) => replay,
                    Err(error) => {
                        return Err((
                            StepFailure::unchanged(format!(
                                "preserve replay state before updating inbound {}: {error}",
                                delta.tag
                            )),
                            journal,
                        ));
                    }
                };
                match self.inner.engine.update_inbound(update_spec(&new)).await {
                    Ok(_) => journal.push(Undo::RestoreHotConfig {
                        current: new.clone(),
                        previous: old.clone(),
                        replay,
                    }),
                    Err(EngineError::ReloadRequired(_)) => {
                        replacements.push((delta.tag.clone(), old, new, replay));
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
        }

        // Listener replacements are one transaction-wide remove-all/add-all
        // phase. This is what permits A:10001/B:10002 -> A:10002/B:10001: every
        // old owner releases its socket before any candidate claims one. Journal
        // ordering removes all candidates before rebuilding any old listener.
        for (_, old, _, replay) in &replacements {
            if let Err(failure) = self.stop_inbound(old).await {
                return Err((failure, journal));
            }
            journal.push(Undo::AddInbound {
                inbound: old.clone(),
                replay: replay.clone(),
            });
        }
        for (tag, old, new, replay) in &replacements {
            if let Err(error) = Box::pin(
                self.inner
                    .engine
                    .add_inbound_with_replay(new.compiled.spec.clone(), replay),
            )
            .await
            {
                return Err((
                    StepFailure::unchanged(format!("start replacement inbound {tag}: {error}")),
                    journal,
                ));
            }
            journal.push(Undo::RemoveInbound {
                live: new.clone(),
                accounting: old.clone(),
            });
        }
        let replaced: BTreeSet<String> = replacements
            .iter()
            .map(|(tag, _, _, _)| tag.clone())
            .collect();

        // Replacements were built from complete desired specs and already contain
        // their final user registries. Reconcile users only on listeners that stayed
        // live (with or without an RCU handler update).
        for delta in &diff.changed {
            if replaced.contains(&delta.tag) {
                continue;
            }
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

            // Retire first.  Besides making revocation immediate, this frees a
            // credential that the same transaction may intentionally assign to a
            // newly added user.
            for id in &delta.removed_users {
                let old_user = old.users.get(id).expect("diff user exists").clone();
                let reservation = match self.reserve_traffic(&old, id) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        return Err((
                            StepFailure::unchanged(format!(
                                "reserve final traffic for user {id} on {}: {error}",
                                delta.tag
                            )),
                            journal,
                        ));
                    }
                };
                match self.remove_user_with_retry(&delta.tag, id).await {
                    Ok(info) => {
                        self.queue_traffic(reservation, &old, info);
                        journal.push(Undo::AddUser {
                            inbound: old.clone(),
                            user: old_user,
                        });
                    }
                    Err(error) => {
                        return Err((
                            StepFailure {
                                operation: format!(
                                    "remove user {id} from {}: {}",
                                    delta.tag, error.message
                                ),
                                rollback: Vec::new(),
                                changed: error.changed,
                                restored: !error.changed,
                            },
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
                        live: new.clone(),
                        accounting: old.clone(),
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
            if let Err(error) =
                Box::pin(self.inner.engine.add_inbound(new.compiled.spec.clone())).await
            {
                return Err((
                    StepFailure::unchanged(format!("add inbound {tag}: {error}")),
                    journal,
                ));
            }
            let accounting = Self::uncommitted_accounting_owner(None, &new);
            journal.push(Undo::RemoveInbound {
                live: new,
                accounting,
            });
        }

        if let Err(failure) = self.flush_changed_traffic_metadata(current, desired, &replaced) {
            return Err((failure, journal));
        }

        Ok(())
    }

    /// Replace one complete Box generation, matching Go's `old.Close(); new.Start()`
    /// boundary instead of exposing a mixture of old and candidate inbounds.
    ///
    /// Every old listener is stopped before the first candidate listener starts.
    /// The undo journal therefore has two clean halves: candidate listeners are
    /// removed first on failure, then the complete previous topology is rebuilt.
    /// Replay leases are retained independently of listener lifetime so the hard
    /// connection cutover cannot reopen VMess/SS replay windows.
    async fn execute_full_reload(
        &self,
        current: &NormalizedConfig,
        desired: &NormalizedConfig,
    ) -> Result<(), (StepFailure, Vec<Undo>)> {
        let mut journal = Vec::new();
        let mut replay_by_tag = BTreeMap::new();

        for (tag, old) in &current.inbounds {
            let replay = match self.inner.engine.preserve_inbound_replay(tag) {
                Ok(replay) => replay,
                Err(error) => {
                    return Err((
                        StepFailure::unchanged(format!(
                            "preserve replay state for inbound {tag}: {error}"
                        )),
                        journal,
                    ));
                }
            };
            if let Err(failure) = self.stop_inbound(old).await {
                return Err((failure, journal));
            }
            replay_by_tag.insert(tag.clone(), replay.clone());
            journal.push(Undo::AddInbound {
                inbound: old.clone(),
                replay,
            });
        }

        for (tag, candidate) in &desired.inbounds {
            let result = match replay_by_tag.get(tag) {
                Some(replay) => {
                    Box::pin(
                        self.inner
                            .engine
                            .add_inbound_with_replay(candidate.compiled.spec.clone(), replay),
                    )
                    .await
                }
                None => {
                    Box::pin(
                        self.inner
                            .engine
                            .add_inbound(candidate.compiled.spec.clone()),
                    )
                    .await
                }
            };
            if let Err(error) = result {
                return Err((
                    StepFailure::unchanged(format!(
                        "start full-reload candidate inbound {tag}: {error}"
                    )),
                    journal,
                ));
            }
            journal.push(Undo::RemoveInbound {
                live: candidate.clone(),
                accounting: Self::uncommitted_accounting_owner(
                    current.inbounds.get(tag),
                    candidate,
                ),
            });
        }

        Ok(())
    }

    async fn replace_inbound(
        &self,
        old: &NormalizedInbound,
        new: &NormalizedInbound,
    ) -> Result<(), StepFailure> {
        let replay = self
            .inner
            .engine
            .preserve_inbound_replay(&old.compiled.spec.tag)
            .map_err(|error| {
                StepFailure::unchanged(format!(
                    "preserve replay state for inbound {}: {error}",
                    old.compiled.spec.tag
                ))
            })?;
        Box::pin(self.replace_inbound_with_replay(old, new, &replay)).await
    }

    async fn replace_inbound_with_replay(
        &self,
        old: &NormalizedInbound,
        new: &NormalizedInbound,
        replay: &InboundReplayLease,
    ) -> Result<(), StepFailure> {
        Box::pin(self.replace_inbound_with_replay_owners(old, old, old, new, replay)).await
    }

    async fn replace_inbound_with_replay_owners(
        &self,
        current: &NormalizedInbound,
        registry: &NormalizedInbound,
        accounting: &NormalizedInbound,
        new: &NormalizedInbound,
        replay: &InboundReplayLease,
    ) -> Result<(), StepFailure> {
        Box::pin(self.stop_inbound_with_owners(current, registry, accounting)).await?;
        match Box::pin(
            self.inner
                .engine
                .add_inbound_with_replay(new.compiled.spec.clone(), replay),
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(operation) => match Box::pin(
                self.inner
                    .engine
                    .add_inbound_with_replay(current.compiled.spec.clone(), replay),
            )
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
                        current.compiled.spec.tag
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
        self.stop_inbound_with_owners(inbound, inbound, inbound)
            .await
    }

    async fn stop_inbound_with_owners(
        &self,
        listener: &NormalizedInbound,
        registry: &NormalizedInbound,
        accounting: &NormalizedInbound,
    ) -> Result<(), StepFailure> {
        debug_assert_eq!(listener.compiled.spec.tag, registry.compiled.spec.tag);
        debug_assert_eq!(listener.compiled.spec.tag, accounting.compiled.spec.tag);
        let tag = &listener.compiled.spec.tag;
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
        for live_user in live_users {
            let Some(spec) = registry.users.get(&live_user.id).cloned() else {
                let rollback = self.restore_users(tag, &removed);
                return Err(StepFailure {
                    operation: format!(
                        "cannot remove inbound {tag}: live user {} is absent from AppliedState",
                        live_user.id
                    ),
                    changed: !removed.is_empty(),
                    restored: rollback.is_empty(),
                    rollback,
                });
            };
            let reservation = match self.reserve_traffic(accounting, &live_user.id) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let rollback = self.restore_users(tag, &removed);
                    return Err(StepFailure {
                        operation: format!(
                            "reserve final traffic for user {} while stopping inbound {tag}: {error}",
                            live_user.id
                        ),
                        changed: !removed.is_empty(),
                        restored: rollback.is_empty(),
                        rollback,
                    });
                }
            };
            match self.remove_user_with_retry(tag, &live_user.id).await {
                Ok(info) => {
                    self.queue_traffic(reservation, accounting, info);
                    removed.push(spec);
                }
                Err(error) => {
                    let rollback = self.restore_users(tag, &removed);
                    return Err(StepFailure {
                        operation: format!(
                            "remove user {} before stopping inbound {tag}: {}",
                            live_user.id, error.message
                        ),
                        changed: error.changed || !removed.is_empty(),
                        // An uncertain final receipt cannot be declared restored:
                        // even if earlier users were re-added, its tombstone and
                        // counters still require recovery.
                        restored: !error.changed && rollback.is_empty(),
                        rollback,
                    });
                }
            }
        }

        if let Err(error) = self.inner.engine.remove_inbound_hard(tag).await {
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

    async fn finish_failed_transaction(&self, transaction: FailedTransaction) -> RuntimeError {
        let FailedTransaction {
            previous,
            previous_replay,
            failure,
            mut journal,
            dns,
        } = transaction;
        // Rotating the process DNS client is itself a live state change even when
        // the first listener operation fails before it mutates anything.
        let restoration_attempted = dns.full_reload || failure.changed || !journal.is_empty();
        let had_previous_topology = !previous.inbounds.is_empty();
        let mut rollback = failure.rollback;
        // Even the first uncommitted Box candidate can build and serve from a DNS
        // resolver before a later listener fails. It had no old generation to
        // rotate away from on entry, but its cache/policy state must still be
        // discarded before the next attempt.
        if dns.full_reload {
            let generation = self.inner.engine.rotate_dns_client_generation().await;
            log::debug!(
                "rotated DNS client state to generation {generation} before rebuilding rollback topology"
            );
            if let Err(error) = self
                .inner
                .engine
                .configure_urltest_probe_dns(previous.urltest_probe_dns.as_ref())
                .await
            {
                rollback.push(format!(
                    "restore generation-global URLTest probe DNS: {error}"
                ));
            }
        }
        let (journal_errors, recovery_live) = Box::pin(self.rollback_journal(&mut journal)).await;
        rollback.extend(journal_errors);
        // `replace_inbound` may already have restored the step that failed before
        // control reached this transaction-wide rollback. Refresh every restored
        // inbound once more after the rollback DNS generation was published, so
        // new logical flows cannot retain a candidate generation's resolver/rule-
        // state graph. Prefer the RCU path here; only a listener without a reload
        // slot needs another bind cycle.
        if dns.client_rotated && failure.restored && rollback.is_empty() {
            for inbound in previous.inbounds.values() {
                match self.inner.engine.update_inbound(update_spec(inbound)).await {
                    Ok(_) => {}
                    Err(EngineError::ReloadRequired(_)) => {
                        if let Err(error) = Box::pin(self.replace_inbound(inbound, inbound)).await {
                            rollback.push(format!(
                                "rebuild rollback DNS state for {}: {}",
                                inbound.compiled.spec.tag,
                                describe_step_failure(error)
                            ));
                        }
                    }
                    Err(error) => rollback.push(format!(
                        "refresh rollback DNS state for {}: {error}",
                        inbound.compiled.spec.tag
                    )),
                }
            }
        }
        let fully_restored = failure.restored && rollback.is_empty();
        let rolled_back = fully_restored && restoration_attempted && had_previous_topology;
        let state_unchanged = fully_restored && !restoration_attempted;

        {
            let mut state = self.write_state();
            // `rolled_back` follows the ACP/Go wire meaning and is only true when a
            // non-empty published topology had to be restored.  State bookkeeping is
            // broader: a preflight/first-step failure and a transaction that restored
            // an empty topology are both fully known as well.
            if fully_restored {
                state.current = Some(previous);
                state.recovery = None;
                state.recovery_live.clear();
            } else {
                state.current = None;
                state.recovery = Some(previous);
                state.recovery_live = recovery_live;
            }
        }
        if fully_restored {
            self.recovery_replay().clear();
            self.inner
                .engine
                .commit_client_chain_group_generation()
                .await;
        } else {
            *self.recovery_replay() = previous_replay;
        }

        RuntimeError::failed(
            failure.operation,
            rollback,
            rolled_back,
            state_unchanged,
            fully_restored,
        )
    }

    async fn rollback_journal(
        &self,
        journal: &mut Vec<Undo>,
    ) -> (Vec<String>, BTreeMap<String, RetiringInbound>) {
        let mut errors = Vec::new();
        let mut recovery_live = BTreeMap::new();
        while let Some(undo) = journal.pop() {
            let (result, survivor) = match undo {
                Undo::AddInbound { inbound, replay } => {
                    let result = Box::pin(
                        self.inner
                            .engine
                            .add_inbound_with_replay(inbound.compiled.spec.clone(), &replay),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        format!("restore inbound {}: {error}", inbound.compiled.spec.tag)
                    });
                    if result.is_ok() {
                        recovery_live.insert(
                            inbound.compiled.spec.tag.clone(),
                            RetiringInbound {
                                live: inbound.clone(),
                                accounting: inbound.clone(),
                            },
                        );
                    }
                    (result, None)
                }
                Undo::RemoveInbound { live, accounting } => {
                    let tag = live.compiled.spec.tag.clone();
                    let result = self
                        .stop_inbound_with_owners(&live, &live, &accounting)
                        .await
                        .map_err(|failure| {
                            format!("remove candidate: {}", describe_step_failure(failure))
                        });
                    if result.is_ok() {
                        recovery_live.remove(&tag);
                    }
                    (result, Some(RetiringInbound { live, accounting }))
                }
                Undo::RestoreHotConfig {
                    current,
                    previous,
                    replay,
                } => {
                    let result = Box::pin(self.replace_inbound_with_replay_owners(
                        &current, &previous, &previous, &previous, &replay,
                    ))
                    .await
                    .map_err(describe_step_failure);
                    if result.is_ok() {
                        recovery_live.insert(
                            previous.compiled.spec.tag.clone(),
                            RetiringInbound {
                                live: previous.clone(),
                                accounting: previous.clone(),
                            },
                        );
                    }
                    (
                        result,
                        Some(RetiringInbound {
                            live: current,
                            accounting: previous,
                        }),
                    )
                }
                Undo::AddUser { inbound, user } => {
                    let id = user.resolved_id().unwrap_or("<unknown>").to_string();
                    (
                        self.inner
                            .engine
                            .add_user(&inbound.compiled.spec.tag, user)
                            .map(|_| ())
                            .map_err(|error| {
                                format!(
                                    "restore user {id} on {}: {error}",
                                    inbound.compiled.spec.tag
                                )
                            }),
                        None,
                    )
                }
                Undo::RemoveUser {
                    live,
                    accounting,
                    user_id,
                } => {
                    let reservation =
                        self.reserve_traffic(&accounting, &user_id)
                            .map_err(|error| {
                                format!(
                                    "reserve candidate user {user_id} traffic on {}: {error}",
                                    live.compiled.spec.tag
                                )
                            });
                    let result = match reservation {
                        Err(error) => Err(error),
                        Ok(reservation) => match self
                            .remove_user_with_retry(&live.compiled.spec.tag, &user_id)
                            .await
                        {
                            Ok(info) => {
                                self.queue_traffic(reservation, &accounting, info);
                                Ok(())
                            }
                            Err(error) => Err(format!(
                                "remove candidate user {user_id} from {}: {}",
                                live.compiled.spec.tag, error.message
                            )),
                        },
                    };
                    (result, Some(RetiringInbound { live, accounting }))
                }
                Undo::RestoreUser {
                    inbound,
                    user,
                    kick,
                } => {
                    let id = user.resolved_id().unwrap_or("<unknown>").to_string();
                    let result = match self.inner.engine.add_user(&inbound.compiled.spec.tag, user)
                    {
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
                    };
                    (result, None)
                }
            };
            if let Err(error) = result {
                if let Some(inbound) = survivor
                    && self
                        .inner
                        .engine
                        .get_inbound(&inbound.live.compiled.spec.tag)
                        .is_some()
                {
                    recovery_live.insert(inbound.live.compiled.spec.tag.clone(), inbound);
                }
                errors.push(error);
            }
        }
        if errors.is_empty() {
            recovery_live.clear();
        }
        (errors, recovery_live)
    }

    async fn recover_if_needed(&self) -> Result<(), RuntimeError> {
        let (recovery, mut recovery_live) = {
            let state = self.read_state();
            if state.current.is_some() {
                return Ok(());
            }
            (
                state.recovery.clone().unwrap_or_default(),
                state.recovery_live.clone(),
            )
        };
        let replay = self.recovery_replay().clone();

        // A failed rollback leaves no trustworthy per-tag model.  Converge through
        // the one state we do know: stop everything the engine reports, then rebuild
        // the retained recovery configuration from complete specs.
        let mut errors = Vec::new();
        let live = self.inner.engine.list_inbounds();
        let live_tags: BTreeSet<String> = live.iter().map(|info| info.tag.clone()).collect();
        recovery_live.retain(|tag, _| live_tags.contains(tag));
        for info in &live {
            if !recovery_live.contains_key(&info.tag)
                && let Some(inbound) = recovery.inbounds.get(&info.tag)
            {
                recovery_live.insert(
                    info.tag.clone(),
                    RetiringInbound {
                        live: inbound.clone(),
                        accounting: inbound.clone(),
                    },
                );
            }
        }
        self.publish_recovery_live(&recovery_live);

        for info in live {
            let known = recovery_live.get(&info.tag);
            if let Err(error) = self.force_stop_tag(&info.tag, known, &info.protocol).await {
                errors.push(error);
            } else {
                recovery_live.remove(&info.tag);
                self.publish_recovery_live(&recovery_live);
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

        // The failed rollback may have bound this generation's URLTest registry
        // to its default system resolver after publishing the intended recovery
        // sidecar failed. With every listener now stopped, rotate before retrying
        // the retained sidecar so a transient bootstrap failure cannot make the
        // fingerprint mismatch permanent until process restart.
        let generation = self.inner.engine.rotate_dns_client_generation().await;
        log::debug!(
            "rotated DNS client state to generation {generation} before rebuilding recovery topology"
        );
        if let Err(error) = self
            .inner
            .engine
            .configure_urltest_probe_dns(recovery.urltest_probe_dns.as_ref())
            .await
        {
            return Err(RuntimeError::failed(
                format!("restore generation-global URLTest probe DNS: {error}"),
                Vec::new(),
                false,
                false,
                false,
            ));
        }

        for inbound in recovery.inbounds.values() {
            let Some(lease) = replay.get(&inbound.compiled.spec.tag) else {
                return Err(RuntimeError::failed(
                    format!(
                        "restore recovery inbound {}: replay namespace was not retained",
                        inbound.compiled.spec.tag
                    ),
                    Vec::new(),
                    false,
                    false,
                    false,
                ));
            };
            if let Err(error) = Box::pin(
                self.inner
                    .engine
                    .add_inbound_with_replay(inbound.compiled.spec.clone(), lease),
            )
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
            recovery_live.insert(
                inbound.compiled.spec.tag.clone(),
                RetiringInbound {
                    live: inbound.clone(),
                    accounting: inbound.clone(),
                },
            );
            self.publish_recovery_live(&recovery_live);
        }

        {
            let mut state = self.write_state();
            state.current = Some(recovery);
            state.recovery = None;
            state.recovery_live.clear();
        }
        self.recovery_replay().clear();
        self.inner
            .engine
            .commit_client_chain_group_generation()
            .await;
        Ok(())
    }

    /// Keep the indeterminate-state metadata aligned with the listener generations
    /// that actually exist after each recovery step. A later bind failure may leave
    /// an already rebuilt previous-generation listener serving until the next retry.
    fn publish_recovery_live(&self, recovery_live: &BTreeMap<String, RetiringInbound>) {
        let mut state = self.write_state();
        debug_assert!(state.current.is_none());
        state.recovery_live = recovery_live.clone();
    }

    async fn force_stop_tag(
        &self,
        tag: &str,
        known: Option<&RetiringInbound>,
        _fallback_protocol: &str,
    ) -> Result<(), String> {
        match self.inner.engine.list_users(tag) {
            Ok(users) => {
                let mut user_ids: BTreeSet<String> =
                    users.into_iter().map(|user| user.id).collect();
                if let Some(inbound) = known.filter(|inbound| inbound.live.dynamic_users) {
                    // `list_users` intentionally omits draining tombstones. Include
                    // the generation's configured ids so recovery can collect an
                    // uncertain finalizer receipt before removing the registry.
                    user_ids.extend(inbound.live.users.keys().cloned());
                    user_ids.extend(inbound.accounting.users.keys().cloned());
                }
                if known.is_none() && !user_ids.is_empty() {
                    return Err(format!(
                        "cannot safely stop untracked inbound {tag}: traffic ownership metadata is unavailable"
                    ));
                }
                for user_id in user_ids {
                    let inbound =
                        known.expect("an untracked inbound with users was rejected above");
                    let reservation = self
                        .reserve_traffic(&inbound.accounting, &user_id)
                        .map_err(|error| {
                            format!(
                                "reserve final traffic for user {} while stopping {tag}: {error}",
                                user_id
                            )
                        })?;
                    match self.remove_user_with_retry(tag, &user_id).await {
                        Ok(info) => self.queue_traffic(reservation, &inbound.accounting, info),
                        // A configured id absent from both the live map and the
                        // tombstone map was already collected by an earlier step.
                        Err(error) if error.missing && !error.changed => {}
                        Err(error) => {
                            return Err(format!(
                                "remove user {user_id} while stopping {tag}: {}",
                                error.message
                            ));
                        }
                    }
                }
            }
            Err(EngineError::Unsupported(_)) => {}
            Err(error) => return Err(format!("list users while stopping {tag}: {error}")),
        }
        self.inner
            .engine
            .remove_inbound_hard(tag)
            .await
            .map(|_| ())
            .map_err(|error| format!("remove inbound {tag}: {error}"))
    }

    async fn close_owned(&self) -> Result<(), RuntimeError> {
        self.inner.closing.cancel();
        let _apply = self.inner.apply.lock().await;
        self.cancel_rule_set_watcher_locked();
        let already_closed = self.read_state().closed;
        if already_closed && self.inner.engine.list_inbounds().is_empty() {
            let mut state = self.write_state();
            state.current = Some(NormalizedConfig::default());
            state.recovery = None;
            state.recovery_live.clear();
            state.committed = false;
            drop(state);
            self.recovery_replay().clear();
            return Ok(());
        }

        let (known, recovery_live) = {
            let state = self.read_state();
            (
                state.current.clone().or_else(|| state.recovery.clone()),
                state.recovery_live.clone(),
            )
        };
        let mut errors = Vec::new();
        for info in self.inner.engine.list_inbounds() {
            let inbound = recovery_live.get(&info.tag).cloned().or_else(|| {
                known.as_ref().and_then(|config| {
                    config
                        .inbounds
                        .get(&info.tag)
                        .map(|inbound| RetiringInbound {
                            live: inbound.clone(),
                            accounting: inbound.clone(),
                        })
                })
            });
            if let Err(error) = self
                .force_stop_tag(&info.tag, inbound.as_ref(), &info.protocol)
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
            state.recovery_live.clear();
            state.committed = false;
        } else {
            // Applying is permanently forbidden once close begins, but a second
            // close must still be able to retry listeners that failed to stop.  Do
            // not publish an empty snapshot while any of them remain live.
            state.current = None;
            state.recovery = known;
            state.recovery_live = recovery_live;
        }
        drop(state);

        if errors.is_empty() {
            self.recovery_replay().clear();
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
        let tags: Vec<String> = {
            let state = self.read_state();
            let Some(current) = &state.current else {
                return ConnectionStats::default();
            };
            current
                .inbounds
                .iter()
                .filter(|(_, inbound)| inbound.compiled.node_id == node_id)
                .map(|(tag, _)| tag.clone())
                .collect()
        };

        let mut active_connections = 0u64;
        let mut online = BTreeSet::new();
        for tag in tags {
            let Ok(users) = self.inner.engine.list_users(&tag) else {
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

    async fn close_user_connections_owned(&self, target: &UserConnectionTarget) -> u64 {
        if target.node_id.is_empty() || target.user_id.is_empty() {
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
                .filter(|(_, inbound)| inbound.compiled.node_id == target.node_id)
                .map(|(tag, _)| tag.clone())
                .collect()
        };
        let mut closed = 0u64;
        for tag in tags {
            match self.inner.engine.kick_user(&tag, &target.user_id) {
                Ok(count) => closed = closed.saturating_add(count),
                // A remote disconnect may legitimately name an offline user or a
                // classic config-credential inbound. Neither leaves a known
                // dynamic-user session behind, so they remain quiet no-ops.
                Err(EngineError::UnknownUser { .. } | EngineError::Unsupported(_)) => {}
                Err(error) => {
                    log::warn!(
                        "close user connections for node {} user {} on inbound {tag}: {error}; stale sessions may still be active",
                        target.node_id,
                        target.user_id
                    );
                }
            }
        }
        closed
    }

    async fn drain_traffic_owned(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        let _apply = self.inner.apply.lock().await;
        // Pending receipts are already durable, so move them into this call's
        // transient result map and free the bounded retention budget before
        // touching live counters. The returned sweep is intentionally not capped:
        // a legal topology may contain more users than the retention budget.
        let mut drained = BTreeMap::new();
        let pending_receipts = self.pending_traffic().drain();
        for receipt in pending_receipts {
            merge_traffic_entry(&mut drained, receipt);
        }
        {
            // The sweep has no await after taking `apply`, and engine counter
            // reads never re-enter runtime state. Borrow the published config
            // instead of cloning its user credentials and diagnostic payload.
            let state = self.read_state();
            if let Some(current) = &state.current {
                for (tag, inbound) in &current.inbounds {
                    match self.inner.engine.take_nonzero_inbound_traffic(tag) {
                        Ok(users) => {
                            for info in users {
                                merge_traffic_entry(&mut drained, traffic_drain(inbound, info));
                            }
                        }
                        Err(EngineError::Unsupported(_) | EngineError::UnknownTag(_)) => {}
                        Err(error) => {
                            // The engine sweep fails before changing this tag's
                            // counters. Returning successful receipts from other tags
                            // is lossless and avoids trying to retain an arbitrarily
                            // large topology inside the bounded pending map.
                            log::error!("take traffic for inbound {tag}: {error}");
                        }
                    }
                }
            }
        }
        Ok(drained.into_values().collect())
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
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
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
    fn begin_close(&self) {
        self.inner.closing.cancel();
    }

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
        let target = Arc::new(UserConnectionTarget::new(node_id, user_id));
        let task_target = Arc::clone(&target);
        let result =
            tokio::spawn(async move { runtime.close_user_connections_owned(&task_target).await })
                .await;
        close_user_connections_task_result(&target, result)
    }

    async fn drain_traffic(&self) -> Result<Vec<TrafficDrain>, RuntimeError> {
        // Unlike topology mutations, the drain has no await after acquiring the
        // apply mutex: every counter take and the final Vec construction complete
        // in that same poll. Await it directly so cancelling while the mutex is
        // contended drops the waiter before anything is taken; detaching this work
        // would let it clear counters after its only receiver disappeared.
        self.drain_traffic_owned().await
    }
}

fn close_user_connections_task_result(
    target: &UserConnectionTarget,
    result: Result<u64, tokio::task::JoinError>,
) -> u64 {
    match result {
        Ok(closed) => closed,
        Err(error) => {
            log::warn!(
                "close user connections task failed for node {} user {}: {error}; stale sessions may still be active",
                target.node_id,
                target.user_id
            );
            0
        }
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
        compiled.spec.tag.clone_from(&tag);

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
        if inbounds.insert(tag.clone(), normalized).is_some() {
            return Err(format!("inbound tag {tag} is listed twice"));
        }
    }
    Ok(NormalizedConfig {
        inbounds,
        rule_set_digest: [0; 32],
        dns_client_fingerprint: config.dns_client_fingerprint,
        urltest_probe_dns: config.urltest_probe_dns,
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
    // Users are reconciled through their atomic endpoints.  Passing them to
    // update_inbound is intentionally rejected by shoes-engine, so avoid copying
    // credentials that would only be discarded here.
    InboundSpec {
        tag: inbound.compiled.spec.tag.clone(),
        config: inbound.compiled.spec.config.clone(),
        users: None,
    }
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
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};
    use shoes::dynamic::{ConnContext, UserRegistry};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

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

    async fn wait_for_inbound_generation(
        runtime: &ShoesRuntime,
        tag: &str,
        previous: &Arc<shoes_engine::InboundSlot>,
        previous_revision: u64,
    ) -> (Arc<shoes_engine::InboundSlot>, u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(inbound) = runtime.engine().get_inbound(tag) {
                    let revision = inbound.revision();
                    // A logical-flow-only update advances the slot revision. A
                    // rule-set content change rotates the complete DNS/Box client
                    // and therefore publishes a new slot whose revision starts at
                    // zero. Accept either observable generation boundary.
                    if !Arc::ptr_eq(&inbound, previous) || revision > previous_revision {
                        return (inbound, revision);
                    }
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

    fn free_udp_addr() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral UDP port");
        socket.local_addr().expect("read ephemeral UDP port")
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

    fn socks(address: SocketAddr, sniff: bool) -> Value {
        json!({
            "address": address.to_string(),
            "protocol": {"type": "socks", "udp_enabled": false},
            "sniff": sniff,
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
            dns_client_fingerprint: [0; 32],
            urltest_probe_dns: None,
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
    async fn changed_inbounds_can_swap_listen_ports_in_one_transaction() {
        let addresses = free_addrs(2);
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"before-swap",
                vec![
                    compiled("a", "node-a", vless(addresses[0]), Some(vec![])),
                    compiled("b", "node-b", vless(addresses[1]), Some(vec![])),
                ],
            ))
            .await
            .expect("start original listeners");
        let replay_a = runtime.engine().preserve_inbound_replay("a").unwrap();
        let replay_b = runtime.engine().preserve_inbound_replay("b").unwrap();

        runtime
            .apply_config(config(
                b"after-swap",
                vec![
                    compiled("a", "node-a", vless(addresses[1]), Some(vec![])),
                    compiled("b", "node-b", vless(addresses[0]), Some(vec![])),
                ],
            ))
            .await
            .expect("all old listeners are removed before either replacement binds");

        let a = runtime.engine().get_inbound("a").unwrap();
        let b = runtime.engine().get_inbound("b").unwrap();
        assert!(a.describe().bind.contains(&addresses[1].to_string()));
        assert!(b.describe().bind.contains(&addresses[0].to_string()));
        assert_eq!(
            replay_a,
            runtime.engine().preserve_inbound_replay("a").unwrap()
        );
        assert_eq!(
            replay_b,
            runtime.engine().preserve_inbound_replay("b").unwrap()
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_two_phase_replacement_restores_ports_and_replay_lineages() {
        let addresses = free_addrs(2);
        let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
        let blocked = blocker.local_addr().unwrap();
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"old",
                vec![
                    compiled("a", "node-a", vless(addresses[0]), Some(vec![])),
                    compiled("b", "node-b", vless(addresses[1]), Some(vec![])),
                ],
            ))
            .await
            .unwrap();
        let replay_a = runtime.engine().preserve_inbound_replay("a").unwrap();
        let replay_b = runtime.engine().preserve_inbound_replay("b").unwrap();

        let error = runtime
            .apply_config(config(
                b"candidate",
                vec![
                    compiled("a", "node-a", vless(addresses[1]), Some(vec![])),
                    compiled("b", "node-b", vless(blocked), Some(vec![])),
                ],
            ))
            .await
            .expect_err("the second replacement cannot claim the blocked port");
        assert!(error.rolled_back(), "{error}");
        assert!(error.rollback_error().is_none(), "{error}");
        assert!(
            runtime
                .engine()
                .get_inbound("a")
                .unwrap()
                .describe()
                .bind
                .contains(&addresses[0].to_string())
        );
        assert!(
            runtime
                .engine()
                .get_inbound("b")
                .unwrap()
                .describe()
                .bind
                .contains(&addresses[1].to_string())
        );
        assert_eq!(
            replay_a,
            runtime.engine().preserve_inbound_replay("a").unwrap()
        );
        assert_eq!(
            replay_b,
            runtime.engine().preserve_inbound_replay("b").unwrap()
        );
        drop(blocker);
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reused_tag_splits_traffic_before_node_metadata_changes() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"node-a",
                vec![compiled(
                    "shared-tag",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .unwrap();
        let registry = runtime
            .engine()
            .get_inbound("shared-tag")
            .unwrap()
            .users()
            .unwrap()
            .clone();
        let alice = registry.find_uuid(&uuid_bytes(ALICE_UUID)).unwrap();
        alice.add_rx(17);
        alice.add_tx(19);

        runtime
            .apply_config(config(
                b"node-b",
                vec![compiled(
                    "shared-tag",
                    "node-b",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .expect("metadata-only ownership change");
        alice.add_rx(5);
        alice.add_tx(7);

        let drains = runtime.drain_traffic().await.unwrap();
        let old = drains
            .iter()
            .find(|drain| drain.node_id == "node-a")
            .expect("old lineage traffic");
        let new = drains
            .iter()
            .find(|drain| drain.node_id == "node-b")
            .expect("new lineage traffic");
        assert_eq!((old.uplink_bytes, old.downlink_bytes), (17, 19));
        assert_eq!((new.uplink_bytes, new.downlink_bytes), (5, 7));
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hot_config_rollback_hard_closes_candidate_generation_connections() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let initial = config(
            b"old",
            vec![compiled("edge", "node-a", socks(address, false), None)],
        );
        runtime.apply_config(initial.clone()).await.unwrap();

        let previous = runtime.read_state().current.clone().unwrap();
        let mut candidate_config = initial;
        candidate_config.inbounds[0].spec.config = socks(address, true);
        let candidate = normalize(candidate_config).unwrap();
        let old = previous.inbounds.get("edge").unwrap().clone();
        let new = candidate.inbounds.get("edge").unwrap().clone();
        let replay = runtime.engine().preserve_inbound_replay("edge").unwrap();
        let old_slot = runtime.engine().get_inbound("edge").unwrap();
        runtime
            .engine()
            .update_inbound(update_spec(&new))
            .await
            .expect("publish candidate handler generation");

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5]).await.unwrap();
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.read(&mut byte))
                .await
                .is_err(),
            "candidate-generation connection stays pending before rollback"
        );

        let mut journal = vec![Undo::RestoreHotConfig {
            current: new,
            previous: old,
            replay,
        }];
        let (errors, survivors) = runtime.rollback_journal(&mut journal).await;
        assert!(errors.is_empty());
        assert!(survivors.is_empty());
        let restored_slot = runtime.engine().get_inbound("edge").unwrap();
        assert!(!Arc::ptr_eq(&old_slot, &restored_slot));
        let closed = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("rollback must close the candidate generation promptly");
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "candidate flow survived rollback"
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hot_config_and_user_rollback_drains_under_the_published_owner() {
        let address = free_udp_addr();
        let runtime = runtime().await;
        let password_user = |id: &str, password: &str| UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(password.to_string()),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        };
        let hysteria2 = |rules: Value| {
            json!({
                "address": address.to_string(),
                "transport": "quic",
                "quic_settings": {
                    "cert": include_str!("../../shoes-engine/tests/fixtures/test.crt"),
                    "key": include_str!("../../shoes-engine/tests/fixtures/test.key"),
                    "alpn_protocols": ["h3"],
                },
                "protocol": {"type": "hysteria2", "udp_enabled": false},
                "rules": rules,
            })
        };
        let mut initial = config(
            b"old",
            vec![compiled(
                "edge",
                "old-node",
                hysteria2(json!([])),
                Some(vec![
                    password_user("alice", "alice-password"),
                    password_user("bob", "bob-password"),
                ]),
            )],
        );
        initial.inbounds[0].protocol = "hysteria2".to_string();
        runtime.apply_config(initial.clone()).await.unwrap();

        let previous = runtime.read_state().current.clone().unwrap();
        let old = previous.inbounds.get("edge").unwrap().clone();
        let registry = runtime
            .engine()
            .get_inbound("edge")
            .unwrap()
            .users()
            .unwrap()
            .clone();
        let alice = registry.find_password("alice-password").unwrap();
        let bob = registry.find_password("bob-password").unwrap();
        alice.add_rx(17);
        bob.add_rx(11);

        let mut candidate_config = initial;
        candidate_config.inbounds[0].node_id = "candidate-node".to_string();
        candidate_config.inbounds[0].spec.config = hysteria2(json!([{
            "masks": "0.0.0.0/0",
            "action": "allow",
        }]));
        candidate_config.inbounds[0].spec.users =
            Some(vec![password_user("alice", "alice-password")]);
        let candidate = normalize(candidate_config).unwrap();
        let new = candidate.inbounds.get("edge").unwrap().clone();
        let replay = runtime.engine().preserve_inbound_replay("edge").unwrap();
        runtime
            .engine()
            .update_inbound(update_spec(&new))
            .await
            .expect("publish the uncommitted handler generation");

        let reservation = runtime.reserve_traffic(&old, "bob").unwrap();
        let bob_info = runtime.remove_user_with_retry("edge", "bob").await.unwrap();
        runtime.queue_traffic(reservation, &old, bob_info);
        alice.add_rx(5);

        let mut journal = vec![
            Undo::RestoreHotConfig {
                current: new,
                previous: old.clone(),
                replay,
            },
            Undo::AddUser {
                inbound: old,
                user: password_user("bob", "bob-password"),
            },
        ];
        let (errors, survivors) = runtime.rollback_journal(&mut journal).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(survivors.is_empty());
        assert_eq!(runtime.engine().list_users("edge").unwrap().len(), 2);

        let drains = runtime.drain_traffic().await.unwrap();
        assert!(drains.iter().all(|drain| drain.node_id == "old-node"));
        assert_eq!(
            drains
                .iter()
                .find(|drain| drain.user_id == "alice")
                .unwrap()
                .uplink_bytes,
            22
        );
        assert_eq!(
            drains
                .iter()
                .find(|drain| drain.user_id == "bob")
                .unwrap()
                .uplink_bytes,
            11
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_of_an_added_user_uses_the_published_inbound_owner() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"old",
                vec![compiled(
                    "edge",
                    "old-node",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .unwrap();
        let old = runtime
            .read_state()
            .current
            .as_ref()
            .unwrap()
            .inbounds
            .get("edge")
            .unwrap()
            .clone();
        let mut candidate = old.clone();
        candidate.compiled.node_id = "candidate-node".to_string();
        candidate
            .users
            .insert("bob".to_string(), user("bob", BOB_UUID));
        runtime
            .engine()
            .add_user("edge", user("bob", BOB_UUID))
            .unwrap();
        runtime
            .engine()
            .get_inbound("edge")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(BOB_UUID))
            .unwrap()
            .add_rx(13);

        let mut journal = vec![Undo::RemoveUser {
            live: candidate,
            accounting: old,
            user_id: "bob".to_string(),
        }];
        let (errors, survivors) = runtime.rollback_journal(&mut journal).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(survivors.is_empty());

        let drains = runtime.drain_traffic().await.unwrap();
        let bob = drains.iter().find(|drain| drain.user_id == "bob").unwrap();
        assert_eq!(bob.node_id, "old-node");
        assert_eq!(bob.uplink_bytes, 13);
        runtime.close().await.unwrap();
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
    async fn forced_reload_replaces_an_identical_inbound_slot() {
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
        assert!(
            !Arc::ptr_eq(&before, &after),
            "Go-compatible reload must rebuild the embedded listener instance"
        );
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forced_reload_hard_closes_a_pre_auth_tcp_connection() {
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

        let mut client = TcpStream::connect(address)
            .await
            .expect("connect to the old listener");
        // VLESS version 0 followed by an incomplete UUID leaves the server inside
        // its pre-auth read. This exercises the connection tree before any user has
        // been bound, including the window a malicious idle peer would occupy.
        client.write_all(&[0]).await.unwrap();
        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), client.read(&mut byte))
                .await
                .is_err(),
            "the pre-auth connection must remain open before reload"
        );

        tokio::time::timeout(Duration::from_secs(2), runtime.reload_config(initial))
            .await
            .expect("forced reload must not hang")
            .expect("forced reload identical topology");

        let closed = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("the old connection must close promptly after hard cutover");
        match closed {
            Ok(0) | Err(_) => {}
            Ok(read) => panic!("old generation unexpectedly returned {read} byte(s)"),
        }

        drop(
            tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(address))
                .await
                .expect("candidate listener connect must not hang")
                .expect("the candidate listener owns the address"),
        );
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn indeterminate_recovery_reuses_the_published_replay_namespace() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"initial",
                vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
            ))
            .await
            .unwrap();
        let previous = runtime
            .read_state()
            .current
            .clone()
            .expect("published topology");
        let replay = runtime.capture_replay_state(&previous).unwrap();
        let before = replay.get("edge").unwrap().clone();

        let error = runtime
            .finish_failed_transaction(FailedTransaction {
                previous,
                previous_replay: replay,
                failure: StepFailure {
                    operation: "candidate and local restore failed".to_string(),
                    rollback: vec!["simulated rollback failure".to_string()],
                    changed: true,
                    restored: false,
                },
                journal: Vec::new(),
                dns: DnsReloadContext {
                    client_rotated: false,
                    full_reload: false,
                },
            })
            .await;
        assert!(!error.running());

        runtime.recover_if_needed().await.unwrap();
        let after = runtime.engine().preserve_inbound_replay("edge").unwrap();
        assert_eq!(before, after);
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_rotates_a_default_bound_probe_registry_before_restoring_sidecar() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"initial",
                vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
            ))
            .await
            .unwrap();
        let previous = runtime
            .read_state()
            .current
            .clone()
            .expect("published topology");
        let replay = runtime.capture_replay_state(&previous).unwrap();
        let mut recovery = previous.clone();
        recovery.urltest_probe_dns = Some(json!({
            "servers": [{"tag": "default-dns", "url": "udp://127.0.0.1:5353"}],
            "final": "default-dns"
        }));
        let inbound = previous.inbounds["edge"].clone();
        {
            let mut state = runtime.write_state();
            state.current = None;
            state.recovery = Some(recovery.clone());
            state.recovery_live = BTreeMap::from([(
                "edge".to_string(),
                RetiringInbound {
                    live: inbound.clone(),
                    accounting: inbound,
                },
            )]);
        }
        *runtime.recovery_replay() = replay;
        let generation_before = runtime.engine().dns_cache_generation().await;

        runtime
            .recover_if_needed()
            .await
            .expect("recovery must replace a registry previously bound to system DNS");

        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            generation_before + 1
        );
        assert_eq!(
            runtime
                .read_state()
                .current
                .as_ref()
                .and_then(|current| current.urltest_probe_dns.as_ref()),
            recovery.urltest_probe_dns.as_ref()
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dns_cache_generation_follows_full_box_candidate_and_rollback_boundaries() {
        let addresses = free_addrs(3);
        let runtime = runtime().await;
        let mut initial = config(
            b"initial",
            vec![compiled(
                "edge",
                "node-a",
                vless(addresses[0]),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        );
        initial.dns_client_fingerprint = [1; 32];
        assert_eq!(runtime.engine().dns_cache_generation().await, 0);
        runtime
            .apply_config(initial.clone())
            .await
            .expect("initial Box starts with its already-empty DNS cache");
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            0,
            "initial bootstrap must not rotate an empty cache"
        );

        let mut users_only = initial.clone();
        users_only.inbounds[0].spec.users =
            Some(vec![user("alice", ALICE_UUID), user("bob", BOB_UUID)]);
        runtime
            .apply_config(users_only.clone())
            .await
            .expect("hot user update");
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            0,
            "inbound/user-only apply retains the Go DNS client"
        );

        let mut full_candidate = users_only.clone();
        full_candidate.dns_client_fingerprint = [2; 32];
        runtime
            .apply_config(full_candidate.clone())
            .await
            .expect("global data-plane change rebuilds Box");
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            1,
            "rotate before candidate, with no success-tail clear"
        );

        let mut failing = config(
            b"failing",
            vec![
                compiled("candidate-a", "node-b", vless(addresses[1]), Some(vec![])),
                compiled("candidate-b", "node-c", vless(addresses[1]), Some(vec![])),
            ],
        );
        failing.dns_client_fingerprint = [3; 32];
        let error = runtime
            .apply_config(failing)
            .await
            .expect_err("second candidate bind conflicts and triggers rollback");
        assert!(error.rolled_back(), "{error}");
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            3,
            "candidate and rollback each receive a fresh cache generation"
        );
        assert!(runtime.engine().get_inbound("edge").is_some());
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn committed_empty_topology_is_not_mistaken_for_process_bootstrap() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let mut dns_a = config(
            b"dns-a",
            vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
        );
        dns_a.dns_client_fingerprint = [1; 32];
        runtime.apply_config(dns_a.clone()).await.unwrap();
        assert_eq!(runtime.engine().dns_cache_generation().await, 0);

        let mut empty_dns_a = config(b"empty-dns-a", vec![]);
        empty_dns_a.dns_client_fingerprint = [1; 32];
        runtime.apply_config(empty_dns_a).await.unwrap();
        assert!(runtime.engine().list_inbounds().is_empty());
        assert_eq!(runtime.engine().dns_cache_generation().await, 0);

        // This is a new Box/DNS client even though the previous committed Box
        // had no listeners. Skipping the rotation would let a later DNS-B
        // inbound consume DNS-A's question-only cache entries.
        let mut empty_dns_b = config(b"empty-dns-b", vec![]);
        empty_dns_b.dns_client_fingerprint = [2; 32];
        runtime.apply_config(empty_dns_b.clone()).await.unwrap();
        assert_eq!(runtime.engine().dns_cache_generation().await, 1);

        let mut dns_b = config(
            b"dns-b",
            vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
        );
        dns_b.dns_client_fingerprint = [2; 32];
        runtime.apply_config(dns_b).await.unwrap();
        assert_eq!(runtime.engine().dns_cache_generation().await, 1);
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_preflight_does_not_rotate_dns_cache() {
        let addresses = free_addrs(2);
        let runtime = runtime().await;
        let mut initial = config(
            b"initial",
            vec![compiled(
                "edge",
                "node-a",
                vless(addresses[0]),
                Some(vec![]),
            )],
        );
        initial.dns_client_fingerprint = [1; 32];
        runtime.apply_config(initial).await.unwrap();

        let mut invalid = config(
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
        invalid.dns_client_fingerprint = [2; 32];
        runtime.apply_config(invalid).await.unwrap_err();
        assert_eq!(runtime.engine().dns_cache_generation().await, 0);
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dns_rotation_before_first_listener_failure_is_reported_as_rolled_back() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"initial",
                vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
            ))
            .await
            .unwrap();
        let previous = runtime
            .read_state()
            .current
            .clone()
            .expect("published topology");
        let previous_replay = runtime.capture_replay_state(&previous).unwrap();

        assert_eq!(runtime.engine().rotate_dns_client_generation().await, 1);
        let error = runtime
            .finish_failed_transaction(FailedTransaction {
                previous,
                previous_replay,
                failure: StepFailure::unchanged("first listener rejected candidate"),
                journal: Vec::new(),
                dns: DnsReloadContext {
                    client_rotated: true,
                    full_reload: true,
                },
            })
            .await;

        assert!(error.rolled_back(), "{error}");
        assert!(!error.state_unchanged());
        assert!(error.running());
        assert_eq!(runtime.engine().dns_cache_generation().await, 2);
        assert!(runtime.engine().get_inbound("edge").is_some());
        runtime.close().await.unwrap();
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
        assert!(runtime.drain_traffic().await.unwrap().is_empty());
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

    #[test]
    fn pending_traffic_aggregates_actual_records_and_skips_zero_records() {
        let mut pending = PendingTraffic::new(1);
        let record = |user: &str, up: u64, down: u64, at: u64| TrafficDrain {
            inbound_tag: "edge".to_string(),
            node_id: "node-a".to_string(),
            protocol: "vless".to_string(),
            user_id: user.to_string(),
            uplink_bytes: up,
            downlink_bytes: down,
            observed_at: Some(UNIX_EPOCH + Duration::from_secs(at)),
        };

        pending.merge(record("zero", 0, 0, 1)).unwrap();
        assert!(pending.entries.is_empty());
        pending.merge(record("alice", 3, 4, 1)).unwrap();
        pending.merge(record("alice", 5, 6, 2)).unwrap();
        assert!(pending.merge(record("bob", 1, 1, 3)).is_err());
        let drained = pending.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(
            (drained[0].uplink_bytes, drained[0].downlink_bytes),
            (8, 10)
        );
        assert_eq!(
            drained[0].observed_at,
            Some(UNIX_EPOCH + Duration::from_secs(2))
        );
    }

    #[test]
    fn more_than_legacy_limit_zero_receipts_consume_no_pending_keys() {
        let mut pending = PendingTraffic::new(MAX_PENDING_TRAFFIC_KEYS);
        for index in 0..=65_536_u32 {
            let drain = TrafficDrain {
                inbound_tag: "edge".to_string(),
                node_id: "node-a".to_string(),
                protocol: "vless".to_string(),
                user_id: format!("user-{index}"),
                uplink_bytes: 0,
                downlink_bytes: 0,
                observed_at: None,
            };
            let key = TrafficDrainKey::from(&drain);
            let owns_reservation = pending.reserve(&key).unwrap();
            pending.merge_reserved(drain, owns_reservation);
        }
        assert!(pending.entries.is_empty());
        assert!(pending.reserved.is_empty());
        assert!(pending.drain().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn retained_pending_traffic_does_not_discard_a_later_user_tail() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let initial = config(
            b"with-alice",
            vec![compiled(
                "edge",
                "node-a",
                vless(address),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        );
        runtime.apply_config(initial).await.unwrap();
        let registry = runtime.engine().get_inbound("edge").unwrap();
        let alice = registry
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap();
        alice.add_rx(9);
        {
            let mut pending = runtime.pending_traffic();
            pending
                .merge(TrafficDrain {
                    inbound_tag: "historic".to_string(),
                    node_id: "historic".to_string(),
                    protocol: "vless".to_string(),
                    user_id: "bob".to_string(),
                    uplink_bytes: 1,
                    downlink_bytes: 0,
                    observed_at: Some(SystemTime::now()),
                })
                .unwrap();
        }

        runtime
            .apply_config(config(
                b"without-alice",
                vec![compiled("edge", "node-a", vless(address), Some(vec![]))],
            ))
            .await
            .expect("pending history must not make a destructive receipt fallible");
        let drains = runtime.drain_traffic().await.unwrap();
        assert_eq!(drains.len(), 2);
        assert!(drains.iter().any(|drain| {
            drain.inbound_tag == "edge" && drain.user_id == "alice" && drain.uplink_bytes == 9
        }));
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_traffic_drain_while_waiting_for_apply_keeps_counters() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"initial",
                vec![compiled(
                    "edge",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .unwrap();
        runtime
            .engine()
            .get_inbound("edge")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap()
            .add_rx(29);

        let apply = runtime.inner.apply.lock().await;
        let mut cancelled = Box::pin(runtime.drain_traffic());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), cancelled.as_mut())
                .await
                .is_err(),
            "the drain must still be waiting for the held apply lock"
        );
        drop(cancelled);
        drop(apply);

        let drains = runtime.drain_traffic().await.unwrap();
        assert_eq!(drains.len(), 1);
        assert_eq!(drains[0].user_id, "alice");
        assert_eq!(drains[0].uplink_bytes, 29);
        assert!(runtime.drain_traffic().await.unwrap().is_empty());
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_keeps_candidate_metadata_when_pending_capacity_blocks_rollback_stop() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        let candidate = normalize(config(
            b"candidate",
            vec![compiled(
                "candidate",
                "candidate-node",
                vless(address),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        ))
        .unwrap()
        .inbounds
        .remove("candidate")
        .unwrap();
        runtime
            .engine()
            .add_inbound(candidate.compiled.spec.clone())
            .await
            .unwrap();
        let alice = runtime
            .engine()
            .get_inbound("candidate")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap();
        alice.add_rx(41);

        {
            let mut pending = runtime.pending_traffic();
            pending.max_keys = 1;
            pending
                .merge(TrafficDrain {
                    inbound_tag: "historic".to_string(),
                    node_id: "historic-node".to_string(),
                    protocol: "vless".to_string(),
                    user_id: "historic-user".to_string(),
                    uplink_bytes: 1,
                    downlink_bytes: 0,
                    observed_at: Some(SystemTime::now()),
                })
                .unwrap();
        }

        let error = runtime
            .finish_failed_transaction(FailedTransaction {
                previous: NormalizedConfig::default(),
                previous_replay: BTreeMap::new(),
                failure: StepFailure {
                    operation: "later candidate failed".to_string(),
                    rollback: Vec::new(),
                    changed: true,
                    restored: true,
                },
                journal: vec![Undo::RemoveInbound {
                    accounting: ShoesRuntime::uncommitted_accounting_owner(None, &candidate),
                    live: candidate,
                }],
                dns: DnsReloadContext {
                    client_rotated: false,
                    full_reload: false,
                },
            })
            .await;
        assert!(error.rollback_error().is_some(), "{error}");
        assert!(runtime.read_state().current.is_none());
        assert_eq!(
            runtime
                .read_state()
                .recovery_live
                .get("candidate")
                .unwrap()
                .live
                .compiled
                .node_id,
            "candidate-node"
        );

        let historic = runtime.drain_traffic().await.unwrap();
        assert_eq!(historic.len(), 1);
        assert_eq!(historic[0].node_id, "historic-node");

        runtime
            .apply_config(config(b"recovered", vec![]))
            .await
            .expect("the next apply cleans the retained candidate after capacity is drained");
        assert!(runtime.engine().list_inbounds().is_empty());
        let tail = runtime.drain_traffic().await.unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].inbound_tag, "candidate");
        assert_eq!(tail[0].node_id, "candidate");
        assert_eq!(tail[0].user_id, "alice");
        assert_eq!(tail[0].uplink_bytes, 41);
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn same_tag_survivor_uses_candidate_metadata_then_restores_old_replay_lineage() {
        let addresses = free_addrs(2);
        let runtime = runtime().await;
        let old_config = config(
            b"old",
            vec![compiled(
                "edge",
                "old-node",
                vless(addresses[0]),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        );
        runtime.apply_config(old_config.clone()).await.unwrap();
        let previous = runtime.read_state().current.clone().unwrap();
        let previous_replay = runtime.capture_replay_state(&previous).unwrap();
        let lease = previous_replay.get("edge").unwrap().clone();
        let old = previous.inbounds.get("edge").unwrap().clone();
        runtime.stop_inbound(&old).await.unwrap();

        let mut candidate = normalize(config(
            b"candidate",
            vec![compiled(
                "edge",
                "candidate-node",
                vless(addresses[1]),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        ))
        .unwrap()
        .inbounds
        .remove("edge")
        .unwrap();
        candidate.compiled.protocol = "candidate-protocol".to_string();
        runtime
            .engine()
            .add_inbound_with_replay(candidate.compiled.spec.clone(), &lease)
            .await
            .unwrap();
        runtime
            .engine()
            .get_inbound("edge")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap()
            .add_rx(23);
        {
            let mut pending = runtime.pending_traffic();
            pending.max_keys = 1;
            pending
                .merge(TrafficDrain {
                    inbound_tag: "historic".to_string(),
                    node_id: "historic-node".to_string(),
                    protocol: "vless".to_string(),
                    user_id: "historic-user".to_string(),
                    uplink_bytes: 1,
                    downlink_bytes: 0,
                    observed_at: Some(SystemTime::now()),
                })
                .unwrap();
        }

        let error = runtime
            .finish_failed_transaction(FailedTransaction {
                previous,
                previous_replay,
                failure: StepFailure {
                    operation: "later replacement failed".to_string(),
                    rollback: Vec::new(),
                    changed: true,
                    restored: true,
                },
                journal: vec![
                    Undo::AddInbound {
                        inbound: old.clone(),
                        replay: lease.clone(),
                    },
                    Undo::RemoveInbound {
                        live: candidate,
                        accounting: old,
                    },
                ],
                dns: DnsReloadContext {
                    client_rotated: false,
                    full_reload: false,
                },
            })
            .await;
        assert!(error.rollback_error().is_some(), "{error}");
        {
            let state = runtime.read_state();
            let survivor = state.recovery_live.get("edge").unwrap();
            assert_eq!(survivor.live.compiled.node_id, "candidate-node");
            assert_eq!(survivor.live.compiled.protocol, "candidate-protocol");
            assert_eq!(survivor.accounting.compiled.node_id, "old-node");
            assert_eq!(survivor.accounting.compiled.protocol, "vless");
        }

        assert_eq!(runtime.drain_traffic().await.unwrap().len(), 1);
        runtime
            .apply_config(old_config)
            .await
            .expect("draining capacity lets recovery retire the candidate and rebuild old");
        let drains = runtime.drain_traffic().await.unwrap();
        let tail = drains
            .iter()
            .find(|drain| drain.user_id == "alice")
            .expect("candidate tail survives recovery");
        assert_eq!(tail.node_id, "old-node");
        assert_eq!(tail.protocol, "vless");
        assert_eq!(tail.uplink_bytes, 23);
        assert_eq!(
            runtime.engine().preserve_inbound_replay("edge").unwrap(),
            lease
        );
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn partial_recovery_relabels_rebuilt_listener_before_the_next_retry() {
        let addresses = free_addrs(3);
        let runtime = runtime().await;
        let old_config = config(
            b"old",
            vec![
                compiled(
                    "a",
                    "old-node-a",
                    vless(addresses[0]),
                    Some(vec![user("alice", ALICE_UUID)]),
                ),
                compiled("b", "old-node-b", vless(addresses[1]), Some(vec![])),
            ],
        );
        runtime.apply_config(old_config).await.unwrap();
        let previous = runtime.read_state().current.clone().unwrap();
        let replay = runtime.capture_replay_state(&previous).unwrap();
        for inbound in previous.inbounds.values() {
            runtime.stop_inbound(inbound).await.unwrap();
        }

        let mut candidate = normalize(config(
            b"candidate",
            vec![compiled(
                "a",
                "candidate-node-a",
                vless(addresses[2]),
                Some(vec![user("alice", ALICE_UUID)]),
            )],
        ))
        .unwrap()
        .inbounds
        .remove("a")
        .unwrap();
        candidate.compiled.protocol = "candidate-protocol".to_string();
        runtime
            .engine()
            .add_inbound_with_replay(candidate.compiled.spec.clone(), replay.get("a").unwrap())
            .await
            .unwrap();
        {
            let mut state = runtime.write_state();
            state.current = None;
            state.recovery = Some(previous.clone());
            state.recovery_live = BTreeMap::from([(
                "a".to_string(),
                RetiringInbound {
                    live: candidate,
                    accounting: previous.inbounds.get("a").unwrap().clone(),
                },
            )]);
        }
        *runtime.recovery_replay() = replay;

        let blocker = TcpListener::bind(addresses[1]).expect("block old inbound b");
        runtime
            .recover_if_needed()
            .await
            .expect_err("old inbound b cannot be rebuilt while its port is occupied");
        {
            let state = runtime.read_state();
            let live = state.recovery_live.get("a").unwrap();
            assert_eq!(live.live.compiled.node_id, "old-node-a");
            assert_eq!(live.live.compiled.protocol, "vless");
            assert_eq!(live.accounting.compiled.node_id, "old-node-a");
        }

        runtime
            .engine()
            .get_inbound("a")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap()
            .add_rx(37);
        drop(blocker);
        runtime.recover_if_needed().await.unwrap();

        let drains = runtime.drain_traffic().await.unwrap();
        let tail = drains
            .iter()
            .find(|drain| drain.user_id == "alice" && drain.uplink_bytes == 37)
            .expect("the partial recovery listener's tail is retained");
        assert_eq!(tail.node_id, "old-node-a");
        assert_eq!(tail.protocol, "vless");
        runtime.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn force_stop_accepts_a_configured_id_after_its_receipt_was_collected() {
        let address = free_addrs(1)[0];
        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"initial",
                vec![compiled(
                    "edge",
                    "node-a",
                    vless(address),
                    Some(vec![user("alice", ALICE_UUID)]),
                )],
            ))
            .await
            .unwrap();
        let inbound = runtime
            .read_state()
            .current
            .as_ref()
            .unwrap()
            .inbounds
            .get("edge")
            .unwrap()
            .clone();
        let alice = runtime
            .engine()
            .get_inbound("edge")
            .unwrap()
            .users()
            .unwrap()
            .find_uuid(&uuid_bytes(ALICE_UUID))
            .unwrap();
        alice.add_rx(13);
        let reservation = runtime.reserve_traffic(&inbound, "alice").unwrap();
        let info = runtime
            .remove_user_with_retry("edge", "alice")
            .await
            .unwrap();
        runtime.queue_traffic(reservation, &inbound, info);
        assert!(runtime.engine().list_users("edge").unwrap().is_empty());

        let retiring = RetiringInbound {
            live: inbound.clone(),
            accounting: inbound,
        };
        runtime
            .force_stop_tag("edge", Some(&retiring), "vless")
            .await
            .expect("known-only ids may already have a durable receipt");
        assert!(runtime.engine().get_inbound("edge").is_none());
        let drains = runtime.drain_traffic().await.unwrap();
        assert_eq!(drains.len(), 1);
        assert_eq!(drains[0].uplink_bytes, 13);
        runtime.close().await.unwrap();
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

    #[tokio::test]
    async fn remote_kick_join_failure_has_an_explicit_fallback_path() {
        let task = tokio::spawn(std::future::pending::<u64>());
        task.abort();
        let error = task
            .await
            .expect_err("aborted kick task returns a join error");

        assert_eq!(
            close_user_connections_task_result(
                &UserConnectionTarget::new("node-a", "alice"),
                Err(error),
            ),
            0,
            "the infallible ACP boundary retains its zero fallback after warning"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_to_empty_is_known_but_not_reported_as_rolled_back() {
        let free = free_addrs(1)[0];
        let blocker = TcpListener::bind("127.0.0.1:0").expect("hold conflict port");
        let blocked = blocker.local_addr().expect("read conflict port");
        let runtime = runtime().await;
        let mut candidate = config(
            b"candidate",
            vec![
                compiled("a", "node-a", vless(free), Some(vec![])),
                compiled("b", "node-b", vless(blocked), Some(vec![])),
            ],
        );
        candidate.dns_client_fingerprint = [1; 32];

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
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            1,
            "the failed first Box candidate must leave behind a fresh empty DNS generation"
        );

        drop(blocker);
        runtime
            .apply_config(candidate)
            .await
            .expect("known empty state accepts a later apply");
        assert_eq!(
            runtime.engine().dns_cache_generation().await,
            1,
            "the retry must use the clean generation rather than the failed candidate's state"
        );
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fully_restored_outer_rollback_prunes_dormant_candidate_urltest_groups() {
        let address = free_addrs(1)[0];
        let blocker = TcpListener::bind("127.0.0.1:0").expect("hold conflict port");
        let blocked = blocker.local_addr().expect("read conflict port");
        let with_urltest = |address: SocketAddr, shared_id: &str| {
            json!({
                "address": address.to_string(),
                "protocol": {"type": "vless", "udp_enabled": false},
                "rules": [{
                    "masks": "0.0.0.0/0",
                    "action": "allow",
                    "client_chains": [{"chain": ["direct"]}],
                    "client_chain_selection": {
                        "type": "urltest",
                        "shared_id": shared_id,
                        "history_keys": [shared_id],
                        "failure_history_keys": [shared_id],
                        "url": "http://127.0.0.1:9/generate_204",
                        "interval_millis": 60000,
                        "tolerance_millis": 50,
                        "idle_timeout_millis": 1800000,
                    },
                }],
            })
        };

        let runtime = runtime().await;
        runtime
            .apply_config(config(
                b"urltest-a",
                vec![compiled(
                    "edge",
                    "node-a",
                    with_urltest(address, "node-agent-urltest-v1:rollback-a"),
                    Some(vec![]),
                )],
            ))
            .await
            .expect("start the published URLTest group");
        assert_eq!(runtime.engine().client_chain_group_count().await, 1);

        let error = runtime
            .apply_config(config(
                b"urltest-b-then-fail",
                vec![
                    compiled(
                        "edge",
                        "node-a",
                        with_urltest(address, "node-agent-urltest-v1:rollback-b"),
                        Some(vec![]),
                    ),
                    compiled("blocked", "node-b", vless(blocked), Some(vec![])),
                ],
            ))
            .await
            .expect_err("the later inbound bind must fail after publishing group B");
        assert!(error.rolled_back(), "unexpected error: {error}");
        assert_eq!(runtime.current_config(), b"urltest-a");
        assert_eq!(
            runtime.engine().client_chain_group_count().await,
            1,
            "outer rollback keeps restored A and prunes dormant candidate B"
        );

        drop(blocker);
        runtime.close().await.expect("close runtime");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn urltest_probe_dns_uses_prepared_rule_set_snapshots_on_first_apply_and_refresh() {
        let initial_bytes = source_rule_set("first.example");
        let (url, server_state, server_cancel, server_task) =
            start_rule_set_server(initial_bytes.clone()).await;
        let temporary = tempfile::tempdir().expect("create rule-set cache directory");
        let cache_path = temporary.path().join("probe-rules.json");
        // This test exercises immutable rule-set snapshots, not host DNS
        // discovery. An explicit loopback server keeps it deterministic on
        // Linux CI hosts that ship resolvectl without a running resolved daemon.
        let probe_dns = json!({
            "servers": [{"tag": "default-dns", "url": "udp://127.0.0.1:5353"}],
            "final": "default-dns",
            "rules": [{
                "rule_set": [{
                    "format": "source",
                    "path": cache_path.to_string_lossy(),
                }],
                "action": "reject",
            }],
        });
        let candidate = |snapshot: &'static [u8]| RuntimeConfig {
            inbounds: Vec::new(),
            rule_sets: vec![RuleSetResource {
                tag: "probe".into(),
                format: "source".into(),
                path: cache_path.clone(),
                source: RuleSetSource::Remote { url: url.clone() },
                update_interval: Duration::from_nanos(1),
            }],
            diagnostic_yaml: snapshot.to_vec(),
            dns_client_fingerprint: [0; 32],
            urltest_probe_dns: Some(probe_dns.clone()),
        };

        let runtime = runtime().await;
        let first = candidate(b"probe-first");
        let prepared = runtime
            .prepare_rule_sets(&first, &runtime.inner.closing)
            .await
            .expect("prepare initial probe rules");
        runtime
            .apply_transaction_locked(first, prepared, false)
            .await
            .expect("the first probe-only rule-set uses its prepared snapshot");
        assert_eq!(runtime.current_config(), b"probe-first");
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("first successful apply publishes the stable cache"),
            initial_bytes
        );

        server_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .body =
            br#"{"version":4,"rules":[{"domain":["invalid.example"],"port":[53]}]}"#.to_vec();
        let refreshed = candidate(b"probe-invalid-refresh");
        let prepared = runtime
            .prepare_rule_sets(&refreshed, &runtime.inner.closing)
            .await
            .expect("prepare syntactically valid refreshed probe rules");
        let error = runtime
            .apply_transaction_locked(refreshed, prepared, false)
            .await
            .expect_err("probe DNS must preflight the refreshed immutable snapshot");
        assert!(error.state_unchanged(), "unexpected error: {error}");
        assert_eq!(runtime.current_config(), b"probe-first");
        assert_eq!(
            tokio::fs::read(&cache_path)
                .await
                .expect("failed refresh preserves the first last-good cache"),
            source_rule_set("first.example")
        );
        runtime.close().await.expect("close runtime");
        server_cancel.cancel();
        server_task.await.expect("stop rule-set server");
    }

    #[tokio::test]
    async fn slow_rule_preparation_allows_drains_kicks_and_close() {
        let runtime = runtime().await;
        runtime
            .apply_config(config(b"before", vec![]))
            .await
            .unwrap();
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, requested) = tokio::sync::oneshot::channel();
        let server_cancel = CancellationToken::new();
        let server_stop = server_cancel.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 512];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            entered.send(()).unwrap();
            server_stop.cancelled().await;
        });
        let temporary = tempfile::tempdir().unwrap();
        let cache = temporary.path().join("slow.json");
        let mut candidate = config(b"slow", vec![]);
        candidate.rule_sets.push(RuleSetResource {
            tag: "slow".into(),
            format: "source".into(),
            path: cache.clone(),
            source: RuleSetSource::Remote {
                url: format!("http://{address}/rules"),
            },
            update_interval: Duration::from_secs(60),
        });
        let apply_runtime = runtime.clone();
        let applying = tokio::spawn(async move { apply_runtime.apply_config(candidate).await });
        tokio::time::timeout(Duration::from_secs(2), requested)
            .await
            .unwrap()
            .unwrap();
        assert!(!applying.is_finished());
        let queued_runtime = runtime.clone();
        let queued =
            tokio::spawn(
                async move { queued_runtime.apply_config(config(b"queued", vec![])).await },
            );

        tokio::time::timeout(Duration::from_secs(1), async {
            assert!(runtime.drain_traffic().await.unwrap().is_empty());
            assert_eq!(runtime.close_user_connections("node", "user").await, 0);
            assert_eq!(runtime.current_config(), b"before");
            runtime.close().await.unwrap();
        })
        .await
        .expect("remote downloads must not hold the mutation lock");
        for task in [applying, queued] {
            let error = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .expect_err("close invalidates prepared and queued candidates");
            assert!(error.state_unchanged());
        }
        assert!(runtime.current_config().is_empty());
        assert!(
            !cache.exists(),
            "cancelled preparation must not publish its cache"
        );
        server_cancel.cancel();
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_rule_sets_retire_the_remote_watcher_and_reject_its_refresh() {
        let (url, _server_state, server_cancel, server_task) =
            start_rule_set_server(source_rule_set("local.example")).await;
        let temporary = tempfile::tempdir().unwrap();
        let watched = RuntimeConfig {
            rule_sets: vec![RuleSetResource {
                tag: "rules".into(),
                format: "source".into(),
                path: temporary.path().join("rules.json"),
                source: RuleSetSource::Remote { url },
                update_interval: Duration::from_secs(60),
            }],
            diagnostic_yaml: b"remote".to_vec(),
            ..RuntimeConfig::default()
        };
        let runtime = runtime().await;
        runtime.apply_config(watched.clone()).await.unwrap();
        let (generation, cancel) = {
            let watcher = runtime.rule_set_watcher();
            (watcher.generation, watcher.cancel.clone().unwrap())
        };

        let mut local = watched.clone();
        local.rule_sets[0].source = RuleSetSource::Local;
        local.diagnostic_yaml = b"local".to_vec();
        runtime.apply_config(local).await.unwrap();
        assert!(cancel.is_cancelled());
        {
            let watcher = runtime.rule_set_watcher();
            assert!(watcher.cancel.is_none());
            assert_ne!(watcher.generation, generation);
        }
        assert!(
            runtime
                .refresh_rule_sets_owned(generation, watched)
                .await
                .is_none()
        );
        assert_eq!(runtime.current_config(), b"local");

        runtime.close().await.unwrap();
        server_cancel.cancel();
        server_task.await.unwrap();
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
            dns_client_fingerprint: [0; 32],
            urltest_probe_dns: None,
        };
        let runtime = runtime().await;
        runtime
            .apply_config(watched.clone())
            .await
            .expect("start watched topology");
        let initial_inbound = runtime
            .engine()
            .get_inbound("edge")
            .expect("watched inbound");
        let initial_revision = initial_inbound.revision();
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
        let after_invalid = runtime
            .engine()
            .get_inbound("edge")
            .expect("old inbound survives candidate parse failure");
        assert!(Arc::ptr_eq(&after_invalid, &initial_inbound));
        assert_eq!(after_invalid.revision(), initial_revision);
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
        let (second_inbound, second_revision) =
            wait_for_inbound_generation(&runtime, "edge", &initial_inbound, initial_revision).await;
        assert!(
            !Arc::ptr_eq(&second_inbound, &initial_inbound),
            "rule-set bytes rotate the complete DNS/Box generation"
        );
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
        let after_download_failure = runtime
            .engine()
            .get_inbound("edge")
            .expect("old inbound survives download failure");
        assert!(Arc::ptr_eq(&after_download_failure, &second_inbound));
        assert_eq!(after_download_failure.revision(), second_revision);
        assert_eq!(runtime.current_config(), b"watched-v1");

        {
            let mut state = server_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.body = source_rule_set("third.example");
            state.fail = false;
        }
        let (third_inbound, _third_revision) =
            wait_for_inbound_generation(&runtime, "edge", &second_inbound, second_revision).await;
        assert!(
            !Arc::ptr_eq(&third_inbound, &second_inbound),
            "the next rule-set content change publishes another complete Box"
        );
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
