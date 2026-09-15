//! Lossy, bounded traffic classification, independent of billing counters.
//!
//! I/O captures an epoch before starting. Completing an operation after a main
//! session change cannot charge the new session. Only the sampler builds rows.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::analysis::{default_config, normalize_config};
use acp_proto::{
    TrafficAnalysisBatch, TrafficAnalysisConfig, TrafficAnalysisDomainMinute,
    TrafficAnalysisStatus, TrafficAnalysisUserMinute,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use prost::Message;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const FLOW_COST: u64 = 1024;
const TARGET_COST: u64 = 1024;
// Include both map keys and row strings, hash-table slack and the known-key
// eviction stack. Rust owns each String rather than sharing Go string backing.
const USER_COST: u64 = 1536;
const DOMAIN_COST: u64 = 4096;
const UNKNOWN: &str = "unknown";
const PENDING_PACKETS: u8 = 8;
const PENDING_BYTES: u64 = 64 << 10;
const PENDING_AGE: Duration = Duration::from_millis(300);
const MAX_PENDING_TARGETS: u64 = 1024;
const REASONS: [&str; 8] = [
    "queue_full",
    "expired",
    "session_reset",
    "send_failed",
    "budget",
    "target_limit",
    "domain_limit",
    "invalid_metadata",
];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub use shoes_engine::AnalysisTarget as Target;

fn valid_target(target: &Target) -> bool {
    !target.host.is_empty() && target.port != 0 && target.host.len() <= 253
}

#[derive(Clone, Debug, Default)]
pub struct Metadata {
    pub node_id: String,
    pub user_id: String,
    pub proxy_protocol: String,
    pub network: String,
    /// The existing sniffer's hostname; never reparsed on the I/O path.
    pub domain: String,
    pub app_protocol: String,
    pub destination: Option<Target>,
    pub sniff_destination: Option<Target>,
}

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

impl Counters {
    fn add(&self, up: u64, down: u64) {
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
    }
    fn drain(&self) -> (u64, u64) {
        (
            self.up.swap(0, Ordering::Relaxed),
            self.down.swap(0, Ordering::Relaxed),
        )
    }
}

#[derive(Clone)]
struct Classification {
    domain: String,
    app: String,
}

struct TargetState {
    counters: Counters,
    started: bool,
    observed: bool,
    classification: Option<Classification>,
    _reservation: TargetReservation,
}

struct PendingCounters {
    up: u64,
    down: u64,
    packets: u8,
    since: Instant,
    _reservation: PendingReservation,
}

struct PendingReservation(Weak<Collector>);

impl Drop for PendingReservation {
    fn drop(&mut self) {
        if let Some(collector) = self.0.upgrade() {
            collector.pending_targets.fetch_sub(1, Ordering::Relaxed);
            collector.release_pending(TARGET_COST);
        }
    }
}

impl PendingCounters {
    fn record(&mut self, up: u64, down: u64) {
        if self.since.elapsed() > PENDING_AGE || self.packets >= PENDING_PACKETS {
            return;
        }
        self.packets += 1;
        let remaining = PENDING_BYTES.saturating_sub(self.up + self.down);
        let accepted_up = up.min(remaining);
        self.up += accepted_up;
        self.down += down.min(remaining - accepted_up);
    }
}

struct TargetReservation(Weak<Collector>);

impl Drop for TargetReservation {
    fn drop(&mut self) {
        if let Some(collector) = self.0.upgrade() {
            collector.targets.fetch_sub(1, Ordering::Relaxed);
            collector.release(TARGET_COST);
        }
    }
}

#[derive(Default)]
struct PacketState {
    retired: bool,
    targets: HashMap<Target, TargetState>,
    pending: HashMap<Target, PendingCounters>,
    unknown: Counters,
}

impl PacketState {
    fn take_pending(&mut self, target: &Target) -> Option<PendingCounters> {
        let pending = self.pending.remove(target);
        self.trim_pending();
        pending
    }

    fn expire_pending(&mut self) {
        self.pending
            .retain(|_, pending| pending.since.elapsed() <= PENDING_AGE);
        self.trim_pending();
    }

    fn trim_pending(&mut self) {
        // Released entries must not leave a large, now uncharged hash table
        // behind on a long-lived association. Small capacity fits FLOW_COST;
        // larger capacity remains covered by the retained entry reservations.
        if self.pending.capacity() > self.pending.len().max(1) * 4 {
            self.pending.shrink_to_fit();
        }
    }
}

struct FlowState {
    epoch: u64,
    counters: Counters,
    started: AtomicBool,
    packets: Mutex<PacketState>,
}

impl FlowState {
    fn new(epoch: u64, started: bool) -> Self {
        Self {
            epoch,
            counters: Counters::default(),
            started: AtomicBool::new(started),
            packets: Mutex::default(),
        }
    }
}

pub struct Flow {
    collector: Weak<Collector>,
    meta: Metadata,
    state: ArcSwapOption<FlowState>,
    closed: AtomicBool,
    inflight: AtomicU64,
    web_seen: AtomicBool,
    cost: u64,
}

impl Flow {
    /// Capture before polling I/O. Zero means that this operation is excluded.
    /// Every nonzero token must be completed or cancelled exactly once.
    pub fn begin_token(&self) -> u64 {
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let state = self.state.load();
        let epoch = state.as_ref().map_or(0, |s| s.epoch);
        let active = self
            .collector
            .upgrade()
            .map_or(0, |c| c.active.load(Ordering::Acquire));
        if self.closed.load(Ordering::SeqCst) || epoch == 0 || epoch != active {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            return 0;
        }
        epoch
    }

    pub fn finish_token(&self, epoch: u64, up: u64, down: u64, target: Option<&Target>) {
        self.finish_observation(epoch, up, down, target, false);
    }

    pub fn finish_web_token(&self, epoch: u64, up: u64, down: u64, target: Option<&Target>) {
        self.finish_observation(epoch, up, down, target, true);
    }

    fn finish_observation(
        &self,
        epoch: u64,
        up: u64,
        down: u64,
        target: Option<&Target>,
        known_web: bool,
    ) {
        if epoch == 0 {
            return;
        }
        if let Some(collector) = self.collector.upgrade() {
            let state = self.state.load();
            if let Some(state) = state.as_ref().filter(|s| s.epoch == epoch)
                && collector.active.load(Ordering::Acquire) == epoch
            {
                if self.meta.network == "udp" {
                    self.record_packet(&collector, state, target, up, down, known_web);
                } else {
                    state.counters.add(up, down);
                }
            }
        }
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn cancel_token(&self, epoch: u64) {
        if epoch != 0 {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub fn begin(self: &Arc<Self>) -> Observation {
        Observation {
            flow: Arc::clone(self),
            epoch: self.begin_token(),
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Charge transient QUIC parsing storage to the same component budget.
    /// The core pairs successful reservations with an RAII release.
    pub fn try_reserve_sniff(&self, bytes: usize) -> bool {
        self.try_reserve_flow_storage(bytes, true, true)
    }

    /// Existing UDP associations may create another target wrapper while the
    /// main session is paused. Keep that storage bounded so the wrapper can
    /// resume with the association after configuration is fetched again.
    pub fn try_reserve_storage(&self, bytes: usize) -> bool {
        self.try_reserve_flow_storage(bytes, false, false)
    }

    pub fn try_reserve_pending_storage(&self, bytes: usize) -> bool {
        self.try_reserve_flow_storage(bytes, false, true)
    }

    fn try_reserve_flow_storage(&self, bytes: usize, require_active: bool, pending: bool) -> bool {
        let Some(collector) = self.collector.upgrade() else {
            return false;
        };
        let eligible = || {
            !self.closed.load(Ordering::Acquire)
                && self.state.load().is_some()
                && (!require_active || collector.is_active())
        };
        if !eligible() {
            return false;
        }
        if !(if pending {
            collector.reserve_pending(bytes as u64)
        } else {
            collector.reserve(bytes as u64)
        }) {
            collector.limited("budget");
            return false;
        }
        // A disable or Close racing the reservation must not admit additional
        // retained storage into a flow whose registry state has been removed.
        if !eligible() {
            if pending {
                collector.release_pending(bytes as u64);
            } else {
                collector.release(bytes as u64);
            }
            return false;
        }
        true
    }

    pub fn release_sniff(&self, bytes: usize) {
        self.release_pending_storage(bytes);
    }

    pub fn release_pending_storage(&self, bytes: usize) {
        if let Some(collector) = self.collector.upgrade() {
            collector.release_pending(bytes as u64);
        }
    }

    pub fn promote_pending_storage(&self, bytes: usize) {
        if let Some(collector) = self.collector.upgrade() {
            collector
                .pending_memory
                .fetch_sub(bytes as u64, Ordering::Relaxed);
        }
    }

    pub fn release_storage(&self, bytes: usize) {
        if let Some(collector) = self.collector.upgrade() {
            collector.release(bytes as u64);
        }
    }

    /// The core may discover a UDP hostname after registration. This updates
    /// only the actually sniffed target and only within the original epoch.
    pub fn classify_target(
        &self,
        epoch: u64,
        target: &Target,
        domain: Option<&str>,
        app_protocol: &str,
    ) -> bool {
        let app_protocol = app_protocol.trim_ascii();
        if epoch == 0 || self.meta.network != "udp" {
            return false;
        }
        let Some(collector) = self.collector.upgrade() else {
            return false;
        };
        if !valid_target(target) || domain.is_some_and(|d| d.len() > 253) || app_protocol.len() > 64
        {
            collector.limited("invalid_metadata");
            return false;
        }
        if app_protocol.is_empty() || app_protocol.eq_ignore_ascii_case(UNKNOWN) {
            return false;
        }
        let state = self.state.load();
        let Some(state) = state.as_ref().filter(|s| s.epoch == epoch) else {
            return false;
        };
        let mut packets = lock(&state.packets);
        if packets.retired || collector.active.load(Ordering::Acquire) != epoch {
            return false;
        }
        // A confirmed target is immutable, even if another wrapper returns a
        // contradictory result. Excluded targets retain no collector tombstone:
        // their owner must stop callbacks after its terminal result.
        if packets.targets.contains_key(target)
            || (self.meta.sniff_destination.as_ref() == Some(target)
                && web_protocol(&self.meta.app_protocol).is_some())
        {
            return true;
        }
        let pending = packets.take_pending(target);
        let Some(web) = web_protocol(app_protocol) else {
            return false;
        };
        let config = collector.limits.load();
        if packets.targets.len() >= config.max_udp_targets_per_session as usize {
            collector.limited("target_limit");
            self.promote_pending_unknown(state, &packets, pending);
            return true;
        }
        if !collector.reserve_target(&config) {
            self.promote_pending_unknown(state, &packets, pending);
            return true;
        }
        let mut target_state = TargetState {
            counters: Counters::default(),
            started: false,
            observed: false,
            classification: Some(Classification {
                domain: domain.unwrap_or_default().into(),
                app: web.into(),
            }),
            _reservation: TargetReservation(self.collector.clone()),
        };
        if let Some(pending) = pending
            && pending.since.elapsed() <= PENDING_AGE
        {
            self.record_web_packet(state, &mut target_state, pending.up, pending.down);
        }
        packets.targets.insert(target.clone(), target_state);
        true
    }

    /// A terminal/expired sniffer releases only its own epoch's unclassified
    /// counters. Confirmed traffic and newer sessions must remain untouched.
    pub fn discard_target(&self, epoch: u64, target: &Target) {
        let state = self.state.load();
        if let Some(state) = state.as_ref().filter(|state| state.epoch == epoch) {
            lock(&state.packets).take_pending(target);
        }
    }

    fn promote_pending_unknown(
        &self,
        state: &FlowState,
        packets: &PacketState,
        pending: Option<PendingCounters>,
    ) {
        if let Some(pending) = pending
            && pending.since.elapsed() <= PENDING_AGE
        {
            self.record_unknown_web(state, packets, pending.up, pending.down);
        }
    }

    fn record_unknown_web(&self, state: &FlowState, packets: &PacketState, up: u64, down: u64) {
        if up != 0 || down != 0 {
            state.counters.add(up, down);
            self.mark_web_seen(state);
            packets.unknown.add(up, down);
        }
    }

    fn record_packet(
        &self,
        collector: &Collector,
        state: &FlowState,
        target: Option<&Target>,
        up: u64,
        down: u64,
        known_web: bool,
    ) {
        if up == 0 && down == 0 {
            return;
        }
        let mut packets = lock(&state.packets);
        if packets.retired || collector.active.load(Ordering::Acquire) != state.epoch {
            return;
        }
        let Some(target) = target.filter(|t| valid_target(t)) else {
            if target.is_some_and(|t| t.host.len() > 253) {
                collector.limited("invalid_metadata");
            }
            return;
        };
        let initial_web = self.meta.sniff_destination.as_ref() == Some(target)
            && web_protocol(&self.meta.app_protocol).is_some();
        if initial_web && !packets.targets.contains_key(target) {
            let cfg = collector.limits.load();
            if packets.targets.len() >= cfg.max_udp_targets_per_session as usize {
                collector.limited("target_limit");
            } else if collector.reserve_target(&cfg) {
                packets.targets.insert(
                    target.clone(),
                    TargetState {
                        counters: Counters::default(),
                        started: false,
                        observed: false,
                        classification: None,
                        _reservation: TargetReservation(self.collector.clone()),
                    },
                );
            }
        }
        if let Some(target) = packets.targets.get_mut(target) {
            self.record_web_packet(state, target, up, down);
        } else if initial_web || known_web {
            self.record_unknown_web(state, &packets, up, down);
        } else {
            packets.expire_pending();
            if !packets.pending.contains_key(target) {
                let cfg = collector.limits.load();
                if packets.pending.len() >= cfg.max_udp_targets_per_session as usize {
                    collector.limited("target_limit");
                    return;
                }
                if !collector.reserve_pending_target(&cfg) {
                    return;
                }
                packets.pending.insert(
                    target.clone(),
                    PendingCounters {
                        up: 0,
                        down: 0,
                        packets: 0,
                        since: Instant::now(),
                        _reservation: PendingReservation(self.collector.clone()),
                    },
                );
            }
            packets.pending.get_mut(target).unwrap().record(up, down);
        }
    }

    fn record_web_packet(&self, state: &FlowState, target: &mut TargetState, up: u64, down: u64) {
        if up == 0 && down == 0 {
            return;
        }
        state.counters.add(up, down);
        if !target.observed {
            target.observed = true;
            target.started = true;
        }
        target.counters.add(up, down);
        self.mark_web_seen(state);
    }

    fn mark_web_seen(&self, state: &FlowState) {
        if !self.web_seen.swap(true, Ordering::Relaxed) {
            if let Some(collector) = self.collector.upgrade() {
                collector
                    .pending_memory
                    .fetch_sub(self.cost, Ordering::Relaxed);
            }
            state.started.store(true, Ordering::Relaxed);
        }
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        // A disabled or closed wrapper may outlive its registry entry. Keep its
        // owned metadata charged until the final wrapper/observation releases it.
        if let Some(collector) = self.collector.upgrade() {
            if self.meta.network == "udp" && !self.web_seen.load(Ordering::Relaxed) {
                collector.release_pending(self.cost);
            } else {
                collector.release(self.cost);
            }
        }
    }
}

/// An owned cancellation-safe observation. The core can instead keep the epoch
/// inline with `begin_token` / `finish_token` to avoid dynamic dispatch allocation.
pub struct Observation {
    flow: Arc<Flow>,
    epoch: u64,
}

impl Observation {
    pub fn done(mut self, up: u64, down: u64) {
        self.flow.finish_token(self.epoch, up, down, None);
        self.epoch = 0;
    }
    pub fn done_packet(mut self, target: &Target, up: u64, down: u64) {
        self.flow.finish_token(self.epoch, up, down, Some(target));
        self.epoch = 0;
    }
    pub fn done_packet_batch<'a>(
        mut self,
        packets: impl IntoIterator<Item = (&'a Target, u64, u64)>,
    ) {
        if self.epoch != 0 {
            if let Some(collector) = self.flow.collector.upgrade() {
                let state = self.flow.state.load();
                if let Some(state) = state.as_ref().filter(|s| s.epoch == self.epoch) {
                    for (target, up, down) in packets {
                        self.flow
                            .record_packet(&collector, state, Some(target), up, down, false);
                    }
                }
            }
            self.flow.cancel_token(self.epoch);
            self.epoch = 0;
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.flow.cancel_token(self.epoch);
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct UserKey {
    node: String,
    user: String,
    proxy: String,
    network: String,
}

impl From<&Metadata> for UserKey {
    fn from(meta: &Metadata) -> Self {
        Self {
            node: meta.node_id.clone(),
            user: meta.user_id.clone(),
            proxy: meta.proxy_protocol.clone(),
            network: meta.network.clone(),
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct DomainKey {
    user: UserKey,
    domain: String,
    root: String,
    app: String,
    source: String,
}

impl DomainKey {
    fn unknown(user: UserKey) -> Self {
        Self {
            user,
            domain: UNKNOWN.into(),
            root: UNKNOWN.into(),
            app: UNKNOWN.into(),
            source: UNKNOWN.into(),
        }
    }
}

struct MinuteBucket {
    minute: i64,
    users: HashMap<UserKey, TrafficAnalysisUserMinute>,
    domains: HashMap<DomainKey, TrafficAnalysisDomainMinute>,
    known: Vec<DomainKey>,
    cost: u64,
}

impl MinuteBucket {
    fn new(minute: i64) -> Self {
        Self {
            minute,
            users: HashMap::new(),
            domains: HashMap::new(),
            known: Vec::new(),
            cost: 0,
        }
    }
}

pub struct QueuedBatch {
    pub message: TrafficAnalysisBatch,
    pub ready_at: Instant,
    pub expires_at: Instant,
    cost: u64,
    completed: AtomicBool,
    collector: Weak<Collector>,
}

impl Drop for QueuedBatch {
    fn drop(&mut self) {
        if let Some(collector) = self.collector.upgrade() {
            collector.drop_batch(self, "session_reset");
            collector.release(self.cost);
        }
    }
}

#[derive(Default)]
struct Inner {
    epoch: u64,
    sequence: u64,
    next_flow: u64,
    session_open: bool,
    configured: bool,
    flows: HashMap<u64, Arc<Flow>>,
    bucket: Option<MinuteBucket>,
    queue: VecDeque<Arc<QueuedBatch>>,
    queue_bytes: u64,
}

pub struct Collector {
    self_weak: Weak<Self>,
    instance: String,
    inner: Mutex<Inner>,
    active: AtomicU64,
    limits: ArcSwap<TrafficAnalysisConfig>,
    wake: Notify,
    memory: AtomicU64,
    targets: AtomicU64,
    pending_targets: AtomicU64,
    pending_memory: AtomicU64,
    limited_events: AtomicU64,
    dropped_batches: AtomicU64,
    dropped_entries: AtomicU64,
    sent: AtomicU64,
    send_failures: AtomicU64,
    last_sample: AtomicI64,
    last_send: AtomicI64,
    drops: [AtomicU64; 8],
}

impl Collector {
    pub fn new(instance: String) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            instance: instance.chars().take(128).collect(),
            inner: Mutex::default(),
            active: AtomicU64::new(0),
            limits: ArcSwap::from_pointee(default_config(false)),
            wake: Notify::new(),
            memory: AtomicU64::new(0),
            targets: AtomicU64::new(0),
            pending_targets: AtomicU64::new(0),
            pending_memory: AtomicU64::new(0),
            limited_events: AtomicU64::new(0),
            dropped_batches: AtomicU64::new(0),
            dropped_entries: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            last_sample: AtomicI64::new(0),
            last_send: AtomicI64::new(0),
            drops: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    fn reserve(&self, bytes: u64) -> bool {
        let limit = self.limits.load().memory_max_bytes;
        self.memory
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(bytes).filter(|next| *next <= limit)
            })
            .is_ok()
    }

    fn release(&self, bytes: u64) {
        self.memory.fetch_sub(bytes, Ordering::Relaxed);
    }

    // Unclassified UDP associations, their live wrappers and QUIC scratch
    // storage share a small sub-budget. Non-Web traffic cannot consume the
    // entire component budget and prevent known Web TCP/UDP registration.
    fn reserve_pending(&self, bytes: u64) -> bool {
        let limit = (self.limits.load().memory_max_bytes / 4).min(16 << 20);
        if self
            .pending_memory
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(bytes).filter(|next| *next <= limit)
            })
            .is_err()
        {
            return false;
        }
        if self.reserve(bytes) {
            return true;
        }
        self.pending_memory.fetch_sub(bytes, Ordering::Relaxed);
        false
    }

    fn release_pending(&self, bytes: u64) {
        self.pending_memory.fetch_sub(bytes, Ordering::Relaxed);
        self.release(bytes);
    }

    fn reserve_pending_target(&self, config: &TrafficAnalysisConfig) -> bool {
        let limit = u64::from(config.max_udp_targets).min(MAX_PENDING_TARGETS);
        if self
            .pending_targets
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < limit).then_some(n + 1)
            })
            .is_err()
        {
            self.limited("target_limit");
            return false;
        }
        if self.reserve_pending(TARGET_COST) {
            return true;
        }
        self.pending_targets.fetch_sub(1, Ordering::Relaxed);
        self.limited("budget");
        false
    }

    fn reason(&self, reason: &str) {
        if let Some(index) = REASONS.iter().position(|r| *r == reason) {
            self.drops[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn limited(&self, reason: &str) {
        self.limited_events.fetch_add(1, Ordering::Relaxed);
        self.reason(reason);
    }

    fn reserve_target(&self, config: &TrafficAnalysisConfig) -> bool {
        if self
            .targets
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < u64::from(config.max_udp_targets)).then_some(n + 1)
            })
            .is_err()
        {
            self.limited("target_limit");
            return false;
        }
        if self.reserve(TARGET_COST) {
            return true;
        }
        self.targets.fetch_sub(1, Ordering::Relaxed);
        self.limited("budget");
        false
    }

    fn retire(&self, flow: &Flow) -> HashMap<Target, TargetState> {
        let Some(state) = flow.state.swap(None) else {
            return HashMap::new();
        };
        let mut packets = lock(&state.packets);
        packets.retired = true;
        packets.pending = HashMap::new();
        std::mem::take(&mut packets.targets)
    }

    fn discard_buffered(&self, inner: &mut Inner) {
        if let Some(bucket) = inner.bucket.take() {
            let entries = bucket.users.len() + bucket.domains.len();
            self.dropped_entries
                .fetch_add(entries as u64, Ordering::Relaxed);
            if entries > 0 {
                self.reason("session_reset");
            }
            self.release(bucket.cost);
        }
        for batch in inner.queue.drain(..) {
            self.drop_batch(&batch, "session_reset");
        }
        inner.queue_bytes = 0;
    }

    /// Fence callbacks immediately, before configuration and authentication I/O.
    pub fn begin_session(&self) -> u64 {
        let mut inner = lock(&self.inner);
        self.active.store(0, Ordering::Release);
        inner.epoch = inner.epoch.wrapping_add(1).max(1);
        inner.session_open = true;
        inner.configured = false;
        self.discard_buffered(&mut inner);
        self.wake.notify_waiters();
        inner.epoch
    }

    pub fn pause(&self, epoch: u64) {
        let mut inner = lock(&self.inner);
        if inner.epoch != epoch {
            return;
        }
        inner.session_open = false;
        self.active.store(0, Ordering::Release);
        self.discard_buffered(&mut inner);
        for flow in inner.flows.values() {
            if flow.meta.network == "udp" {
                let state = flow.state.load();
                if let Some(state) = state.as_ref() {
                    lock(&state.packets).pending = HashMap::new();
                }
            }
        }
        self.wake.notify_waiters();
    }

    /// Only the current main session's first fresh configuration is accepted.
    pub fn configure(&self, epoch: u64, config: Option<&TrafficAnalysisConfig>) -> bool {
        let mut inner = lock(&self.inner);
        if inner.epoch != epoch || !inner.session_open || inner.configured {
            return false;
        }
        inner.configured = true;
        self.active.store(0, Ordering::Release);
        let config = normalize_config(config);
        self.limits.store(Arc::new(config));
        inner.flows.retain(|_, flow| {
            let old_targets = self.retire(flow);
            if !config.enabled
                || flow.closed.load(Ordering::SeqCst)
                || self.memory.load(Ordering::Relaxed) > config.memory_max_bytes
            {
                if config.enabled && !flow.closed.load(Ordering::SeqCst) {
                    self.limited("budget");
                }
                return false;
            }
            let next = Arc::new(FlowState::new(epoch, false));
            let mut packets = lock(&next.packets);
            for (target, mut old) in old_targets {
                if packets.targets.len() >= config.max_udp_targets_per_session as usize
                    || self.targets.load(Ordering::Relaxed) > u64::from(config.max_udp_targets)
                {
                    self.limited("target_limit");
                } else {
                    // Transfer target storage and its reservation together;
                    // reconnect does not allocate duplicate retained metadata.
                    old.counters = Counters::default();
                    old.started = false;
                    packets.targets.insert(target, old);
                }
            }
            drop(packets);
            flow.state.store(Some(next));
            true
        });
        self.active
            .store(if config.enabled { epoch } else { 0 }, Ordering::Release);
        self.wake.notify_waiters();
        true
    }

    pub fn register(self: &Arc<Self>, metadata: Metadata) -> Option<Arc<Flow>> {
        self.register_at_epoch(self.active_epoch(), metadata)
    }

    /// Preserve eligibility from before routing/configuration work. A flow that
    /// started in a retired main session must never enroll in its replacement.
    pub fn register_at_epoch(
        self: &Arc<Self>,
        expected: u64,
        mut metadata: Metadata,
    ) -> Option<Arc<Flow>> {
        let web = web_protocol(&metadata.app_protocol);
        if metadata.network != "udp" && web.is_none() {
            return None;
        }
        if let Some(web) = web {
            metadata.app_protocol = web.into();
        }
        if expected == 0
            || expected != self.active_epoch()
            || metadata.user_id.is_empty()
            || metadata.node_id.is_empty()
        {
            return None;
        }
        let lengths = [
            (&metadata.node_id, 128),
            (&metadata.user_id, 128),
            (&metadata.proxy_protocol, 64),
            (&metadata.network, 16),
            (&metadata.domain, 253),
            (&metadata.app_protocol, 64),
        ];
        if lengths.iter().any(|(value, limit)| value.len() > *limit)
            || metadata
                .destination
                .as_ref()
                .is_some_and(|t| t.host.len() > 253)
            || metadata
                .sniff_destination
                .as_ref()
                .is_some_and(|t| t.host.len() > 253)
        {
            self.limited("invalid_metadata");
            return None;
        }
        let mut inner = lock(&self.inner);
        let epoch = self.active.load(Ordering::Acquire);
        if epoch == 0 || epoch != expected {
            return None;
        }
        let cost = FLOW_COST
            + lengths.iter().map(|(s, _)| s.len() as u64).sum::<u64>()
            + metadata
                .destination
                .as_ref()
                .map_or(0, |t| t.host.len() as u64)
            + metadata
                .sniff_destination
                .as_ref()
                .map_or(0, |t| t.host.len() as u64);
        if !(if metadata.network == "udp" {
            self.reserve_pending(cost)
        } else {
            self.reserve(cost)
        }) {
            self.limited("budget");
            return None;
        }
        // Clone only retained bounded contents: an input String's capacity may
        // otherwise retain an arbitrarily large parsing buffer.
        let metadata = Metadata {
            node_id: metadata.node_id.clone(),
            user_id: metadata.user_id.clone(),
            proxy_protocol: metadata.proxy_protocol.clone(),
            network: metadata.network.clone(),
            domain: metadata.domain.clone(),
            app_protocol: metadata.app_protocol.clone(),
            destination: metadata.destination.clone(),
            sniff_destination: metadata.sniff_destination.clone(),
        };
        let tcp = metadata.network != "udp";
        let flow = Arc::new(Flow {
            collector: Arc::downgrade(self),
            meta: metadata,
            state: ArcSwapOption::from(Some(Arc::new(FlowState::new(epoch, tcp)))),
            closed: AtomicBool::new(false),
            inflight: AtomicU64::new(0),
            web_seen: AtomicBool::new(tcp),
            cost,
        });
        inner.next_flow = inner.next_flow.wrapping_add(1);
        let id = inner.next_flow;
        inner.flows.insert(id, Arc::clone(&flow));
        Some(flow)
    }

    fn new_domain(&self, bucket: &mut MinuteBucket, key: DomainKey) {
        let row = TrafficAnalysisDomainMinute {
            user_id: key.user.user.clone(),
            node_id: key.user.node.clone(),
            proxy_protocol: key.user.proxy.clone(),
            network: key.user.network.clone(),
            minute_at_unix: bucket.minute,
            domain: key.domain.clone(),
            root_domain: key.root.clone(),
            app_protocol: key.app.clone(),
            domain_source: key.source.clone(),
            ..Default::default()
        };
        bucket.domains.insert(key, row);
        bucket.cost += DOMAIN_COST;
    }

    fn ensure_unknown(&self, bucket: &mut MinuteBucket, user: &UserKey) -> bool {
        let key = DomainKey::unknown(user.clone());
        if bucket.domains.contains_key(&key) {
            return true;
        }
        let full = bucket.domains.len() >= self.limits.load().minute_max_domain_keys as usize;
        if !full && self.reserve(DOMAIN_COST) {
            self.new_domain(bucket, key);
            return true;
        }
        self.reason(if full { "domain_limit" } else { "budget" });
        while let Some(old_key) = bucket.known.pop() {
            if let Some(old) = bucket.domains.remove(&old_key) {
                if let Some(unknown) = bucket.domains.get_mut(&DomainKey::unknown(old_key.user)) {
                    unknown.uplink_bytes += old.uplink_bytes;
                    unknown.downlink_bytes += old.downlink_bytes;
                    unknown.target_sessions += old.target_sessions;
                }
                // Transfer the existing reservation to the new unknown row.
                bucket.cost -= DOMAIN_COST;
                self.new_domain(bucket, key);
                self.limited_events.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    fn add_domain(
        &self,
        bucket: &mut MinuteBucket,
        mut key: DomainKey,
        up: u64,
        down: u64,
        started: u64,
    ) {
        if up == 0 && down == 0 && started == 0 {
            return;
        }
        if !bucket.domains.contains_key(&key) && (key.domain != UNKNOWN || key.app != UNKNOWN) {
            let full = bucket.domains.len() >= self.limits.load().minute_max_domain_keys as usize;
            if !full && self.reserve(DOMAIN_COST) {
                self.new_domain(bucket, key.clone());
                bucket.known.push(key.clone());
            } else {
                self.limited(if full { "domain_limit" } else { "budget" });
                key = DomainKey::unknown(key.user);
            }
        }
        if !bucket.domains.contains_key(&key) && !self.ensure_unknown(bucket, &key.user) {
            self.dropped_entries.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Some(row) = bucket.domains.get_mut(&key) {
            row.uplink_bytes += up;
            row.downlink_bytes += down;
            row.target_sessions += started;
        }
    }

    /// Drain into the observed UTC minute. Clock reversal never reopens a bucket.
    pub fn sample(&self, now_unix: i64) {
        let mut inner = lock(&self.inner);
        self.last_sample.store(now_unix, Ordering::Relaxed);
        let epoch = self.active.load(Ordering::Acquire);
        if epoch == 0 {
            inner.flows.retain(|_, flow| {
                if flow.closed.load(Ordering::SeqCst) && flow.inflight.load(Ordering::SeqCst) == 0 {
                    self.retire(flow);
                    false
                } else {
                    true
                }
            });
            return;
        }
        let minute = now_unix.div_euclid(60) * 60;
        if inner.bucket.as_ref().is_some_and(|b| minute > b.minute) {
            let bucket = inner.bucket.take().expect("checked bucket");
            self.seal(&mut inner, bucket, now_unix);
        }
        let mut bucket = inner
            .bucket
            .take()
            .unwrap_or_else(|| MinuteBucket::new(minute));
        inner.flows.retain(|_, flow| {
            let state = flow.state.load();
            let Some(state) = state.as_ref().filter(|s| s.epoch == epoch) else {
                return true;
            };
            let finished =
                flow.closed.load(Ordering::SeqCst) && flow.inflight.load(Ordering::SeqCst) == 0;
            let mut packets = (flow.meta.network == "udp").then(|| lock(&state.packets));
            let (up, down) = state.counters.drain();
            let started = u64::from(state.started.swap(false, Ordering::Relaxed));
            let user = UserKey::from(&flow.meta);
            let nonzero = up != 0 || down != 0 || started != 0;
            if !bucket.users.contains_key(&user) && nonzero && self.reserve(USER_COST) {
                bucket.users.insert(
                    user.clone(),
                    TrafficAnalysisUserMinute {
                        node_id: user.node.clone(),
                        user_id: user.user.clone(),
                        proxy_protocol: user.proxy.clone(),
                        network: user.network.clone(),
                        minute_at_unix: bucket.minute,
                        ..Default::default()
                    },
                );
                bucket.cost += USER_COST;
                self.ensure_unknown(&mut bucket, &user);
            }
            let retained = bucket.users.contains_key(&user);
            if let Some(row) = bucket.users.get_mut(&user) {
                row.uplink_bytes += up;
                row.downlink_bytes += down;
                row.started_sessions += started;
            } else if nonzero {
                self.dropped_entries.fetch_add(1, Ordering::Relaxed);
                self.reason("budget");
            }
            let (mut identified_up, mut identified_down) = (0, 0);
            if let Some(packets) = packets.as_mut() {
                packets.expire_pending();
                for (target, target_state) in &mut packets.targets {
                    let (up, down) = target_state.counters.drain();
                    let started = u64::from(std::mem::take(&mut target_state.started));
                    if up == 0 && down == 0 && started == 0 {
                        continue;
                    }
                    let mut key = identity(&flow.meta, Some(target), true);
                    if let Some(classification) = &target_state.classification {
                        if !classification.domain.is_empty() {
                            (key.domain, key.root) = canonical_domain(&classification.domain);
                            key.source = if key.domain == UNKNOWN {
                                UNKNOWN
                            } else {
                                "sniff"
                            }
                            .into();
                        }
                        if !classification.app.is_empty() {
                            key.app.clone_from(&classification.app);
                        }
                    }
                    if key.domain != UNKNOWN {
                        identified_up += up;
                        identified_down += down;
                    }
                    if retained {
                        self.add_domain(&mut bucket, key, up, down, started);
                    }
                }
                let (up, down) = packets.unknown.drain();
                if retained {
                    self.add_domain(&mut bucket, DomainKey::unknown(user.clone()), up, down, 0);
                }
            } else if nonzero {
                let key = identity(&flow.meta, flow.meta.destination.as_ref(), false);
                if key.domain != UNKNOWN {
                    identified_up += up;
                    identified_down += down;
                }
                if retained {
                    self.add_domain(&mut bucket, key, up, down, started);
                }
            }
            if let Some(row) = bucket.users.get_mut(&user) {
                row.identified_uplink_bytes += identified_up;
                row.identified_downlink_bytes += identified_down;
            }
            drop(packets);
            if finished {
                self.retire(flow);
                false
            } else {
                true
            }
        });
        inner.bucket = Some(bucket);
    }

    fn new_message(&self, inner: &mut Inner, now_unix: i64) -> TrafficAnalysisBatch {
        inner.sequence = inner.sequence.wrapping_add(1);
        TrafficAnalysisBatch {
            agent_instance_id: self.instance.clone(),
            epoch: inner.epoch,
            sequence: inner.sequence,
            generated_at_unix: now_unix,
            ..Default::default()
        }
    }

    fn seal(&self, inner: &mut Inner, bucket: MinuteBucket, now_unix: i64) {
        let config = self.limits.load();
        let mut message = self.new_message(inner, now_unix);
        let mut size = message.encoded_len();
        for row in bucket.users.into_values() {
            let row_size = row.encoded_len() + 8;
            if entries(&message) >= config.batch_max_entries as usize
                || size + row_size > config.batch_max_bytes as usize
            {
                self.enqueue(inner, message, now_unix);
                message = self.new_message(inner, now_unix);
                size = message.encoded_len();
            }
            message.user_minutes.push(row);
            size += row_size;
        }
        for row in bucket.domains.into_values() {
            if row.uplink_bytes == 0 && row.downlink_bytes == 0 && row.target_sessions == 0 {
                continue;
            }
            let row_size = row.encoded_len() + 8;
            if entries(&message) >= config.batch_max_entries as usize
                || size + row_size > config.batch_max_bytes as usize
            {
                self.enqueue(inner, message, now_unix);
                message = self.new_message(inner, now_unix);
                size = message.encoded_len();
            }
            message.domain_minutes.push(row);
            size += row_size;
        }
        self.enqueue(inner, message, now_unix);
        self.release(bucket.cost);
    }

    fn enqueue(&self, inner: &mut Inner, mut message: TrafficAnalysisBatch, now_unix: i64) {
        if entries(&message) == 0 {
            return;
        }
        // Small Vecs otherwise retain spare row slots, which is particularly
        // expensive for prost messages containing several owned Strings.
        message.user_minutes.shrink_to_fit();
        message.domain_minutes.shrink_to_fit();
        let config = self.limits.load();
        let bytes = message.encoded_len() as u64;
        // Include both retained protobuf structs and the sender's cloned row
        // structs, in addition to their owned strings and message overhead.
        let cost = bytes * 2 + entries(&message) as u64 * 512 + 256;
        let reason = if bytes > u64::from(config.batch_max_bytes) {
            Some("budget")
        } else if inner.queue_bytes.saturating_add(cost) > config.queue_max_bytes {
            Some("queue_full")
        } else if !self.reserve(cost) {
            Some("budget")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.dropped_batches.fetch_add(1, Ordering::Relaxed);
            self.dropped_entries
                .fetch_add(entries(&message) as u64, Ordering::Relaxed);
            self.reason(reason);
            return;
        }
        let now = Instant::now();
        // Production sampling uses wall time; deterministic historical samples
        // retain their age rather than acquiring a fresh send window.
        let elapsed = Duration::from_secs(unix_now().saturating_sub(now_unix).max(0) as u64);
        let age = Duration::from_secs(u64::from(config.queue_max_age_seconds));
        let jitter = Duration::from_millis(rand::random::<u64>() % 10_001);
        let expires_at = now + age.saturating_sub(elapsed);
        let ready_at = (now + jitter.saturating_sub(elapsed)).min(expires_at);
        inner.queue.push_back(Arc::new(QueuedBatch {
            message,
            ready_at,
            expires_at,
            cost,
            completed: AtomicBool::new(false),
            collector: self.self_weak.clone(),
        }));
        inner.queue_bytes += cost;
        self.wake.notify_one();
    }

    pub async fn next(&self, cancel: &CancellationToken, epoch: u64) -> Option<Arc<QueuedBatch>> {
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let delay = {
                let mut inner = lock(&self.inner);
                if self.active.load(Ordering::Acquire) != epoch || epoch == 0 {
                    return None;
                }
                let mut delay = Duration::from_secs(1);
                while let Some(batch) = inner.queue.front() {
                    let now = Instant::now();
                    if now >= batch.expires_at {
                        let batch = inner.queue.pop_front().expect("front present");
                        inner.queue_bytes -= batch.cost;
                        self.drop_batch(&batch, "expired");
                        continue;
                    }
                    if now < batch.ready_at {
                        delay = batch.ready_at.duration_since(now);
                        break;
                    }
                    let batch = inner.queue.pop_front().expect("front present");
                    inner.queue_bytes -= batch.cost;
                    return Some(batch);
                }
                delay
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return None,
                () = &mut notified => {},
                () = tokio::time::sleep(delay) => {},
            }
        }
    }

    pub fn complete(&self, batch: &QueuedBatch, sent: bool) {
        if !sent {
            self.drop_batch(batch, "send_failed");
            return;
        }
        if batch.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.last_send.store(unix_now(), Ordering::Relaxed);
    }

    pub fn drop_batch(&self, batch: &QueuedBatch, reason: &str) {
        if batch.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.dropped_batches.fetch_add(1, Ordering::Relaxed);
        self.dropped_entries
            .fetch_add(entries(&batch.message) as u64, Ordering::Relaxed);
        let reason = if REASONS.contains(&reason) {
            reason
        } else {
            "send_failed"
        };
        self.reason(reason);
        if reason == "send_failed" {
            self.send_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn run_sampling(&self, cancel: &CancellationToken) {
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let boundary =
                Duration::from_secs(60) - Duration::from_millis((now.as_millis() % 60_000) as u64);
            let delay = Duration::from_secs(u64::from(self.limits.load().sample_interval_seconds))
                .min(boundary);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                () = tokio::time::sleep(delay) => self.sample(unix_now()),
            }
        }
    }

    pub fn config(&self) -> TrafficAnalysisConfig {
        **self.limits.load()
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    pub fn active_epoch(&self) -> u64 {
        self.active.load(Ordering::Acquire)
    }

    pub fn status(&self) -> TrafficAnalysisStatus {
        let inner = lock(&self.inner);
        self.status_locked(&inner)
    }

    /// Telemetry must not wait behind classification or protobuf batching.
    /// The next heartbeat can include the state once the sampler releases it.
    pub fn try_status(&self) -> Option<TrafficAnalysisStatus> {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        Some(self.status_locked(&inner))
    }

    fn status_locked(&self, inner: &Inner) -> TrafficAnalysisStatus {
        TrafficAnalysisStatus {
            enabled: self.active.load(Ordering::Acquire) != 0,
            epoch: inner.epoch,
            tracked_connections: inner.flows.len() as u64,
            udp_targets: self.targets.load(Ordering::Relaxed),
            buffered_domain_keys: inner.bucket.as_ref().map_or(0, |b| b.domains.len() as u64),
            queue_bytes: inner.queue_bytes,
            queued_batches: inner.queue.len() as u64,
            sent_batches: self.sent.load(Ordering::Relaxed),
            dropped_batches: self.dropped_batches.load(Ordering::Relaxed),
            dropped_entries: self.dropped_entries.load(Ordering::Relaxed),
            limited_events: self.limited_events.load(Ordering::Relaxed),
            last_send_at_unix: self.last_send.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
            last_sample_at_unix: self.last_sample.load(Ordering::Relaxed),
            memory_bytes: self.memory.load(Ordering::Relaxed),
            dropped_by_reason: REASONS
                .iter()
                .zip(&self.drops)
                .map(|(reason, count)| ((*reason).into(), count.load(Ordering::Relaxed)))
                .collect(),
        }
    }
}

fn entries(batch: &TrafficAnalysisBatch) -> usize {
    batch.user_minutes.len() + batch.domain_minutes.len()
}

fn web_protocol(protocol: &str) -> Option<&'static str> {
    let protocol = protocol.trim_ascii();
    ["http", "tls", "quic"]
        .into_iter()
        .find(|web| protocol.eq_ignore_ascii_case(web))
}

fn identity(meta: &Metadata, target: Option<&Target>, packet: bool) -> DomainKey {
    let mut domain = "";
    let mut app = UNKNOWN;
    let mut source = UNKNOWN;
    if !packet || (target.is_some() && target == meta.sniff_destination.as_ref()) {
        domain = &meta.domain;
        app = &meta.app_protocol;
        if !domain.is_empty() {
            source = "sniff";
        }
    }
    if domain.is_empty()
        && let Some(target) = target
    {
        domain = &target.host;
        source = "destination";
    }
    let (domain, root) = canonical_domain(domain);
    if domain == UNKNOWN {
        source = UNKNOWN;
    }
    DomainKey {
        user: UserKey::from(meta),
        domain,
        root,
        app: if app.is_empty() { UNKNOWN } else { app }.into(),
        source: source.into(),
    }
}

fn canonical_domain(raw: &str) -> (String, String) {
    let raw = raw.trim().trim_end_matches('.');
    let invalid = || (UNKNOWN.to_owned(), UNKNOWN.to_owned());
    if raw.is_empty()
        || raw.len() > 253
        || raw.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | ':' | '@' | '%')
        })
        || raw.parse::<IpAddr>().is_ok()
    {
        return invalid();
    }
    let Ok(url::Host::Domain(domain)) = url::Host::parse(raw) else {
        return invalid();
    };
    if domain.len() > 253
        || domain.ends_with(".arpa")
        || domain.contains("sp.packet-addr")
        || domain.contains("sp.v2.udp-over-tcp")
        || domain.contains("sp.udp-over-tcp")
        || domain
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return invalid();
    }
    let root = psl::domain_str(&domain).unwrap_or(&domain).to_owned();
    (domain, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collector(config: TrafficAnalysisConfig) -> (Arc<Collector>, u64) {
        let collector = Collector::new("test-instance".into());
        let epoch = collector.begin_session();
        assert!(collector.configure(epoch, Some(&config)));
        (collector, epoch)
    }

    fn target(host: &str) -> Target {
        Target {
            host: host.into(),
            port: 443,
        }
    }

    fn metadata(network: &str) -> Metadata {
        Metadata {
            node_id: "node-1".into(),
            user_id: "user-1".into(),
            proxy_protocol: "vless".into(),
            network: network.into(),
            domain: "WWW.Example.COM.".into(),
            app_protocol: "tls".into(),
            destination: Some(target("example.com")),
            sniff_destination: None,
        }
    }

    fn totals(collector: &Collector) -> (u64, u64, u64, u64) {
        let inner = lock(&collector.inner);
        inner.bucket.as_ref().map_or((0, 0, 0, 0), |b| {
            b.users.values().fold((0, 0, 0, 0), |a, r| {
                (
                    a.0 + r.uplink_bytes,
                    a.1 + r.downlink_bytes,
                    a.2 + r.started_sessions,
                    a.3 + r.identified_uplink_bytes,
                )
            })
        })
    }

    #[test]
    fn reconnect_discards_old_io_and_resumes_living_flow_without_new_session() {
        let (collector, first) = collector(default_config(true));
        let flow = collector.register(metadata("tcp")).unwrap();
        let pending = flow.begin();
        flow.begin().done(10, 20);
        collector.sample(180);
        collector.pause(first);
        assert!(collector.register(metadata("tcp")).is_none());
        let next = collector.begin_session();
        assert!(collector.configure(next, Some(&default_config(true))));
        pending.done(1000, 1000);
        flow.begin().done(3, 4);
        collector.pause(first);
        assert!(!collector.configure(first, Some(&default_config(false))));
        collector.sample(240);
        assert_eq!(totals(&collector), (3, 4, 0, 3));
        collector.pause(next);
        assert!(!collector.configure(next, Some(&default_config(true))));
    }

    #[test]
    fn disabled_to_enabled_only_enrolls_new_flows() {
        let (collector, epoch) = collector(default_config(true));
        let old = collector.register(metadata("tcp")).unwrap();
        collector.pause(epoch);
        let epoch = collector.begin_session();
        collector.configure(epoch, None);
        assert_eq!(collector.status().tracked_connections, 0);
        let epoch = collector.begin_session();
        collector.configure(epoch, Some(&default_config(true)));
        old.begin().done(100, 100);
        collector
            .register(metadata("tcp"))
            .unwrap()
            .begin()
            .done(7, 8);
        collector.sample(60);
        assert_eq!(totals(&collector), (7, 8, 1, 7));
    }

    #[test]
    fn delayed_registration_cannot_adopt_the_replacement_epoch() {
        let (collector, first) = collector(default_config(true));
        let captured = collector.active_epoch();
        assert_eq!(captured, first);
        let next = collector.begin_session();
        assert!(
            collector
                .register_at_epoch(captured, metadata("udp"))
                .is_none()
        );
        collector.configure(next, Some(&default_config(true)));
        assert!(
            collector
                .register_at_epoch(captured, metadata("udp"))
                .is_none()
        );
        assert!(collector.register_at_epoch(0, metadata("udp")).is_none());
        assert!(collector.register_at_epoch(next, metadata("udp")).is_some());
        assert_eq!(collector.status().tracked_connections, 1);
    }

    #[test]
    fn close_waits_for_tail_and_dropped_observation_releases_inflight() {
        let (collector, _) = collector(default_config(true));
        let flow = collector.register(metadata("tcp")).unwrap();
        let pending = flow.begin();
        let cancelled = flow.begin();
        flow.close();
        flow.close();
        collector.sample(60);
        assert_eq!(collector.status().tracked_connections, 1);
        pending.done(55, 34);
        drop(cancelled);
        collector.sample(65);
        collector.sample(70);
        assert_eq!(collector.status().tracked_connections, 0);
        assert_eq!(totals(&collector), (55, 34, 1, 55));
        assert_eq!(flow.begin_token(), 0);
    }

    #[test]
    fn minute_boundary_and_clock_reversal_never_reopen_sealed_data() {
        let (collector, _) = collector(default_config(true));
        let flow = collector.register(metadata("tcp")).unwrap();
        flow.begin().done(5, 0);
        collector.sample(119);
        flow.begin().done(7, 0);
        collector.sample(120);
        let inner = lock(&collector.inner);
        let sealed: u64 = inner
            .queue
            .iter()
            .flat_map(|b| &b.message.user_minutes)
            .map(|r| {
                assert_eq!(r.minute_at_unix, 60);
                r.uplink_bytes
            })
            .sum();
        assert_eq!(sealed, 5);
        drop(inner);
        assert_eq!(totals(&collector).0, 7);
        flow.close();
        collector.sample(118);
        assert_eq!(lock(&collector.inner).bucket.as_ref().unwrap().minute, 120);
    }

    #[test]
    fn udp_targets_never_share_the_first_sni() {
        let (collector, epoch) = collector(default_config(true));
        let mut meta = metadata("udp");
        meta.sniff_destination = Some(target("1.1.1.1"));
        let flow = collector.register(meta).unwrap();
        let targets = [
            target("1.1.1.1"),
            target("2.2.2.2"),
            target("sub.other.co.uk"),
        ];
        flow.classify_target(epoch, &targets[2], None, "quic");
        flow.begin()
            .done_packet_batch(targets.iter().zip([10, 20, 30]).map(|(t, n)| (t, n, 0)));
        flow.close();
        collector.sample(60);
        assert_eq!(totals(&collector), (40, 0, 1, 40));
        let inner = lock(&collector.inner);
        let domains: HashMap<_, _> = inner
            .bucket
            .as_ref()
            .unwrap()
            .domains
            .values()
            .map(|r| (r.domain.as_str(), r.uplink_bytes))
            .collect();
        assert_eq!(domains["www.example.com"], 10);
        assert_eq!(domains[UNKNOWN], 0);
        assert_eq!(domains["sub.other.co.uk"], 30);
        assert!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .any(|r| r.root_domain == "other.co.uk")
        );
        drop(inner);
        assert_eq!(collector.status().udp_targets, 0);
    }

    #[test]
    fn delayed_udp_classification_is_target_bound_and_epoch_fenced() {
        let (collector, epoch) = collector(default_config(true));
        let mut meta = metadata("udp");
        meta.domain.clear();
        meta.app_protocol.clear();
        let flow = collector.register(meta).unwrap();
        let first = target("1.1.1.1");
        let other = target("2.2.2.2");
        let observation = flow.begin();
        flow.classify_target(epoch, &first, Some("video.youtube.com"), "quic");
        observation.done_packet(&first, 20, 0);
        flow.begin().done_packet(&other, 30, 0);
        collector.sample(60);
        assert_eq!(totals(&collector), (20, 0, 1, 20));
        collector.pause(epoch);
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        flow.classify_target(epoch, &first, Some("wrong.example.com"), "tls");
        flow.begin().done_packet(&first, 7, 0);
        flow.close();
        collector.sample(120);
        assert_eq!(totals(&collector), (7, 0, 0, 7));
        let inner = lock(&collector.inner);
        let row = inner
            .bucket
            .as_ref()
            .unwrap()
            .domains
            .values()
            .find(|r| r.uplink_bytes > 0)
            .unwrap();
        assert_eq!(row.domain, "video.youtube.com");
        assert_eq!(row.app_protocol, "quic");
        assert_eq!(row.target_sessions, 0);
        assert_eq!(row.domain_source, "sniff");
    }

    #[test]
    fn classification_only_targets_obey_the_same_global_limit() {
        let mut config = default_config(true);
        config.max_udp_targets = 2;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        for i in 0..10 {
            flow.classify_target(
                epoch,
                &target(&format!("10.0.0.{i}")),
                Some("example.com"),
                "quic",
            );
        }
        assert_eq!(collector.status().udp_targets, 2);
        collector.sample(60);
        let inner = lock(&collector.inner);
        assert_eq!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .map(|r| r.target_sessions)
                .sum::<u64>(),
            0
        );
        drop(inner);
        flow.close();
        collector.sample(65);
        assert_eq!(collector.status().udp_targets, 0);
    }

    #[test]
    fn domain_limit_preserves_identified_user_totals_and_unknown_overflow() {
        let mut config = default_config(true);
        config.minute_max_domain_keys = 1;
        let (collector, _) = collector(config);
        collector
            .register(metadata("tcp"))
            .unwrap()
            .begin()
            .done(51, 0);
        collector.sample(60);
        assert_eq!(totals(&collector), (51, 0, 1, 51));
        let inner = lock(&collector.inner);
        let bucket = inner.bucket.as_ref().unwrap();
        assert_eq!(bucket.domains.len(), 1);
        let row = bucket.domains.values().next().unwrap();
        assert_eq!(row.domain, UNKNOWN);
        assert_eq!(row.uplink_bytes, 51);
    }

    #[test]
    fn many_users_keep_totals_after_detail_exhaustion() {
        let mut config = default_config(true);
        config.minute_max_domain_keys = 2;
        let (collector, _) = collector(config);
        for i in 0..20 {
            let mut meta = metadata("tcp");
            meta.user_id = format!("user-{i}");
            let flow = collector.register(meta).unwrap();
            flow.begin().done(100, 0);
            flow.close();
        }
        collector.sample(60);
        assert_eq!(totals(&collector), (2000, 0, 20, 2000));
        assert!(collector.status().buffered_domain_keys <= 2);
        assert_eq!(collector.status().tracked_connections, 0);
    }

    #[test]
    fn udp_target_limit_parallel_callbacks_and_reconnect_do_not_lose_totals() {
        let mut config = default_config(true);
        config.max_udp_targets_per_session = 1;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        flow.classify_target(epoch, &target("10.0.0.1"), None, "quic");
        std::thread::scope(|scope| {
            for i in 0..8 {
                let flow = &flow;
                scope.spawn(move || {
                    let target = target(&format!("10.0.0.{}", i + 1));
                    for _ in 0..100 {
                        flow.begin().done_packet(&target, 1, 0);
                    }
                });
            }
        });
        collector.sample(60);
        assert_eq!(totals(&collector).0, 100);
        assert_eq!(collector.status().udp_targets, 1);
        collector.pause(epoch);
        let epoch = collector.begin_session();
        collector.configure(epoch, Some(&config));
        let existing = {
            let state = flow.state.load();
            let packets = lock(&state.as_ref().unwrap().packets);
            packets.targets.keys().next().unwrap().clone()
        };
        flow.begin().done_packet(&existing, 9, 0);
        flow.close();
        collector.sample(120);
        assert_eq!(totals(&collector), (9, 0, 0, 0));
        assert_eq!(collector.status().udp_targets, 0);
        let inner = lock(&collector.inner);
        assert_eq!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .map(|r| r.target_sessions)
                .sum::<u64>(),
            0
        );
    }

    #[tokio::test]
    async fn batches_are_bounded_expire_and_release_exactly_once() {
        let mut config = default_config(true);
        config.batch_max_entries = 2;
        config.batch_max_bytes = 1024;
        let (collector, epoch) = collector(config);
        for i in 0..10 {
            let mut meta = metadata("tcp");
            meta.user_id = i.to_string();
            let flow = collector.register(meta).unwrap();
            flow.begin().done(1, 1);
            flow.close();
        }
        collector.sample(60);
        collector.sample(120);
        for batch in &lock(&collector.inner).queue {
            assert!(entries(&batch.message) <= 2);
            assert!(batch.message.encoded_len() <= 1024);
        }
        let cancel = CancellationToken::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), collector.next(&cancel, epoch))
                .await
                .is_err()
        );
        assert_eq!(collector.status().queue_bytes, 0);
        assert_eq!(collector.status().queued_batches, 0);
        collector.pause(epoch);
        assert_eq!(collector.status().memory_bytes, 0);
        assert!(collector.status().dropped_by_reason["expired"] > 0);
    }

    #[tokio::test]
    async fn sender_completion_and_old_session_callbacks_are_idempotent() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("tcp")).unwrap();
        flow.begin().done(1, 2);
        flow.close();
        let now = unix_now();
        collector.sample(now - 60);
        collector.sample(now);
        let batch = {
            let mut inner = lock(&collector.inner);
            let batch = inner.queue.pop_front().unwrap();
            inner.queue_bytes -= batch.cost;
            batch
        };
        collector.pause(epoch);
        collector.complete(&batch, true);
        collector.complete(&batch, true);
        collector.drop_batch(&batch, "send_failed");
        assert_eq!(collector.status().sent_batches, 1);
        assert_eq!(collector.status().send_failures, 0);
        assert!(collector.status().memory_bytes >= batch.cost);
        drop(batch);
        drop(flow);
        assert_eq!(collector.status().memory_bytes, 0);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(collector.next(&cancel, epoch).await.is_none());
    }

    #[test]
    fn small_memory_budget_limits_registrations_and_releases_on_disable() {
        let mut config = default_config(true);
        config.memory_max_bytes = 1 << 20;
        let (collector, _) = collector(config);
        let mut accepted = 0;
        for _ in 0..10000 {
            if collector.register(metadata("tcp")).is_some() {
                accepted += 1;
            }
        }
        assert!(accepted > 0 && accepted < 10000);
        assert!(collector.status().memory_bytes <= config.memory_max_bytes);
        assert!(collector.status().dropped_by_reason["budget"] > 0);
        let epoch = collector.begin_session();
        collector.configure(epoch, None);
        assert_eq!(collector.status().memory_bytes, 0);
        assert_eq!(collector.status().tracked_connections, 0);
    }

    #[test]
    fn disabled_wrappers_and_sniff_storage_remain_charged_until_released() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        let baseline = collector.status().memory_bytes;
        assert!(flow.try_reserve_sniff(20 << 10));
        flow.classify_target(epoch, &target("1.1.1.1"), Some("example.com"), "quic");
        assert_eq!(
            collector.status().memory_bytes,
            baseline + (20 << 10) + TARGET_COST
        );
        let epoch = collector.begin_session();
        collector.configure(epoch, None);
        assert_eq!(collector.status().tracked_connections, 0);
        assert_eq!(collector.status().udp_targets, 0);
        assert_eq!(collector.status().memory_bytes, baseline + (20 << 10));
        flow.release_sniff(20 << 10);
        assert_eq!(collector.status().memory_bytes, baseline);
        drop(flow);
        assert_eq!(collector.status().memory_bytes, 0);
    }

    #[test]
    fn paused_association_storage_is_bounded_and_released_after_disable() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        let baseline = collector.status().memory_bytes;
        collector.pause(epoch);
        assert!(flow.try_reserve_storage(2048));
        assert!(!flow.try_reserve_sniff(2048));
        assert_eq!(collector.status().memory_bytes, baseline + 2048);
        assert!(!flow.try_reserve_storage(collector.config().memory_max_bytes as usize));
        assert!(collector.status().dropped_by_reason["budget"] > 0);
        flow.release_storage(2048);
        assert_eq!(collector.status().memory_bytes, baseline);

        assert!(flow.try_reserve_storage(4096));
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        assert!(flow.try_reserve_storage(1024));
        let disabled = collector.begin_session();
        collector.configure(disabled, None);
        assert!(!flow.try_reserve_storage(1024));
        assert_eq!(collector.status().memory_bytes, baseline + 4096 + 1024);
        flow.release_storage(4096);
        flow.release_storage(1024);
        assert_eq!(collector.status().memory_bytes, baseline);
        drop(flow);
        assert_eq!(collector.status().memory_bytes, 0);
    }

    #[test]
    fn closed_flows_reject_storage_even_before_the_sampler_retires_them() {
        let (collector, _) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        assert!(flow.try_reserve_storage(1024));
        flow.close();
        assert!(!flow.try_reserve_storage(1024));
        assert!(!flow.try_reserve_sniff(1024));
        flow.release_storage(1024);
        collector.sample(60);
        drop(flow);
        collector.pause(collector.active_epoch());
        assert_eq!(collector.status().memory_bytes, 0);
    }

    #[test]
    fn queue_overload_drops_batches_without_exceeding_reserved_limits() {
        let mut config = default_config(true);
        config.queue_max_bytes = 256 << 10;
        config.batch_max_entries = 4;
        let (collector, epoch) = collector(config);
        for i in 0..800 {
            let mut meta = metadata("tcp");
            meta.user_id = format!("user-{i}");
            meta.domain = format!("domain-{i}.example.com");
            let flow = collector.register(meta).unwrap();
            flow.begin().done(100, 200);
            flow.close();
        }
        collector.sample(60);
        assert_eq!(totals(&collector).0, 80000);
        collector.sample(120);
        let status = collector.status();
        assert!(status.queued_batches > 0);
        assert!(status.queue_bytes <= config.queue_max_bytes);
        assert!(status.memory_bytes <= config.memory_max_bytes);
        assert!(status.dropped_by_reason["queue_full"] > 0);
        collector.pause(epoch);
        assert_eq!(collector.status().memory_bytes, 0);
    }

    #[test]
    fn malformed_metadata_and_internal_destinations_never_become_domains() {
        let (collector, _) = collector(default_config(true));
        let mut meta = metadata("tcp");
        meta.domain = "x".repeat(254);
        assert!(collector.register(meta).is_none());
        for raw in [
            "",
            "127.0.0.1",
            "[::1]",
            "a b.com",
            "user@example.com",
            "foo.arpa",
            "sp.packet-addr",
            "sp.v2.udp-over-tcp",
            "a%20b.com",
            "https://example.com",
        ] {
            assert_eq!(canonical_domain(raw).0, UNKNOWN, "{raw}");
        }
        assert_eq!(
            canonical_domain(" WWW.Example.COM. "),
            ("www.example.com".into(), "example.com".into())
        );
        assert_eq!(canonical_domain("a.b.co.uk").1, "b.co.uk");
        assert_eq!(canonical_domain("a.github.io").1, "a.github.io");
        assert_eq!(canonical_domain("bücher.de").0, "xn--bcher-kva.de");
    }

    #[test]
    fn telemetry_snapshot_never_waits_for_a_sampling_lock() {
        let (collector, _) = collector(default_config(true));
        let sampling = lock(&collector.inner);
        assert!(collector.try_status().is_none());
        drop(sampling);
        assert!(collector.try_status().unwrap().enabled);
    }

    #[test]
    fn tcp_analysis_only_registers_recognized_web_protocols() {
        let (collector, _) = collector(default_config(true));
        for protocol in ["", "unknown", "ftp", "SSH", "dns", "smtp", "http2"] {
            let mut meta = metadata("tcp");
            meta.app_protocol = protocol.into();
            assert!(collector.register(meta).is_none(), "{protocol}");
        }
        assert_eq!(collector.status().tracked_connections, 0);
        for protocol in ["http", "HTTP", "tls", "TLS", "quic", "QUIC", " \tTLS\r\n"] {
            let mut meta = metadata("tcp");
            meta.app_protocol = protocol.into();
            let flow = collector.register(meta).unwrap();
            flow.begin().done(10, 20);
            flow.close();
        }
        collector.sample(60);
        assert_eq!(totals(&collector), (70, 140, 7, 70));
        let inner = lock(&collector.inner);
        assert!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .filter(|row| row.uplink_bytes > 0)
                .all(|row| ["http", "tls", "quic"].contains(&row.app_protocol.as_str()))
        );
    }

    #[test]
    fn mixed_udp_excludes_dns_ssh_ftp_and_unknown_from_all_analysis_totals() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        for (i, protocol) in ["dns", "SSH", "ftp"].into_iter().enumerate() {
            let destination = target(&format!("192.0.2.{}", i + 1));
            flow.begin().done_packet(&destination, 10, 20);
            flow.classify_target(epoch, &destination, Some("not-web.example.com"), protocol);
            // A terminal non-Web result detaches the wrapper. The collector
            // retains neither target state nor an unbounded rejected-key set.
            assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
            assert_eq!(collector.status().udp_targets, 0);
        }
        flow.begin()
            .done_packet(&target("unclassified.example.com"), 500, 600);
        collector.sample(60);
        assert_eq!(totals(&collector), (0, 0, 0, 0));
        assert!(
            lock(&collector.inner)
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .is_empty()
        );
        assert_eq!(collector.status().dropped_entries, 0);

        let web = target("192.0.2.100");
        flow.classify_target(epoch, &web, Some("video.youtube.com"), "QUIC");
        flow.begin().done_packet(&web, 7, 9);
        collector.sample(65);
        assert_eq!(totals(&collector), (7, 9, 1, 7));
        let inner = lock(&collector.inner);
        let rows = &inner.bucket.as_ref().unwrap().domains;
        assert_eq!(rows.values().map(|row| row.uplink_bytes).sum::<u64>(), 7);
        assert!(
            rows.values()
                .filter(|row| row.uplink_bytes > 0)
                .all(|row| row.app_protocol == "quic" && row.domain == "video.youtube.com")
        );
    }

    #[test]
    fn udp_first_fragments_promote_once_and_terminal_classification_never_changes() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        let destination = target("192.0.2.1");
        flow.begin().done_packet(&destination, 11, 0);
        flow.begin().done_packet(&destination, 13, 5);
        collector.sample(60);
        assert_eq!(totals(&collector), (0, 0, 0, 0));
        flow.classify_target(epoch, &destination, Some("video.youtube.com"), "QuIc");
        flow.begin().done_packet(&destination, 17, 7);
        flow.classify_target(epoch, &destination, Some("wrong.example.com"), "dns");
        flow.classify_target(epoch, &destination, Some("wrong.example.com"), "quic");
        collector.sample(65);
        collector.sample(70);
        assert_eq!(totals(&collector), (41, 12, 1, 41));
        let inner = lock(&collector.inner);
        let rows = &inner.bucket.as_ref().unwrap().domains;
        let row = rows.values().find(|row| row.uplink_bytes > 0).unwrap();
        assert_eq!(row.domain, "video.youtube.com");
        assert_eq!(row.app_protocol, "quic");
        assert_eq!(row.target_sessions, 1);
        assert_eq!(rows.values().map(|row| row.uplink_bytes).sum::<u64>(), 41);
    }

    #[tokio::test(start_paused = true)]
    async fn unclassified_udp_pending_window_has_packet_byte_and_time_limits() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        let packets = target("192.0.2.1");
        for _ in 0..9 {
            flow.begin().done_packet(&packets, 10, 0);
        }
        flow.classify_target(epoch, &packets, None, "quic");
        let bytes = target("192.0.2.2");
        flow.begin()
            .done_packet(&bytes, PENDING_BYTES, PENDING_BYTES);
        flow.classify_target(epoch, &bytes, None, "quic");
        let expired = target("192.0.2.3");
        flow.begin().done_packet(&expired, 1000, 2000);
        tokio::time::advance(PENDING_AGE + Duration::from_millis(1)).await;
        collector.sample(60);
        flow.classify_target(epoch, &expired, None, "quic");
        flow.begin().done_packet(&expired, 7, 0);
        collector.sample(65);
        assert_eq!(totals(&collector), (80 + PENDING_BYTES + 7, 0, 1, 0));
        assert_eq!(collector.status().dropped_entries, 0);
        let inner = lock(&collector.inner);
        assert_eq!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .map(|row| row.uplink_bytes)
                .sum::<u64>(),
            80 + PENDING_BYTES + 7
        );
    }

    #[test]
    fn reconnect_discards_unclassified_pending_and_counts_first_web_association_once() {
        let (collector, epoch) = collector(default_config(true));
        let flow = collector.register(metadata("udp")).unwrap();
        let destination = target("192.0.2.1");
        flow.begin().done_packet(&destination, 1000, 2000);
        collector.pause(epoch);
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        flow.classify_target(epoch, &destination, Some("wrong.example.com"), "quic");
        collector.sample(60);
        assert_eq!(totals(&collector), (0, 0, 0, 0));
        flow.classify_target(resumed, &destination, Some("youtube.com"), "quic");
        flow.begin().done_packet(&destination, 7, 9);
        collector.sample(65);
        assert_eq!(totals(&collector), (7, 9, 1, 7));
        collector.pause(resumed);
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        flow.begin().done_packet(&destination, 3, 4);
        collector.sample(120);
        assert_eq!(totals(&collector), (3, 4, 0, 3));
        let inner = lock(&collector.inner);
        assert_eq!(
            inner
                .bucket
                .as_ref()
                .unwrap()
                .domains
                .values()
                .map(|row| row.target_sessions)
                .sum::<u64>(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn excluded_and_expired_candidates_release_limits_for_later_web_targets() {
        let mut config = default_config(true);
        config.max_udp_targets = 1;
        config.max_udp_targets_per_session = 1;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        let baseline = collector.memory.load(Ordering::Relaxed);
        for i in 0..128 {
            let dns = target(&format!("192.0.2.{i}"));
            flow.begin().done_packet(&dns, 100, 200);
            assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 1);
            flow.classify_target(epoch, &dns, None, "dns");
            assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
            assert_eq!(collector.memory.load(Ordering::Relaxed), baseline);
        }
        let unknown = target("192.0.2.200");
        flow.begin().done_packet(&unknown, 300, 400);
        tokio::time::advance(PENDING_AGE + Duration::from_millis(1)).await;
        collector.sample(60);
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
        assert_eq!(collector.memory.load(Ordering::Relaxed), baseline);
        let web = target("192.0.2.201");
        flow.classify_target(epoch, &web, Some("youtube.com"), "quic");
        flow.begin().done_packet(&web, 7, 9);
        collector.sample(65);
        assert_eq!(totals(&collector), (7, 9, 1, 7));
    }

    #[test]
    fn pending_pool_exhaustion_keeps_known_web_capacity_and_charges_live_storage() {
        let mut config = default_config(true);
        config.memory_max_bytes = 1 << 20;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        let mut leases = 0;
        while flow.try_reserve_pending_storage(1024) {
            leases += 1;
        }
        assert!(leases > 0);
        let pending = collector.pending_memory.load(Ordering::Relaxed);
        assert!(pending <= (1 << 18));
        assert!(pending > (1 << 18) - 1024);
        // An excluded wrapper is still allocated: discard cannot release its
        // storage lease or pretend to recover the pending memory sub-budget.
        let unknown = target("192.0.2.1");
        flow.discard_target(epoch, &unknown);
        assert_eq!(collector.pending_memory.load(Ordering::Relaxed), pending);
        let tcp = collector.register(metadata("tcp")).unwrap();
        tcp.begin().done(3, 4);
        // Already identified QUIC can use the independent confirmed-target pool.
        flow.classify_target(epoch, &unknown, Some("youtube.com"), "quic");
        flow.begin().done_packet(&unknown, 7, 9);
        collector.sample(60);
        assert_eq!(totals(&collector), (10, 13, 2, 10));
        for _ in 0..leases {
            flow.release_pending_storage(1024);
        }
        assert_eq!(collector.pending_memory.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn pending_target_pool_does_not_consume_confirmed_target_slots() {
        let mut config = default_config(true);
        config.max_udp_targets = 1;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        flow.begin().done_packet(&target("192.0.2.1"), 100, 200);
        flow.begin().done_packet(&target("192.0.2.2"), 300, 400);
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 1);
        assert_eq!(collector.status().udp_targets, 0);
        let web = target("192.0.2.3");
        flow.classify_target(epoch, &web, Some("youtube.com"), "quic");
        flow.begin().done_packet(&web, 7, 9);
        collector.sample(60);
        assert_eq!(totals(&collector), (7, 9, 1, 7));
        assert!(collector.status().dropped_by_reason["target_limit"] > 0);
        collector.pause(epoch);
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        let candidate = target("192.0.2.4");
        flow.begin().done_packet(&candidate, 10, 20);
        flow.discard_target(epoch, &candidate);
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 1);
        flow.discard_target(resumed, &candidate);
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn confirmed_web_overflow_promotes_fragments_to_unknown_without_pending_reregistration() {
        let mut config = default_config(true);
        config.max_udp_targets_per_session = 1;
        let (collector, epoch) = collector(config);
        let flow = collector.register(metadata("udp")).unwrap();
        flow.classify_target(
            epoch,
            &target("192.0.2.1"),
            Some("first.example.com"),
            "quic",
        );
        let overflow = target("192.0.2.2");
        flow.begin().done_packet(&overflow, 11, 0);
        flow.begin().done_packet(&overflow, 13, 5);
        assert!(flow.classify_target(epoch, &overflow, Some("second.example.com"), "quic"));
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
        for _ in 0..10 {
            let token = flow.begin_token();
            flow.finish_web_token(token, 7, 9, Some(&overflow));
        }
        collector.sample(60);
        assert_eq!(totals(&collector), (94, 95, 1, 0));
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
        assert_eq!(collector.status().udp_targets, 1);
        let inner = lock(&collector.inner);
        let bucket = inner.bucket.as_ref().unwrap();
        assert!(
            bucket
                .domains
                .values()
                .filter(|row| row.uplink_bytes > 0)
                .all(|row| row.domain == UNKNOWN)
        );
        assert_eq!(
            bucket
                .domains
                .values()
                .map(|row| row.uplink_bytes)
                .sum::<u64>(),
            94
        );
        drop(inner);
        let old = flow.begin_token();
        collector.pause(epoch);
        let resumed = collector.begin_session();
        collector.configure(resumed, Some(&default_config(true)));
        assert!(!flow.classify_target(epoch, &overflow, Some("stale.example.com"), "quic"));
        flow.finish_web_token(old, 1000, 2000, Some(&overflow));
        let token = flow.begin_token();
        flow.finish_web_token(token, 3, 4, Some(&overflow));
        collector.sample(120);
        assert_eq!(totals(&collector), (3, 4, 0, 0));
        assert_eq!(collector.pending_targets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn missing_sniff_domain_uses_destination_only_when_it_is_a_hostname() {
        let (collector, epoch) = collector(default_config(true));
        for network in ["tcp", "udp"] {
            for host in ["192.0.2.1", "destination.example.com"] {
                let destination = target(host);
                let mut meta = metadata(network);
                meta.domain.clear();
                meta.destination = Some(destination.clone());
                meta.sniff_destination = Some(destination.clone());
                meta.app_protocol = if network == "tcp" { "tls" } else { "quic" }.into();
                let flow = collector.register(meta).unwrap();
                if network == "tcp" {
                    flow.begin().done(7, 9);
                } else {
                    flow.classify_target(epoch, &destination, None, "quic");
                    flow.begin().done_packet(&destination, 7, 9);
                }
            }
        }
        collector.sample(60);
        assert_eq!(totals(&collector), (28, 36, 4, 14));
        let inner = lock(&collector.inner);
        for row in inner
            .bucket
            .as_ref()
            .unwrap()
            .domains
            .values()
            .filter(|row| row.uplink_bytes > 0)
        {
            assert_eq!(row.uplink_bytes, 7);
            assert_eq!(
                row.domain_source,
                if row.domain == UNKNOWN {
                    UNKNOWN
                } else {
                    "destination"
                }
            );
            assert!(matches!(row.app_protocol.as_str(), "tls" | "quic"));
        }
    }

    #[test]
    fn recognized_web_without_a_hostname_still_retains_its_protocol() {
        let (collector, epoch) = collector(default_config(true));
        let mut tcp = metadata("tcp");
        tcp.domain.clear();
        tcp.destination = Some(target("192.0.2.1"));
        let tcp = collector.register(tcp).unwrap();
        tcp.begin().done(10, 20);
        let udp = collector.register(metadata("udp")).unwrap();
        let destination = target("192.0.2.2");
        udp.classify_target(epoch, &destination, None, "quic");
        udp.begin().done_packet(&destination, 30, 40);
        collector.sample(60);
        assert_eq!(totals(&collector), (40, 60, 2, 0));
        let inner = lock(&collector.inner);
        let rows = &inner.bucket.as_ref().unwrap().domains;
        assert!(rows.values().any(|row| row.domain == UNKNOWN
            && row.app_protocol == "tls"
            && row.uplink_bytes == 10));
        assert!(rows.values().any(|row| row.domain == UNKNOWN
            && row.app_protocol == "quic"
            && row.uplink_bytes == 30));
    }
}
