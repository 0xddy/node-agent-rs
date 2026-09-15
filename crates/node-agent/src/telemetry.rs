//! Process-lifetime sampling with independent, latest-only telemetry delivery.

mod collector;
mod stream;

pub use collector::{DiskUsage, HostCollector, HostSnapshot, NetworkInterface};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::{DiskUsageTelemetry, NetworkInterfaceTelemetry, TelemetrySnapshot};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::policy::PolicyState;
use crate::runtime::{ConnectionStats, NodeRuntime};

pub const TELEMETRY_INTERVAL: Duration = Duration::from_secs(3);
pub const TELEMETRY_SEND_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_SAMPLE_AGE: Duration = Duration::from_secs(6);

/// Created once at startup, outside the authenticated session loop.
pub struct TelemetryReporter {
    machine_id: String,
    node_id: String,
    policy: Arc<PolicyState>,
    started_at: Instant,
    instance_id: String,
    sequence: AtomicU64,
    latest: watch::Sender<Option<Arc<TelemetrySnapshot>>>,
    analysis: OnceLock<Arc<crate::analysis::Collector>>,
}

impl TelemetryReporter {
    pub fn new(machine_id: String, node_id: String, policy: Arc<PolicyState>) -> Self {
        let (latest, _) = watch::channel(None);
        Self {
            machine_id,
            node_id,
            policy,
            started_at: Instant::now(),
            instance_id: acp_proto::auth::new_nonce(16),
            sequence: AtomicU64::new(0),
            latest,
            analysis: OnceLock::new(),
        }
    }

    pub fn set_analysis(&self, analysis: Arc<crate::analysis::Collector>) {
        let _ = self.analysis.set(analysis);
    }

    pub fn start_sampling(
        self: Arc<Self>,
        cancel: CancellationToken,
        runtime: Arc<dyn NodeRuntime>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let workers_cancel = cancel.child_token();
            let _workers_guard = workers_cancel.clone().drop_guard();
            let collector = HostCollector::new();
            if let Err(error) = collector.start_workers(workers_cancel.clone()) {
                log::error!("start telemetry collectors: {error}");
                return;
            }
            let mut interval = tokio::time::interval(TELEMETRY_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_collection = None;
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = collector.changed() => {},
                    _ = interval.tick() => {},
                }
                // New counters are sampled immediately. The interval only keeps
                // invalid heartbeats alive if the OS worker stalls, avoiding a
                // second independently ticking clock delaying healthy samples.
                let mut host = collector.collect();
                let Some(collected_at) = sample_collection(&mut host, &mut last_collection) else {
                    continue;
                };
                let elapsed_ms = collected_at
                    .checked_duration_since(self.started_at.into_std())
                    .unwrap_or_default()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                let at = SystemTime::now()
                    .checked_sub(collected_at.elapsed())
                    .unwrap_or(UNIX_EPOCH);
                let timestamp_unix = unix_timestamp(at);
                // Non-blocking runtime lookup keeps reloads out of the
                // host clock measurement and never stops the sampler.
                let stats = runtime.connection_stats_snapshot(&self.node_id);
                self.publish(host, timestamp_unix, elapsed_ms, stats);
            }
            workers_cancel.cancel();
        })
    }

    fn elapsed_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn publish(
        &self,
        host: HostSnapshot,
        timestamp_unix: i64,
        elapsed_ms: u64,
        stats: Option<ConnectionStats>,
    ) {
        let stats_valid = stats.is_some();
        let mut snapshot = build_snapshot(
            &self.machine_id,
            timestamp_unix,
            host,
            stats.unwrap_or_default(),
            self.policy.maintenance(),
        );
        snapshot.agent_instance_id.clone_from(&self.instance_id);
        snapshot.sample_seq = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        snapshot.sample_elapsed_ms = elapsed_ms;
        snapshot.connection_stats_valid = stats_valid;
        // Minute aggregation may be busy normalizing many domains. Optional
        // analysis diagnostics must never delay the host telemetry heartbeat.
        snapshot.traffic_analysis = self
            .analysis
            .get()
            .and_then(|collector| collector.try_status());
        // Publication never waits, including while disconnected or flow-controlled.
        self.latest.send_replace(Some(Arc::new(snapshot)));
    }
}

/// Cached valid counters retain their original clock. If OS collection stalls,
/// continue the heartbeat with explicitly invalid metrics and fresh runtime stats.
fn sample_collection(
    host: &mut HostSnapshot,
    last_collection: &mut Option<std::time::Instant>,
) -> Option<std::time::Instant> {
    let now = std::time::Instant::now();
    let stale = host
        .collected_at
        .is_none_or(|at| now.saturating_duration_since(at) > MAX_SAMPLE_AGE);
    if stale {
        host.cpu_valid = false;
        host.cpu_percent = 0.0;
        host.memory_valid = false;
        host.memory_used_bytes = 0;
        host.memory_total_bytes = 0;
        host.network_interfaces_valid = false;
        for interface in &mut host.network_interfaces {
            interface.counters_valid = false;
            interface.rx_bytes = 0;
            interface.tx_bytes = 0;
            interface.rx_packets = 0;
            interface.tx_packets = 0;
        }
        *last_collection = Some(now);
        return Some(now);
    }
    // A probe can finish just before an invalid heartbeat but publish its cache
    // just after it. Never move the monotonic sample clock backward in that race.
    if host.collected_at <= *last_collection {
        return None;
    }
    *last_collection = host.collected_at;
    host.collected_at
}

pub fn build_snapshot(
    machine_id: &str,
    timestamp_unix: i64,
    host: HostSnapshot,
    stats: ConnectionStats,
    maintenance: bool,
) -> TelemetrySnapshot {
    TelemetrySnapshot {
        machine_id: machine_id.to_string(),
        timestamp_unix,
        cpu_percent: host.cpu_percent,
        cpu_valid: host.cpu_valid,
        cpu_brand: host.cpu_brand,
        cpu_cores: host.cpu_cores,
        cpu_threads: host.cpu_threads,
        memory_used_bytes: host.memory_used_bytes,
        memory_total_bytes: host.memory_total_bytes,
        memory_valid: host.memory_valid,
        active_connections: stats.active_connections,
        online_users: stats.online_users,
        sing_box_state: if maintenance {
            "maintenance"
        } else {
            "running"
        }
        .to_string(),
        network_interfaces_valid: host.network_interfaces_valid,
        network_interfaces: host
            .network_interfaces
            .into_iter()
            .map(|interface| NetworkInterfaceTelemetry {
                name: interface.name,
                hardware_addr: interface.hardware,
                addresses: interface.addresses,
                rx_bytes: interface.rx_bytes,
                tx_bytes: interface.tx_bytes,
                rx_packets: interface.rx_packets,
                tx_packets: interface.tx_packets,
                is_up: interface.is_up,
                interface_index: interface.index,
                counters_valid: interface.counters_valid,
            })
            .collect(),
        disk_valid: host.disk_valid,
        disk_collected_at_unix_ms: host
            .disk_collected_at
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| duration.as_millis().try_into().ok())
            .unwrap_or_default(),
        disk_usages: host
            .disk_usages
            .into_iter()
            .map(|disk| DiskUsageTelemetry {
                path: disk.path,
                fstype: disk.fs_type,
                used_bytes: disk.used_bytes,
                total_bytes: disk.total_bytes,
            })
            .collect(),
        ..Default::default()
    }
}

fn unix_timestamp(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_secs().try_into().ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
