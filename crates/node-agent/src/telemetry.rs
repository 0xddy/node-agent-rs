//! Host telemetry collection and the ACP telemetry stream.
//!
//! The protobuf keeps the historical `sing_box_state` spelling even though the
//! embedded data plane is shoes. Collection order, sorting, the immediate first
//! frame, and the 30-second cadence mirror the Go agent.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acp_proto::telemetry_service_client::TelemetryServiceClient;
use acp_proto::{DiskUsageTelemetry, NetworkInterfaceTelemetry, TelemetrySnapshot};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::policy::PolicyState;
use crate::runtime::{ConnectionStats, NodeRuntime};
use crate::session::{SHUTDOWN_GRACE_PERIOD, SessionAuthenticator, SessionError};

pub const TELEMETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostSnapshot {
    pub cpu_percent: f64,
    pub cpu_brand: String,
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub network_interfaces: Vec<NetworkInterface>,
    pub disk_usages: Vec<DiskUsage>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInterface {
    pub name: String,
    pub hardware: String,
    pub addresses: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub is_up: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskUsage {
    pub path: String,
    pub fs_type: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// Reusable collector. Keeping one `System` is important because CPU usage is a
/// delta; recreating it for every frame would make every sample a first sample.
pub struct HostCollector {
    system: System,
    networks: Networks,
    disks: Disks,
}

impl Default for HostCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCollector {
    pub fn new() -> Self {
        let refresh = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything());
        Self {
            system: System::new_with_specifics(refresh),
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
        }
    }

    pub fn collect(&mut self) -> HostSnapshot {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.networks.refresh(true);
        self.disks.refresh(true);

        let cpu_brand = self
            .system
            .cpus()
            .iter()
            .map(|cpu| cpu.brand().trim())
            .find(|brand| !brand.is_empty())
            .unwrap_or_default()
            .to_string();
        let cpu_cores = System::physical_core_count()
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or_default();
        let cpu_threads = u32::try_from(self.system.cpus().len()).unwrap_or(u32::MAX);

        HostSnapshot {
            cpu_percent: f64::from(self.system.global_cpu_usage()),
            cpu_brand,
            cpu_cores,
            cpu_threads,
            memory_used_bytes: self.system.used_memory(),
            memory_total_bytes: self.system.total_memory(),
            network_interfaces: collect_network_interfaces(&self.networks),
            disk_usages: collect_disk_usages(&self.disks),
        }
    }
}

fn collect_network_interfaces(networks: &Networks) -> Vec<NetworkInterface> {
    let mut status = BTreeMap::<String, bool>::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let is_up = interface.is_oper_up();
            status
                .entry(interface.name)
                .and_modify(|current| *current |= is_up)
                .or_insert(is_up);
        }
    }

    let mut interfaces = networks
        .iter()
        .map(|(name, data)| {
            let mut addresses = data
                .ip_networks()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            addresses.sort();
            NetworkInterface {
                name: name.clone(),
                hardware: if data.mac_address().is_unspecified() {
                    String::new()
                } else {
                    data.mac_address().to_string()
                },
                addresses,
                rx_bytes: data.total_received(),
                tx_bytes: data.total_transmitted(),
                rx_packets: data.total_packets_received(),
                tx_packets: data.total_packets_transmitted(),
                is_up: status.get(name).copied().unwrap_or(false),
            }
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    interfaces
}

fn collect_disk_usages(disks: &Disks) -> Vec<DiskUsage> {
    let mut seen = BTreeSet::new();
    let mut usages = Vec::new();
    for disk in disks {
        let path = disk.mount_point().to_string_lossy().trim().to_string();
        let total_bytes = disk.total_space();
        if path.is_empty() || total_bytes == 0 || !seen.insert(path.clone()) {
            continue;
        }
        usages.push(DiskUsage {
            path,
            fs_type: disk.file_system().to_string_lossy().trim().to_string(),
            used_bytes: total_bytes.saturating_sub(disk.available_space()),
            total_bytes,
        });
    }
    usages.sort_by(|left, right| left.path.cmp(&right.path));
    usages
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
        cpu_brand: host.cpu_brand,
        cpu_cores: host.cpu_cores,
        cpu_threads: host.cpu_threads,
        memory_used_bytes: host.memory_used_bytes,
        memory_total_bytes: host.memory_total_bytes,
        active_connections: stats.active_connections,
        online_users: stats.online_users,
        sing_box_state: if maintenance {
            "maintenance"
        } else {
            "running"
        }
        .to_string(),
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
            })
            .collect(),
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
    }
}

/// Runs one authenticated client-streaming telemetry RPC. A frame is produced
/// immediately, then every 30 seconds. The session layer reconnects this runner
/// after transport failures.
pub async fn run_telemetry_stream(
    cancel: CancellationToken,
    channel: Channel,
    authenticator: SessionAuthenticator,
    machine_id: String,
    node_id: String,
    policy: Arc<PolicyState>,
    runtime: Arc<dyn NodeRuntime>,
) -> Result<(), SessionError> {
    let (sender, receiver) = mpsc::channel(1);
    let producer_cancel = cancel.child_token();
    let producer_token = producer_cancel.clone();
    let producer = tokio::spawn(async move {
        produce_snapshots(
            producer_token,
            sender,
            machine_id,
            node_id,
            policy,
            runtime,
            HostCollector::new(),
        )
        .await
    });

    let mut client = TelemetryServiceClient::new(authenticator.intercepted_channel(channel));
    let response = client.telemetry_stream(ReceiverStream::new(receiver));
    tokio::pin!(response);

    tokio::select! {
        result = &mut response => {
            producer_cancel.cancel();
            let producer_result = producer.await.map_err(|error| SessionError::Task {
                name: "telemetry producer".to_string(),
                message: error.to_string(),
            })?;
            producer_result?;
            match result {
                Err(status) => Err(SessionError::Rpc(status)),
                Ok(_) if cancel.is_cancelled() => Ok(()),
                Ok(_) => Err(SessionError::CriticalStreamEnded("telemetry stream closed".into())),
            }
        }
        () = cancel.cancelled() => {
            producer_cancel.cancel();
            producer.await.map_err(|error| SessionError::Task {
                name: "telemetry producer".to_string(),
                message: error.to_string(),
            })??;
            let _ = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, &mut response).await;
            Ok(())
        }
    }
}

async fn produce_snapshots(
    cancel: CancellationToken,
    sender: mpsc::Sender<TelemetrySnapshot>,
    machine_id: String,
    node_id: String,
    policy: Arc<PolicyState>,
    runtime: Arc<dyn NodeRuntime>,
    mut collector: HostCollector,
) -> Result<(), SessionError> {
    let mut interval = tokio::time::interval(TELEMETRY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let host = collector.collect();
                let stats = runtime.connection_stats(&node_id);
                let snapshot = build_snapshot(
                    &machine_id,
                    unix_now(),
                    host,
                    stats,
                    policy.maintenance(),
                );
                if sender.send(snapshot).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_mapping_preserves_every_wire_field() {
        let host = HostSnapshot {
            cpu_percent: 12.5,
            cpu_brand: "cpu".into(),
            cpu_cores: 4,
            cpu_threads: 8,
            memory_used_bytes: 10,
            memory_total_bytes: 20,
            network_interfaces: vec![NetworkInterface {
                name: "eth0".into(),
                hardware: "00:11:22:33:44:55".into(),
                addresses: vec!["10.0.0.1/24".into()],
                rx_bytes: 1,
                tx_bytes: 2,
                rx_packets: 3,
                tx_packets: 4,
                is_up: true,
            }],
            disk_usages: vec![DiskUsage {
                path: "/".into(),
                fs_type: "ext4".into(),
                used_bytes: 30,
                total_bytes: 40,
            }],
        };
        let snapshot = build_snapshot(
            "machine",
            123,
            host,
            ConnectionStats {
                active_connections: 5,
                online_users: 6,
            },
            true,
        );
        assert_eq!(snapshot.machine_id, "machine");
        assert_eq!(snapshot.timestamp_unix, 123);
        assert_eq!(snapshot.cpu_percent, 12.5);
        assert_eq!(snapshot.cpu_brand, "cpu");
        assert_eq!((snapshot.cpu_cores, snapshot.cpu_threads), (4, 8));
        assert_eq!(
            (snapshot.memory_used_bytes, snapshot.memory_total_bytes),
            (10, 20)
        );
        assert_eq!((snapshot.active_connections, snapshot.online_users), (5, 6));
        assert_eq!(snapshot.sing_box_state, "maintenance");
        assert_eq!(snapshot.network_interfaces.len(), 1);
        assert_eq!(snapshot.network_interfaces[0].addresses, ["10.0.0.1/24"]);
        assert!(snapshot.network_interfaces[0].is_up);
        assert_eq!(snapshot.disk_usages.len(), 1);
        assert_eq!(snapshot.disk_usages[0].fstype, "ext4");
    }

    #[test]
    fn running_state_uses_the_historical_proto_value() {
        let snapshot = build_snapshot(
            "machine",
            1,
            HostSnapshot::default(),
            ConnectionStats::default(),
            false,
        );
        assert_eq!(snapshot.sing_box_state, "running");
    }

    #[test]
    fn real_collection_is_sorted_and_internally_consistent() {
        let snapshot = HostCollector::new().collect();
        assert!(
            snapshot
                .network_interfaces
                .windows(2)
                .all(|items| items[0].name <= items[1].name)
        );
        assert!(snapshot.network_interfaces.iter().all(|item| {
            item.addresses
                .windows(2)
                .all(|values| values[0] <= values[1])
        }));
        assert!(
            snapshot
                .disk_usages
                .windows(2)
                .all(|items| items[0].path <= items[1].path)
        );
        assert!(
            snapshot
                .disk_usages
                .iter()
                .all(|item| item.used_bytes <= item.total_bytes)
        );
    }
}
