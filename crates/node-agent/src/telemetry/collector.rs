//! Host probes run on a fixed set of dedicated threads. In particular, a hung
//! filesystem probe cannot occupy a Tokio worker, delay heartbeats, or create an
//! unbounded stream of replacement blocking tasks after reconnects.

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

#[cfg(all(not(target_os = "linux"), not(windows)))]
use sysinfo::Networks;
use sysinfo::{CpuRefreshKind, RefreshKind, System};
#[cfg(not(target_os = "linux"))]
use sysinfo::{DiskRefreshKind, Disks, MemoryRefreshKind};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const DYNAMIC_INTERVAL: Duration = Duration::from_secs(3);
const HARDWARE_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DISK_INTERVAL: Duration = Duration::from_secs(60);
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DYNAMIC_MAX_AGE: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostSnapshot {
    /// The actual dynamic probe completion time, independent of sender cadence.
    pub collected_at: Option<Instant>,
    pub cpu_valid: bool,
    pub memory_valid: bool,
    pub network_interfaces_valid: bool,
    pub disk_valid: bool,
    pub disk_collected_at: Option<SystemTime>,
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
    pub index: u32,
    pub counters_valid: bool,
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

#[derive(Default)]
struct Hardware {
    brand: String,
    cores: u32,
    threads: u32,
}

#[derive(Default)]
struct DiskInventory {
    usages: Vec<DiskUsage>,
    valid: bool,
    collected_at: Option<SystemTime>,
}

#[derive(Default)]
struct Cache {
    dynamic: HostSnapshot,
    hardware: Hardware,
    disks: DiskInventory,
}

#[derive(Default)]
struct Shared {
    cache: RwLock<Cache>,
    started: AtomicBool,
    dynamic_changed: Arc<Notify>,
}

/// Reuse this collector for the entire agent lifetime, including reconnects.
/// Construction performs no probes, and `collect` only copies cached results.
#[derive(Clone, Default)]
pub struct HostCollector {
    shared: Arc<Shared>,
}

impl HostCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts at most three workers, once. Pass the process/sampler lifetime
    /// token, not the token for an individual gRPC connection.
    ///
    /// Threads are deliberately detached: some OS calls cannot be interrupted.
    /// Cancellation stops scheduling new probes immediately; a stuck probe
    /// never prevents async shutdown or causes replacement workers to spawn.
    pub fn start_workers(&self, cancel: CancellationToken) -> io::Result<()> {
        if self.shared.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let worker_cancel = cancel.child_token();
        let result = (|| {
            let mut reader = None;
            let changed = Arc::clone(&self.shared.dynamic_changed);
            spawn_periodic(
                "telemetry-host",
                Arc::downgrade(&self.shared),
                worker_cancel.clone(),
                DYNAMIC_INTERVAL,
                move || {
                    read_dynamic_with_budget(
                        || reader.get_or_insert_with(DynamicReader::default).read(),
                        DYNAMIC_INTERVAL,
                    )
                },
                move |cache, dynamic| {
                    cache.dynamic = dynamic;
                    // There is one sampler. A retained permit closes the gap
                    // between reading the cache and awaiting its next update.
                    changed.notify_one();
                },
            )?;
            spawn_periodic(
                "telemetry-hardware",
                Arc::downgrade(&self.shared),
                worker_cancel.clone(),
                HARDWARE_INTERVAL,
                read_hardware,
                |cache, hardware| cache.hardware = hardware,
            )?;
            spawn_periodic(
                "telemetry-disks",
                Arc::downgrade(&self.shared),
                worker_cancel.clone(),
                DISK_INTERVAL,
                || {
                    let (usages, valid) = read_disks();
                    DiskInventory {
                        usages,
                        valid,
                        collected_at: Some(SystemTime::now()),
                    }
                },
                |cache, disks| cache.disks = disks,
            )?;
            Ok(())
        })();
        if result.is_err() {
            worker_cancel.cancel();
        }
        result
    }

    pub fn collect(&self) -> HostSnapshot {
        let cache = self
            .shared
            .cache
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let mut snapshot = cache.dynamic.clone();
        snapshot.cpu_brand.clone_from(&cache.hardware.brand);
        snapshot.cpu_cores = cache.hardware.cores;
        snapshot.cpu_threads = cache.hardware.threads;
        snapshot.disk_usages.clone_from(&cache.disks.usages);
        snapshot.disk_valid = cache.disks.valid;
        snapshot.disk_collected_at = cache.disks.collected_at;
        // A stuck dynamic probe must not make an old counter look like a valid
        // new observation. Keep the original timestamp for sender deduplication.
        if snapshot
            .collected_at
            .is_none_or(|at| at.elapsed() > DYNAMIC_MAX_AGE)
        {
            snapshot.cpu_valid = false;
            snapshot.memory_valid = false;
            snapshot.network_interfaces_valid = false;
            for interface in &mut snapshot.network_interfaces {
                interface.counters_valid = false;
            }
        }
        snapshot
    }

    /// Wakes the sole sampler as soon as new dynamic data is available. Multiple
    /// updates coalesce into one permit; the cache remains the source of truth.
    pub async fn changed(&self) {
        self.shared.dynamic_changed.notified().await;
    }
}

fn spawn_periodic<T: Send + 'static>(
    name: &str,
    shared: Weak<Shared>,
    cancel: CancellationToken,
    interval: Duration,
    mut read: impl FnMut() -> T + Send + 'static,
    publish: impl Fn(&mut Cache, T) + Send + 'static,
) -> io::Result<()> {
    thread::Builder::new().name(name.into()).spawn(move || {
        let mut next = Instant::now();
        while !cancel.is_cancelled() && shared.strong_count() > 0 {
            let result = read();
            if cancel.is_cancelled() {
                break;
            }
            let Some(cache_shared) = shared.upgrade() else {
                break;
            };
            {
                let mut cache = cache_shared
                    .cache
                    .write()
                    .unwrap_or_else(|error| error.into_inner());
                publish(&mut cache, result);
            }
            drop(cache_shared);
            // Skip missed intervals; do not burst after a slow OS call.
            next += interval;
            if next <= Instant::now() {
                next = Instant::now() + interval;
            }
            while !cancel.is_cancelled() && shared.strong_count() > 0 {
                let wait = next.saturating_duration_since(Instant::now());
                if wait.is_zero() {
                    break;
                }
                thread::sleep(wait.min(CANCEL_POLL_INTERVAL));
            }
        }
    })?;
    Ok(())
}

fn read_hardware() -> Hardware {
    let system =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));
    Hardware {
        brand: system
            .cpus()
            .iter()
            .map(|cpu| {
                let brand = cpu.brand().trim();
                if brand.is_empty() {
                    cpu.vendor_id().trim()
                } else {
                    brand
                }
            })
            .find(|brand| !brand.is_empty())
            .unwrap_or_default()
            .to_owned(),
        cores: System::physical_core_count()
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or_default(),
        threads: u32::try_from(system.cpus().len()).unwrap_or(u32::MAX),
    }
}

fn read_dynamic_with_budget(read: impl FnOnce() -> HostSnapshot, budget: Duration) -> HostSnapshot {
    let started_at = Instant::now();
    let snapshot = read();
    if started_at.elapsed() >= budget {
        // An OS call may ignore cancellation. Discard late dynamic readings so
        // CPU values read before a stalled memory/network probe cannot acquire
        // its later completion timestamp. The sampler still emits an invalid
        // heartbeat, and the independent hardware/disk caches remain available.
        return HostSnapshot::default();
    }
    snapshot
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct DynamicReader {
    cpu: Option<CpuCounters>,
}

#[cfg(target_os = "linux")]
impl DynamicReader {
    fn read(&mut self) -> HostSnapshot {
        let mut snapshot = HostSnapshot::default();
        let cpu = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|contents| parse_cpu(&contents));
        if let Some(percent) = cpu
            .zip(self.cpu)
            .and_then(|(current, previous)| current.percent_since(previous))
        {
            snapshot.cpu_percent = percent;
            snapshot.cpu_valid = true;
        }
        // A failed read resets the baseline instead of silently reusing counters.
        self.cpu = cpu;
        if let Some((used, total)) = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|contents| parse_memory(&contents))
        {
            snapshot.memory_used_bytes = used;
            snapshot.memory_total_bytes = total;
            snapshot.memory_valid = true;
        }
        (
            snapshot.network_interfaces,
            snapshot.network_interfaces_valid,
        ) = read_networks();
        snapshot.collected_at = Some(Instant::now());
        snapshot
    }
}

#[cfg(windows)]
#[derive(Default)]
struct DynamicReader {
    cpu: Option<CpuCounters>,
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
#[derive(Default)]
struct DynamicReader {
    system: System,
    cpu_primed: bool,
}

#[cfg(not(target_os = "linux"))]
impl DynamicReader {
    fn read(&mut self) -> HostSnapshot {
        #[cfg(windows)]
        let percent = {
            let cpu = read_windows_cpu();
            let percent = cpu
                .zip(self.cpu)
                .and_then(|(current, previous)| current.percent_since(previous));
            self.cpu = cpu;
            percent
        };
        #[cfg(not(windows))]
        let percent = {
            self.system.refresh_cpu_usage();
            let percent = f64::from(self.system.global_cpu_usage());
            let valid = self.cpu_primed
                && !self.system.cpus().is_empty()
                && percent.is_finite()
                && (0.0..=100.0).contains(&percent);
            self.cpu_primed = !self.system.cpus().is_empty();
            valid.then_some(percent)
        };
        // A fresh memory object prevents an unsuccessful refresh from retaining
        // the previous successful memory reading.
        let memory = System::new_with_specifics(
            RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
        );
        let (network_interfaces, network_interfaces_valid) = read_networks();
        HostSnapshot {
            collected_at: Some(Instant::now()),
            cpu_percent: percent.unwrap_or_default(),
            cpu_valid: percent.is_some(),
            memory_valid: memory.total_memory() > 0
                && memory.used_memory() <= memory.total_memory(),
            memory_used_bytes: memory.used_memory(),
            memory_total_bytes: memory.total_memory(),
            network_interfaces,
            network_interfaces_valid,
            ..HostSnapshot::default()
        }
    }
}

fn interface_addresses() -> io::Result<BTreeMap<String, NetworkInterface>> {
    let mut result = BTreeMap::<String, NetworkInterface>::new();
    for interface in if_addrs::get_if_addrs()? {
        let item = result.entry(interface.name.clone()).or_default();
        item.name = interface.name.clone();
        item.index = interface.index.unwrap_or(item.index);
        item.is_up |= interface.is_oper_up();
        item.addresses.push(match interface.addr {
            if_addrs::IfAddr::V4(addr) => format!("{}/{}", addr.ip, addr.prefixlen),
            if_addrs::IfAddr::V6(addr) => format!("{}/{}", addr.ip, addr.prefixlen),
        });
    }
    for interface in result.values_mut() {
        interface.addresses.sort();
        interface.addresses.dedup();
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn read_networks() -> (Vec<NetworkInterface>, bool) {
    // Enumerating sysfs includes interfaces with no IP address and interfaces
    // whose counters cannot be read. Neither may disappear from the inventory.
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return (Vec::new(), false);
    };
    let counters = std::fs::read_to_string("/proc/net/dev")
        .map(|contents| parse_network_counters(&contents))
        .unwrap_or_default();
    let mut addresses = interface_addresses().unwrap_or_default();
    let mut interfaces = Vec::new();
    let mut valid = true;
    for entry in entries {
        let Ok(entry) = entry else {
            valid = false;
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        let mut interface = addresses.remove(&name).unwrap_or_default();
        interface.name = name;
        interface.index = std::fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(interface.index);
        if interface.index == 0 {
            valid = false;
        }
        interface.hardware = std::fs::read_to_string(entry.path().join("address"))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        if interface.hardware == "00:00:00:00:00:00" {
            interface.hardware.clear();
        }
        if let Some(flags) = std::fs::read_to_string(entry.path().join("flags"))
            .ok()
            .and_then(|value| u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok())
        {
            // Match Go net.FlagUp (administrative state, including loopback).
            interface.is_up = flags & libc::IFF_UP as u32 != 0;
        }
        if let Some(counter) = counters.get(&interface.name) {
            interface.counters_valid = true;
            interface.rx_bytes = counter[0];
            interface.rx_packets = counter[1];
            interface.tx_bytes = counter[2];
            interface.tx_packets = counter[3];
        }
        interfaces.push(interface);
    }
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    (interfaces, valid)
}

#[cfg(windows)]
fn read_windows_cpu() -> Option<CpuCounters> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetSystemTimes;

    let (mut idle, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: all three output pointers refer to live writable FILETIMEs.
    unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.ok()?;
    let ticks =
        |value: FILETIME| u64::from(value.dwHighDateTime) << 32 | u64::from(value.dwLowDateTime);
    // Windows kernel time includes idle, just as in gopsutil's Times(false).
    let total = ticks(kernel).checked_add(ticks(user))?;
    Some(CpuCounters {
        total,
        busy: total.checked_sub(ticks(idle))?,
    })
}

#[cfg(windows)]
fn read_networks() -> (Vec<NetworkInterface>, bool) {
    use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    use windows::Win32::NetworkManagement::Ndis::NET_IF_ADMIN_STATUS_UP;

    struct Table(*mut MIB_IF_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            // SAFETY: the successful GetIfTable2 allocated this table, and this
            // guard releases it exactly once after all row references are gone.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
    let mut table = std::ptr::null_mut();
    // SAFETY: table is writable storage for the OS-owned allocation pointer.
    if unsafe { GetIfTable2(&mut table) }.is_err() || table.is_null() {
        return (Vec::new(), false);
    }
    let table = Table(table);
    // SAFETY: GetIfTable2 returns NumEntries initialized rows in its variable
    // sized allocation; the table guard outlives this slice.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    let mut addresses = interface_addresses().unwrap_or_default();
    let mut interfaces = BTreeMap::new();
    let mut valid = true;
    for row in rows {
        let name_length = row
            .Alias
            .iter()
            .position(|ch| *ch == 0)
            .unwrap_or(row.Alias.len());
        let name = String::from_utf16_lossy(&row.Alias[..name_length]);
        if name.is_empty() || row.InterfaceIndex == 0 {
            valid = false;
        }
        let mut interface = addresses.remove(&name).unwrap_or_default();
        interface.name = name.clone();
        interface.index = row.InterfaceIndex;
        interface.is_up = row.AdminStatus == NET_IF_ADMIN_STATUS_UP;
        let hardware_length = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
        interface.hardware = row.PhysicalAddress[..hardware_length]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        interface.counters_valid = true;
        interface.rx_bytes = row.InOctets;
        interface.tx_bytes = row.OutOctets;
        interface.rx_packets = row.InUcastPkts.saturating_add(row.InNUcastPkts);
        interface.tx_packets = row.OutUcastPkts.saturating_add(row.OutNUcastPkts);
        interfaces.insert(name, interface);
    }
    (interfaces.into_values().collect(), valid)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn read_networks() -> (Vec<NetworkInterface>, bool) {
    let (mut inventory, mut valid) = match interface_addresses() {
        Ok(inventory) => (inventory, true),
        Err(_) => (BTreeMap::new(), false),
    };
    #[cfg(unix)]
    match unix_interface_identities() {
        Ok(identities) => {
            for (name, (index, is_up)) in identities {
                let interface = inventory.entry(name.clone()).or_default();
                interface.name = name;
                interface.index = index;
                interface.is_up = is_up;
            }
        }
        Err(_) => valid = false,
    }
    // A new list avoids marking previously cached counters valid after failure.
    let counters = Networks::new_with_refreshed_list();
    for (name, data) in &counters {
        let interface = inventory.entry(name.clone()).or_default();
        interface.name.clone_from(name);
        interface.counters_valid = true;
        interface.hardware = if data.mac_address().is_unspecified() {
            String::new()
        } else {
            data.mac_address().to_string()
        };
        if interface.addresses.is_empty() {
            interface.addresses = data.ip_networks().iter().map(ToString::to_string).collect();
            interface.addresses.sort();
        }
        interface.rx_bytes = data.total_received();
        interface.tx_bytes = data.total_transmitted();
        interface.rx_packets = data.total_packets_received();
        interface.tx_packets = data.total_packets_transmitted();
    }
    if inventory.values().any(|interface| interface.index == 0) {
        valid = false;
    }
    (inventory.into_values().collect(), valid)
}

// Build this helper on Linux in tests as well, while keeping Linux's production
// sysfs inventory unchanged. getifaddrs includes link records without IP addresses.
#[cfg(all(unix, any(not(target_os = "linux"), test)))]
fn unix_interface_identities() -> io::Result<BTreeMap<String, (u32, bool)>> {
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces {
        fn drop(&mut self) {
            // SAFETY: getifaddrs allocated this list; this guard frees it once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut list = std::ptr::null_mut();
    // SAFETY: list is writable storage for the OS allocation's head pointer.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = Interfaces(list);
    // SAFETY: successful getifaddrs returns a valid, terminated linked list;
    // the guard owns every record/name for the duration of this traversal.
    unsafe { unix_interface_identities_from_list(list.0) }
}

#[cfg(all(unix, any(not(target_os = "linux"), test)))]
unsafe fn unix_interface_identities_from_list(
    mut current: *const libc::ifaddrs,
) -> io::Result<BTreeMap<String, (u32, bool)>> {
    let mut identities = BTreeMap::new();
    while !current.is_null() {
        // SAFETY: caller guarantees every linked record remains valid.
        let record = unsafe { &*current };
        if record.ifa_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "network interface has no name",
            ));
        }
        // SAFETY: getifaddrs interface names are NUL-terminated and list-owned.
        let name = unsafe { std::ffi::CStr::from_ptr(record.ifa_name) };
        // SAFETY: name points to a valid NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        identities.insert(
            name.to_string_lossy().into_owned(),
            (index, record.ifa_flags & libc::IFF_UP as u32 != 0),
        );
        current = record.ifa_next;
    }
    Ok(identities)
}

#[cfg(any(target_os = "linux", windows))]
#[derive(Clone, Copy)]
struct CpuCounters {
    total: u64,
    busy: u64,
}

#[cfg(any(target_os = "linux", windows))]
impl CpuCounters {
    fn percent_since(self, previous: Self) -> Option<f64> {
        let total = self.total.checked_sub(previous.total)?;
        let busy = self.busy.checked_sub(previous.busy)?;
        if total == 0 || busy > total {
            return None;
        }
        Some(busy as f64 / total as f64 * 100.0)
    }
}

#[cfg(target_os = "linux")]
fn parse_cpu(contents: &str) -> Option<CpuCounters> {
    let mut fields = contents.lines().next()?.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    // Guest time is already included in user/nice; count the first eight fields
    // only. Like gopsutil, idle and iowait do not count as CPU work.
    let times = fields
        .take(8)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if times.len() < 4 {
        return None;
    }
    let total = times
        .iter()
        .try_fold(0_u64, |sum, value| sum.checked_add(*value))?;
    let idle = times[3].checked_add(times.get(4).copied().unwrap_or_default())?;
    Some(CpuCounters {
        total,
        busy: total.checked_sub(idle)?,
    })
}

#[cfg(target_os = "linux")]
fn parse_memory(contents: &str) -> Option<(u64, u64)> {
    let fields = contents
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect::<BTreeMap<_, _>>();
    let read = |name| {
        let mut values = fields.get(name)?.split_whitespace();
        let value = values.next()?.parse::<u64>().ok()?;
        if values.next()? != "kB" {
            return None;
        }
        value.checked_mul(1024)
    };
    let total = read("MemTotal")?;
    if total == 0 {
        return None;
    }
    let available = if fields.contains_key("MemAvailable") {
        read("MemAvailable")?
    } else {
        read("MemFree")?
            .checked_add(read("Cached")?)?
            .checked_add(read("SReclaimable").unwrap_or_default())?
    };
    Some((total.checked_sub(available)?, total))
}

#[cfg(target_os = "linux")]
fn parse_network_counters(contents: &str) -> BTreeMap<String, [u64; 4]> {
    contents
        .lines()
        .filter_map(|line| {
            let (name, fields) = line.rsplit_once(':')?;
            let values = fields
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            if values.len() < 16 || name.trim().is_empty() {
                return None;
            }
            Some((
                name.trim().to_owned(),
                [values[0], values[1], values[8], values[9]],
            ))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn read_disks() -> (Vec<DiskUsage>, bool) {
    let read = || -> Option<Vec<(String, String)>> {
        let filesystems = std::fs::read_to_string("/proc/filesystems").ok()?;
        let mountinfo = std::fs::read_to_string("/proc/1/mountinfo")
            .or_else(|_| std::fs::read_to_string("/proc/self/mountinfo"))
            .ok()?;
        parse_mounts(&mountinfo, &filesystems)
    };
    let Some(mounts) = read() else {
        return (Vec::new(), false);
    };
    let mut valid = true;
    let mut disks = Vec::new();
    for (path, fs_type) in mounts {
        match disk_usage(&path, fs_type) {
            Some(usage) => disks.push(usage),
            None => valid = false,
        }
    }
    (disks, valid)
}

#[cfg(target_os = "linux")]
fn parse_mounts(contents: &str, filesystems: &str) -> Option<Vec<(String, String)>> {
    let filesystems = filesystems
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                [name] => Some(*name),
                ["nodev", "zfs"] => Some("zfs"),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>();
    let mut mounts = BTreeMap::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let (left, right) = line.split_once(" - ")?;
        let fields = left.split_whitespace().collect::<Vec<_>>();
        let after = right.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 || after.len() < 2 {
            return None;
        }
        let (root, path, fs_type, source) = (fields[3], fields[4], after[0], after[1]);
        if !filesystems.contains(fs_type) {
            continue;
        }
        let is_subvolume = after.get(2).is_some_and(|options| {
            options
                .split(',')
                .any(|option| option.strip_prefix("subvol=") == Some(root))
        });
        // Go's Partitions(false) skips bind mounts, while retaining btrfs subvolumes.
        if source.starts_with('/') && root != "/" && !is_subvolume {
            continue;
        }
        let path = path
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        if !path.trim().is_empty() {
            mounts.entry(path).or_insert_with(|| fs_type.to_owned());
        }
    }
    Some(mounts.into_iter().collect())
}

#[cfg(target_os = "linux")]
// The statvfs integer fields have different widths on 32-bit and 64-bit libc.
#[allow(clippy::unnecessary_cast)]
fn disk_usage(path: &str, fs_type: String) -> Option<DiskUsage> {
    let path_c = std::ffi::CString::new(path).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path_c is NUL terminated, and stat points to enough writable
    // storage. The contents are used only after statvfs reports success.
    if unsafe { libc::statvfs(path_c.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful statvfs call initialized the entire struct.
    let stat = unsafe { stat.assume_init() };
    let block_size = stat.f_frsize as u64;
    let total_bytes = (stat.f_blocks as u64).checked_mul(block_size)?;
    let used_bytes = (stat.f_blocks as u64)
        .checked_sub(stat.f_bfree as u64)?
        .checked_mul(block_size)?;
    if total_bytes == 0 || used_bytes > total_bytes {
        return None;
    }
    Some(DiskUsage {
        path: path.to_owned(),
        fs_type,
        used_bytes,
        total_bytes,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_disks() -> (Vec<DiskUsage>, bool) {
    let disks = Disks::new_with_refreshed_list_specifics(DiskRefreshKind::nothing().with_storage());
    // sysinfo does not expose enumeration errors. An empty result cannot safely
    // be presented as a successful zero-capacity observation on these systems.
    let mut valid = !disks.is_empty();
    let mut result = BTreeMap::new();
    for disk in &disks {
        let path = disk.mount_point().to_string_lossy().trim().to_owned();
        let total_bytes = disk.total_space();
        let available_bytes = disk.available_space();
        if path.is_empty() {
            continue;
        }
        if total_bytes == 0 || available_bytes > total_bytes {
            valid = false;
            continue;
        }
        result.entry(path.clone()).or_insert_with(|| DiskUsage {
            path,
            fs_type: disk.file_system().to_string_lossy().trim().to_owned(),
            total_bytes,
            used_bytes: total_bytes - available_bytes,
        });
    }
    (result.into_values().collect(), valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn late_dynamic_probe_cannot_timestamp_old_cpu_as_fresh() {
        let snapshot = read_dynamic_with_budget(
            || {
                // CPU is observed before an uninterruptible later OS probe.
                let mut snapshot = HostSnapshot {
                    cpu_percent: 50.0,
                    cpu_valid: true,
                    memory_valid: true,
                    network_interfaces_valid: true,
                    network_interfaces: vec![NetworkInterface {
                        counters_valid: true,
                        ..NetworkInterface::default()
                    }],
                    ..HostSnapshot::default()
                };
                thread::sleep(Duration::from_millis(10));
                snapshot.collected_at = Some(Instant::now());
                snapshot
            },
            Duration::from_millis(1),
        );
        assert_eq!(snapshot, HostSnapshot::default());

        let timely = HostSnapshot {
            collected_at: Some(Instant::now()),
            cpu_valid: true,
            cpu_percent: 25.0,
            ..HostSnapshot::default()
        };
        assert_eq!(
            read_dynamic_with_budget(|| timely.clone(), Duration::from_secs(60)),
            timely
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_link_only_interfaces_keep_native_index_and_administrative_state() {
        let native = unix_interface_identities().expect("native interface inventory");
        let (name, (expected_index, _)) = native
            .iter()
            .find(|(name, (index, _))| name.starts_with("lo") && *index != 0)
            .expect("loopback interface has a native index");
        let name = std::ffi::CString::new(name.as_str()).unwrap();
        // SAFETY: ifaddrs is entirely raw pointers and integer flags, all of
        // which permit zero. The only populated pointer refers to name below.
        let mut record: libc::ifaddrs = unsafe { std::mem::zeroed() };
        record.ifa_name = name.as_ptr().cast_mut();
        record.ifa_flags = libc::IFF_UP as u32;
        // No IPv4/IPv6 address: if-addrs omits this record, but its interface
        // identity and administrative status must still reach telemetry.
        assert!(record.ifa_addr.is_null());
        // SAFETY: record is a terminated one-element list and name stays alive.
        let identities = unsafe { unix_interface_identities_from_list(&record) }.unwrap();
        assert_eq!(
            identities.get(name.to_str().unwrap()),
            Some(&(*expected_index, true))
        );

        // IFF_RUNNING describes operational state, not Go net.FlagUp.
        record.ifa_flags = libc::IFF_RUNNING as u32;
        // SAFETY: the same one-element list/name remain valid.
        let identities = unsafe { unix_interface_identities_from_list(&record) }.unwrap();
        assert_eq!(
            identities.get(name.to_str().unwrap()),
            Some(&(*expected_index, false))
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_missing_interface_index_remains_invalid() {
        let name = std::ffi::CString::new("acp-missing-interface-name-beyond-ifnamsiz").unwrap();
        // SAFETY: ifaddrs contains only raw pointers and integer flags.
        let mut record: libc::ifaddrs = unsafe { std::mem::zeroed() };
        record.ifa_name = name.as_ptr().cast_mut();
        // SAFETY: this is a terminated one-element list with a live name.
        let identities = unsafe { unix_interface_identities_from_list(&record) }.unwrap();
        // The caller's existing index==0 validation must reject an interface
        // that disappeared or whose native identity cannot be obtained.
        assert_eq!(identities.get(name.to_str().unwrap()), Some(&(0, false)));
    }

    #[test]
    fn empty_or_stale_cache_never_claims_valid_zero_readings() {
        let collector = HostCollector::new();
        let snapshot = collector.collect();
        assert_eq!(snapshot, HostSnapshot::default());
        let at = Instant::now() - DYNAMIC_MAX_AGE - Duration::from_secs(1);
        collector.shared.cache.write().unwrap().dynamic = HostSnapshot {
            collected_at: Some(at),
            cpu_valid: true,
            memory_valid: true,
            network_interfaces_valid: true,
            network_interfaces: vec![NetworkInterface {
                counters_valid: true,
                ..NetworkInterface::default()
            }],
            ..HostSnapshot::default()
        };
        let stale = collector.collect();
        assert_eq!(stale.collected_at, Some(at));
        assert!(!stale.cpu_valid && !stale.memory_valid && !stale.network_interfaces_valid);
        assert!(!stale.network_interfaces[0].counters_valid);
    }

    #[test]
    fn slow_disk_worker_does_not_block_dynamic_cache_or_cancellation() {
        let collector = HostCollector::new();
        let cancel = CancellationToken::new();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        spawn_periodic(
            "test-slow-disk",
            Arc::downgrade(&collector.shared),
            cancel.clone(),
            DISK_INTERVAL,
            move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                finished_tx.send(()).unwrap();
                DiskInventory {
                    valid: true,
                    collected_at: Some(SystemTime::now()),
                    ..DiskInventory::default()
                }
            },
            |cache, disks| cache.disks = disks,
        )
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (dynamic_tx, dynamic_rx) = mpsc::sync_channel(1);
        spawn_periodic(
            "test-dynamic",
            Arc::downgrade(&collector.shared),
            cancel.clone(),
            DYNAMIC_INTERVAL,
            HostSnapshot::default,
            move |cache, mut snapshot| {
                snapshot.collected_at = Some(Instant::now());
                snapshot.memory_valid = true;
                cache.dynamic = snapshot;
                dynamic_tx.send(()).unwrap();
            },
        )
        .unwrap();
        dynamic_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let snapshot = collector.collect();
        assert!(snapshot.memory_valid);
        assert!(!snapshot.disk_valid);
        assert!(snapshot.disk_collected_at.is_none());
        cancel.cancel();
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // Cancellation discards a late probe; it cannot publish a false refresh.
        assert!(collector.collect().disk_collected_at.is_none());
    }

    #[test]
    fn disk_failure_replaces_previous_valid_inventory_with_failure_timestamp() {
        let collector = HostCollector::new();
        let initial_at = SystemTime::now();
        collector.shared.cache.write().unwrap().disks = DiskInventory {
            usages: vec![DiskUsage {
                path: "/".into(),
                total_bytes: 10,
                used_bytes: 5,
                fs_type: "ext4".into(),
            }],
            valid: true,
            collected_at: Some(initial_at),
        };
        assert!(collector.collect().disk_valid);
        let failed_at = initial_at + Duration::from_secs(60);
        collector.shared.cache.write().unwrap().disks = DiskInventory {
            valid: false,
            collected_at: Some(failed_at),
            ..DiskInventory::default()
        };
        let failed = collector.collect();
        assert!(!failed.disk_valid);
        assert_eq!(failed.disk_collected_at, Some(failed_at));
        assert!(failed.disk_usages.is_empty());
    }

    #[test]
    fn worker_cancellation_interrupts_the_sixty_second_wait() {
        struct Finished(mpsc::SyncSender<()>);
        impl Drop for Finished {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let collector = HostCollector::new();
        let cancel = CancellationToken::new();
        let (published_tx, published_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let finished = Finished(finished_tx);
        spawn_periodic(
            "test-cancel-disk",
            Arc::downgrade(&collector.shared),
            cancel.clone(),
            DISK_INTERVAL,
            move || {
                let _keep_guard_alive = &finished;
            },
            move |_, ()| published_tx.send(()).unwrap(),
        )
        .unwrap();
        published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        cancel.cancel();
        finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn disk_worker_refreshes_at_its_own_interval() {
        let collector = HostCollector::new();
        let cancel = CancellationToken::new();
        let (published_tx, published_rx) = mpsc::sync_channel(4);
        spawn_periodic(
            "test-disk-cadence",
            Arc::downgrade(&collector.shared),
            cancel.clone(),
            Duration::from_millis(20),
            || DiskInventory {
                usages: vec![DiskUsage {
                    path: "/".into(),
                    used_bytes: 1,
                    total_bytes: 2,
                    fs_type: "ext4".into(),
                }],
                valid: true,
                collected_at: Some(SystemTime::now()),
            },
            move |cache, disks| {
                let at = disks.collected_at;
                cache.disks = disks;
                published_tx.send(at).unwrap();
            },
        )
        .unwrap();
        let first = published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        cancel.cancel();
        assert!(second > first);
        let snapshot = collector.collect();
        assert!(snapshot.disk_valid);
        assert!(snapshot.disk_collected_at >= second);
        assert_eq!(snapshot.disk_usages.len(), 1);
        assert!(!snapshot.memory_valid);
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn real_network_inventory_contains_loopback_and_indices() {
        let (interfaces, valid) = read_networks();
        assert!(valid);
        assert!(!interfaces.is_empty());
        assert!(interfaces.iter().all(|interface| interface.index > 0));
        assert!(
            interfaces
                .windows(2)
                .all(|items| items[0].name <= items[1].name)
        );
        assert!(interfaces.iter().any(|interface| {
            interface
                .addresses
                .iter()
                .any(|address| address.starts_with("127.") || address.starts_with("::1/"))
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cpu_rejects_malformed_and_reset_counters() {
        assert!(parse_cpu("cpu broken 1 2 3").is_none());
        assert!(parse_cpu("cpu0 1 2 3 4").is_none());
        let first = parse_cpu("cpu 10 0 10 70 10 0 0 0 999 999").unwrap();
        let second = parse_cpu("cpu 20 0 20 140 20 0 0 0 999 999").unwrap();
        assert_eq!(second.percent_since(first), Some(20.0));
        assert!(first.percent_since(second).is_none());
        assert!(first.percent_since(first).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_memory_distinguishes_valid_empty_usage_from_probe_failure() {
        assert_eq!(
            parse_memory("MemTotal: 100 kB\nMemAvailable: 100 kB"),
            Some((0, 102400))
        );
        assert_eq!(
            parse_memory("MemTotal: 100 kB\nMemAvailable: 30 kB"),
            Some((71680, 102400))
        );
        assert!(parse_memory("MemTotal: 100 kB").is_none());
        assert!(parse_memory("MemTotal: 100 kB\nMemAvailable: bad kB").is_none());
        assert!(parse_memory("MemTotal: 0 kB\nMemAvailable: 0 kB").is_none());
        assert!(parse_memory("MemTotal: 100 kB\nMemAvailable: 101 kB").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_network_invalid_counter_rows_stay_absent() {
        let counters = parse_network_counters(
            "Inter-| Receive\n eth0: 10 2 0 0 0 0 0 0 20 3 0 0 0 0 0 0\n broken: 1 bad\n zero: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
        );
        assert_eq!(counters["eth0"], [10, 2, 20, 3]);
        assert_eq!(counters["zero"], [0, 0, 0, 0]);
        assert!(!counters.contains_key("broken"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disks_match_physical_filesystems_and_skip_bind_mounts() {
        let mounts = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 0 8:1 /etc /etc rw - ext4 /dev/sda1 rw\n3 0 0:1 / /proc rw - proc proc rw\n4 0 8:2 /@home /home rw - btrfs /dev/sdb1 rw,subvol=/@home\n5 0 8:3 / /space\\040dir rw - zfs pool rw";
        assert_eq!(
            parse_mounts(mounts, "ext4\nbtrfs\nnodev proc\nnodev zfs").unwrap(),
            vec![
                ("/".into(), "ext4".into()),
                ("/home".into(), "btrfs".into()),
                ("/space dir".into(), "zfs".into())
            ]
        );
        assert!(parse_mounts("broken", "ext4").is_none());
        assert!(
            disk_usage(
                "/definitely-not-an-existing-mount-telemetry-test",
                "ext4".into()
            )
            .is_none()
        );
    }
}
