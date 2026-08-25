//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents an ordered sequence of proxy hops, where each hop
//! can be a pool of connectors (for round-robin selection). Traffic flows through
//! each hop in sequence to reach the final destination.
//!
//! ## Design: InitialHopEntry for Hop 0
//!
//! Hop 0 is fundamentally different from subsequent hops:
//! - **Hop 0**: Creates socket AND optionally sets up protocol (if not direct)
//! - **Hops 1+**: Only set up protocol on existing stream
//!
//! To handle mixed pools at hop 0 (e.g., direct + various proxy types), we use
//! `InitialHopEntry` which pairs socket and proxy together, ensuring they are
//! always selected atomically during round-robin.
//!
//! ## Structure
//!
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use futures::{StreamExt, stream};
use log::debug;
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;
use url::Url;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::{ClientChainSelectionConfig, DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS};
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// Entry in the initial hop (hop 0) pool.
///
/// Each entry pairs socket creation with optional protocol setup,
/// ensuring they are always selected together during round-robin.
pub enum InitialHopEntry {
    /// Direct connection - socket only, no protocol setup.
    /// Connects directly to the next hop's proxy or final destination.
    Direct(Box<dyn SocketConnector>),

    /// Proxy connection - socket + protocol setup paired together.
    /// Socket connects to proxy_location, then protocol wraps the stream.
    Proxy {
        socket: Box<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) => true, // Direct always supports UDP
            InitialHopEntry::Proxy { proxy, .. } => {
                proxy.supports_udp_over_tcp() || proxy.supports_native_udp()
            }
        }
    }
}

/// A chain of proxy hops with paired initial hop entries.
///
/// Structure:
/// - `initial_hop`: Pool of InitialHopEntry for hop 0 (socket + optional proxy paired)
/// - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation needed)
pub struct ClientProxyChain {
    /// Initial hop pool: each entry is either Direct or Proxy.
    /// Socket and proxy are paired and selected together.
    initial_hop: Vec<InitialHopEntry>,
    /// Round-robin index for initial hop selection.
    initial_hop_next_index: AtomicU32,

    /// Protocol connectors for subsequent hops (hops 1+).
    /// Outer vec = hops, inner vec = round-robin pool per hop.
    subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    /// Round-robin indices for each subsequent hop's pool.
    subsequent_next_indices: Vec<AtomicU32>,

    /// Indices into the FINAL hop pool for UDP-capable entries.
    /// This is either indices into initial_hop (if no subsequent hops),
    /// or indices into the last subsequent hop pool.
    udp_final_hop_indices: Vec<usize>,
    /// Round-robin index for UDP-capable final hop entries.
    udp_final_hop_next_index: AtomicU32,
    /// Flag indicating which pool udp_final_hop_indices refers to.
    /// true = udp_final_hop_indices points to initial_hop
    /// false = udp_final_hop_indices points to last subsequent hop
    udp_uses_initial_hop: bool,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("initial_hop_count", &self.initial_hop.len())
            .field(
                "subsequent_hops",
                &self
                    .subsequent_hops
                    .iter()
                    .map(|h| h.len())
                    .collect::<Vec<_>>(),
            )
            .field("udp_final_hop_indices", &self.udp_final_hop_indices)
            .field("udp_uses_initial_hop", &self.udp_uses_initial_hop)
            .finish()
    }
}

impl ClientProxyChain {
    /// Create a new chain from initial hop entries and subsequent hop pools.
    ///
    /// # Arguments
    /// * `initial_hop` - Pool of InitialHopEntry for hop 0
    /// * `subsequent_hops` - Protocol connectors for hops 1+
    ///
    /// # Panics
    /// Panics if initial_hop is empty.
    pub fn new(
        initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );

        // Compute UDP-capable indices in the FINAL hop pool.
        // The final hop is either initial_hop (if no subsequent) or the last subsequent hop.
        // Only the hop that calls setup_udp_stream() needs UDP support.
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            // No subsequent hops: initial hop IS the final hop
            // Filter initial_hop for UDP-capable entries
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
            // Has subsequent hops: filter the FINAL subsequent hop for UDP-capable entries
            let final_hop = subsequent_hops.last().unwrap();
            let indices = final_hop
                .iter()
                .enumerate()
                .filter(|(_, p)| p.supports_udp_over_tcp())
                .map(|(i, _)| i)
                .collect();
            (indices, false)
        };

        let subsequent_next_indices = subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect();

        Self {
            initial_hop,
            initial_hop_next_index: AtomicU32::new(0),
            subsequent_hops,
            subsequent_next_indices,
            udp_final_hop_indices,
            udp_final_hop_next_index: AtomicU32::new(0),
            udp_uses_initial_hop,
        }
    }

    /// Returns the total number of hops.
    #[cfg(test)]
    pub fn num_hops(&self) -> usize {
        1 + self.subsequent_hops.len()
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        !self.udp_final_hop_indices.is_empty()
    }

    /// Returns true if this chain is "direct-only": all initial hops are Direct
    /// and there are no subsequent hops. Such chains can be used for UDP/QUIC
    /// DNS while still supporting bind_interface.
    pub fn is_direct_only(&self) -> bool {
        if !self.subsequent_hops.is_empty() {
            return false;
        }
        self.initial_hop
            .iter()
            .all(|entry| matches!(entry, InitialHopEntry::Direct(_)))
    }

    /// Returns the bind_interface from a direct-only chain.
    /// Returns None if not direct-only or if no bind_interface is configured.
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        // All entries should have the same bind_interface, return from the first.
        self.initial_hop.first().and_then(|entry| match entry {
            InitialHopEntry::Direct(socket) => socket.bind_interface(),
            InitialHopEntry::Proxy { .. } => None,
        })
    }

    /// Select an initial hop entry (round-robin).
    fn select_initial_hop_entry(&self) -> &InitialHopEntry {
        if self.initial_hop.len() == 1 {
            &self.initial_hop[0]
        } else {
            let idx = self.initial_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.initial_hop[idx % self.initial_hop.len()]
        }
    }

    /// Select proxy connectors for subsequent hops (round-robin per hop).
    fn select_subsequent_proxies(&self) -> Vec<&dyn ProxyConnector> {
        self.subsequent_hops
            .iter()
            .enumerate()
            .map(|(i, hop)| {
                if hop.len() == 1 {
                    hop[0].as_ref()
                } else {
                    let idx =
                        self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed) as usize;
                    hop[idx % hop.len()].as_ref()
                }
            })
            .collect()
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.connect_tcp_inner(remote_location, resolver, false)
            .await
            .map(|(setup, _)| setup)
    }

    /// Connect while observing the final protocol's write-handshake boundary.
    ///
    /// This is used by URLTest to match sing-box's latency window.  Normal
    /// callers use [`Self::connect_tcp`] and do not install any observer.
    async fn connect_tcp_with_write_handshake_boundary(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(TcpClientSetupResult, Option<Instant>)> {
        self.connect_tcp_inner(remote_location, resolver, true)
            .await
    }

    async fn connect_tcp_inner(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        observe_final_write_handshake: bool,
    ) -> std::io::Result<(TcpClientSetupResult, Option<Instant>)> {
        // Select initial hop entry (socket + optional proxy paired)
        let entry = self.select_initial_hop_entry();

        // Select proxy connectors for subsequent hops
        let subsequent_proxies = self.select_subsequent_proxies();

        debug!(
            "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
            subsequent_proxies.len(),
            remote_location.location()
        );

        // Determine first target after initial hop (proxy locations need wrapping)
        let first_subsequent_target: ResolvedLocation = subsequent_proxies
            .first()
            .map(|p| p.proxy_location().into())
            .unwrap_or_else(|| remote_location.clone());

        // Connect based on initial hop type
        let (mut result, mut write_handshake_started_at) = match entry {
            InitialHopEntry::Direct(socket) => {
                // Socket connects to first subsequent proxy (or final target)
                debug!(
                    "Initial hop: Direct -> {}",
                    first_subsequent_target.location()
                );
                let stream = socket.connect(resolver, &first_subsequent_target).await?;
                (
                    TcpClientSetupResult {
                        client_stream: stream,
                        early_data: None,
                    },
                    None,
                )
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                // Socket connects to this proxy's location
                debug!(
                    "Initial hop: Proxy {} -> {}",
                    proxy.proxy_location(),
                    first_subsequent_target.location()
                );
                let proxy_loc = proxy.proxy_location().into();
                let stream = socket.connect(resolver, &proxy_loc).await?;
                // Protocol setup targeting first subsequent proxy (or final target)
                if observe_final_write_handshake && subsequent_proxies.is_empty() {
                    proxy
                        .setup_tcp_stream_with_write_handshake_boundary(
                            stream,
                            &first_subsequent_target,
                        )
                        .await?
                } else {
                    (
                        proxy
                            .setup_tcp_stream(stream, &first_subsequent_target)
                            .await?,
                        None,
                    )
                }
            }
        };

        // Process subsequent hops
        for (i, proxy) in subsequent_proxies.iter().enumerate() {
            let target: ResolvedLocation = subsequent_proxies
                .get(i + 1)
                .map(|p| p.proxy_location().into())
                .unwrap_or_else(|| remote_location.clone());

            debug!(
                "Subsequent hop {}/{}: {} -> {}",
                i + 1,
                subsequent_proxies.len(),
                proxy.proxy_location(),
                target.location()
            );

            if observe_final_write_handshake && i == subsequent_proxies.len() - 1 {
                (result, write_handshake_started_at) = proxy
                    .setup_tcp_stream_with_write_handshake_boundary(result.client_stream, &target)
                    .await?;
            } else {
                result = proxy
                    .setup_tcp_stream(result.client_stream, &target)
                    .await?;
            }

            // Early data from intermediate hops is unexpected
            if let Some(data) = &result.early_data
                && i < subsequent_proxies.len() - 1
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Unexpected early data ({} bytes) from intermediate hop {}",
                        data.len(),
                        i + 1
                    ),
                ));
            }
        }

        debug!(
            "Chain TCP complete: {} total hop(s) to {}",
            1 + subsequent_proxies.len(),
            remote_location.location()
        );

        Ok((result, write_handshake_started_at))
    }

    /// Connect for bidirectional UDP traffic through the chain.
    ///
    /// Returns an AsyncMessageStream that sends/receives UDP packets to the target.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // Check if UDP is supported
        if self.udp_final_hop_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Chain does not support UDP",
            ));
        }

        if self.udp_uses_initial_hop {
            // Case 1: No subsequent hops - initial hop IS the final hop
            // Select from UDP-capable initial hop entries
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let entry = &self.initial_hop[pool_idx];

            debug!(
                "Chain UDP connect: 1 hop (initial IS final), target={}",
                target.location()
            );

            match entry {
                InitialHopEntry::Direct(socket) => {
                    debug!("Chain UDP: Direct connection (native UDP)");
                    socket.connect_udp_bidirectional(resolver, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} (UDP, no subsequent)",
                        proxy.proxy_location()
                    );
                    if proxy.supports_native_udp() {
                        // Native proxy UDP starts with a datagram socket connected
                        // to the proxy itself. The protocol wrapper then puts the
                        // final target into every encrypted packet.
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket
                            .connect_udp_bidirectional(resolver, proxy_loc)
                            .await?;
                        proxy.setup_native_udp(stream, target).await
                    } else {
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket.connect(resolver, &proxy_loc).await?;
                        proxy.setup_udp_bidirectional(stream, target).await
                    }
                }
            }
        } else {
            // Case 2: Has subsequent hops - select initial hop normally,
            // select intermediate hops normally, select final hop from UDP-capable

            // Select initial hop normally (ALL entries work - they just do TCP)
            let entry = self.select_initial_hop_entry();

            // Select intermediate hops normally (ALL entries work - they just do TCP)
            let intermediate_proxies: Vec<&dyn ProxyConnector> = self
                .subsequent_hops
                .iter()
                .enumerate()
                .take(self.subsequent_hops.len() - 1) // All but last
                .map(|(i, hop)| {
                    if hop.len() == 1 {
                        hop[0].as_ref()
                    } else {
                        let idx = self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed)
                            as usize;
                        hop[idx % hop.len()].as_ref()
                    }
                })
                .collect();

            // Select final hop from UDP-capable entries
            let final_hop_pool = self.subsequent_hops.last().unwrap();
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let final_proxy = final_hop_pool[pool_idx].as_ref();

            debug!(
                "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                intermediate_proxies.len(),
                target.location()
            );

            // Build the chain: initial -> intermediates -> final (UDP)
            match entry {
                InitialHopEntry::Direct(socket) => {
                    // Determine first target after initial hop
                    let first_target: ResolvedLocation =
                        if let Some(first) = intermediate_proxies.first() {
                            first.proxy_location().into()
                        } else {
                            final_proxy.proxy_location().into()
                        };

                    debug!("Chain UDP: Direct -> {} (TCP)", first_target.location());
                    let mut stream = socket.connect(resolver, &first_target).await?;

                    // Process intermediate hops (all TCP)
                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target: ResolvedLocation = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location().into())
                            .unwrap_or_else(|| final_proxy.proxy_location().into());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target.location()
                        );
                        let result = proxy.setup_tcp_stream(stream, &next_target).await?;
                        stream = result.client_stream;
                    }

                    // Final hop: UDP stream
                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    final_proxy.setup_udp_bidirectional(stream, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    // Determine first target after initial hop
                    let first_target: ResolvedLocation =
                        if let Some(first) = intermediate_proxies.first() {
                            first.proxy_location().into()
                        } else {
                            final_proxy.proxy_location().into()
                        };

                    debug!(
                        "Chain UDP: Proxy {} -> {} (TCP)",
                        proxy.proxy_location(),
                        first_target.location()
                    );
                    let proxy_loc = proxy.proxy_location().into();
                    let stream = socket.connect(resolver, &proxy_loc).await?;
                    let result = proxy.setup_tcp_stream(stream, &first_target).await?;
                    let mut stream = result.client_stream;

                    // Process intermediate hops (all TCP)
                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target: ResolvedLocation = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location().into())
                            .unwrap_or_else(|| final_proxy.proxy_location().into());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target.location()
                        );
                        let result = proxy.setup_tcp_stream(stream, &next_target).await?;
                        stream = result.client_stream;
                    }

                    // Final hop: UDP stream
                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    final_proxy.setup_udp_bidirectional(stream, target).await
                }
            }
        }
    }
}

const NO_CHAIN_SELECTED: usize = usize::MAX;
const URLTEST_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Debug)]
struct UrlTestSelectionState {
    histories_millis: RwLock<Vec<Option<u64>>>,
    selected_tcp: AtomicUsize,
    selected_udp: AtomicUsize,
    tolerance_millis: u64,
    reselect_on_connection_failure: bool,
    /// Serializes history invalidation with selection replacement. Selection
    /// reads stay lock-free, while a late failure from an old connection cannot
    /// overwrite a newer selection.
    selection_update: Mutex<()>,
    activity: Mutex<UrlTestActivity>,
}

#[derive(Debug)]
struct UrlTestActivity {
    ticker_active: bool,
    last_active: Instant,
}

#[derive(Debug)]
struct UrlTestWorkerControl {
    closed: AtomicBool,
    notify: Notify,
}

struct UrlTestWorkerParams {
    weak_chains: Weak<Vec<ClientProxyChain>>,
    weak_resolver: Weak<dyn Resolver>,
    weak_state: Weak<UrlTestSelectionState>,
    udp_chain_indices: Vec<usize>,
    url: Url,
    use_native_roots: bool,
    interval: Duration,
    idle_timeout: Duration,
    control: Arc<UrlTestWorkerControl>,
}

impl UrlTestSelectionState {
    fn new(
        chain_count: usize,
        tolerance_millis: u64,
        reselect_on_connection_failure: bool,
    ) -> Self {
        Self {
            histories_millis: RwLock::new(vec![None; chain_count]),
            selected_tcp: AtomicUsize::new(NO_CHAIN_SELECTED),
            selected_udp: AtomicUsize::new(NO_CHAIN_SELECTED),
            tolerance_millis,
            reselect_on_connection_failure,
            selection_update: Mutex::new(()),
            activity: Mutex::new(UrlTestActivity {
                ticker_active: false,
                last_active: Instant::now(),
            }),
        }
    }

    fn selected(&self, udp: bool) -> &AtomicUsize {
        if udp {
            &self.selected_udp
        } else {
            &self.selected_tcp
        }
    }

    /// Select using sing-box's hysteresis: a candidate only replaces the
    /// current healthy selection when it is faster by more than tolerance.
    fn update_selection(&self, eligible: impl Iterator<Item = usize>, udp: bool) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let _selection_guard = self.selection_update.lock();
        let current = self.selected(udp).load(Ordering::Acquire);
        let current_eligible = current != NO_CHAIN_SELECTED && eligible.contains(&current);
        let candidate = match self.preferred_historical_candidate(&eligible, current) {
            Some(candidate) => candidate,
            None if current_eligible => current,
            None => *eligible.first()?,
        };
        self.selected(udp).store(candidate, Ordering::Release);
        Some(candidate)
    }

    fn clear_history(&self, index: usize) {
        let _selection_guard = self.selection_update.lock();
        self.clear_history_locked(index);
    }

    fn clear_history_locked(&self, index: usize) {
        if let Some(history) = self.histories_millis.write().get_mut(index) {
            *history = None;
        }
    }

    fn preferred_historical_candidate(&self, eligible: &[usize], current: usize) -> Option<usize> {
        let histories = self.histories_millis.read();
        let mut best = if current != NO_CHAIN_SELECTED && eligible.contains(&current) {
            histories[current].map(|delay| (current, delay))
        } else {
            None
        };
        for &index in eligible {
            let Some(delay) = histories[index] else {
                continue;
            };
            if best.is_none_or(|(_, best_delay)| {
                best_delay == 0 || best_delay > delay.saturating_add(self.tolerance_millis)
            }) {
                best = Some((index, delay));
            }
        }
        best.map(|(index, _)| index)
    }

    /// Invalidate a failed chain. The default Go-compatible mode preserves the
    /// selected member; the shoes-only opt-in immediately moves the affected
    /// network's selection. TCP and UDP selections remain independent even
    /// though their probe histories are shared.
    fn handle_connection_failure(
        &self,
        failed_index: usize,
        eligible: impl Iterator<Item = usize>,
        udp: bool,
    ) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let _selection_guard = self.selection_update.lock();
        self.clear_history_locked(failed_index);

        let selected = self.selected(udp);
        let current = selected.load(Ordering::Acquire);
        if !self.reselect_on_connection_failure {
            return (current != NO_CHAIN_SELECTED && eligible.contains(&current))
                .then_some(current);
        }
        if current != failed_index {
            return (current != NO_CHAIN_SELECTED && eligible.contains(&current))
                .then_some(current);
        }

        // A measured healthy member wins. If no history remains, try another
        // member in declaration order so the next connection does not
        // immediately reuse the known failure. A single-member group keeps its
        // only possible fallback.
        let replacement = self
            .preferred_historical_candidate(&eligible, NO_CHAIN_SELECTED)
            .or_else(|| {
                eligible
                    .iter()
                    .copied()
                    .find(|&index| index != failed_index)
            })
            .or_else(|| eligible.first().copied());
        selected.store(replacement.unwrap_or(NO_CHAIN_SELECTED), Ordering::Release);
        replacement
    }

    fn selected_or_fallback(
        &self,
        eligible: impl Iterator<Item = usize>,
        udp: bool,
    ) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let current = self.selected(udp).load(Ordering::Acquire);
        if current != NO_CHAIN_SELECTED && eligible.contains(&current) {
            Some(current)
        } else {
            self.update_selection(eligible.into_iter(), udp)
        }
    }

    fn touch(&self, control: &UrlTestWorkerControl) {
        let mut activity = self.activity.lock();
        if activity.ticker_active {
            activity.last_active = Instant::now();
        } else {
            activity.ticker_active = true;
            control.notify.notify_one();
        }
    }
}

#[derive(Debug)]
enum ClientChainGroupSelection {
    RoundRobin,
    UrlTest(Arc<UrlTestSelectionState>),
}

/// A group of proxy chains with configurable chain selection.
pub struct ClientChainGroup {
    chains: Arc<Vec<ClientProxyChain>>,
    next_tcp_index: AtomicU32,
    pub(crate) udp_chain_indices: Vec<usize>,
    next_udp_index: AtomicU32,
    selection: ClientChainGroupSelection,
    /// Kept by the live group; the background worker only holds a Weak pointer.
    urltest_resolver: Option<Arc<dyn Resolver>>,
    urltest_worker: Option<Arc<UrlTestWorkerControl>>,
}

impl std::fmt::Debug for ClientChainGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChainGroup")
            .field("chains_count", &self.chains.len())
            .field("udp_chain_indices", &self.udp_chain_indices)
            .field("selection", &self.selection)
            .field("has_urltest_resolver", &self.urltest_resolver.is_some())
            .field("has_urltest_worker", &self.urltest_worker.is_some())
            .finish()
    }
}

impl ClientChainGroup {
    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        Self::new_internal(chains, ClientChainSelectionConfig::RoundRobin, None)
    }

    pub fn new_with_selection(
        chains: Vec<ClientProxyChain>,
        selection_config: ClientChainSelectionConfig,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_internal(chains, selection_config, Some(resolver))
    }

    fn new_internal(
        chains: Vec<ClientProxyChain>,
        selection_config: ClientChainSelectionConfig,
        resolver: Option<Arc<dyn Resolver>>,
    ) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup must have at least one chain"
        );

        let udp_chain_indices: Vec<usize> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| chain.supports_udp())
            .map(|(i, _)| i)
            .collect();

        let chains = Arc::new(chains);
        let (selection, background) = match selection_config {
            ClientChainSelectionConfig::RoundRobin => (ClientChainGroupSelection::RoundRobin, None),
            ClientChainSelectionConfig::UrlTest {
                url,
                use_native_roots,
                reselect_on_connection_failure,
                interval_millis,
                tolerance_millis,
                idle_timeout_millis,
            } => {
                assert!(
                    interval_millis > 0,
                    "urltest interval_millis must be validated as greater than zero"
                );
                let url = Url::parse(if url.is_empty() {
                    DEFAULT_URLTEST_URL
                } else {
                    &url
                })
                .expect("urltest URL must be validated before building chains");
                let state = Arc::new(UrlTestSelectionState::new(
                    chains.len(),
                    tolerance_millis,
                    reselect_on_connection_failure,
                ));
                let idle_timeout_millis = if idle_timeout_millis == 0 {
                    DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS
                } else {
                    idle_timeout_millis
                };
                (
                    ClientChainGroupSelection::UrlTest(state.clone()),
                    Some((
                        url,
                        use_native_roots,
                        Duration::from_millis(interval_millis),
                        Duration::from_millis(idle_timeout_millis),
                        Arc::downgrade(&state),
                    )),
                )
            }
        };

        let worker_control = background.as_ref().map(|_| {
            Arc::new(UrlTestWorkerControl {
                closed: AtomicBool::new(false),
                notify: Notify::new(),
            })
        });
        let group = Self {
            chains: chains.clone(),
            next_tcp_index: AtomicU32::new(0),
            udp_chain_indices,
            next_udp_index: AtomicU32::new(0),
            selection,
            urltest_resolver: if background.is_some() { resolver } else { None },
            urltest_worker: worker_control.clone(),
        };

        if let Some((url, use_native_roots, interval, idle_timeout, state)) = background {
            let resolver = group
                .urltest_resolver
                .as_ref()
                .expect("urltest selection requires a resolver");
            spawn_urltest_task(UrlTestWorkerParams {
                weak_chains: Arc::downgrade(&chains),
                weak_resolver: Arc::downgrade(resolver),
                weak_state: state,
                udp_chain_indices: group.udp_chain_indices.clone(),
                url,
                use_native_roots,
                interval,
                idle_timeout,
                control: worker_control.expect("urltest selection created a worker control"),
            });
        }

        group
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let chain_index = match &self.selection {
            ClientChainGroupSelection::RoundRobin => {
                self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize % self.chains.len()
            }
            ClientChainGroupSelection::UrlTest(state) => {
                state.touch(
                    self.urltest_worker
                        .as_deref()
                        .expect("urltest selection has a worker control"),
                );
                state
                    .selected_or_fallback(0..self.chains.len(), false)
                    .expect("ClientChainGroup has at least one TCP chain")
            }
        };
        let result = self.chains[chain_index]
            .connect_tcp(remote_location, resolver)
            .await;
        if result.is_err()
            && let ClientChainGroupSelection::UrlTest(state) = &self.selection
        {
            let _ = state.handle_connection_failure(chain_index, 0..self.chains.len(), false);
        }
        result
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let chain_idx = match &self.selection {
            ClientChainGroupSelection::RoundRobin => {
                let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
                self.udp_chain_indices[idx % self.udp_chain_indices.len()]
            }
            ClientChainGroupSelection::UrlTest(state) => {
                state.touch(
                    self.urltest_worker
                        .as_deref()
                        .expect("urltest selection has a worker control"),
                );
                state
                    .selected_or_fallback(self.udp_chain_indices.iter().copied(), true)
                    .expect("UDP-capable chain indices are non-empty")
            }
        };
        let chain = &self.chains[chain_idx];
        let result = chain.connect_udp_bidirectional(resolver, target).await;
        if result.is_err()
            && let ClientChainGroupSelection::UrlTest(state) = &self.selection
        {
            let _ = state.handle_connection_failure(
                chain_idx,
                self.udp_chain_indices.iter().copied(),
                true,
            );
        }
        result
    }

    /// Returns whether at least one chain can carry fixed-destination UDP.
    /// Datagram-based users such as DNS-over-QUIC use this to reject a
    /// TCP-only detour before attempting a connection.
    pub fn supports_udp(&self) -> bool {
        !self.udp_chain_indices.is_empty()
    }

    /// Returns true if all chains are direct-only.
    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(|chain| chain.is_direct_only())
    }

    /// Returns the bind_interface if all chains are direct-only and share
    /// the same bind_interface (or all have None).
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        // Return bind_interface from first chain (all should be the same in a group).
        self.chains
            .first()
            .and_then(|chain| chain.get_bind_interface())
    }
}

impl Drop for ClientChainGroup {
    fn drop(&mut self) {
        if let Some(worker) = &self.urltest_worker {
            worker.closed.store(true, Ordering::Release);
            worker.notify.notify_waiters();
        }
    }
}

fn spawn_urltest_task(params: UrlTestWorkerParams) {
    let UrlTestWorkerParams {
        weak_chains,
        weak_resolver,
        weak_state,
        udp_chain_indices,
        url,
        use_native_roots,
        interval,
        idle_timeout,
        control,
    } = params;
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        log::warn!(
            "URLTest client-chain selection was built outside a Tokio runtime; background probing was not started"
        );
        return;
    };

    runtime.spawn(async move {
        // PostStart semantics: probe exactly once. Periodic probing begins only
        // after the group is touched by real TCP/UDP use.
        let (Some(chains), Some(resolver), Some(state)) = (
            weak_chains.upgrade(),
            weak_resolver.upgrade(),
            weak_state.upgrade(),
        ) else {
            return;
        };
        run_urltest_round(
            chains,
            resolver,
            state,
            &udp_chain_indices,
            &url,
            use_native_roots,
        )
        .await;

        loop {
            if control.closed.load(Ordering::Acquire) {
                return;
            }
            control.notify.notified().await;
            if control.closed.load(Ordering::Acquire) {
                return;
            }

            let Some(state) = weak_state.upgrade() else {
                return;
            };
            let run_immediately = {
                let mut activity = state.activity.lock();
                if !activity.ticker_active {
                    false
                } else if activity.last_active.elapsed() > interval {
                    activity.last_active = Instant::now();
                    true
                } else {
                    false
                }
            };
            drop(state);

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;

            if run_immediately {
                let (Some(chains), Some(resolver), Some(state)) = (
                    weak_chains.upgrade(),
                    weak_resolver.upgrade(),
                    weak_state.upgrade(),
                ) else {
                    return;
                };
                run_urltest_round(
                    chains,
                    resolver,
                    state,
                    &udp_chain_indices,
                    &url,
                    use_native_roots,
                )
                .await;
            }

            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    _ = control.notify.notified() => {
                        if control.closed.load(Ordering::Acquire) {
                            return;
                        }
                        continue;
                    }
                }

                let Some(state) = weak_state.upgrade() else {
                    return;
                };
                let should_stop = {
                    let mut activity = state.activity.lock();
                    if activity.last_active.elapsed() > idle_timeout {
                        activity.ticker_active = false;
                        true
                    } else {
                        false
                    }
                };
                drop(state);
                if should_stop {
                    break;
                }

                let (Some(chains), Some(resolver), Some(state)) = (
                    weak_chains.upgrade(),
                    weak_resolver.upgrade(),
                    weak_state.upgrade(),
                ) else {
                    return;
                };
                run_urltest_round(
                    chains,
                    resolver,
                    state,
                    &udp_chain_indices,
                    &url,
                    use_native_roots,
                )
                .await;
            }
        }
    });
}

async fn run_urltest_round(
    chains: Arc<Vec<ClientProxyChain>>,
    resolver: Arc<dyn Resolver>,
    state: Arc<UrlTestSelectionState>,
    udp_chain_indices: &[usize],
    url: &Url,
    use_native_roots: bool,
) {
    stream::iter(0..chains.len())
        .for_each_concurrent(10, |index| {
            let chains = chains.clone();
            let resolver = resolver.clone();
            let state = state.clone();
            let url = url.clone();
            async move {
                let result = tokio::time::timeout(
                    URLTEST_TIMEOUT,
                    probe_chain_http_head(&chains[index], &resolver, &url, use_native_roots),
                )
                .await;

                match result {
                    Ok(Ok(delay)) => {
                        debug!("URLTest chain {index} available: {delay}ms");
                        state.histories_millis.write()[index] = Some(delay);
                    }
                    Ok(Err(error)) => {
                        debug!("URLTest chain {index} unavailable: {error}");
                        state.clear_history(index);
                    }
                    Err(_) => {
                        debug!("URLTest chain {index} unavailable: timed out after 15s");
                        state.clear_history(index);
                    }
                }
            }
        })
        .await;

    state.update_selection(0..chains.len(), false);
    state.update_selection(udp_chain_indices.iter().copied(), true);
}

async fn probe_chain_http_head(
    chain: &ClientProxyChain,
    resolver: &Arc<dyn Resolver>,
    url: &Url,
    use_native_roots: bool,
) -> std::io::Result<u64> {
    let host = url.host_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URLTest URL is missing a host",
        )
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URLTest URL has no known port",
        )
    })?;
    let target = NetLocation::new(Address::from(host)?, port).into();
    let started = Instant::now();
    let (setup, write_handshake_started_at) = chain
        .connect_tcp_with_write_handshake_boundary(target, resolver)
        .await?;
    // Go's URLTest resets its timer when the returned connection implements
    // NeedHandshakeForWrite.  Shoes sends Trojan/VLESS headers eagerly during
    // setup, so their handlers report the equivalent instant from inside the
    // final hop (after socket, detour, and transport setup).
    let started = write_handshake_started_at.unwrap_or(started);
    if setup.early_data.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "URLTest chain returned application data before the HEAD request",
        ));
    }
    let mut io: Box<dyn AsyncStream> = setup.client_stream;

    if url.scheme() == "https" {
        static BUNDLED_ROOTS_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        static NATIVE_ROOTS_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        let config = if use_native_roots {
            &NATIVE_ROOTS_TLS_CONFIG
        } else {
            &BUNDLED_ROOTS_TLS_CONFIG
        }
        .get_or_init(|| {
            Arc::new(crate::rustls_config_util::create_client_config(
                true,
                Vec::new(),
                vec!["http/1.1".to_string()],
                true,
                None,
                false,
                use_native_roots,
            ))
        })
        .clone();
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid URLTest TLS server name: {error}"),
                )
            })?;
        let client = rustls::ClientConnection::new(config, server_name).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not create URLTest TLS client: {error}"),
            )
        })?;
        let mut connection = CryptoConnection::new_rustls_client(client);
        perform_crypto_handshake(&mut connection, &mut io, 16_384).await?;
        io = Box::new(CryptoTlsStream::new(io, connection));
    }

    let mut request_target = url.path().to_string();
    if request_target.is_empty() {
        request_target.push('/');
    }
    if let Some(query) = url.query() {
        request_target.push('?');
        request_target.push_str(query);
    }
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = format!(
        "HEAD {request_target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: shoes-urltest/1\r\nConnection: close\r\n\r\n"
    );
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    const MAX_RESPONSE_HEADERS: usize = 64 * 1024;
    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "URLTest HTTP server closed before response headers completed",
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_RESPONSE_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "URLTest HTTP response headers exceed 64 KiB",
            ));
        }
    }

    let status_line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "URLTest HTTP response has no status line",
            )
        })?;
    let status_line = std::str::from_utf8(&response[..status_line_end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "URLTest HTTP response status line is not UTF-8",
        )
    })?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || status.parse::<u16>().is_err()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid URLTest HTTP status line: {status_line:?}"),
        ));
    }

    Ok(started.elapsed().as_millis().min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::net::TcpListener;

    use crate::address::NetLocation;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::tcp::proxy_connector::ProxyConnector;
    use crate::tcp::socket_connector::SocketConnector;

    struct TestDuplexStream(DuplexStream);

    impl AsyncRead for TestDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestDuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestDuplexStream {}

    #[derive(Debug)]
    struct DelayedHttpSocketConnector {
        connect_delay: Duration,
        response_delay: Duration,
    }

    #[async_trait]
    impl SocketConnector for DelayedHttpSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            tokio::time::sleep(self.connect_delay).await;
            let (client, mut server) = tokio::io::duplex(4096);
            let response_delay = self.response_delay;
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(read) = server.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                tokio::time::sleep(response_delay).await;
                let _ = server
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
            Ok(Box::new(TestDuplexStream(client)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "timing mock has no UDP support",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[derive(Debug)]
    struct TimedBoundaryProxyConnector {
        location: NetLocation,
        before_boundary: Duration,
        after_boundary: Duration,
        marks_write_handshake: bool,
    }

    impl TimedBoundaryProxyConnector {
        fn new(
            port: u16,
            before_boundary: Duration,
            after_boundary: Duration,
            marks_write_handshake: bool,
        ) -> Self {
            Self {
                location: NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), port),
                before_boundary,
                after_boundary,
                marks_write_handshake,
            }
        }
    }

    #[async_trait]
    impl ProxyConnector for TimedBoundaryProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            false
        }

        fn needs_handshake_for_write(&self) -> bool {
            self.marks_write_handshake
        }

        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            tokio::time::sleep(self.before_boundary).await;
            if self.marks_write_handshake {
                crate::tcp::write_handshake::mark_started();
            }
            tokio::time::sleep(self.after_boundary).await;
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: None,
            })
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "timing mock has no UDP support",
            ))
        }
    }

    #[test]
    fn urltest_selection_falls_back_and_applies_tolerance() {
        let state = UrlTestSelectionState::new(3, 50, false);

        // No history: preserve member order for startup fallback.
        assert_eq!(state.update_selection(0..3, false), Some(0));

        // A 30 ms improvement is inside the 50 ms tolerance, so chain 0 stays.
        *state.histories_millis.write() = vec![Some(100), Some(70), Some(200)];
        assert_eq!(state.update_selection(0..3, false), Some(0));

        // A 60 ms improvement exceeds tolerance and switches to chain 1.
        state.histories_millis.write()[1] = Some(40);
        assert_eq!(state.update_selection(0..3, false), Some(1));

        // UDP has independent selection and only sees its eligible chain set.
        assert_eq!(state.update_selection([2].into_iter(), true), Some(2));
        assert_eq!(state.selected_tcp.load(Ordering::Relaxed), 1);
        assert_eq!(state.selected_udp.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn urltest_connection_failure_defaults_to_go_history_only_semantics() {
        let state = UrlTestSelectionState::new(3, 10, false);
        *state.histories_millis.write() = vec![Some(100), Some(40), Some(70)];
        state.selected_tcp.store(0, Ordering::Relaxed);
        state.selected_udp.store(0, Ordering::Relaxed);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(0));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 0);
        assert_eq!(state.selected_udp.load(Ordering::Acquire), 0);
    }

    #[test]
    fn urltest_connection_failure_reselects_only_the_affected_network() {
        let state = UrlTestSelectionState::new(3, 10, true);
        *state.histories_millis.write() = vec![Some(100), Some(40), Some(70)];
        state.selected_tcp.store(0, Ordering::Relaxed);
        state.selected_udp.store(0, Ordering::Relaxed);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(1));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 1);
        assert_eq!(
            state.selected_udp.load(Ordering::Acquire),
            0,
            "a TCP failure must not replace the independent UDP selection"
        );

        assert_eq!(
            state.handle_connection_failure(0, [0, 2].into_iter(), true),
            Some(2)
        );
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 1);
        assert_eq!(state.selected_udp.load(Ordering::Acquire), 2);
    }

    #[test]
    fn urltest_connection_failure_uses_an_ordered_unmeasured_fallback() {
        let state = UrlTestSelectionState::new(3, 50, true);
        state.selected_tcp.store(0, Ordering::Relaxed);

        assert_eq!(
            state.handle_connection_failure(0, 0..3, false),
            Some(1),
            "a known failure must not be immediately selected again when another member exists"
        );

        state.selected_tcp.store(0, Ordering::Relaxed);
        assert_eq!(
            state.handle_connection_failure(0, [0].into_iter(), false),
            Some(0),
            "a single-member group must retain its only fallback"
        );
    }

    #[test]
    fn urltest_late_failure_does_not_overwrite_a_newer_selection() {
        let state = UrlTestSelectionState::new(3, 0, true);
        *state.histories_millis.write() = vec![Some(10), Some(20), Some(30)];
        state.selected_tcp.store(2, Ordering::Release);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(2));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn urltest_sends_head_through_complete_direct_chain() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("HEAD /health?probe=1 HTTP/1.1\r\n"));
            assert!(request.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health?probe=1")).unwrap();
        let delay = tokio::time::timeout(
            Duration::from_secs(2),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(delay < 2_000);
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn urltest_latency_starts_at_final_write_handshake_boundary() {
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                DelayedHttpSocketConnector {
                    connect_delay: Duration::from_millis(100),
                    response_delay: Duration::from_millis(15),
                },
            ))],
            vec![
                // This hop has the same marker as Trojan/VLESS, but only the
                // final outbound may reset URLTest's timer.
                vec![Box::new(TimedBoundaryProxyConnector::new(
                    1080,
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                    true,
                ))],
                vec![Box::new(TimedBoundaryProxyConnector::new(
                    1081,
                    Duration::from_millis(40),
                    Duration::from_millis(25),
                    true,
                ))],
            ],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let url = Url::parse("http://example.com/health").unwrap();

        let wall_started = Instant::now();
        let delay = probe_chain_http_head(&chain, &resolver, &url, false)
            .await
            .unwrap();

        assert_eq!(wall_started.elapsed(), Duration::from_millis(210));
        assert_eq!(delay, 40, "only final header + HEAD RTT should be measured");
    }

    #[tokio::test(start_paused = true)]
    async fn write_handshake_boundary_follows_the_selected_final_pool_member() {
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                DelayedHttpSocketConnector {
                    connect_delay: Duration::from_millis(5),
                    response_delay: Duration::ZERO,
                },
            ))],
            vec![vec![
                Box::new(TimedBoundaryProxyConnector::new(
                    1080,
                    Duration::from_millis(7),
                    Duration::from_millis(11),
                    false,
                )),
                Box::new(TimedBoundaryProxyConnector::new(
                    1081,
                    Duration::from_millis(13),
                    Duration::from_millis(17),
                    true,
                )),
            ]],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let target: ResolvedLocation =
            NetLocation::new(Address::from("example.com").unwrap(), 80).into();

        let (_, first_boundary) = chain
            .connect_tcp_with_write_handshake_boundary(target.clone(), &resolver)
            .await
            .unwrap();
        assert!(
            first_boundary.is_none(),
            "the first selected member has no write handshake"
        );

        let (_, second_boundary) = chain
            .connect_tcp_with_write_handshake_boundary(target, &resolver)
            .await
            .unwrap();
        let second_boundary = second_boundary.expect("second pool member should set a boundary");
        assert_eq!(second_boundary.elapsed(), Duration::from_millis(17));
    }

    #[tokio::test]
    async fn urltest_background_does_not_keep_replaced_group_alive() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let group = ClientChainGroup::new_with_selection(
            vec![chain],
            ClientChainSelectionConfig::UrlTest {
                url: format!("http://127.0.0.1:{port}/health"),
                use_native_roots: false,
                reselect_on_connection_failure: false,
                interval_millis: 60_000,
                tolerance_millis: 50,
                idle_timeout_millis: DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS,
            },
            resolver,
        );
        let weak_chains = Arc::downgrade(&group.chains);
        let weak_state = match &group.selection {
            ClientChainGroupSelection::UrlTest(state) => Arc::downgrade(state),
            ClientChainGroupSelection::RoundRobin => panic!("expected urltest selection"),
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let measured = weak_state
                    .upgrade()
                    .is_some_and(|state| state.histories_millis.read()[0].is_some());
                if measured {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        server.await.unwrap();
        drop(group);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if weak_chains.upgrade().is_none() && weak_state.upgrade().is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("URLTest worker retained a dropped chain group");
    }

    #[tokio::test]
    async fn urltest_periodic_checks_start_on_touch_and_stop_when_idle() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let server_requests = server_requests.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    if stream.read(&mut request).await.unwrap_or(0) == 0 {
                        return;
                    }
                    server_requests.fetch_add(1, Ordering::Relaxed);
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
                });
            }
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let group = ClientChainGroup::new_with_selection(
            vec![chain],
            ClientChainSelectionConfig::UrlTest {
                url: format!("http://127.0.0.1:{port}/health"),
                use_native_roots: false,
                reselect_on_connection_failure: false,
                interval_millis: 50,
                tolerance_millis: 0,
                idle_timeout_millis: 150,
            },
            resolver,
        );
        let state = match &group.selection {
            ClientChainGroupSelection::UrlTest(state) => state,
            ClientChainGroupSelection::RoundRobin => panic!("expected urltest selection"),
        };
        let control = group.urltest_worker.as_deref().unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            requests.load(Ordering::Relaxed),
            1,
            "PostStart must not start the periodic ticker"
        );

        state.touch(control);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(350)).await;
        let after_idle = requests.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            requests.load(Ordering::Relaxed),
            after_idle,
            "periodic URLTest probes must stop after idle_timeout"
        );

        state.touch(control);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) <= after_idle {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("touch did not wake an idle URLTest group");

        drop(group);
        server.abort();
    }

    /// Mock SocketConnector that fails on connect (for unit testing structure).
    #[derive(Debug)]
    struct MockSocketConnector;

    #[async_trait]
    impl SocketConnector for MockSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect not implemented",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect_udp_bidirectional not implemented",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// Mock ProxyConnector for testing.
    #[derive(Debug)]
    struct MockProxyConnector {
        location: NetLocation,
        supports_udp: bool,
    }

    impl MockProxyConnector {
        fn new(port: u16, supports_udp: bool) -> Self {
            Self {
                location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
                supports_udp,
            }
        }
    }

    #[async_trait]
    impl ProxyConnector for MockProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            self.supports_udp
        }

        async fn setup_tcp_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockProxyConnector::setup_tcp_stream not implemented",
            ))
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockProxyConnector::setup_udp_bidirectional not implemented",
            ))
        }
    }

    fn mock_socket(_id: usize) -> Box<dyn SocketConnector> {
        Box::new(MockSocketConnector)
    }

    fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
        Box::new(MockProxyConnector::new(port, supports_udp))
    }

    fn direct_entry(id: usize) -> InitialHopEntry {
        InitialHopEntry::Direct(mock_socket(id))
    }

    fn proxy_entry(id: usize, port: u16, supports_udp: bool) -> InitialHopEntry {
        InitialHopEntry::Proxy {
            socket: mock_socket(id),
            proxy: mock_proxy(port, supports_udp),
        }
    }

    #[test]
    fn test_initial_hop_entry_direct_supports_udp() {
        let entry = direct_entry(0);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_supports_udp() {
        let entry = proxy_entry(0, 1080, true);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_no_udp() {
        let entry = proxy_entry(0, 1080, false);
        assert!(!entry.supports_udp());
    }

    #[test]
    fn test_chain_single_direct() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy_no_udp() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, true)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent_no_udp() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, false)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp()); // Subsequent doesn't support UDP
    }

    #[test]
    fn test_chain_proxy_with_subsequent() {
        let chain = ClientProxyChain::new(
            vec![proxy_entry(0, 1080, true)],
            vec![vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_mixed_initial_pool() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // VMess proxy
                proxy_entry(1, 1081, true), // VLESS proxy
                direct_entry(2),            // Direct
            ],
            vec![],
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
        // All 3 entries support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_chain_mixed_initial_pool_partial_udp() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // No UDP
                proxy_entry(1, 1081, true),  // Has UDP
                direct_entry(2),             // Has UDP
            ],
            vec![],
        );
        assert!(chain.supports_udp());
        // Only entries 1 and 2 support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_two_subsequent_hops() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pool_at_subsequent_hop() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(1080, true),
                mock_proxy(1081, false),
                mock_proxy(1082, true),
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp()); // At least one in pool supports UDP
    }

    #[test]
    #[should_panic(expected = "must have at least one initial hop entry")]
    fn test_chain_empty_initial_hop_panics() {
        ClientProxyChain::new(vec![], vec![]);
    }

    #[test]
    fn test_group_single_chain() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        let group = ClientChainGroup::new(vec![chain]);
        assert!(group.supports_udp());
    }

    #[test]
    #[should_panic(expected = "must have at least one chain")]
    fn test_group_empty_chains_panics() {
        ClientChainGroup::new(vec![]);
    }

    #[test]
    fn test_group_mixed_udp_support() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0]);
    }

    #[test]
    fn test_group_all_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![direct_entry(1)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0, 1]);
    }

    #[test]
    fn test_group_none_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(!group.supports_udp());
        assert!(group.udp_chain_indices.is_empty());
    }

    #[test]
    fn test_pool_pairing_fix_socket_proxy_always_paired() {
        // Create a mixed pool simulating: vmess@1080, vless@1081, direct
        // Each with a unique socket ID matching its position
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // socket_id=0, proxy_port=1080
                proxy_entry(1, 1081, true), // socket_id=1, proxy_port=1081
                direct_entry(2),            // socket_id=2, no proxy
            ],
            vec![],
        );

        // Select entries multiple times and verify pairing
        // Round-robin should cycle: 0, 1, 2, 0, 1, 2, ...
        for iteration in 0..6 {
            let entry = chain.select_initial_hop_entry();
            let expected_idx = iteration % 3;

            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 0: should be vmess proxy at port 1080
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1080,
                        "Iteration {}: expected proxy port 1080, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 1: should be vless proxy at port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "Iteration {}: expected proxy port 1081, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (2, InitialHopEntry::Direct(_)) => {
                    // Entry 2: should be direct (no proxy)
                    // This is correct - direct has no proxy to mismatch
                }
                (idx, entry) => {
                    panic!(
                        "Iteration {}: unexpected entry type at index {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_pool_pairing_fix_udp_selection_also_paired() {
        // Create a mixed pool where only some support UDP
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // socket_id=0, NO UDP
                proxy_entry(1, 1081, true),  // socket_id=1, HAS UDP, port 1081
                direct_entry(2),             // socket_id=2, HAS UDP (direct always does)
            ],
            vec![],
        );

        // UDP selection should only return entries 1 and 2 (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify UDP selection cycles through UDP-capable entries only
        // Manually select using the new logic
        for iteration in 0..4 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let entry = &chain.initial_hop[pool_idx];
            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_initial_hop_indices

            match (expected_udp_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // UDP index 0 -> initial_hop[1] -> port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "UDP iteration {}: expected proxy port 1081",
                        iteration
                    );
                }
                (1, InitialHopEntry::Direct(_)) => {
                    // UDP index 1 -> initial_hop[2] -> direct
                    // Correct!
                }
                (idx, entry) => {
                    panic!(
                        "UDP iteration {}: unexpected at udp_idx {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_udp_selection_with_subsequent_hops() {
        // Test that when udp_uses_initial_hop = false, we select:
        // - Initial hop normally (from all entries)
        // - Final hop from udp_final_hop_indices
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP (but should be usable for UDP!)
                proxy_entry(1, 1081, false), // Another HTTP
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert!(!chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify that initial hop selection would use all entries (indices 0 and 1)
        // We can't easily test this without calling connect_udp_bidirectional(), but we can verify
        // that the normal round-robin will cycle through both
        for i in 0..4 {
            let entry = chain.select_initial_hop_entry();
            let expected_idx = i % 2;
            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1080);
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1081);
                }
                _ => panic!("Unexpected entry"),
            }
        }

        // Verify that final hop selection cycles through udp_final_hop_indices only
        let final_hop = chain.subsequent_hops.last().unwrap();
        for iteration in 0..6 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let proxy = &final_hop[pool_idx];

            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_final_hop_indices
            match expected_udp_idx {
                0 => {
                    // udp_final_hop_indices[0] = 1 -> VMess at port 443
                    assert_eq!(proxy.proxy_location().port(), 443);
                }
                1 => {
                    // udp_final_hop_indices[1] = 2 -> VLESS at port 444
                    assert_eq!(proxy.proxy_location().port(), 444);
                }
                _ => panic!("Unexpected index"),
            }
        }
    }

    #[test]
    fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
        // Test the key insight: when has subsequent hops, udp_final_hop_indices
        // points to the FINAL subsequent hop, not the initial hop
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP
                proxy_entry(1, 1081, true),  // SOCKS5 - has UDP (irrelevant!)
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());

        // Key: udp_uses_initial_hop should be FALSE
        assert!(!chain.udp_uses_initial_hop);

        // udp_final_hop_indices should point to indices in the FINAL subsequent hop
        // NOT the initial hop! Only indices 1 and 2 (VMess, VLESS) support UDP
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
        // direct -> http (no UDP) -> vmess (has UDP)
        // Should support UDP because only final hop matters
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_all_intermediate_no_udp_final_has_udp() {
        // direct -> http -> socks5 -> vmess
        // Three intermediate hops, none with UDP, but final has UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_intermediate_has_udp_final_no_udp() {
        // direct -> vmess (has UDP) -> http (no UDP)
        // Should NOT support UDP because final hop doesn't
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(443, true)],   // VMess - has UDP
                vec![mock_proxy(8080, false)], // HTTP - no UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_partial_udp() {
        // direct -> [http (no UDP), vmess (has UDP), vless (has UDP)]
        // Should support UDP because final hop pool has UDP-capable connectors
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(443, true),   // VMess - has UDP
                mock_proxy(444, true),   // VLESS - has UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_no_udp() {
        // direct -> [http, socks5] (neither has UDP)
        // Should NOT support UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(1080, false), // SOCKS5 - no UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_complex_multi_hop_mixed_udp() {
        // direct -> http (no UDP) -> socks5 (no UDP) -> [http (no), vmess (yes)]
        // Should support UDP: intermediate hops don't matter, final pool has vmess
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![
                    mock_proxy(8081, false), // HTTP - no UDP
                    mock_proxy(443, true),   // VMess - has UDP
                ],
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }
}
