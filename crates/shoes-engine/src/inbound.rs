use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use log::debug;
use shoes::config::ServerConfig;
use shoes::dynamic::{InboundReplayState, ServerHandle, UserRegistry};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_server::ResolvedBind;
use shoes_api::InboundInfo;

use crate::users::MemoryUserRegistry;

/// Everything needed to publish a fully started inbound.
///
/// Keeping these related resources in one value prevents call sites from
/// accidentally swapping similarly shaped positional arguments as startup grows
/// new bookkeeping state.
pub(super) struct InboundSlotInit {
    pub(super) info: InboundInfo,
    pub(super) keys: Vec<BindKey>,
    pub(super) handles: Vec<ServerHandle>,
    pub(super) replay_state: InboundReplayState,
    pub(super) replay_lineage: Arc<()>,
    pub(super) users: Option<Arc<MemoryUserRegistry>>,
}

/// One listener group's fully prepared in-place reload.
pub(super) struct ReloadCandidate {
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    resolved_bind: ResolvedBind,
}

impl ReloadCandidate {
    pub(super) fn new(
        config: ServerConfig,
        resolver: Arc<dyn Resolver>,
        resolved_bind: ResolvedBind,
    ) -> Self {
        Self {
            config,
            resolver,
            resolved_bind,
        }
    }
}

/// How long [`InboundSlot::shutdown`] waits for the accept loops to let go of
/// their sockets before aborting them.
///
/// A TCP accept loop returns as soon as it sees the token, so this bound is only
/// ever reached by QUIC, whose endpoint drains its live connections before it can
/// release the UDP port -- so this must be longer than
/// `shoes::quic_server::QUIC_DRAIN_TIMEOUT`, or we would abort the endpoint
/// mid-drain and cut exactly the connections the drain exists to protect.
const LISTENER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Which kind of socket actually occupies an address.
///
/// Not [`shoes::config::Transport`], for two reasons. It is narrower -- by the time
/// an inbound starts, the transport has been resolved to one of these two -- and it
/// derives `Hash`, which the upstream type does not and which nothing here should
/// make it start doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SocketKind {
    Tcp,
    Udp,
}

impl SocketKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One thing an inbound occupies exclusively, and the unit the engine's address
/// registry is keyed by.
///
/// The address alone is not it. A TCP listener and a QUIC endpoint on `:443` are two
/// different sockets, and running both is the ordinary way to serve HTTP/3 beside
/// HTTP/2 -- keying on the address alone made the engine refuse the second as a
/// conflict. A unix socket has no address at all, so it needs its own variant rather
/// than being left out of the registry entirely, which is what let two inbounds claim
/// one path and the second silently delete the first one's socket file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum BindKey {
    Socket(SocketAddr, SocketKind),
    Path(String),
}

impl std::fmt::Display for BindKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(address, kind) => write!(f, "{address} ({})", kind.name()),
            Self::Path(path) => write!(f, "{path}"),
        }
    }
}

/// The resolved listen targets of one inbound.
#[derive(Debug, Clone)]
pub(crate) enum BindTargets {
    Addresses {
        addresses: Vec<SocketAddr>,
        kind: SocketKind,
    },
    /// Unix domain socket path (TCP transport only, unix only).
    Path(PathBuf),
}

impl BindTargets {
    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        match self {
            Self::Addresses { addresses, .. } => addresses,
            Self::Path(_) => &[],
        }
    }

    /// The socket kind, for an address-backed target that needs a pre-flight bind.
    pub(crate) const fn kind(&self) -> Option<SocketKind> {
        match self {
            Self::Addresses { kind, .. } => Some(*kind),
            Self::Path(_) => None,
        }
    }

    /// Everything this target claims, in the form the engine's registry is keyed by.
    ///
    /// A unix path is included here even though it has no `SocketAddr`, which is the
    /// whole point: it is claimed exclusively just as an address is.
    pub(crate) fn keys(&self) -> Vec<BindKey> {
        match self {
            Self::Addresses { addresses, kind } => addresses
                .iter()
                .map(|address| BindKey::Socket(*address, *kind))
                .collect(),
            Self::Path(path) => vec![BindKey::Path(path.display().to_string())],
        }
    }

    pub(crate) fn display(&self) -> Vec<String> {
        match self {
            Self::Addresses { addresses, .. } => {
                addresses.iter().map(ToString::to_string).collect()
            }
            Self::Path(p) => vec![p.display().to_string()],
        }
    }

    /// The exact plan passed to shoes' listener starter and reload checks.
    pub(crate) fn resolved_bind(&self) -> ResolvedBind {
        match self {
            Self::Addresses { addresses, .. } => ResolvedBind::Addresses(addresses.clone()),
            Self::Path(path) => ResolvedBind::Path(path.clone()),
        }
    }
}

/// One registered inbound: its metadata plus the handles to the listeners backing
/// it.
///
/// Listener handles and their connection-cancellation trees are held here. Upstream
/// detaches every accepted connection with `tokio::spawn`, so graceful shutdown and
/// reload leave those sessions independent; an explicit hard shutdown reaches them
/// through the separate connection tree.
pub struct InboundSlot {
    info: InboundInfo,
    /// The protocol label, which a reload can change.
    ///
    /// Separate from `info` because it is the one field of it that is not fixed for
    /// the life of the inbound. A reload rebuilds the handlers from a new config, and
    /// while a *dynamic* inbound may not change the credential shape it authenticates
    /// with, a classic one may become another protocol entirely -- and reporting the
    /// protocol it was created as would then be a plain lie to whoever is listing
    /// inbounds. The transport needs no such treatment: `check_reload` refuses to
    /// change it.
    protocol: ArcSwap<String>,
    /// Everything this inbound claims exclusively, as the engine's registry keys it.
    ///
    /// Stored as keys rather than as the `BindTargets` they came from, because an
    /// inbound can expand to several targets of different shapes and the flattening
    /// this replaced kept only their addresses -- so a unix socket was never released
    /// on removal, having never been recorded as claimed.
    keys: Vec<BindKey>,
    /// One handle per server config this inbound expanded to, in start order.
    ///
    /// A reload re-expands the incoming config and pairs the result against this
    /// list positionally, which is why the order is preserved rather than keyed.
    handles: Vec<ServerHandle>,
    /// Security state spans every expanded listener group and every replacement
    /// generation of this one logical inbound.
    replay_state: InboundReplayState,
    /// Unforgeable authority for this tag's replay namespace. The engine keeps
    /// only a `Weak` registry entry; the live slot and any explicit rollback
    /// leases are the owners that keep the lineage admissible.
    replay_lineage: Arc<()>,
    /// The authority for this inbound's users, when it has one.
    ///
    /// `None` means the inbound was created without a `users` list and answers
    /// from its config credential, so there is nothing here to add users to.
    ///
    /// The same `Arc` is inside the running handlers. Mutating it is what makes a
    /// user addition take effect on the next handshake with no restart, and why
    /// this is not behind the control lock: the registry is already concurrent.
    ///
    /// A reload hands the *same* `Arc` to the rebuilt handlers, so online users
    /// and their counters survive a rule change untouched.
    users: Option<Arc<MemoryUserRegistry>>,
}

impl InboundSlot {
    pub(super) fn new(init: InboundSlotInit) -> Self {
        let InboundSlotInit {
            info,
            keys,
            handles,
            replay_state,
            replay_lineage,
            users,
        } = init;
        Self {
            protocol: ArcSwap::from_pointee(info.protocol.clone()),
            info,
            keys,
            handles,
            replay_state,
            replay_lineage,
            users,
        }
    }

    pub(super) fn tag(&self) -> &str {
        &self.info.tag
    }

    pub(crate) fn replay_state(&self) -> InboundReplayState {
        self.replay_state.clone()
    }

    pub(crate) fn replay_lineage(&self) -> Arc<()> {
        Arc::clone(&self.replay_lineage)
    }

    /// A snapshot of this inbound, with the current protocol, user count and
    /// revision filled in.
    ///
    /// All three are read here rather than served from `info`, because all three
    /// change without going through it -- a cached copy would go stale silently, and
    /// a stale *protocol* is the one that misleads rather than merely lags.
    pub fn describe(&self) -> InboundInfo {
        let mut info = self.info.clone();
        info.protocol = self.protocol.load().as_str().to_string();
        info.users = self.users.as_ref().map(|users| users.len());
        info.revision = self.revision();
        info
    }

    /// How many times this inbound's handlers or rules have been swapped since it
    /// started.
    ///
    /// One number for both, because an inbound only ever has one kind of slot: a
    /// handler slot for everything that goes through a `TcpServerHandler`, a rule
    /// slot for hysteria2 and TUIC, which do not.
    pub fn revision(&self) -> u64 {
        self.handles
            .iter()
            .map(ServerHandle::generation)
            .max()
            .unwrap_or(0)
    }

    /// The user registry backing this inbound, or `None` if it has none.
    pub fn users(&self) -> Option<&Arc<MemoryUserRegistry>> {
        self.users.as_ref()
    }

    /// What this inbound is holding, to be released when it stops.
    pub(crate) fn keys(&self) -> &[BindKey] {
        &self.keys
    }

    /// Replaces this inbound's routing rules and protocol settings in place.
    ///
    /// `configs` must be the re-expansion of the caller's new payload, paired with
    /// the resolver each config should use, in the same order as the configs this
    /// inbound was started from. Nothing rebinds: the listeners keep running, and
    /// every connection they have already accepted keeps the handler -- and
    /// therefore the rules -- it was accepted with. Only connections accepted after
    /// this returns see the new config.
    ///
    /// Returns the new revision.
    ///
    /// # Errors
    ///
    /// If the new config does not describe the listeners that are running: a
    /// different listen set, a different transport, or a different number of
    /// expanded configs. Changing any of those means closing and reopening sockets,
    /// which cannot be rolled back if the new bind fails, so it is left to the
    /// caller to do explicitly as a remove plus an add.
    pub(super) fn reload(&self, candidates: Vec<ReloadCandidate>) -> std::io::Result<u64> {
        if candidates.len() != self.handles.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot reload in place: running {} listener group(s), the new config \
                     expands to {}",
                    self.handles.len(),
                    candidates.len()
                ),
            ));
        }

        // Check every handle before swapping any of them, so a config that one
        // group rejects leaves the whole inbound on its previous revision instead
        // of half of it on the new one.
        for (handle, candidate) in self.handles.iter().zip(&candidates) {
            handle.check_reload_resolved(&candidate.config, &candidate.resolved_bind)?;
        }

        let users = self
            .users
            .clone()
            .map(|registry| registry as Arc<dyn UserRegistry>);

        // Read before the candidates are consumed below. The first expansion names the
        // inbound, the same way it did at creation.
        let protocol = crate::protocol::display_name(&candidates[0].config.protocol);

        let mut revision = 0;
        for (handle, candidate) in self.handles.iter().zip(candidates) {
            revision = revision.max(handle.reload_resolved(
                candidate.config,
                &candidate.resolver,
                users.as_ref(),
                &candidate.resolved_bind,
            )?);
        }

        // After the swaps, not before: until they land, the old label is the true one.
        self.protocol.store(Arc::new(protocol));

        debug!("inbound {} reloaded to revision {revision}", self.info.tag);

        Ok(revision)
    }

    /// Stop accepting, without waiting. See [`ServerHandle::stop_accepting`].
    ///
    /// For the paths that have no `await` to spend: a `Drop` cleaning up after a
    /// request that was cancelled part-way through.
    pub(crate) fn stop_accepting(&self) {
        for handle in &self.handles {
            handle.stop_accepting();
        }
    }

    /// Synchronously signal both accept loops and established connection trees.
    pub(crate) fn hard_stop(&self) {
        for handle in &self.handles {
            handle.hard_stop();
        }
    }

    /// Stop accepting and wait until every listener has released its socket.
    /// Established connections retain the ordinary graceful semantics.
    pub(crate) async fn shutdown(&self) {
        for handle in &self.handles {
            handle.shutdown(LISTENER_DRAIN_TIMEOUT).await;
        }
    }

    pub(crate) async fn hard_shutdown(&self) {
        // Signal every expanded listener before awaiting any one of them, so a slow
        // endpoint cannot leave another group accepting or serving connections.
        self.hard_stop();
        for handle in &self.handles {
            handle.shutdown(LISTENER_DRAIN_TIMEOUT).await;
        }
    }
}

impl std::fmt::Debug for InboundSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundSlot")
            .field("tag", &self.info.tag)
            .field("protocol", &self.info.protocol)
            .field("bind", &self.info.bind)
            .field("revision", &self.revision())
            .field("users", &self.users.as_ref().map(|u| u.len()))
            .finish_non_exhaustive()
    }
}

/// Stops listeners that will never be registered, after a failure part-way
/// through starting an inbound.
///
/// These listeners were never committed, so no connection accepted in their brief
/// startup window may survive into a restored topology. Signal every connection
/// tree first, then await socket release so a retry cannot collide with it.
pub(crate) async fn abandon(handles: Vec<ServerHandle>) {
    for handle in &handles {
        handle.hard_stop();
    }
    for handle in &handles {
        handle.shutdown(LISTENER_DRAIN_TIMEOUT).await;
    }
}
