use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use shoes_api::InboundInfo;
use tokio::task::JoinHandle;

use crate::users::MemoryUserRegistry;

/// The resolved listen targets of one inbound.
#[derive(Debug, Clone)]
pub(crate) enum BindTargets {
    Addresses(Vec<SocketAddr>),
    /// Unix domain socket path (TCP transport only, unix only).
    Path(String),
}

impl BindTargets {
    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        match self {
            Self::Addresses(addrs) => addrs,
            Self::Path(_) => &[],
        }
    }

    pub(crate) fn display(&self) -> Vec<String> {
        match self {
            Self::Addresses(addrs) => addrs.iter().map(|a| a.to_string()).collect(),
            Self::Path(p) => vec![p.clone()],
        }
    }
}

/// One registered inbound: its metadata plus the listener tasks backing it.
///
/// Only *listener* tasks are held here. Upstream `run_tcp_server` detaches every
/// accepted connection with `tokio::spawn`, so a connection's lifetime is fully
/// independent of the listener task it was accepted by. That independence is what
/// makes [`InboundSlot::shutdown`] safe for established TCP sessions.
pub struct InboundSlot {
    info: InboundInfo,
    targets: BindTargets,
    listeners: Mutex<Vec<JoinHandle<()>>>,
    /// The authority for this inbound's users, when it has one.
    ///
    /// `None` means the inbound was created without a `users` list and answers
    /// from its config credential, so there is nothing here to add users to.
    ///
    /// The same `Arc` is inside the running handlers. Mutating it is what makes a
    /// user addition take effect on the next handshake with no restart, and why
    /// this is not behind the control lock: the registry is already concurrent.
    users: Option<Arc<MemoryUserRegistry>>,
}

impl InboundSlot {
    pub(crate) fn new(
        info: InboundInfo,
        targets: BindTargets,
        listeners: Vec<JoinHandle<()>>,
        users: Option<Arc<MemoryUserRegistry>>,
    ) -> Self {
        Self {
            info,
            targets,
            listeners: Mutex::new(listeners),
            users,
        }
    }

    /// A snapshot of this inbound, with the current user count filled in.
    ///
    /// The count is computed here rather than stored, because it changes every time
    /// a user is added or removed and a cached copy would go stale silently.
    pub fn describe(&self) -> InboundInfo {
        let mut info = self.info.clone();
        info.users = self.users.as_ref().map(|users| users.len());
        info
    }

    /// The user registry backing this inbound, or `None` if it has none.
    pub fn users(&self) -> Option<&Arc<MemoryUserRegistry>> {
        self.users.as_ref()
    }

    pub(crate) fn targets(&self) -> &BindTargets {
        &self.targets
    }

    /// Returns the first listener task that has already exited, if any.
    ///
    /// `run_tcp_server` creates its listener *inside* the spawned task and
    /// `.unwrap()`s the result (`shoes/src/tcp/tcp_server.rs:39`, `:460`), so a
    /// failed bind does not come back as an `Err` from `start_servers` -- it shows
    /// up as a listener task that panicked. Checking for an early exit is how the
    /// engine turns that into a synchronous API error.
    pub(crate) fn take_dead_listener(&self) -> Option<JoinHandle<()>> {
        let mut listeners = self.listeners.lock().unwrap();
        let index = listeners.iter().position(|h| h.is_finished())?;
        Some(listeners.swap_remove(index))
    }

    /// Stops accepting new connections on this inbound.
    ///
    /// Established connections are deliberately left running to completion:
    /// aborting a listener task cannot reach the detached per-connection tasks it
    /// spawned. This is the "smooth handover" property for TCP.
    ///
    /// KNOWN LIMITATION (addressed in phase 4): for QUIC transports the
    /// `quinn::Endpoint` is owned by the accept task, so aborting it drops the
    /// endpoint and does tear down live QUIC connections. Graceful QUIC teardown
    /// needs a `CancellationToken` threaded into the hysteria2/tuic accept loops.
    pub(crate) fn shutdown(&self) {
        let mut listeners = self.listeners.lock().unwrap();
        for handle in listeners.drain(..) {
            handle.abort();
        }
    }
}

impl std::fmt::Debug for InboundSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundSlot")
            .field("tag", &self.info.tag)
            .field("protocol", &self.info.protocol)
            .field("bind", &self.info.bind)
            .field("users", &self.users.as_ref().map(|u| u.len()))
            .finish()
    }
}
