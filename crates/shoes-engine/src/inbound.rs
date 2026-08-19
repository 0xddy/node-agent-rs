use std::net::SocketAddr;
use std::sync::Mutex;

use shoes_api::InboundInfo;
use tokio::task::JoinHandle;

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
}

impl InboundSlot {
    pub(crate) fn new(
        info: InboundInfo,
        targets: BindTargets,
        listeners: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            info,
            targets,
            listeners: Mutex::new(listeners),
        }
    }

    pub fn info(&self) -> &InboundInfo {
        &self.info
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
            .finish()
    }
}
