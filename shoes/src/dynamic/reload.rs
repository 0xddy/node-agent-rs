//! Read-copy-update for a running inbound.
//!
//! Two things have to change while an inbound is serving traffic: the rules it
//! routes by, and whether it is listening at all. This module holds the mechanism
//! for both, and nothing about when to use it -- deciding that is the embedder's
//! job, since only the embedder knows what the caller asked for.
//!
//! # The grace period is the `Arc`
//!
//! An accept loop reads its handler out of a [`HandlerSlot`] once per accepted
//! connection and hands that `Arc` to the connection. Everything the connection
//! needs afterwards -- the protocol settings, the routing rules, the TLS config --
//! hangs off it, so the connection is pinned to the generation it started on. A
//! [`HandlerSlot::store`] therefore cannot affect anything already running: it
//! only changes what the *next* `load` returns. The old handler is freed when its
//! last connection ends, which is the whole of the grace period; there is nothing
//! to count, drain or wait for.
//!
//! This is why the swap is at the handler rather than inside the rule list.
//! `ClientProxySelector::judge` returns a decision that borrows the rule it
//! matched, so a rule list that could change under a live borrow would need every
//! caller to hold a guard. Replacing the handler wholesale needs no such
//! cooperation, and it can change strictly more: protocol options and
//! certificates travel with it.
//!
//! # Stopping a listener without stopping its connections
//!
//! Every accepted connection is `tokio::spawn`ed, so a listener task is only ever
//! the accept loop -- cancelling it cannot reach the connections it started. That
//! is what makes [`ServerHandle::shutdown`] safe for TCP: the token stops the
//! loop, the listener is dropped, the port is free, and established sessions run
//! to completion against the rules they were accepted under.
//!
//! QUIC cannot be quite that clean. Its connections are multiplexed over one UDP
//! socket owned by the endpoint, so releasing the port *is* tearing the
//! connections down. The accept loops there stop accepting, refuse new handshakes
//! and then wait for the live connections to finish, bounded, before dropping the
//! endpoint -- see `quic_server::QUIC_DRAIN_TIMEOUT`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use log::debug;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{BindLocation, ConfigSelection, ServerConfig, Transport};
use crate::dynamic::UserRegistry;
use crate::resolver::Resolver;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;

/// How long [`ServerHandle::shutdown`] waits for an *aborted* listener to
/// actually stop before it gives up and returns anyway.
///
/// Short on purpose: by this point the listener has already ignored both its
/// cancellation token and the caller's drain budget, so this is not a grace
/// period so much as the last chance for the runtime to run the cancellation.
const ABORT_GRACE: Duration = Duration::from_millis(250);

/// `ArcSwap` stores a thin pointer and `Arc<dyn TcpServerHandler>` is a fat one,
/// so the trait object goes behind one sized indirection.
struct HandlerCell(Arc<dyn TcpServerHandler>);

/// The handler an accept loop hands to each connection it accepts, replaceable
/// while the listener stays up.
///
/// See the module docs for why the swap lives here and what makes it safe.
pub struct HandlerSlot {
    current: ArcSwap<HandlerCell>,
    generation: AtomicU64,
}

impl HandlerSlot {
    pub fn new(handler: Arc<dyn TcpServerHandler>) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(HandlerCell(handler)),
            generation: AtomicU64::new(0),
        })
    }

    /// The handler for a connection being accepted now.
    ///
    /// On the hot path, once per connection. `load` is a lock-free read; the clone
    /// is one uncontended refcount bump, the same one the old
    /// `server_handler.clone()` did.
    #[inline]
    pub fn load(&self) -> Arc<dyn TcpServerHandler> {
        Arc::clone(&self.current.load().0)
    }

    /// Install `handler` for connections accepted from here on, and return the
    /// generation it was given.
    ///
    /// Connections already running keep the handler they were accepted with.
    pub fn store(&self, handler: Arc<dyn TcpServerHandler>) -> u64 {
        self.current.store(Arc::new(HandlerCell(handler)));
        self.generation.fetch_add(1, Ordering::Release) + 1
    }

    /// How many times this slot has been swapped since the listener started.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for HandlerSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerSlot")
            .field("generation", &self.generation())
            .field("handler", &self.current.load().0)
            .finish()
    }
}

/// Which listener a [`HandlerSlot`] belongs to.
///
/// Handlers are shared per bind IP rather than per port: a protocol's state does
/// not depend on the port, but some of it does depend on the address it will hand
/// out to clients, so two ports on one IP share a handler and two IPs never do.
/// A unix socket has no address to share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HandlerKey {
    Ip(IpAddr),
    Path,
}

/// One started inbound: its listener tasks, their handler slots, and the token
/// that stops them.
///
/// Dropping this does **not** stop anything. The listeners hold their own clones
/// of the token and the slots, so an embedder that never wants to reload or stop
/// can throw the handle away -- which is what [`crate::tcp::tcp_server::start_servers`]
/// does for a config-file run.
pub struct ServerHandle {
    transport: Transport,
    /// Every address this inbound listens on, in the order they were bound.
    /// Compared against a new config on reload: a different listen set is a
    /// different set of listeners, which is not something to change silently.
    binds: Vec<SocketAddr>,
    /// Empty for a protocol that authenticates inside its own accept loop
    /// (hysteria2, TUIC): those never go through a `TcpServerHandler`, so there is
    /// nothing here to swap.
    slots: Vec<(HandlerKey, Arc<HandlerSlot>)>,
    cancel: CancellationToken,
    listeners: Mutex<Vec<JoinHandle<()>>>,
}

impl ServerHandle {
    pub(crate) fn new(transport: Transport, cancel: CancellationToken) -> Self {
        Self {
            transport,
            binds: Vec::new(),
            slots: Vec::new(),
            cancel,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// The token every listener task in this handle selects on.
    pub(crate) fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub(crate) fn push_listener(&mut self, handle: JoinHandle<()>) {
        self.listeners.lock().unwrap().push(handle);
    }

    pub(crate) fn push_address(&mut self, address: SocketAddr) {
        self.binds.push(address);
    }

    /// Record the slot serving `ip`, or return the one already recorded for it.
    ///
    /// Mirrors the `HashMap<IpAddr, _>` the start functions use to share a handler
    /// between two ports on one address.
    pub(crate) fn slot_for_ip(
        &mut self,
        ip: IpAddr,
        build: impl FnOnce() -> Arc<dyn TcpServerHandler>,
    ) -> Arc<HandlerSlot> {
        let key = HandlerKey::Ip(ip);
        if let Some((_, slot)) = self.slots.iter().find(|(k, _)| *k == key) {
            return Arc::clone(slot);
        }
        let slot = HandlerSlot::new(build());
        self.slots.push((key, Arc::clone(&slot)));
        slot
    }

    pub(crate) fn slot_for_path(&mut self, handler: Arc<dyn TcpServerHandler>) -> Arc<HandlerSlot> {
        let slot = HandlerSlot::new(handler);
        self.slots.push((HandlerKey::Path, Arc::clone(&slot)));
        slot
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.lock().unwrap().len()
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.binds
    }

    /// The highest generation any of this inbound's slots has reached.
    pub fn generation(&self) -> u64 {
        self.slots
            .iter()
            .map(|(_, slot)| slot.generation())
            .max()
            .unwrap_or(0)
    }

    /// Returns the first listener task that has already exited, if any.
    ///
    /// The start functions create their listener *inside* the spawned task and
    /// `.unwrap()` the result, so a failed bind does not come back as an `Err` --
    /// it shows up as a listener task that panicked. Checking for an early exit is
    /// how an embedder turns that into a synchronous error.
    pub fn take_dead_listener(&self) -> Option<JoinHandle<()>> {
        let mut listeners = self.listeners.lock().unwrap();
        let index = listeners.iter().position(|h| h.is_finished())?;
        Some(listeners.swap_remove(index))
    }

    /// Everything about a reload that can fail, without doing any of it.
    ///
    /// One config becomes several `ServerConfig`s when its groups are expanded, so
    /// an embedder reloading several handles at once can check them all first and
    /// keep the whole reload all-or-nothing rather than half applied.
    pub fn check_reload(&self, config: &ServerConfig) -> std::io::Result<()> {
        if config.transport != self.transport {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot change transport in place: listening as {:?}, config says {:?}",
                    self.transport, config.transport
                ),
            ));
        }

        if self.slots.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this protocol authenticates inside its own accept loop, so its \
                 settings are fixed until the listener is replaced",
            ));
        }

        self.check_bind_location(&config.bind_location)?;

        if config.rules.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no rules to route by",
            ));
        }

        Ok(())
    }

    /// Rebuild this inbound's handlers from `config` and swap them in.
    ///
    /// Nothing rebinds and no connection is disturbed: the listeners keep running
    /// and the connections they have already accepted keep the handler they
    /// started with. Only connections accepted after this returns see `config`.
    ///
    /// For a TCP inbound this covers everything above the socket -- routing rules,
    /// protocol options, TLS certificates -- because all of it is built into the
    /// handler. For QUIC the certificates are in the endpoint instead, so they are
    /// fixed until the listener is replaced.
    ///
    /// `users` must be the same registry the inbound was started with if it has
    /// one, so that online users and their counters survive the swap.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::check_reload`] rejects, and nothing else: once the checks
    /// pass, building and storing the handlers cannot fail.
    pub fn reload(
        &self,
        config: ServerConfig,
        resolver: &Arc<dyn Resolver>,
        users: Option<&Arc<dyn UserRegistry>>,
    ) -> std::io::Result<u64> {
        self.check_reload(&config)?;

        let ServerConfig {
            protocol, rules, ..
        } = config;

        let rules = rules.map(ConfigSelection::unwrap_config).into_vec();

        // Built once and shared by every handler, exactly as at start: the
        // selector is immutable, and sharing it means one rule set and one
        // routing cache per inbound rather than per bind IP.
        let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));

        // Everything fallible is done before the first store, so a rejected reload
        // leaves every slot on its previous generation rather than half of them.
        let mut rebuilt = Vec::with_capacity(self.slots.len());
        for (key, slot) in &self.slots {
            let bind_ip = match key {
                HandlerKey::Ip(ip) => Some(*ip),
                HandlerKey::Path => None,
            };
            let handler: Arc<dyn TcpServerHandler> =
                create_tcp_server_handler(protocol.clone(), &selector, resolver, bind_ip, users)
                    .into();
            rebuilt.push((slot, handler));
        }

        let mut generation = 0;
        for (slot, handler) in rebuilt {
            generation = generation.max(slot.store(handler));
        }

        debug!(
            "reloaded {} handler slot(s) on {:?} to generation {generation}",
            self.slots.len(),
            self.binds
        );

        Ok(generation)
    }

    /// Rejects a config whose listen set is not the one this handle is serving.
    fn check_bind_location(&self, bind_location: &BindLocation) -> std::io::Result<()> {
        match bind_location {
            BindLocation::Address(addresses) => {
                let mut wanted = Vec::new();
                for address in addresses.clone().into_vec() {
                    wanted.extend(address.to_socket_addrs()?);
                }
                wanted.sort();
                wanted.dedup();

                let mut running = self.binds.clone();
                running.sort();
                running.dedup();

                if wanted != running {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "cannot change the listen set in place: listening on {}, config says {}",
                            display_addresses(&running),
                            display_addresses(&wanted)
                        ),
                    ));
                }
                Ok(())
            }
            BindLocation::Path(_) => {
                if self.slots.iter().any(|(key, _)| *key == HandlerKey::Path) {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot move from an address to a unix socket in place",
                    ))
                }
            }
        }
    }

    /// Stop accepting new connections, and wait for the listeners to let go of
    /// their sockets.
    ///
    /// Established connections are deliberately left running: they were spawned
    /// off the accept loop and hold their own handler, so they finish under the
    /// rules they started with. For TCP the wait is only as long as it takes the
    /// accept loop to notice; for QUIC it also covers the endpoint's own drain,
    /// which is why there is a bound. A listener still running when `drain`
    /// elapses is aborted, which for QUIC does cut its connections short.
    pub async fn shutdown(&self, drain: Duration) {
        self.cancel.cancel();

        let mut listeners: Vec<JoinHandle<()>> = {
            let mut guard = self.listeners.lock().unwrap();
            guard.drain(..).collect()
        };
        if listeners.is_empty() {
            return;
        }

        let joined = futures::future::join_all(listeners.iter_mut());
        if tokio::time::timeout(drain, joined).await.is_err() {
            debug!(
                "listener(s) on {:?} did not stop within {drain:?}; aborting",
                self.binds
            );
            for handle in &listeners {
                handle.abort();
            }
            // `abort` only *schedules* the cancellation. Awaiting the handles
            // afterwards is what makes "the sockets are free when this returns"
            // true rather than nearly true -- a caller handing the same address
            // to a new inbound would otherwise race the dying task.
            //
            // Finished handles are filtered out because their output was already
            // taken by the join above, and polling a `JoinHandle` twice panics.
            let aborted =
                futures::future::join_all(listeners.iter_mut().filter(|task| !task.is_finished()));
            // Bounded again: a task that cannot be stopped at all must not turn a
            // shutdown into a hang.
            if tokio::time::timeout(ABORT_GRACE, aborted).await.is_err() {
                debug!(
                    "listener(s) on {:?} still had not stopped {ABORT_GRACE:?} after being aborted",
                    self.binds
                );
            }
        }
    }

    /// The listener tasks, for a caller that will never reload or stop this
    /// inbound and only wants something to await on.
    pub fn into_listeners(self) -> Vec<JoinHandle<()>> {
        self.listeners.into_inner().unwrap()
    }

    /// Fold another handle's listeners, slots and addresses into this one.
    ///
    /// One config can produce several sets of listeners; they share a cancellation
    /// token so the embedder holds one handle per inbound rather than one per
    /// listener.
    pub(crate) fn absorb(&mut self, other: ServerHandle) {
        let ServerHandle {
            binds,
            slots,
            listeners,
            ..
        } = other;
        self.binds.extend(binds);
        self.slots.extend(slots);
        self.listeners
            .lock()
            .unwrap()
            .extend(listeners.into_inner().unwrap());
    }
}

fn display_addresses(addresses: &[SocketAddr]) -> String {
    if addresses.is_empty() {
        return "nothing".to_string();
    }
    addresses
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("transport", &self.transport)
            .field("binds", &self.binds)
            .field("slots", &self.slots.len())
            .field("generation", &self.generation())
            .field("listeners", &self.listener_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;

    use crate::async_stream::AsyncStream;
    use crate::tcp::tcp_handler::TcpServerSetupResult;

    /// A handler that does nothing but say which generation it belongs to.
    ///
    /// `TcpServerHandler` requires `Debug`, so its rendering is enough to tell two
    /// handlers apart without setting up a stream for them.
    #[derive(Debug)]
    struct Marker(&'static str);

    #[async_trait]
    impl TcpServerHandler for Marker {
        async fn setup_server_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Err(std::io::Error::other(self.0))
        }
    }

    fn marker(name: &'static str) -> Arc<dyn TcpServerHandler> {
        Arc::new(Marker(name))
    }

    fn name_of(handler: &Arc<dyn TcpServerHandler>) -> String {
        format!("{handler:?}")
    }

    fn resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }

    #[test]
    fn load_returns_the_current_handler() {
        let slot = HandlerSlot::new(marker("first"));
        assert_eq!(name_of(&slot.load()), "Marker(\"first\")");
        assert_eq!(slot.generation(), 0);
    }

    #[test]
    fn store_changes_what_the_next_load_sees() {
        let slot = HandlerSlot::new(marker("first"));
        assert_eq!(slot.store(marker("second")), 1);
        assert_eq!(name_of(&slot.load()), "Marker(\"second\")");
        assert_eq!(slot.generation(), 1);
    }

    #[test]
    fn a_handler_already_loaded_is_unaffected_by_a_store() {
        // The whole of the RCU guarantee: a connection accepted before the swap
        // keeps the handler it was given, for as long as it holds the `Arc`.
        let slot = HandlerSlot::new(marker("old"));
        let in_flight = slot.load();
        slot.store(marker("new"));
        assert_eq!(name_of(&in_flight), "Marker(\"old\")");
        assert_eq!(name_of(&slot.load()), "Marker(\"new\")");
    }

    #[test]
    fn slots_are_shared_per_ip_and_not_across_ips() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        let first = handle.slot_for_ip("127.0.0.1".parse().unwrap(), || marker("a"));
        let same = handle.slot_for_ip("127.0.0.1".parse().unwrap(), || marker("b"));
        let other = handle.slot_for_ip("127.0.0.2".parse().unwrap(), || marker("c"));

        assert!(Arc::ptr_eq(&first, &same), "one handler per bind IP");
        assert!(!Arc::ptr_eq(&first, &other), "never shared across IPs");
        assert_eq!(handle.slots.len(), 2);
    }

    #[tokio::test]
    async fn shutdown_cancels_the_listeners_it_holds() {
        let cancel = CancellationToken::new();
        let mut handle = ServerHandle::new(Transport::Tcp, cancel.clone());
        let token = cancel.clone();
        handle.push_listener(tokio::spawn(async move { token.cancelled().await }));

        handle.shutdown(Duration::from_secs(5)).await;

        assert!(cancel.is_cancelled());
        assert_eq!(handle.listener_count(), 0);
    }

    #[tokio::test]
    async fn shutdown_aborts_a_listener_that_ignores_the_token() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        let stuck = tokio::spawn(std::future::pending::<()>());
        let abort_handle = stuck.abort_handle();
        handle.push_listener(stuck);

        // Short bound: the point is that shutdown returns rather than hanging.
        handle.shutdown(Duration::from_millis(50)).await;

        // Not merely "abort was called": shutdown waits for the abort to land, so
        // that a caller may reuse the address the moment this returns.
        assert!(abort_handle.is_finished());
    }

    #[test]
    fn a_handle_without_slots_refuses_to_reload() {
        // hysteria2 and TUIC: nothing to swap, so say so instead of pretending.
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        let config: ServerConfig =
            serde_yaml::from_str("address: 127.0.0.1:1080\nprotocol:\n  type: socks\n").unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("no slots to swap");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn reload_rejects_a_different_listen_set() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.slot_for_ip("127.0.0.1".parse().unwrap(), || marker("running"));

        let config: ServerConfig =
            serde_yaml::from_str("address: 127.0.0.1:1081\nprotocol:\n  type: socks\n").unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("the port moved");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("127.0.0.1:1081"),
            "the message should name both sets: {err}"
        );
    }

    #[test]
    fn reload_rejects_a_different_transport() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.slot_for_ip("127.0.0.1".parse().unwrap(), || marker("running"));

        let config: ServerConfig = serde_yaml::from_str(
            "address: 127.0.0.1:1080\ntransport: quic\nprotocol:\n  type: socks\n",
        )
        .unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("the transport changed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reload_swaps_every_slot_and_reports_one_generation() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.push_address("127.0.0.1:1081".parse().unwrap());
        let shared = handle.slot_for_ip("127.0.0.1".parse().unwrap(), || marker("old"));

        let config: ServerConfig = serde_yaml::from_str(
            "address:\n  - 127.0.0.1:1080\n  - 127.0.0.1:1081\nprotocol:\n  type: socks\n",
        )
        .unwrap();

        let in_flight = shared.load();
        assert_eq!(handle.reload(config, &resolver(), None).unwrap(), 1);
        assert_eq!(handle.generation(), 1);
        // The slot now holds a real socks handler, but the connection that loaded
        // before the swap still holds the marker.
        assert_eq!(name_of(&in_flight), "Marker(\"old\")");
        assert_ne!(name_of(&shared.load()), "Marker(\"old\")");
    }
}
