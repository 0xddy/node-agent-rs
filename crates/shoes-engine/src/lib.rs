//! Dynamic, API-driven engine facade over the shoes proxy core.
//!
//! # Why this crate exists
//!
//! Upstream shoes is a config-file-driven CLI: `main.rs` loads YAML, validates
//! it, starts every listener, and then blocks forever. This crate provides the
//! same startup path *without* a config file, so the process can come up with
//! **zero inbounds and zero users** and be populated afterwards over an API.
//!
//! # Layering
//!
//! `shoes/` stays an **engine**. It gets extension points -- a trait to look a
//! credential up, a per-user record to account against -- and nothing that decides
//! policy, speaks a wire protocol to an operator, or manages a process. Concretely,
//! nothing under `shoes/src/dynamic/` knows about HTTP, JSON, or a user database.
//!
//! The dependency list is the test, and it is easy to apply: `shoes/src/dynamic/`
//! added exactly one crate, `arc-swap`, for the pointer swap a reload is built on.
//! That is a concurrency primitive of the same kind as the `tokio` already there. If
//! a change to this module would need a transport or a store, it belongs out here
//! instead.
//!
//! Everything application-shaped lives out here:
//!
//! | crate | role |
//! |---|---|
//! | `shoes` | the proxy engine, plus the hooks below |
//! | `shoes-engine` | **the integration point**: programmatic control of inbounds and users |
//! | `shoes-api` | the argument and report types those methods use, re-exported here |
//!
//! There is deliberately no crate above this one. An embedder links `shoes-engine`
//! as a library and drives [`Engine`] directly from its own service layer -- gRPC,
//! HTTP, FFI, whatever it already speaks. This repository does not ship a wire
//! protocol or a daemon, because doing so would put policy and transport decisions
//! in the one place that has to stay mergeable with upstream.
//!
//! # Invasiveness
//!
//! Nothing here reimplements shoes logic. Every step reuses the exact upstream
//! entry points that `main.rs` uses:
//!
//! | step | upstream item |
//! |---|---|
//! | inline file-backed certs | [`shoes::config::convert_cert_paths`] |
//! | validate + expand groups | [`shoes::config::create_server_configs`] |
//! | build resolvers | [`shoes::dns::build_dns_registry`] |
//! | start listeners | [`shoes::tcp::tcp_server::start_servers_with_users`] |
//!
//! The footprint inside `shoes/`, which is what every future merge of upstream has
//! to survive, is roughly 3,200 new lines under `src/dynamic/` plus 28 touched files
//! elsewhere. Those 28 are of four kinds:
//!
//! - **Visibility widenings**: `pub mod tcp;`, `pub mod socket_util;`,
//!   `pub mod dynamic;`, and exporting `DnsRegistry`. Plus one dependency,
//!   `arc-swap`; `[profile.release]` moved to the workspace root because Cargo
//!   ignores profiles declared by a non-root member; and a package-scoped
//!   `[lints.clippy]` allow, without which `--all-targets` will not lint any test
//!   code in the workspace.
//! - **The new `shoes::dynamic` module**: the [`shoes::dynamic::UserRegistry`] trait,
//!   the per-user record it returns, the traffic meter, the reload slots, wire-format
//!   credential derivation, and a `StaticUserRegistry` for config-file users.
//! - **Registry injection at eight authentication sites**: VLESS, Trojan, VMess,
//!   Shadowsocks 2022, Hysteria2, TUIC, AnyTLS and NaiveProxy now ask a registry
//!   instead of comparing against a hardcoded credential. NaiveProxy's own
//!   `UserLookup` was deleted, since the registry answers everything it answered.
//! - **Metering and reload threading**: an `Option<Arc<dyn UserRegistry>>` and a
//!   `metered` flag through the handler factory and the accept loops, and a
//!   `HandlerSlot` (or, for the two QUIC-native protocols, a `SelectorSlot`) where a
//!   bare handler or selector used to sit.
//!
//! Two of those sites brought new wire-format code with them --
//! `shadowsocks/eih.rs` for 2022 identity headers, `vmess/auth.rs` for auth ids --
//! which lives inside `shoes/` on purpose: it is protocol, and putting it out here
//! would mean a second implementation of a wire format in the tree.
//!
//! The third point is the only upstream *behaviour* change, and it is behaviour
//! preserving by construction: with no registry injected, each handler builds a
//! `StaticUserRegistry` holding exactly the credentials from its own config, so a
//! plain YAML config authenticates precisely as it did before.
//!
//! `docs/dynamic-engine-design.md` covers the design these hooks implement, and
//! collects the invariants a new protocol conversion has to preserve.

pub const DATA_PLANE_VERSION: &str = shoes::VERSION;

mod error;
mod inbound;
mod protocol;
mod users;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use log::{debug, info, warn};
use tokio::task::{JoinError, JoinHandle};

use shoes::config::{
    BindLocation, Config, ExpandedDnsGroup, ServerConfig, Transport, ValidatedConfigs,
    convert_cert_paths,
};
use shoes::dns::{DnsRegistry, build_dns_registry};
use shoes::dynamic::{ServerHandle, UserRegistry};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_server::start_servers_with_users;

pub use error::{EngineError, EngineResult};
pub use inbound::InboundSlot;
/// The vocabulary of [`Engine`]'s own method signatures, re-exported so that an
/// embedder needs exactly one dependency to write against it.
///
/// These live in a separate crate only because conversion code -- a gRPC service, an
/// FFI shim -- may want to name them without linking the proxy engine. Whether that
/// crate stays separate is an implementation detail nobody depending on
/// `shoes-engine` has to care about.
pub use shoes_api::{EngineStatus, InboundInfo, InboundSpec, UserInfo, UserSpec};
pub use users::{CredentialKinds, MemoryUserRegistry};

use inbound::{BindKey, BindTargets, SocketKind};

/// How long to wait before deciding a freshly started listener is healthy.
///
/// See [`InboundSlot::take_dead_listener`] for why this probe is needed at all.
const LISTENER_HEALTH_GRACE: Duration = Duration::from_millis(50);

/// State that may only be touched by one control-plane operation at a time.
///
/// Serialising mutations is what lets the engine treat its own address registry
/// as authoritative: two concurrent `add_inbound` calls can never both pass the
/// conflict check for the same port.
struct ControlState {
    /// Shared resolver registry for inbounds that do not declare their own DNS.
    dns: DnsRegistry,
}

struct EngineInner {
    control: tokio::sync::Mutex<ControlState>,
    /// tag -> inbound. Read-mostly and lock-free, so `list_inbounds` never
    /// contends with an in-flight reload.
    inbounds: DashMap<String, Arc<InboundSlot>>,
    /// bind address -> owning tag.
    bound: DashMap<BindKey, String>,
}

impl Drop for EngineInner {
    /// Stop accepting on every inbound when the last [`Engine`] handle goes.
    ///
    /// An engine is the only thing that can name its inbounds, so an engine that has
    /// been dropped leaves listeners nobody can reach: still bound, still serving,
    /// still authenticating against registries no caller can change. Whatever an
    /// embedder meant by dropping their last handle, it was not that.
    ///
    /// Only the synchronous half -- `Drop` cannot await a drain, and this may well be
    /// running with no runtime left to spawn one on. Established connections are left
    /// to finish, which is the same thing `remove_inbound` does.
    fn drop(&mut self) {
        for entry in self.inbounds.iter() {
            entry.value().stop_accepting();
        }
    }
}

/// Handle to a running engine. Cheap to clone; all clones share one instance.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

impl Engine {
    /// Brings up the engine with no inbounds, no users, and no config file.
    ///
    /// This is the "empty state" requirement: the process is fully operational
    /// and merely has nothing to do yet.
    pub async fn bootstrap() -> EngineResult<Self> {
        // What `main` does before it parses anything: shoes' QUIC paths read a
        // process-wide thread count to size their endpoint pools, and they `unwrap`
        // it, so an embedder that skipped this would panic the first time an operator
        // added a QUIC inbound rather than at startup. Repeat calls are ignored, so
        // this is safe in a process that bootstraps more than one engine.
        shoes::dynamic::set_num_threads(std::cmp::max(
            2,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        ));

        // An empty group list yields an empty registry that lazily creates the
        // default system resolver on first use (`dns/builder.rs:47`).
        let dns = build_dns_registry(vec![]).await?;

        info!("engine bootstrapped with 0 inbounds");

        Ok(Self {
            inner: Arc::new(EngineInner {
                control: tokio::sync::Mutex::new(ControlState { dns }),
                inbounds: DashMap::new(),
                bound: DashMap::new(),
            }),
        })
    }

    pub fn status(&self) -> EngineStatus {
        let mut bound_addresses: Vec<String> = self
            .inner
            .bound
            .iter()
            .map(|entry| entry.key().to_string())
            .collect();
        bound_addresses.sort();

        EngineStatus {
            version: DATA_PLANE_VERSION.to_string(),
            inbounds: self.inner.inbounds.len(),
            bound_addresses,
        }
    }

    pub fn list_inbounds(&self) -> Vec<InboundInfo> {
        let mut infos: Vec<InboundInfo> = self
            .inner
            .inbounds
            .iter()
            .map(|entry| entry.value().describe())
            .collect();
        infos.sort_by(|a, b| a.tag.cmp(&b.tag));
        infos
    }

    pub fn get_inbound(&self, tag: &str) -> Option<Arc<InboundSlot>> {
        self.inner.inbounds.get(tag).map(|e| e.value().clone())
    }

    /// Validates a complete inbound payload without opening sockets or changing
    /// engine state.
    ///
    /// A control plane should call this before replacing a running inbound. It
    /// checks the shoes schema and all dynamic-user credential constraints, so an
    /// invalid candidate can be rejected while the healthy listener is still up.
    /// Bind conflicts and operating-system failures are necessarily checked by
    /// [`Self::add_inbound`] when the replacement is actually started.
    pub async fn validate_inbound(&self, spec: &InboundSpec) -> EngineResult<()> {
        let tag = spec.tag.trim();
        if tag.is_empty() {
            return Err(EngineError::InvalidConfig("tag must not be empty".into()));
        }

        let mut config = spec.config.clone();
        if spec.users.is_some() {
            protocol::install_placeholder_credentials(&mut config)?;
        }

        let ValidatedInbound {
            configs: server_configs,
            ..
        } = validate_inbound_config(config).await?;

        if let Some(users) = &spec.users {
            Self::build_user_registry(&server_configs, users.clone())?;
        }

        // Resolve and de-duplicate the candidate's own listen set as well. Do not
        // compare it with `inner.bound` here: the ordinary reason to preflight is
        // replacing an inbound that already owns the same socket.
        let mut claimed = Vec::new();
        for server_config in &server_configs {
            let targets =
                resolve_bind_targets(&server_config.bind_location, &server_config.transport)?;
            for key in targets.keys() {
                if claimed.contains(&key) {
                    return Err(EngineError::AddressInUse {
                        address: key.to_string(),
                        tag: tag.to_string(),
                    });
                }
                claimed.push(key);
            }
        }

        Ok(())
    }

    /// Validates, binds and starts one inbound, then registers it under `tag`.
    ///
    /// On any failure the engine is left exactly as it was: partially started
    /// listeners are torn down and no address is left claimed.
    ///
    /// When `spec.users` is present the inbound is put in dynamic mode: an
    /// in-memory registry becomes its sole credential authority, and it is live
    /// from the first accepted connection onward. See
    /// [`Engine::build_user_registry`] for what "present" is allowed to mean.
    ///
    /// # If this future is dropped
    ///
    /// Sockets are opened before the inbound is registered, so a cancelled call can
    /// land in between. It does not leak: the listeners are told to stop, and the
    /// addresses are never claimed. What it cannot promise is *when* they are free,
    /// since nothing is left to await the drain -- so a caller that retries the same
    /// address immediately may lose a race with the listener it just cancelled.
    /// Driving this future to completion and calling [`Engine::remove_inbound`]
    /// avoids the question.
    pub async fn add_inbound(&self, spec: InboundSpec) -> EngineResult<InboundInfo> {
        let InboundSpec {
            tag,
            mut config,
            users,
        } = spec;

        if tag.trim().is_empty() {
            return Err(EngineError::InvalidConfig("tag must not be empty".into()));
        }

        // In dynamic mode the protocol's own credential field is dead but still
        // mandatory in shoes' schema, so fill it before deserializing. This also
        // rejects a caller-supplied credential, which would otherwise be silently
        // overruled by the registry.
        if users.is_some() {
            protocol::install_placeholder_credentials(&mut config)?;
        }

        // Parse and validate *before* taking the control lock: a malformed
        // payload should not delay other operations.
        let ValidatedInbound {
            configs: server_configs,
            dns_groups,
        } = validate_inbound_config(config).await?;

        let registry = match users {
            Some(users) => Some(Self::build_user_registry(&server_configs, users)?),
            None => None,
        };

        let mut control = self.inner.control.lock().await;

        if self.inner.inbounds.contains_key(&tag) {
            return Err(EngineError::DuplicateTag(tag));
        }

        // Resolve every listen target up front so conflicts are caught before a
        // single socket is opened.
        let mut targets = Vec::with_capacity(server_configs.len());
        for server_config in &server_configs {
            targets.push(resolve_bind_targets(
                &server_config.bind_location,
                &server_config.transport,
            )?);
        }

        // Two inbounds in one payload can collide with each other as easily as with
        // one already running, and neither is registered yet.
        let mut claimed: Vec<BindKey> = Vec::new();
        for target in &targets {
            for key in target.keys() {
                if let Some(owner) = self.inner.bound.get(&key) {
                    return Err(EngineError::AddressInUse {
                        address: key.to_string(),
                        tag: owner.value().clone(),
                    });
                }
                if claimed.contains(&key) {
                    return Err(EngineError::AddressInUse {
                        address: key.to_string(),
                        tag: tag.clone(),
                    });
                }
                claimed.push(key);
            }

            // Faithful pre-flight bind, using the same socket options as the real
            // listener. This catches permission errors and invalid addresses
            // synchronously, with the actual OS error, instead of letting them
            // surface as a panic inside a detached listener task. A unix socket has
            // no `kind`, and probing one would create the very file the listener is
            // about to warn about replacing.
            if let Some(kind) = target.kind() {
                for address in target.addresses() {
                    probe_bind(*address, kind)?;
                }
            }
        }

        let protocol = protocol::display_name(&server_configs[0].protocol);
        let transport = transport_name(&server_configs[0].transport).to_string();

        // Listeners are live from the moment `start_servers_with_users` returns, but
        // this inbound is not registered until the health probe below passes -- and
        // in between there are awaits. A caller whose request is cancelled there (a
        // gRPC client hanging up, a request timeout) drops this whole future, and
        // without the guard the listeners would go on serving with no tag left to
        // name them and no way to stop them. See [`AbandonOnDrop`].
        let mut started = AbandonOnDrop::new();
        let mut bind_display: Vec<String> = Vec::new();

        for (server_config, target) in server_configs.into_iter().zip(targets.iter()) {
            let resolver = match Self::resolver_for(&mut control, &server_config, &dns_groups).await
            {
                Ok(resolver) => resolver,
                Err(e) => {
                    inbound::abandon(started.disarm()).await;
                    return Err(e);
                }
            };

            // `Arc<MemoryUserRegistry>` is cloned per listener, so every handler
            // built from this spec authenticates against the one same table.
            let registry_ref = registry.clone().map(|r| r as Arc<dyn UserRegistry>);

            match start_servers_with_users(Config::Server(server_config), resolver, registry_ref)
                .await
            {
                Ok(handle) => started.push(handle),
                Err(e) => {
                    // Roll back anything already started under this tag.
                    inbound::abandon(started.disarm()).await;
                    return Err(EngineError::Io(e));
                }
            }

            bind_display.extend(target.display());
        }

        let info = InboundInfo {
            tag: tag.clone(),
            protocol,
            transport,
            bind: bind_display,
            listeners: started.listener_count(),
            // Both filled in live by `InboundSlot::describe`; see its doc comment.
            revision: 0,
            users: None,
        };

        // Give the listener tasks a moment to fail, then confirm they are alive. The
        // guard is still armed across this await, which is the longest of the
        // unregistered windows.
        tokio::time::sleep(LISTENER_HEALTH_GRACE).await;
        if let Some(dead) = started.take_dead_listener() {
            let reason = describe_dead_listener(dead).await;
            inbound::abandon(started.disarm()).await;
            return Err(EngineError::Io(std::io::Error::other(format!(
                "inbound {tag} failed to start: {reason}"
            ))));
        }

        // From here the slot owns the listeners and registration is synchronous, so
        // there is no longer a window for the guard to cover.
        //
        // `claimed` is every key across every target, already checked for conflicts
        // above. Reusing it rather than re-deriving addresses is what makes a unix
        // socket releasable: the flattening this replaced kept only `SocketAddr`s,
        // so a path was never recorded and never freed.
        let slot = Arc::new(InboundSlot::new(
            info.clone(),
            claimed.clone(),
            started.disarm(),
            registry,
        ));

        let info = slot.describe();

        for key in &claimed {
            self.inner.bound.insert(key.clone(), tag.clone());
        }
        self.inner.inbounds.insert(tag.clone(), slot);

        info!(
            "inbound {} started: {} over {} on {} ({})",
            info.tag,
            info.protocol,
            info.transport,
            info.bind.join(", "),
            match info.users {
                Some(0) => "dynamic users, none registered yet".to_string(),
                Some(n) => format!("{n} dynamic user(s)"),
                None => "config credentials".to_string(),
            }
        );

        Ok(info)
    }

    /// Replaces the routing rules and protocol settings of a running inbound,
    /// without restarting its listeners.
    ///
    /// This is the RCU path. Nothing rebinds, nothing is drained, and no
    /// established connection is disturbed: each one holds the handler it was
    /// accepted with, and therefore the rules it was accepted under, until it ends.
    /// Connections accepted after this returns route by the new config.
    ///
    /// For a TCP inbound that covers everything above the socket, TLS certificates
    /// included. For QUIC the certificates belong to the endpoint rather than the
    /// handler, so those stay as they were until the inbound is replaced.
    ///
    /// # What it deliberately refuses
    ///
    /// - **A different listen set, or a different transport.** Either would mean
    ///   closing sockets and opening others, which cannot be undone if the new bind
    ///   fails, so the engine will not do it behind a caller's back. Do it as a
    ///   [`Engine::remove_inbound`] plus an [`Engine::add_inbound`] and accept the
    ///   gap in service that implies.
    /// - **A `users` list.** Users have their own endpoints, which are atomic one
    ///   user at a time; folding them into a config update would make a partly
    ///   applied update possible, and would leave "the list omits Bob" ambiguous
    ///   between revoking Bob and not mentioning him.
    /// - **Protocol settings on hysteria2 and TUIC.** These authenticate inside
    ///   their own QUIC accept loops rather than through a handler, and that loop
    ///   reads its settings once before it starts. Their *rules* do reload, through
    ///   a `SelectorSlot`; anything else in their protocol object is refused by
    ///   name rather than accepted as a no-op.
    ///
    /// The inbound's user registry is carried over untouched, so online users, their
    /// credentials and their counters all survive the swap.
    pub async fn update_inbound(&self, spec: InboundSpec) -> EngineResult<InboundInfo> {
        let InboundSpec {
            tag,
            mut config,
            users,
        } = spec;

        if users.is_some() {
            return Err(EngineError::Unsupported(format!(
                "a config update for {tag} cannot carry users; change them with \
                 add_user/remove_user, which apply one user at a time"
            )));
        }

        // Unlike `add_inbound`, the payload is prepared under the control lock:
        // whether the placeholder credential is needed depends on whether the
        // running inbound is in dynamic mode, and reading that outside the lock
        // would let a concurrent remove-and-re-add change the answer underneath.
        let mut control = self.inner.control.lock().await;

        let slot = self
            .inner
            .inbounds
            .get(&tag)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| EngineError::UnknownTag(tag.clone()))?;

        // In dynamic mode the protocol's credential field is dead but still
        // mandatory in shoes' schema. Same treatment as at creation, so an update
        // is written exactly like the add that created the inbound.
        if slot.users().is_some() {
            protocol::install_placeholder_credentials(&mut config)?;
        }

        let ValidatedInbound {
            configs: server_configs,
            dns_groups,
        } = validate_inbound_config(config).await?;

        // A reload rebuilds the handlers from this config and hands them the registry
        // the inbound already has, so an update can do everything an add can -- and an
        // update never goes through `build_user_registry`, so the refusals have to be
        // repeated here rather than inherited.
        //
        // The extra rule an update needs is that the credential shape may not change.
        // The registry was built to answer one set of questions and its users hold
        // credentials of those shapes, so a swap to a protocol asking different ones
        // is never what the caller meant. It fails in both directions and neither is
        // visible: swapping VLESS for Trojan leaves every user unable to authenticate,
        // and swapping VLESS for a plain SOCKS proxy leaves the inbound open to
        // everyone while the API still reports the users it is no longer consulting.
        if let Some(registry) = slot.users() {
            let kinds = Self::registry_kinds_for(&server_configs)?;
            if kinds != registry.kinds() {
                return Err(EngineError::ReloadRequired(format!(
                    "cannot change what this inbound authenticates with in place: its \
                     users hold {} and the new config asks for {}. Their credentials \
                     would have to be reissued, so do it as a remove plus an add",
                    registry.kinds().accepted_fields(),
                    kinds.accepted_fields()
                )));
            }
        }

        let mut paired = Vec::with_capacity(server_configs.len());
        for server_config in server_configs {
            let resolver = Self::resolver_for(&mut control, &server_config, &dns_groups).await?;
            paired.push((server_config, resolver));
        }

        let revision = slot
            .reload(paired)
            .map_err(EngineError::from_reload_rejection)?;

        let info = slot.describe();
        info!(
            "inbound {} reloaded to revision {revision}; \
             established connections keep their previous rules",
            info.tag
        );

        Ok(info)
    }

    /// Stops accepting new connections on `tag` and unregisters it.
    ///
    /// Established connections keep running to completion -- see
    /// [`InboundSlot::shutdown`] for the mechanism.
    ///
    /// Awaits the listeners letting go of their sockets before it returns, so the
    /// same addresses can be handed straight to a new inbound. For TCP that is
    /// immediate; a QUIC inbound first drains the connections that share its UDP
    /// socket, which is also why the control lock is held throughout -- the port is
    /// genuinely still in use until the drain finishes, and another `add_inbound`
    /// must not be told otherwise.
    ///
    /// # If this future is dropped
    ///
    /// Cancelling it -- a request timeout, a client hanging up -- still stops the
    /// listeners and still releases their addresses, but does not wait for the drain.
    /// So the inbound is gone either way; what a cancelled call gives up is the
    /// guarantee that the port is free the instant it returns. Rebinding the same
    /// address immediately afterwards may lose a race with a QUIC endpoint still
    /// finishing its connections.
    pub async fn remove_inbound(&self, tag: &str) -> EngineResult<InboundInfo> {
        let _control = self.inner.control.lock().await;

        let (_, slot) = self
            .inner
            .inbounds
            .remove(tag)
            .ok_or_else(|| EngineError::UnknownTag(tag.to_string()))?;

        // The slot is out of `inbounds` and its keys are still in `bound`, and the
        // drain below is an await. A caller cancelled there used to leave the
        // addresses claimed by a tag that no longer exists -- unusable, and with
        // nothing left to release them. The guard releases them whichever way this
        // future ends.
        let release = ReleaseOnDrop {
            inner: Arc::clone(&self.inner),
            slot: Arc::clone(&slot),
        };

        slot.shutdown().await;
        drop(release);

        let info = slot.describe();
        info!(
            "inbound {} stopped; established connections continue to drain",
            info.tag
        );

        Ok(info)
    }

    /// Builds the credential authority for an inbound in dynamic mode.
    ///
    /// The refusals here are the important part. Only some protocols consult a
    /// registry, so accepting a `users` list on any other one would leave the caller
    /// believing they had configured access control that is not actually consulted --
    /// fail-open, and invisible until someone connects with a credential nobody
    /// granted. So a `users` list on an inbound the registry cannot serve is an error,
    /// not a no-op.
    ///
    /// The second refusal is narrower: the inbound *is* registry-backed, but its
    /// targets disagree about what a user's one `password` field means. See
    /// [`CredentialKinds::conflict`].
    ///
    /// The check runs over the *expanded* configs, so it sees through TLS, Reality,
    /// ShadowTLS and Websocket nesting rather than just the outer protocol name.
    ///
    /// [`Engine::registry_kinds_for`] is where the refusals live, so that
    /// [`Engine::update_inbound`] applies exactly the same ones.
    fn build_user_registry(
        server_configs: &[ServerConfig],
        users: Vec<UserSpec>,
    ) -> EngineResult<Arc<MemoryUserRegistry>> {
        let kinds = Self::registry_kinds_for(server_configs)?;

        let registry = MemoryUserRegistry::new(kinds);
        for user in users {
            // Reported by id, and every id in one payload must be distinct: an
            // upsert would otherwise let a duplicate id in the same list silently
            // overwrite an earlier entry.
            let id = user
                .resolved_id()
                .ok_or_else(|| EngineError::InvalidUser("a user needs an `id` or a `uuid`".into()))?
                .to_string();
            if registry.get(&id).is_some() {
                return Err(EngineError::InvalidUser(format!(
                    "user {id} is listed twice"
                )));
            }
            registry.upsert(user)?;
        }

        Ok(registry)
    }

    /// The credential forms a dynamic inbound's registry must answer, or the reason
    /// this config cannot be governed by a `users` list at all.
    ///
    /// Three refusals, in the order that produces the most specific message:
    ///
    /// 1. **A target that leaves the inbound open, or cannot act on a registry.** The
    ///    narrowest question and the only fail-open one, so it is asked first --
    ///    `credential_kinds` returning non-empty on some *other* target would
    ///    otherwise let it through. See [`protocol::unservable_registry_target`].
    /// 2. **Nothing here authenticates through a registry.** The list would never be
    ///    consulted, so accepting it would report access control that does not exist.
    /// 3. **The targets disagree about what one `password` means.** See
    ///    [`CredentialKinds::conflict`].
    fn registry_kinds_for(server_configs: &[ServerConfig]) -> EngineResult<CredentialKinds> {
        for server_config in server_configs {
            if let Some(reason) = protocol::unservable_registry_target(&server_config.protocol) {
                return Err(EngineError::Unsupported(reason));
            }
        }

        let mut kinds = CredentialKinds::NONE;
        for server_config in server_configs {
            kinds.merge(protocol::credential_kinds(&server_config.protocol));
        }

        if kinds.is_empty() {
            return Err(EngineError::Unsupported(format!(
                "{} does not authenticate through the engine's user registry yet, so it \
                 cannot take a `users` list; omit `users` to use the credential in `config`",
                protocol::display_name(&server_configs[0].protocol)
            )));
        }
        if let Some(reason) = kinds.conflict() {
            return Err(EngineError::InvalidConfig(format!(
                "this inbound cannot take a single `users` list: {reason}"
            )));
        }

        Ok(kinds)
    }

    /// Adds or updates one user on `tag`, effective on the next handshake.
    ///
    /// Updating an existing id keeps that user's counters and their established
    /// connections; only the credential and the enabled flag are replaced.
    /// An id whose previous removal has not yet returned its final counters cannot
    /// be reused; call [`Self::remove_user`] again to collect that result first.
    pub fn add_user(&self, tag: &str, user: UserSpec) -> EngineResult<UserInfo> {
        self.registry_for(tag)?.upsert(user)
    }

    /// Removes one user from `tag` and actively closes every connection currently
    /// authenticated as them.
    ///
    /// The credential is revoked before this method waits, so no new session can
    /// race into the drain. The returned [`UserInfo`] is produced only after every
    /// registered connection has exited and therefore contains the user's final
    /// traffic and connection counters. If this future is cancelled while draining,
    /// calling `remove_user` again with the same id attaches to that removal and
    /// returns the recoverable final snapshot. The id remains reserved until that
    /// result is collected, so a re-add cannot silently discard the old counters.
    pub async fn remove_user(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        self.registry_for(tag)?.remove(tag, id).await
    }

    /// Closes every connection currently authenticated as `id` while keeping the
    /// user registered and eligible to reconnect.
    ///
    /// This is intentionally distinct from [`Self::remove_user`]. It is useful for
    /// credential rotation and remote administrative disconnects, where the old
    /// sessions must end but the current credential must remain authorized.
    pub fn kick_user(&self, tag: &str, id: &str) -> EngineResult<u64> {
        self.registry_for(tag)?.kick(tag, id)
    }

    pub fn list_users(&self, tag: &str) -> EngineResult<Vec<UserInfo>> {
        Ok(self.registry_for(tag)?.list())
    }

    /// Reports one user's traffic and zeroes it in the same step, for closing a
    /// billing period.
    ///
    /// The returned [`UserInfo`] carries the bytes that were taken, not the zeroes
    /// left behind. Reading with [`Self::get_user`] and zeroing afterwards would
    /// drop whatever moved in between; this cannot.
    ///
    /// Live and lifetime connection counts are deliberately untouched: one is
    /// current state and the other is a total, and neither belongs to a period.
    pub fn take_user_traffic(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        self.registry_for(tag)?.take_traffic(tag, id)
    }

    /// The same for every user on `tag` at once, which is the usual shape of a
    /// billing sweep.
    ///
    /// Each user is taken individually rather than as one snapshot, so traffic
    /// moving while the sweep runs is split between two periods rather than
    /// double-counted or lost. A user removed mid-sweep may be absent from the
    /// result -- [`Self::remove_user`] already reports their final counters, which is
    /// where their last bytes are.
    pub fn take_inbound_traffic(&self, tag: &str) -> EngineResult<Vec<UserInfo>> {
        Ok(self.registry_for(tag)?.take_all_traffic())
    }

    pub fn get_user(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        self.registry_for(tag)?
            .get(id)
            .ok_or_else(|| EngineError::UnknownUser {
                tag: tag.to_string(),
                id: id.to_string(),
            })
    }

    /// The user authority for `tag`, or an error explaining which of the two ways
    /// to have none applies.
    fn registry_for(&self, tag: &str) -> EngineResult<Arc<MemoryUserRegistry>> {
        let slot = self
            .inner
            .inbounds
            .get(tag)
            .ok_or_else(|| EngineError::UnknownTag(tag.to_string()))?;

        slot.users().cloned().ok_or_else(|| {
            EngineError::Unsupported(format!(
                "inbound {tag} was created without a `users` list, so its credentials come \
                 from its config and cannot be changed at runtime"
            ))
        })
    }

    /// Picks the resolver for one server config, mirroring `main.rs`.
    ///
    /// Inbounds without a `dns` section share the engine-wide registry, so they
    /// share one resolver and its cache. An inbound that declares its own DNS
    /// gets a registry built just for it; the returned `Arc<dyn Resolver>` keeps
    /// it alive after the registry itself is dropped.
    ///
    /// Takes `&mut ControlState` rather than `&self` because the caller already
    /// holds the control lock -- `tokio::sync::Mutex` is not reentrant.
    async fn resolver_for(
        control: &mut ControlState,
        server_config: &ServerConfig,
        dns_groups: &[ExpandedDnsGroup],
    ) -> EngineResult<Arc<dyn Resolver>> {
        let dns_ref = server_config.dns.as_ref();

        if dns_ref.is_none() {
            return Ok(control.dns.get_for_server(None));
        }

        // The groups come from the *same* expansion that produced `server_config`,
        // and they have to: validation rewrites an inline `dns.servers` list into a
        // generated group named `__inline_dns_N` and leaves a reference to it behind.
        // Re-expanding the rewritten config -- which is what this used to do -- finds
        // nothing inline left to extract, so the reference dangles and every inbound
        // carrying a `dns` section was rejected with the name of a group its author
        // never wrote.
        let mut registry = build_dns_registry(dns_groups.to_vec()).await?;
        Ok(registry.get_for_server(dns_ref))
    }
}

/// Turns an API payload into validated, startable server configs.
///
/// YAML 1.2 is a superset of JSON, so re-encoding the JSON payload and handing it
/// to `serde_yaml` runs it through the *same* deserializers the YAML config files
/// use -- including `ServerConfig`'s hand-written `Deserialize` impl. No parallel
/// JSON schema to maintain.
///
/// The step order mirrors `shoes/src/main.rs:339`: certs are inlined *before*
/// validation. That order is load-bearing rather than cosmetic --
/// `create_server_configs` reaches `embed_pem_from_map`, which `panic!`s on a PEM
/// path it has not seen loaded (`shoes/src/config/pem.rs:466`). Skipping the
/// conversion turns any file-backed cert into a panicked request task instead of an
/// error response.
/// One inbound's startable configs, together with the DNS groups they reference.
///
/// The two travel as a pair because validation rewrites an inline `dns.servers` list
/// into a generated group and leaves a *reference* behind. Separating them loses the
/// group, and the reference then names something nothing can resolve.
pub(crate) struct ValidatedInbound {
    configs: Vec<ServerConfig>,
    dns_groups: Vec<ExpandedDnsGroup>,
}

async fn validate_inbound_config(config: serde_json::Value) -> EngineResult<ValidatedInbound> {
    if !config.is_object() {
        return Err(EngineError::InvalidConfig(
            "config must be a single server config object".into(),
        ));
    }

    let json_text = serde_json::to_string(&config)
        .map_err(|e| EngineError::InvalidConfig(format!("could not re-encode payload: {e}")))?;

    let parsed: Config =
        serde_yaml::from_str(&json_text).map_err(|e| EngineError::InvalidConfig(e.to_string()))?;

    if !matches!(parsed, Config::Server(_)) {
        return Err(EngineError::Unsupported(
            "only `server` configs can be added through the API".into(),
        ));
    }

    // Reads any `cert`/`key` that names a file and replaces it with the PEM text.
    // A missing or unreadable file surfaces here, as an `InvalidConfig` carrying
    // the OS error, rather than as a panic inside a listener task.
    let (parsed, loaded) = convert_cert_paths(vec![parsed])
        .await
        .map_err(|e| EngineError::InvalidConfig(format!("could not load cert files: {e}")))?;
    if loaded > 0 {
        debug!("inlined {loaded} cert(s)/key(s) from files");
    }

    let ValidatedConfigs {
        configs,
        dns_groups,
    } = shoes::config::create_server_configs(parsed)
        .map_err(|e| EngineError::InvalidConfig(e.to_string()))?;

    let mut server_configs = Vec::with_capacity(configs.len());
    for config in configs {
        match config {
            Config::Server(server_config) => {
                // `start_tcp_or_quic_servers` has `Transport::Udp => todo!()`
                // (`shoes/src/tcp/tcp_server.rs:395`). Reject it here rather than
                // letting a `todo!()` panic escape into the API task.
                if matches!(server_config.transport, Transport::Udp) {
                    return Err(EngineError::Unsupported(
                        "the udp transport is not implemented upstream".into(),
                    ));
                }
                server_configs.push(server_config);
            }
            other => {
                return Err(EngineError::Unsupported(format!(
                    "config kind not startable through the API: {other:?}"
                )));
            }
        }
    }

    if server_configs.is_empty() {
        return Err(EngineError::InvalidConfig(
            "payload produced no startable server config".into(),
        ));
    }

    Ok(ValidatedInbound {
        configs: server_configs,
        dns_groups,
    })
}

fn resolve_bind_targets(
    bind_location: &BindLocation,
    transport: &Transport,
) -> EngineResult<BindTargets> {
    match bind_location {
        BindLocation::Address(addresses) => {
            let mut resolved = Vec::new();
            for address in addresses.iter() {
                resolved.extend(address.to_socket_addrs()?);
            }
            if resolved.is_empty() {
                return Err(EngineError::InvalidConfig(
                    "bind location resolved to no addresses".into(),
                ));
            }
            Ok(BindTargets::Addresses {
                addresses: resolved,
                kind: socket_kind(transport),
            })
        }
        BindLocation::Path(path) => Ok(BindTargets::Path(path.display().to_string())),
    }
}

/// Which socket a transport actually opens.
///
/// QUIC is carried on UDP, which is the whole reason the engine's registry cannot be
/// keyed on the address alone: `:443` over TCP and `:443` over QUIC are two sockets,
/// and serving HTTP/3 beside HTTP/2 means holding both.
fn socket_kind(transport: &Transport) -> SocketKind {
    match transport {
        Transport::Tcp => SocketKind::Tcp,
        // Rejected long before here as unimplemented upstream, but it is a UDP
        // socket either way and guessing TCP would be the wrong guess.
        Transport::Quic | Transport::Udp => SocketKind::Udp,
    }
}

/// Releases an inbound's address claims once it has stopped, cancelled or not.
///
/// The two steps of `remove_inbound` -- drain the listeners, then let go of the
/// addresses -- are separated by an await, and dropping the future in between left
/// the addresses claimed forever by a tag already gone from `inbounds`. Since the
/// slot is removed first, nothing else could have released them.
///
/// Deliberately releases even on the cancelled path. The listeners have been told to
/// stop by then, so holding the claim would outlast the thing it was protecting.
struct ReleaseOnDrop {
    inner: Arc<EngineInner>,
    slot: Arc<InboundSlot>,
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        // Cheap insurance on the cancelled path: `shutdown` may not have run at all.
        self.slot.stop_accepting();
        for key in self.slot.keys() {
            self.inner.bound.remove(key);
        }
    }
}

/// Listeners that are running but not yet owned by a registered inbound.
///
/// `add_inbound` starts sockets and only registers them once they have proved
/// healthy, and there are awaits in between. Dropping the future in that window --
/// which is what a cancelled request does -- would otherwise leave the listeners
/// serving with nothing left that names them: no tag to remove, no handle to stop,
/// and the port held until the process ends.
///
/// `Drop` cannot await, so this cancels the accept loops synchronously and leaves the
/// drain to whatever runtime is still there. That is weaker than
/// [`InboundSlot::shutdown`], which every non-cancelled path still uses: the sockets
/// are released shortly after rather than by the time anything returns. It is the
/// difference between a port that frees itself and one that never does.
struct AbandonOnDrop {
    handles: Vec<ServerHandle>,
}

impl AbandonOnDrop {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    fn push(&mut self, handle: ServerHandle) {
        self.handles.push(handle);
    }

    fn listener_count(&self) -> usize {
        self.handles.iter().map(ServerHandle::listener_count).sum()
    }

    /// The first listener task that has already exited, if any.
    ///
    /// `run_tcp_server` creates its listener *inside* the spawned task and
    /// `.unwrap()`s the result, so a failed bind does not come back as an `Err` from
    /// `start_servers_with_users` -- it shows up as a listener task that panicked.
    /// Checking for an early exit is how the engine turns that into a synchronous
    /// API error instead of a port that silently never opened.
    fn take_dead_listener(&self) -> Option<JoinHandle<()>> {
        self.handles
            .iter()
            .find_map(ServerHandle::take_dead_listener)
    }

    /// Hand the listeners on to whoever will own them, so `Drop` has nothing to do.
    ///
    /// Every path out of `add_inbound` calls this: the success path passes them to
    /// the slot, the error paths pass them to `abandon`, which awaits the drain
    /// properly. Only a dropped future leaves them here.
    fn disarm(&mut self) -> Vec<ServerHandle> {
        std::mem::take(&mut self.handles)
    }
}

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        warn!(
            "abandoning {} listener group(s) started for an inbound that was never              registered: the request was cancelled part-way through",
            self.handles.len()
        );
        for handle in &self.handles {
            handle.stop_accepting();
        }
    }
}

/// Opens and immediately closes a listener with the production socket options.
///
/// The socket has to match the one the listener will really open. Probing a TCP
/// listener for a QUIC inbound tests the wrong port entirely: it passes while the UDP
/// port is taken, and fails while it is free but a TCP listener holds the number.
fn probe_bind(address: SocketAddr, kind: SocketKind) -> EngineResult<()> {
    match kind {
        SocketKind::Tcp => {
            let listener = shoes::socket_util::new_tcp_listener(address, 1, None)?;
            drop(listener);
        }
        SocketKind::Udp => {
            // Same options `start_quic_servers` uses, so a failure here is the one
            // the endpoint would have hit.
            let socket = shoes::socket_util::new_socket2_udp_socket(
                address.is_ipv6(),
                None,
                Some(address),
                false,
            )?;
            drop(socket);
        }
    }
    debug!("pre-flight bind ok for {address} ({})", kind.name());
    Ok(())
}

fn transport_name(transport: &Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Quic => "quic",
        Transport::Udp => "udp",
    }
}

/// Extracts a human-readable reason from a listener task that exited early.
async fn describe_dead_listener(handle: JoinHandle<()>) -> String {
    match handle.await {
        Ok(()) => "listener task exited immediately".to_string(),
        Err(e) if e.is_panic() => panic_message(e),
        Err(e) => format!("listener task failed: {e}"),
    }
}

fn panic_message(error: JoinError) -> String {
    let payload = error.into_panic();
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else {
        warn!("listener task panicked with an unknown payload type");
        "listener task panicked".to_string()
    }
}
