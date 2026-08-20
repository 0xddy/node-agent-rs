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
//! nothing under `shoes/src/dynamic/` knows about HTTP, JSON, or a user database;
//! that is why it pulls in no new dependency at all.
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
//! to survive, is:
//!
//! - three visibility widenings (`pub mod tcp;`, `pub mod socket_util;`, and
//!   exporting `DnsRegistry`), plus `[profile.release]` moved to the workspace root
//!   because Cargo ignores profiles in a non-root member
//! - a new `shoes::dynamic` module: the [`shoes::dynamic::UserRegistry`] trait,
//!   the per-user record it returns, wire-format credential derivation, and a
//!   `StaticUserRegistry` for config-file users
//! - an `Option<Arc<dyn UserRegistry>>` threaded through the handler factory, and
//!   two authentication sites (VLESS, Trojan) changed from comparing against one
//!   hardcoded credential to asking the registry
//!
//! That last point is the only upstream *behaviour* change, and it is behaviour
//! preserving by construction: with no registry injected, each handler builds a
//! `StaticUserRegistry` holding exactly the credential from its own config, so a
//! plain YAML config authenticates precisely as it did before.

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
    BindLocation, Config, ServerConfig, Transport, ValidatedConfigs, convert_cert_paths,
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

use inbound::BindTargets;

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
    bound: DashMap<SocketAddr, String>,
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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

    /// Validates, binds and starts one inbound, then registers it under `tag`.
    ///
    /// On any failure the engine is left exactly as it was: partially started
    /// listeners are torn down and no address is left claimed.
    ///
    /// When `spec.users` is present the inbound is put in dynamic mode: an
    /// in-memory registry becomes its sole credential authority, and it is live
    /// from the first accepted connection onward. See
    /// [`Engine::build_user_registry`] for what "present" is allowed to mean.
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
        let server_configs = validate_inbound_config(config).await?;

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
            targets.push(resolve_bind_targets(&server_config.bind_location)?);
        }

        for target in &targets {
            for address in target.addresses() {
                if let Some(owner) = self.inner.bound.get(address) {
                    return Err(EngineError::AddressInUse {
                        address: address.to_string(),
                        tag: owner.value().clone(),
                    });
                }
                // Faithful pre-flight bind, using the same socket options as the
                // real listener (`shoes::socket_util::new_tcp_listener`). This
                // catches permission errors and invalid addresses synchronously,
                // with the actual OS error, instead of letting them surface as a
                // panic inside a detached listener task.
                if matches!(target, BindTargets::Addresses(_)) {
                    probe_bind(*address)?;
                }
            }
        }

        let protocol = protocol::display_name(&server_configs[0].protocol);
        let transport = transport_name(&server_configs[0].transport).to_string();

        let mut handles: Vec<ServerHandle> = Vec::new();
        let mut bind_display: Vec<String> = Vec::new();

        for (server_config, target) in server_configs.into_iter().zip(targets.iter()) {
            let resolver = match Self::resolver_for(&mut control, &server_config).await {
                Ok(resolver) => resolver,
                Err(e) => {
                    inbound::abandon(handles).await;
                    return Err(e);
                }
            };

            // `Arc<MemoryUserRegistry>` is cloned per listener, so every handler
            // built from this spec authenticates against the one same table.
            let registry_ref = registry.clone().map(|r| r as Arc<dyn UserRegistry>);

            match start_servers_with_users(Config::Server(server_config), resolver, registry_ref)
                .await
            {
                Ok(handle) => handles.push(handle),
                Err(e) => {
                    // Roll back anything already started under this tag.
                    inbound::abandon(handles).await;
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
            listeners: handles.iter().map(ServerHandle::listener_count).sum(),
            // Both filled in live by `InboundSlot::describe`; see its doc comment.
            revision: 0,
            users: None,
        };

        let all_addresses: Vec<SocketAddr> = targets
            .iter()
            .flat_map(|t| t.addresses().to_vec())
            .collect();

        let slot = Arc::new(InboundSlot::new(
            info.clone(),
            BindTargets::Addresses(all_addresses.clone()),
            handles,
            registry,
        ));

        // Give the listener tasks a moment to fail, then confirm they are alive.
        tokio::time::sleep(LISTENER_HEALTH_GRACE).await;
        if let Some(dead) = slot.take_dead_listener() {
            let reason = describe_dead_listener(dead).await;
            slot.shutdown().await;
            return Err(EngineError::Io(std::io::Error::other(format!(
                "inbound {tag} failed to start: {reason}"
            ))));
        }

        let info = slot.describe();

        for address in &all_addresses {
            self.inner.bound.insert(*address, tag.clone());
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

        let server_configs = validate_inbound_config(config).await?;

        let mut paired = Vec::with_capacity(server_configs.len());
        for server_config in server_configs {
            let resolver = Self::resolver_for(&mut control, &server_config).await?;
            paired.push((server_config, resolver));
        }

        let revision = slot.reload(paired).map_err(EngineError::from_rejection)?;

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
    pub async fn remove_inbound(&self, tag: &str) -> EngineResult<InboundInfo> {
        let _control = self.inner.control.lock().await;

        let (_, slot) = self
            .inner
            .inbounds
            .remove(tag)
            .ok_or_else(|| EngineError::UnknownTag(tag.to_string()))?;

        slot.shutdown().await;

        for address in slot.targets().addresses() {
            self.inner.bound.remove(address);
        }

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
    fn build_user_registry(
        server_configs: &[ServerConfig],
        users: Vec<UserSpec>,
    ) -> EngineResult<Arc<MemoryUserRegistry>> {
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

    /// Adds or updates one user on `tag`, effective on the next handshake.
    ///
    /// Updating an existing id keeps that user's counters and their established
    /// connections; only the credential and the enabled flag are replaced.
    pub fn add_user(&self, tag: &str, user: UserSpec) -> EngineResult<UserInfo> {
        self.registry_for(tag)?.upsert(user)
    }

    /// Removes one user from `tag`.
    ///
    /// Their established connections keep running and keep being accounted for --
    /// each one holds its own `Arc<UserContext>`, taken at handshake time. Only
    /// the lookup path forgets the credential, so no new session can use it.
    pub fn remove_user(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        self.registry_for(tag)?.remove(tag, id)
    }

    pub fn list_users(&self, tag: &str) -> EngineResult<Vec<UserInfo>> {
        Ok(self.registry_for(tag)?.list())
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
    ) -> EngineResult<Arc<dyn Resolver>> {
        let dns_ref = server_config.dns.as_ref();

        if dns_ref.is_none() {
            return Ok(control.dns.get_for_server(None));
        }

        // `create_server_configs` already expanded and validated this config's DNS
        // group, so re-running the expansion for a single config is safe and keeps
        // the resolver private to the inbound.
        let ValidatedConfigs { dns_groups, .. } =
            shoes::config::create_server_configs(vec![Config::Server(server_config.clone())])
                .map_err(|e| EngineError::InvalidConfig(e.to_string()))?;

        let mut registry = build_dns_registry(dns_groups).await?;
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
async fn validate_inbound_config(config: serde_json::Value) -> EngineResult<Vec<ServerConfig>> {
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

    let ValidatedConfigs { configs, .. } = shoes::config::create_server_configs(parsed)
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

    Ok(server_configs)
}

fn resolve_bind_targets(bind_location: &BindLocation) -> EngineResult<BindTargets> {
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
            Ok(BindTargets::Addresses(resolved))
        }
        BindLocation::Path(path) => Ok(BindTargets::Path(path.display().to_string())),
    }
}

/// Opens and immediately closes a listener with the production socket options.
fn probe_bind(address: SocketAddr) -> EngineResult<()> {
    let listener = shoes::socket_util::new_tcp_listener(address, 1, None)?;
    drop(listener);
    debug!("pre-flight bind ok for {address}");
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
