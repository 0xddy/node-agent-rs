//! Dynamic, API-driven engine facade over the shoes proxy core.
//!
//! # Why this crate exists
//!
//! Upstream shoes is a config-file-driven CLI: `main.rs` loads YAML, validates
//! it, starts every listener, and then blocks forever. This crate provides the
//! same startup path *without* a config file, so the process can come up with
//! **zero inbounds and zero users** and be populated afterwards over an API.
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
//! | start listeners | [`shoes::tcp::tcp_server::start_servers`] |
//!
//! The only changes required inside `shoes/` for this phase were three
//! visibility widenings (`pub mod tcp;`, `pub mod socket_util;`, and exporting
//! `DnsRegistry`). No upstream behaviour was modified.

mod error;
mod inbound;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use log::{debug, info, warn};
use tokio::task::{JoinHandle, JoinError};

use shoes::config::{BindLocation, Config, ServerConfig, Transport, ValidatedConfigs};
use shoes::dns::{DnsRegistry, build_dns_registry};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_server::start_servers;
use shoes_api::{EngineStatus, InboundInfo, InboundSpec};

pub use error::{EngineError, EngineResult};
pub use inbound::InboundSlot;

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
            .map(|entry| entry.value().info().clone())
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
    pub async fn add_inbound(&self, spec: InboundSpec) -> EngineResult<InboundInfo> {
        let InboundSpec { tag, config } = spec;

        if tag.trim().is_empty() {
            return Err(EngineError::InvalidConfig("tag must not be empty".into()));
        }

        // Parse and validate *before* taking the control lock: a malformed
        // payload should not delay other operations.
        let server_configs = validate_inbound_config(config)?;

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

        let protocol = server_configs[0].protocol.to_string();
        let transport = transport_name(&server_configs[0].transport).to_string();

        let mut listeners: Vec<JoinHandle<()>> = Vec::new();
        let mut bind_display: Vec<String> = Vec::new();

        for (server_config, target) in server_configs.into_iter().zip(targets.iter()) {
            let resolver = match Self::resolver_for(&mut control, &server_config).await {
                Ok(resolver) => resolver,
                Err(e) => {
                    for handle in listeners {
                        handle.abort();
                    }
                    return Err(e);
                }
            };

            match start_servers(Config::Server(server_config), resolver).await {
                Ok(handles) => listeners.extend(handles),
                Err(e) => {
                    // Roll back anything already started under this tag.
                    for handle in listeners {
                        handle.abort();
                    }
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
            listeners: listeners.len(),
        };

        let all_addresses: Vec<SocketAddr> = targets
            .iter()
            .flat_map(|t| t.addresses().to_vec())
            .collect();

        let slot = Arc::new(InboundSlot::new(
            info.clone(),
            BindTargets::Addresses(all_addresses.clone()),
            listeners,
        ));

        // Give the listener tasks a moment to fail, then confirm they are alive.
        tokio::time::sleep(LISTENER_HEALTH_GRACE).await;
        if let Some(dead) = slot.take_dead_listener() {
            let reason = describe_dead_listener(dead).await;
            slot.shutdown();
            return Err(EngineError::Io(std::io::Error::other(format!(
                "inbound {tag} failed to start: {reason}"
            ))));
        }

        for address in &all_addresses {
            self.inner.bound.insert(*address, tag.clone());
        }
        self.inner.inbounds.insert(tag.clone(), slot);

        info!(
            "inbound {} started: {} over {} on {}",
            info.tag,
            info.protocol,
            info.transport,
            info.bind.join(", ")
        );

        Ok(info)
    }

    /// Stops accepting new connections on `tag` and unregisters it.
    ///
    /// Established TCP connections keep running to completion -- see
    /// [`InboundSlot::shutdown`] for the mechanism and the QUIC caveat.
    pub async fn remove_inbound(&self, tag: &str) -> EngineResult<InboundInfo> {
        let _control = self.inner.control.lock().await;

        let (_, slot) = self
            .inner
            .inbounds
            .remove(tag)
            .ok_or_else(|| EngineError::UnknownTag(tag.to_string()))?;

        slot.shutdown();

        for address in slot.targets().addresses() {
            self.inner.bound.remove(address);
        }

        let info = slot.info().clone();
        info!(
            "inbound {} stopped; established connections continue to drain",
            info.tag
        );

        Ok(info)
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
fn validate_inbound_config(config: serde_json::Value) -> EngineResult<Vec<ServerConfig>> {
    if !config.is_object() {
        return Err(EngineError::InvalidConfig(
            "config must be a single server config object".into(),
        ));
    }

    let json_text = serde_json::to_string(&config)
        .map_err(|e| EngineError::InvalidConfig(format!("could not re-encode payload: {e}")))?;

    let parsed: Config = serde_yaml::from_str(&json_text)
        .map_err(|e| EngineError::InvalidConfig(e.to_string()))?;

    if !matches!(parsed, Config::Server(_)) {
        return Err(EngineError::Unsupported(
            "only `server` configs can be added through the API".into(),
        ));
    }

    let ValidatedConfigs { configs, .. } = shoes::config::create_server_configs(vec![parsed])
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
