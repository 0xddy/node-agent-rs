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
//! `../shoes-plus/` stays an **engine**. It gets extension points -- a trait to look a
//! credential up, a per-user record to account against -- and nothing that decides
//! policy, speaks a wire protocol to an operator, or manages a process. Concretely,
//! nothing under `../shoes-plus/src/dynamic/` knows about HTTP, JSON, or a user database.
//!
//! The dependency list is the test, and it is easy to apply: `../shoes-plus/src/dynamic/`
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
//! The footprint inside `../shoes-plus/`, which is what every future merge of upstream has
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
//! which lives inside `../shoes-plus/` on purpose: it is protocol, and putting it out here
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use dashmap::DashMap;
use log::{debug, info, warn};
use sha2::{Digest as _, Sha256};
use tokio::task::{JoinError, JoinHandle};

use shoes::config::{
    BindLocation, Config, ExpandedDnsGroup, ServerConfig, Transport, ValidatedConfigs,
    convert_cert_paths,
};
#[cfg(test)]
use shoes::dns::build_dns_registry;
use shoes::dns::{DnsRegistry, PolicyStateRegistry, build_dns_registry_with_policy_state};
use shoes::dynamic::{
    ClientChainGroupRegistry, InboundReplayScope, InboundReplayScopeWeak, InboundReplayState,
    ServerHandle, UserRegistry,
};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_server::start_servers_with_users_and_replay_scope_resolved;

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

use inbound::{BindKey, BindTargets, InboundSlotInit, ReloadCandidate, SocketKind};

/// How long to wait before deciding a freshly started listener is healthy.
///
/// See [`InboundSlot::take_dead_listener`] for why this probe is needed at all.
const LISTENER_HEALTH_GRACE: Duration = Duration::from_millis(50);
const MAX_REPLAY_LINEAGES: usize = 65_536;

type InlineDnsCacheKey = [u8; 32];

/// Identity and revision observed before preparing an inbound update.
///
/// Keeping the three fence inputs together makes it impossible to accidentally
/// compare a tag against another slot's revision when the lock is reacquired.
struct InboundUpdateSnapshot {
    tag: String,
    slot: Arc<InboundSlot>,
    revision: u64,
}

impl InboundUpdateSnapshot {
    fn new(slot: Arc<InboundSlot>) -> Self {
        let revision = slot.revision();
        let tag = slot.tag().to_string();
        Self {
            tag,
            slot,
            revision,
        }
    }

    /// Close the gap between lock-free preparation and publication.
    ///
    /// Absence here is not the same as absence at the API's initial lookup: the
    /// tag existed when this operation began and was removed while its candidate
    /// was being prepared, so it is the same retryable race as replacement or
    /// reload.
    fn verify(&self, inbounds: &DashMap<String, Arc<InboundSlot>>) -> EngineResult<()> {
        let unchanged = inbounds.get(&self.tag).is_some_and(|current| {
            Arc::ptr_eq(current.value(), &self.slot) && self.slot.revision() == self.revision
        });
        if !unchanged {
            return Err(EngineError::concurrent_modification(format!(
                "inbound {} was removed, replaced, or reloaded",
                self.tag
            )));
        }
        Ok(())
    }
}

/// Opaque proof that a replacement belongs to the same replay-protection
/// namespace as the running inbound named by `tag`.
#[derive(Clone)]
pub struct InboundReplayLease {
    tag: String,
    engine_identity: Arc<()>,
    lineage: Arc<()>,
    state: InboundReplayState,
}

impl PartialEq for InboundReplayLease {
    fn eq(&self, other: &Self) -> bool {
        self.tag == other.tag
            && Arc::ptr_eq(&self.engine_identity, &other.engine_identity)
            && Arc::ptr_eq(&self.lineage, &other.lineage)
            && self.state == other.state
    }
}

impl Eq for InboundReplayLease {}

impl std::fmt::Debug for InboundReplayLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundReplayLease")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// State that may only be touched by one control-plane operation at a time.
///
/// Serialising mutations is what lets the engine treat its own address registry
/// as authoritative: two concurrent `add_inbound` calls can never both pass the
/// conflict check for the same port.
struct ControlState {
    /// One logical URLTest state per compiled outbound for the current global
    /// data-plane generation. Repeated route/DNS/inbound references reuse it.
    client_chain_groups: ClientChainGroupRegistry,
    /// Shared resolver registry for inbounds that do not declare their own DNS.
    dns: DnsRegistry,
    /// Identical inline DNS sections share one policy/upstream graph across
    /// inbounds, matching sing-box's process-wide DNS router and cache.
    inline_dns: HashMap<InlineDnsCacheKey, Weak<dyn Resolver>>,
    /// Process-wide mutable DNS rule state, strongly retained for the current
    /// DNS-client generation so inbound-only remove/add updates preserve rule
    /// windows.
    dns_policy_state: PolicyStateRegistry,
    /// Currently owned replay authority for each tag. The registry is weak so a
    /// removed inbound which has no retained rollback lease can be reclaimed; a
    /// live slot or lease keeps its entry admissible. Publishing a fresh authority
    /// under the same tag invalidates every older lease by pointer identity.
    replay_lineages: ReplayLineages,
}

struct ReplayLineageEntry {
    /// Lease authority. Both a live scope and an explicit rollback lease retain it.
    authority: Weak<()>,
    /// Only listener/handler generations retain this owner. A lease deliberately
    /// does not, so a hard-removed tag can start a genuinely fresh generation.
    live: InboundReplayScopeWeak,
}

impl ControlState {
    fn prune_inline_dns(&mut self) {
        self.inline_dns
            .retain(|_, candidate| candidate.strong_count() != 0);
    }
}

/// Resolver state shared by every server config produced from one payload.
///
/// Inline DNS expansion, its cache identity, and resolvers awaiting publication
/// must stay together. Bundling them avoids repeating a five-argument resolver
/// call and prevents a cache key from being paired with another expansion's DNS
/// groups.
struct CandidateResolvers<'a> {
    dns_groups: &'a [ExpandedDnsGroup],
    dns_cache_key: Option<&'a InlineDnsCacheKey>,
    pending: HashMap<InlineDnsCacheKey, Arc<dyn Resolver>>,
}

impl<'a> CandidateResolvers<'a> {
    fn new(
        dns_groups: &'a [ExpandedDnsGroup],
        dns_cache_key: Option<&'a InlineDnsCacheKey>,
    ) -> Self {
        Self {
            dns_groups,
            dns_cache_key,
            pending: HashMap::new(),
        }
    }

    async fn resolve(
        &mut self,
        control: &mut ControlState,
        server_config: &ServerConfig,
    ) -> EngineResult<Arc<dyn Resolver>> {
        let dns_ref = server_config.dns.as_ref();

        if dns_ref.is_none() {
            return Ok(control.dns.get_for_server(None));
        }

        if let Some(shared) = self
            .dns_cache_key
            .and_then(|key| self.pending.get(key).cloned())
        {
            return Ok(shared);
        }

        if let Some(shared) = self
            .dns_cache_key
            .and_then(|key| control.inline_dns.get(key))
            .and_then(Weak::upgrade)
        {
            return Ok(shared);
        }

        // The groups come from the same expansion that produced `server_config`.
        // Validation rewrites inline servers to a generated group reference, so
        // re-expanding the rewritten config would leave that reference dangling.
        let mut registry = build_dns_registry_with_policy_state(
            self.dns_groups.to_vec(),
            &control.dns_policy_state,
        )
        .await?;
        let resolver = registry.get_for_server(dns_ref);
        if let Some(key) = self.dns_cache_key {
            self.pending.insert(*key, resolver.clone());
        }
        Ok(resolver)
    }

    fn publish(self, control: &mut ControlState) {
        control.prune_inline_dns();
        for (key, resolver) in self.pending {
            control.inline_dns.insert(key, Arc::downgrade(&resolver));
        }
    }
}

struct EngineInner {
    /// Unique authority carried by replay leases. It is deliberately separate from
    /// the EngineInner Arc so retaining a lease cannot keep listeners alive.
    replay_identity: Arc<()>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundRemovalMode {
    Graceful,
    Hard,
}

enum ReplayAdmission {
    Fresh,
    Preserved {
        state: InboundReplayState,
        lineage: Arc<()>,
    },
}

struct PreparedReplay {
    state: InboundReplayState,
    lineage: Arc<()>,
    scope: InboundReplayScope,
}

struct ReplayLineages {
    entries: HashMap<String, ReplayLineageEntry>,
    limit: usize,
}

impl ReplayLineages {
    fn new(limit: usize) -> Self {
        Self {
            entries: HashMap::new(),
            limit,
        }
    }

    fn prepare(&mut self, tag: &str, admission: ReplayAdmission) -> EngineResult<PreparedReplay> {
        self.entries
            .retain(|_, entry| entry.authority.strong_count() != 0);
        match admission {
            ReplayAdmission::Fresh => {
                if let Some(scope) = self.entries.get(tag).and_then(|entry| entry.live.upgrade()) {
                    return Ok(PreparedReplay {
                        state: scope.state(),
                        lineage: scope.lineage(),
                        scope,
                    });
                }
                if !self.entries.contains_key(tag) && self.entries.len() >= self.limit {
                    return Err(EngineError::InvalidConfig(format!(
                        "replay lineage limit {} is full; cannot admit new inbound tag {tag:?}",
                        self.limit
                    )));
                }
                let state = InboundReplayState::default();
                let scope = InboundReplayScope::new(state.clone());
                Ok(PreparedReplay {
                    state,
                    lineage: scope.lineage(),
                    scope,
                })
            }
            ReplayAdmission::Preserved { state, lineage } => {
                let current = self
                    .entries
                    .get(tag)
                    .and_then(|entry| entry.authority.upgrade());
                if !current
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &lineage))
                {
                    return Err(EngineError::InvalidConfig(format!(
                        "replay lease for inbound {tag} is stale"
                    )));
                }
                let scope = self
                    .entries
                    .get(tag)
                    .and_then(|entry| entry.live.upgrade())
                    .filter(|scope| Arc::ptr_eq(&scope.lineage(), &lineage))
                    .unwrap_or_else(|| {
                        InboundReplayScope::with_lineage(state.clone(), Arc::clone(&lineage))
                    });
                Ok(PreparedReplay {
                    state,
                    lineage,
                    scope,
                })
            }
        }
    }

    fn publish(&mut self, tag: String, replay: &PreparedReplay) {
        self.entries.insert(
            tag,
            ReplayLineageEntry {
                authority: Arc::downgrade(&replay.lineage),
                live: replay.scope.downgrade(),
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
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

        // The DNS client owns both long-lived policy windows and one
        // generation-scoped question cache. Build the default registry from
        // that same state so configured and implicit resolvers share it.
        let dns_policy_state = PolicyStateRegistry::default();
        let dns = build_dns_registry_with_policy_state(vec![], &dns_policy_state).await?;

        info!("engine bootstrapped with 0 inbounds");

        Ok(Self {
            inner: Arc::new(EngineInner {
                replay_identity: Arc::new(()),
                control: tokio::sync::Mutex::new(ControlState {
                    client_chain_groups: ClientChainGroupRegistry::default(),
                    dns,
                    inline_dns: HashMap::new(),
                    dns_policy_state,
                    replay_lineages: ReplayLineages::new(MAX_REPLAY_LINEAGES),
                }),
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

    /// Rotate the process-client DNS generation before a full topology rebuild.
    /// Cached questions and generation-scoped DNS rule state are both cleared.
    pub async fn rotate_dns_client_generation(&self) -> u64 {
        let mut control = self.inner.control.lock().await;
        // A still-running connection can keep an old inline resolver graph
        // alive after its listener is retired. Do not let a full rebuild adopt
        // that graph, because it embeds the previous generation's rule state.
        control.inline_dns.clear();
        control.client_chain_groups = ClientChainGroupRegistry::default();
        let generation = control.dns_policy_state.rotate_dns_client_generation();
        control.dns = DnsRegistry::with_policy_state(&control.dns_policy_state);
        generation
    }

    /// Current Go-compatible DNS client cache generation. Exposed for runtime
    /// diagnostics and transaction-boundary verification.
    pub async fn dns_cache_generation(&self) -> u64 {
        let control = self.inner.control.lock().await;
        control.dns_policy_state.query_cache_generation()
    }

    /// Validate the generation-global DNS graph used by URLTest background
    /// probes without publishing it.
    pub async fn validate_urltest_probe_dns(
        &self,
        dns: Option<&serde_json::Value>,
    ) -> EngineResult<()> {
        let _ = validate_urltest_probe_dns_config(dns).await?;
        Ok(())
    }

    /// Publish the generation-global, no-inbound-context resolver used by every
    /// shared URLTest worker. The same graph is idempotent; changing it requires
    /// [`Self::rotate_dns_client_generation`].
    pub async fn configure_urltest_probe_dns(
        &self,
        dns: Option<&serde_json::Value>,
    ) -> EngineResult<()> {
        let probe = validate_urltest_probe_dns_config(dns).await?;
        let mut control = self.inner.control.lock().await;
        control.prune_inline_dns();
        let registry = control.client_chain_groups.clone();
        let result =
            Self::ensure_urltest_probe_resolver(&mut control, &registry, probe.as_ref()).await;
        drop(control);
        result
    }

    /// Release URLTest groups that are no longer reachable from the topology
    /// published by the embedder. This must be called only after the embedder's
    /// complete multi-inbound transaction commits: an individual Shoes listener
    /// commit may still be followed by an outer rollback that needs the old
    /// group's selection and worker state.
    pub async fn commit_client_chain_group_generation(&self) {
        let control = self.inner.control.lock().await;
        control.client_chain_groups.prune_dormant_committed();
    }

    /// Number of URLTest groups retained by the active client-chain generation.
    /// Exposed for runtime governance diagnostics and transaction tests.
    pub async fn client_chain_group_count(&self) -> usize {
        let control = self.inner.control.lock().await;
        control.client_chain_groups.active_group_count()
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

    /// Retain the replay namespace while the same tagged inbound is explicitly
    /// stopped and rebuilt.
    pub fn preserve_inbound_replay(&self, tag: &str) -> EngineResult<InboundReplayLease> {
        let slot = self
            .inner
            .inbounds
            .get(tag)
            .ok_or_else(|| EngineError::UnknownTag(tag.to_string()))?;
        Ok(InboundReplayLease {
            tag: tag.to_string(),
            engine_identity: Arc::clone(&self.inner.replay_identity),
            lineage: slot.replay_lineage(),
            state: slot.replay_state(),
        })
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
        let targets = resolve_bind_targets_for_configs(&server_configs).await?;
        let mut claimed = Vec::new();
        for targets in targets {
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
        Box::pin(self.add_inbound_inner(spec, ReplayAdmission::Fresh)).await
    }

    /// Start a replacement listener without reopening the VMess/SS replay window.
    ///
    /// The lease is tag-bound, so it cannot accidentally merge the security
    /// namespaces of two independently configured inbounds.
    pub async fn add_inbound_with_replay(
        &self,
        spec: InboundSpec,
        replay: &InboundReplayLease,
    ) -> EngineResult<InboundInfo> {
        if spec.tag != replay.tag {
            return Err(EngineError::InvalidConfig(format!(
                "replay lease for inbound {} cannot start inbound {}",
                replay.tag, spec.tag
            )));
        }
        if !Arc::ptr_eq(&self.inner.replay_identity, &replay.engine_identity) {
            return Err(EngineError::InvalidConfig(format!(
                "replay lease for inbound {} belongs to another engine",
                replay.tag
            )));
        }
        Box::pin(self.add_inbound_inner(
            spec,
            ReplayAdmission::Preserved {
                state: replay.state.clone(),
                lineage: Arc::clone(&replay.lineage),
            },
        ))
        .await
    }

    async fn add_inbound_inner(
        &self,
        spec: InboundSpec,
        replay: ReplayAdmission,
    ) -> EngineResult<InboundInfo> {
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
            dns_cache_key,
        } = validate_inbound_config(config).await?;

        let registry = match users {
            Some(users) => Some(Self::build_user_registry(&server_configs, users)?),
            None => None,
        };

        // Preserve the existing error priority without retaining the lock across
        // name resolution. The definitive check is repeated after resolution to
        // close the race with another add publishing the same tag meanwhile.
        {
            let _control = self.inner.control.lock().await;
            if self.inner.inbounds.contains_key(&tag) {
                return Err(EngineError::DuplicateTag(tag));
            }
        }

        // `NetLocationPortRange::to_socket_addrs` ultimately uses the platform's
        // blocking name service. Resolve before taking the global control lock and
        // on Tokio's blocking pool, so one slow listen hostname cannot stall an
        // unrelated add, update, removal, or DNS-generation rotation.
        let targets = resolve_bind_targets_for_configs(&server_configs).await?;

        let mut control = self.inner.control.lock().await;
        control.prune_inline_dns();
        let client_chain_groups = control.client_chain_groups.clone();

        if self.inner.inbounds.contains_key(&tag) {
            return Err(EngineError::DuplicateTag(tag));
        }

        let prepared_replay = control.replay_lineages.prepare(&tag, replay)?;

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

        Self::ensure_default_urltest_probe_resolver(&mut control, &client_chain_groups).await?;
        let client_chain_transaction = client_chain_groups.transaction();
        let mut resolvers = CandidateResolvers::new(&dns_groups, dns_cache_key.as_ref());

        // Listeners are live from the moment `start_servers_with_users` returns, but
        // this inbound is not registered until the health probe below passes -- and
        // in between there are awaits. A caller whose request is cancelled there (a
        // gRPC client hanging up, a request timeout) drops this whole future, and
        // without the guard the listeners would go on serving with no tag left to
        // name them and no way to stop them. See [`AbandonOnDrop`].
        let mut started = AbandonOnDrop::new();
        let mut bind_display: Vec<String> = Vec::new();

        for (server_config, target) in server_configs.into_iter().zip(targets) {
            let resolver = match client_chain_transaction
                .scope(resolvers.resolve(&mut control, &server_config))
                .await
            {
                Ok(resolver) => resolver,
                Err(e) => {
                    inbound::abandon(started.disarm()).await;
                    control.prune_inline_dns();
                    return Err(e);
                }
            };
            // `Arc<MemoryUserRegistry>` is cloned per listener, so every handler
            // built from this spec authenticates against the one same table.
            let registry_ref = registry.clone().map(|r| r as Arc<dyn UserRegistry>);

            match client_chain_transaction
                .scope(Box::pin(
                    start_servers_with_users_and_replay_scope_resolved(
                        Config::Server(server_config),
                        resolver,
                        registry_ref,
                        prepared_replay.scope.clone(),
                        target.resolved_bind(),
                    ),
                ))
                .await
            {
                Ok(handle) => {
                    started.push(handle);
                }
                Err(e) => {
                    // Roll back anything already started under this tag.
                    inbound::abandon(started.disarm()).await;
                    control.prune_inline_dns();
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
            control.prune_inline_dns();
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
        let slot = Arc::new(InboundSlot::new(InboundSlotInit {
            info: info.clone(),
            keys: claimed.clone(),
            handles: started.disarm(),
            replay_state: prepared_replay.state.clone(),
            replay_lineage: Arc::clone(&prepared_replay.lineage),
            users: registry,
        }));

        let info = slot.describe();

        for key in &claimed {
            self.inner.bound.insert(key.clone(), tag.clone());
        }
        // Publish only after every fallible startup/health step. This also refreshes
        // the weak live owner after a preserved hard replacement. Do it before the
        // slot so lock-free lease capture cannot observe an authority absent here.
        control
            .replay_lineages
            .publish(tag.clone(), &prepared_replay);
        self.inner.inbounds.insert(tag.clone(), slot);
        client_chain_transaction.commit_and_start();
        resolvers.publish(&mut control);
        drop(control);

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

        // Snapshot the target under the control lock, then release it before config
        // validation. Validation may read certificate/key files and must not stall
        // unrelated engine mutations. The identity/revision fence below rejects
        // this candidate if another operation changes the target in the meantime.
        let snapshot = {
            let _control = self.inner.control.lock().await;
            let slot = self
                .inner
                .inbounds
                .get(&tag)
                .map(|entry| entry.value().clone())
                .ok_or_else(|| EngineError::UnknownTag(tag.clone()))?;
            InboundUpdateSnapshot::new(slot)
        };

        // In dynamic mode the protocol's credential field is dead but still
        // mandatory in shoes' schema. Same treatment as at creation, so an update
        // is written exactly like the add that created the inbound.
        if snapshot.slot.users().is_some() {
            protocol::install_placeholder_credentials(&mut config)?;
        }

        let ValidatedInbound {
            configs: server_configs,
            dns_groups,
            dns_cache_key,
        } = validate_inbound_config(config).await?;

        // Hostname resolution is part of candidate preparation, not publication.
        // The exact result is carried through the generation fence and consumed by
        // every reload check below; no code holding `control` consults DNS.
        let targets = resolve_bind_targets_for_configs(&server_configs).await?;

        let mut control = self.inner.control.lock().await;
        control.prune_inline_dns();
        snapshot.verify(&self.inner.inbounds)?;
        let client_chain_groups = control.client_chain_groups.clone();

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
        if let Some(registry) = snapshot.slot.users() {
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

        Self::ensure_default_urltest_probe_resolver(&mut control, &client_chain_groups).await?;
        let client_chain_transaction = client_chain_groups.transaction();
        let mut resolvers = CandidateResolvers::new(&dns_groups, dns_cache_key.as_ref());

        let mut paired = Vec::with_capacity(server_configs.len());
        for (server_config, target) in server_configs.into_iter().zip(targets) {
            let resolver = client_chain_transaction
                .scope(resolvers.resolve(&mut control, &server_config))
                .await?;
            paired.push(ReloadCandidate::new(
                server_config,
                resolver,
                target.resolved_bind(),
            ));
        }

        let revision = match client_chain_transaction
            .scope(async { snapshot.slot.reload(paired) })
            .await
        {
            Ok(revision) => revision,
            Err(error) => {
                // A rejected reload may have constructed a resolver which is no
                // longer owned once `reload` returns its error.
                control.prune_inline_dns();
                return Err(EngineError::from_reload_rejection(error));
            }
        };
        client_chain_transaction.commit_and_start();
        resolvers.publish(&mut control);
        control.prune_inline_dns();
        drop(control);

        let info = snapshot.slot.describe();
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
        self.remove_inbound_inner(tag, InboundRemovalMode::Graceful)
            .await
    }

    /// Unregisters `tag`, stops accepting, and forcibly closes its established
    /// connection tree.
    ///
    /// Use this for a full listener replacement whose old generation must not remain
    /// connected. [`Engine::remove_inbound`] remains the smooth-handover API.
    pub async fn remove_inbound_hard(&self, tag: &str) -> EngineResult<InboundInfo> {
        self.remove_inbound_inner(tag, InboundRemovalMode::Hard)
            .await
    }

    async fn remove_inbound_inner(
        &self,
        tag: &str,
        mode: InboundRemovalMode,
    ) -> EngineResult<InboundInfo> {
        let mut control = self.inner.control.lock().await;
        control.prune_inline_dns();

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
            hard: mode == InboundRemovalMode::Hard,
        };

        match mode {
            InboundRemovalMode::Graceful => slot.shutdown().await,
            InboundRemovalMode::Hard => slot.hard_shutdown().await,
        }
        drop(release);

        let info = slot.describe();
        drop(slot);
        control.prune_inline_dns();
        drop(control);
        match mode {
            InboundRemovalMode::Graceful => info!(
                "inbound {} stopped; established connections continue to drain",
                info.tag
            ),
            InboundRemovalMode::Hard => info!(
                "inbound {} stopped; established connections were closed",
                info.tag
            ),
        }

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
    /// Inbounds without a `dns` section share the engine-wide registry. Inbounds
    /// with an identical inline DNS section also share its resolver graph, cache,
    /// and per-rule state; distinct policies remain isolated.
    ///
    /// Takes `&mut ControlState` rather than `&self` because the caller already
    /// holds the control lock -- `tokio::sync::Mutex` is not reentrant.
    #[cfg(test)]
    async fn resolver_for(
        control: &mut ControlState,
        server_config: &ServerConfig,
        dns_groups: &[ExpandedDnsGroup],
        dns_cache_key: Option<&InlineDnsCacheKey>,
    ) -> EngineResult<Arc<dyn Resolver>> {
        let mut resolvers = CandidateResolvers::new(dns_groups, dns_cache_key);
        let resolver = resolvers.resolve(control, server_config).await?;
        resolvers.publish(control);
        Ok(resolver)
    }

    async fn ensure_default_urltest_probe_resolver(
        control: &mut ControlState,
        registry: &ClientChainGroupRegistry,
    ) -> EngineResult<()> {
        if registry.probe_resolver_is_bound() {
            return Ok(());
        }
        Self::ensure_urltest_probe_resolver(control, registry, None).await
    }

    async fn ensure_urltest_probe_resolver(
        control: &mut ControlState,
        registry: &ClientChainGroupRegistry,
        probe: Option<&ValidatedUrlTestProbe>,
    ) -> EngineResult<()> {
        let fingerprint = probe
            .map(|probe| probe.fingerprint)
            .unwrap_or_else(|| Sha256::digest(b"shoes/urltest-probe/system/v1").into());
        if registry
            .probe_resolver_matches(fingerprint)
            .map_err(EngineError::Io)?
        {
            return Ok(());
        }

        // The global DNS graph may itself dial through a shared URLTest outbound.
        // Build it with the same registry while the registry's probe resolver is
        // still unbound, then connect the late back-reference and publish all
        // groups together. This is independent of any one listener transaction:
        // Go's global outbounds exist for the whole Box generation as well.
        let transaction = registry.transaction();
        let resolver = match probe {
            Some(probe) => {
                let mut resolvers =
                    CandidateResolvers::new(&probe.dns_groups, probe.dns_cache_key.as_ref());
                transaction
                    .scope_without_probe_generation(
                        resolvers.resolve(control, &probe.server_config),
                    )
                    .await?
            }
            None => control.dns.get_for_server(None),
        };
        registry
            .bind_probe_resolver(fingerprint, resolver)
            .map_err(EngineError::Io)?;
        transaction.commit_and_start();
        // This canonical graph was intentionally built without a probe-generation
        // lease to avoid a resolver/group reference cycle. Never publish it into
        // the ordinary inbound cache: a matching inbound must build a leased
        // wrapper that keeps this generation alive until its slot is dropped.
        Ok(())
    }
}

/// Turns an API payload into validated, startable server configs.
///
/// YAML 1.2 is a superset of JSON, so re-encoding the JSON payload and handing it
/// to `serde_yaml` runs it through the *same* deserializers the YAML config files
/// use -- including `ServerConfig`'s hand-written `Deserialize` impl. No parallel
/// JSON schema to maintain.
///
/// The step order mirrors `../shoes-plus/src/main.rs:339`: certs are inlined *before*
/// validation. That order is load-bearing rather than cosmetic --
/// `create_server_configs` reaches `embed_pem_from_map`, which `panic!`s on a PEM
/// path it has not seen loaded (`../shoes-plus/src/config/pem.rs:466`). Skipping the
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
    dns_cache_key: Option<InlineDnsCacheKey>,
}

struct ValidatedUrlTestProbe {
    server_config: ServerConfig,
    dns_groups: Vec<ExpandedDnsGroup>,
    dns_cache_key: Option<InlineDnsCacheKey>,
    fingerprint: InlineDnsCacheKey,
}

async fn validate_inbound_config(config: serde_json::Value) -> EngineResult<ValidatedInbound> {
    if !config.is_object() {
        return Err(EngineError::InvalidConfig(
            "config must be a single server config object".into(),
        ));
    }

    let dns_cache_key = inline_dns_cache_key(&config)?;
    let (server_configs, dns_groups) = validate_server_config_payload(config).await?;

    Ok(ValidatedInbound {
        configs: server_configs,
        dns_groups,
        dns_cache_key,
    })
}

async fn validate_urltest_probe_dns_config(
    dns: Option<&serde_json::Value>,
) -> EngineResult<Option<ValidatedUrlTestProbe>> {
    let Some(dns) = dns.filter(|dns| !dns.is_null()) else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(dns).map_err(|error| {
        EngineError::InvalidConfig(format!(
            "could not encode URLTest probe DNS section: {error}"
        ))
    })?;
    let fingerprint = Sha256::digest(encoded).into();
    let payload = serde_json::json!({
        "address": "127.0.0.1:0",
        "protocol": {"type": "socks", "udp_enabled": false},
        "rules": [{"masks": "0.0.0.0/0", "action": "allow"}],
        "dns": dns,
    });
    let (mut configs, dns_groups) = validate_server_config_payload(payload).await?;
    let server_config = configs
        .drain(..)
        .next()
        .expect("validated URLTest probe payload is non-empty");
    Ok(Some(ValidatedUrlTestProbe {
        server_config,
        dns_groups,
        dns_cache_key: Some(fingerprint),
        fingerprint,
    }))
}

async fn validate_server_config_payload(
    config: serde_json::Value,
) -> EngineResult<(Vec<ServerConfig>, Vec<ExpandedDnsGroup>)> {
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
                // (`../shoes-plus/src/tcp/tcp_server.rs:395`). Reject it here rather than
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

    Ok((server_configs, dns_groups))
}

fn inline_dns_cache_key(config: &serde_json::Value) -> EngineResult<Option<InlineDnsCacheKey>> {
    let Some(dns) = config.get("dns").filter(|dns| !dns.is_null()) else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(dns)
        .map_err(|e| EngineError::InvalidConfig(format!("could not encode DNS section: {e}")))?;
    Ok(Some(Sha256::digest(encoded).into()))
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
            if resolved.iter().any(|address| address.port() == 0) {
                return Err(EngineError::InvalidConfig(
                    "bind port 0 is not supported by the dynamic engine: the operating system \
                     would choose an ephemeral port that could not be represented faithfully in \
                     address ownership or inbound metadata"
                        .into(),
                ));
            }
            Ok(BindTargets::Addresses {
                addresses: resolved,
                kind: socket_kind(transport),
            })
        }
        BindLocation::Path(path) => Ok(BindTargets::Path(path.clone())),
    }
}

/// Resolve every listen target without blocking a Tokio worker or holding the
/// engine's global control lock. Resolution has no side effects, so cancellation
/// may leave the blocking job to finish without changing engine state.
async fn resolve_bind_targets_for_configs(
    server_configs: &[ServerConfig],
) -> EngineResult<Vec<BindTargets>> {
    let inputs: Vec<(BindLocation, Transport)> = server_configs
        .iter()
        .map(|config| (config.bind_location.clone(), config.transport.clone()))
        .collect();
    tokio::task::spawn_blocking(move || {
        inputs
            .into_iter()
            .map(|(bind_location, transport)| resolve_bind_targets(&bind_location, &transport))
            .collect()
    })
    .await
    .map_err(|error| {
        EngineError::Io(std::io::Error::other(format!(
            "bind target resolution task failed: {error}"
        )))
    })?
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
    /// Preserve hard-removal semantics even if the caller drops the future while
    /// its listeners are releasing their sockets.
    hard: bool,
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        // Cheap insurance on the cancelled path: shutdown may not have run at all.
        if self.hard {
            self.slot.hard_stop();
        } else {
            self.slot.stop_accepting();
        }
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
/// `Drop` cannot await, so this cancels both accepts and the uncommitted connection
/// trees synchronously and leaves socket cleanup to the runtime. No candidate flow
/// is allowed to outlive an add future that never published its inbound.
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
            handle.hard_stop();
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

#[cfg(test)]
mod dns_sharing_tests {
    use super::*;
    use serde_json::json;
    use shoes::dns::{DnsPolicyError, DnsPolicyFailure, DnsRejectMethod};
    use shoes::resolver::{Address, NetLocation};

    #[test]
    fn dynamic_bind_rejects_ephemeral_port_zero_before_accounting() {
        let bind = BindLocation::from(NetLocation::new(
            Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ));
        let error = resolve_bind_targets(&bind, &Transport::Tcp)
            .expect_err("port zero cannot be represented by exact ownership metadata");
        assert!(matches!(error, EngineError::InvalidConfig(_)));
        assert!(error.to_string().contains("port 0"));
    }

    #[test]
    fn replay_lineage_limit_counts_only_live_authorities() {
        let mut lineages = ReplayLineages::new(1);
        let first = lineages.prepare("a", ReplayAdmission::Fresh).unwrap();
        lineages.publish("a".to_string(), &first);

        let error = match lineages.prepare("b", ReplayAdmission::Fresh) {
            Ok(_) => panic!("a retained authority must consume the bounded registry"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("lineage limit"));

        drop(first);
        let second = lineages
            .prepare("b", ReplayAdmission::Fresh)
            .expect("an unowned removed lineage must be reclaimed before the capacity check");
        assert_eq!(lineages.len(), 0, "dead weak entries were pruned");
        drop(second);
    }

    #[test]
    fn fresh_reuses_live_scope_but_invalidates_a_lease_only_lineage() {
        let mut lineages = ReplayLineages::new(1);
        let old = lineages
            .prepare("same-tag", ReplayAdmission::Fresh)
            .unwrap();
        let old_state = old.state.clone();
        let old_lineage = Arc::clone(&old.lineage);
        lineages.publish("same-tag".to_string(), &old);

        let reused = lineages
            .prepare("same-tag", ReplayAdmission::Fresh)
            .expect("a live retired handler makes a fresh add reuse its namespace");
        assert!(old_state == reused.state);
        assert!(Arc::ptr_eq(&old.lineage, &reused.lineage));
        assert!(Arc::ptr_eq(&old.scope.lineage(), &reused.scope.lineage()));

        // A hard removal leaves only the explicit lease. That must not make a
        // normal add look like an old handler is still able to authenticate.
        drop(old.scope);
        drop(reused.scope);
        let fresh = lineages
            .prepare("same-tag", ReplayAdmission::Fresh)
            .expect("a lease-only lineage can be superseded without growing the registry");
        assert!(old_state != fresh.state);
        lineages.publish("same-tag".to_string(), &fresh);

        let stale = match lineages.prepare(
            "same-tag",
            ReplayAdmission::Preserved {
                state: old_state,
                lineage: old_lineage,
            },
        ) {
            Ok(_) => panic!("fresh publication must make every older lease stale"),
            Err(error) => error,
        };
        assert!(stale.to_string().contains("stale"));

        let admitted = lineages
            .prepare(
                "same-tag",
                ReplayAdmission::Preserved {
                    state: fresh.state.clone(),
                    lineage: Arc::clone(&fresh.lineage),
                },
            )
            .expect("the currently published lineage remains admissible");
        assert!(Arc::ptr_eq(&admitted.lineage, &fresh.lineage));
        assert!(admitted.state == fresh.state);
        assert!(Arc::ptr_eq(
            &admitted.scope.lineage(),
            &fresh.scope.lineage()
        ));
    }

    fn inbound_with_dns(server: &str) -> serde_json::Value {
        inbound_with_dns_rules(server, json!([{"action": "reject"}]))
    }

    fn free_tcp_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("reserve test bind address");
        listener.local_addr().expect("read reserved bind address")
    }

    fn inbound_with_dns_at(address: SocketAddr, server: &str) -> serde_json::Value {
        let mut config = inbound_with_dns(server);
        config["address"] = json!(address.to_string());
        config
    }

    fn inbound_with_dns_rules(server: &str, rules: serde_json::Value) -> serde_json::Value {
        let config = json!({
            "address": "127.0.0.1:0",
            "protocol": {
                "type": "socks",
                "udp_enabled": false
            },
            "rules": [{"masks": "0.0.0.0/0", "action": "allow"}],
            "dns": {
                "servers": [{"tag": "default-dns", "url": server}],
                "rules": rules
            }
        });
        drop(rules);
        config
    }

    fn inbound_with_shared_urltest(port: u16, shared_id: &str) -> serde_json::Value {
        json!({
            "address": format!("127.0.0.1:{port}"),
            "protocol": {
                "type": "socks",
                "udp_enabled": false
            },
            "rules": [{
                "masks": "0.0.0.0/0",
                "action": "allow",
                "client_chains": [
                    {"chain": ["direct"]},
                    {"chain": ["direct"]}
                ],
                "client_chain_selection": {
                    "type": "urltest",
                    "shared_id": shared_id,
                    "url": "http://127.0.0.1:9/generate_204",
                    "interval_millis": 60000,
                    "tolerance_millis": 50,
                    "idle_timeout_millis": 1800000
                }
            }]
        })
    }

    #[tokio::test]
    async fn repeated_inbounds_share_one_generation_scoped_urltest_group() {
        let reserve_port = || {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("reserve test port");
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            port
        };
        let first_port = reserve_port();
        let mut second_port = reserve_port();
        while second_port == first_port {
            second_port = reserve_port();
        }
        let engine = Engine::bootstrap().await.unwrap();
        let shared_id = "node-agent-urltest-v1:engine-shared";

        for (tag, port) in [("first", first_port), ("second", second_port)] {
            engine
                .add_inbound(InboundSpec {
                    tag: tag.to_string(),
                    config: inbound_with_shared_urltest(port, shared_id),
                    users: None,
                })
                .await
                .unwrap();
        }

        let active_groups = {
            let control = engine.inner.control.lock().await;
            control.client_chain_groups.active_group_count()
        };
        assert_eq!(active_groups, 1);
        engine.remove_inbound_hard("first").await.unwrap();
        engine.remove_inbound_hard("second").await.unwrap();
        let active_groups = {
            let control = engine.inner.control.lock().await;
            control.client_chain_groups.active_group_count()
        };
        assert_eq!(
            active_groups, 1,
            "a remove/add gap must not reset global URLTest state"
        );

        engine.rotate_dns_client_generation().await;
        let active_groups = {
            let control = engine.inner.control.lock().await;
            control.client_chain_groups.active_group_count()
        };
        assert_eq!(active_groups, 0);
    }

    #[test]
    fn inline_dns_cache_key_is_a_fixed_sha256_digest_without_raw_secrets() {
        let secret = "dns-proxy-password-that-must-not-be-retained";
        let config = json!({
            "dns": {
                "servers": [{
                    "tag": "private",
                    "url": "tls://resolver.example",
                    "client_chain": [{
                        "protocol": {"type": "trojan", "password": secret}
                    }]
                }],
                "final": "private"
            }
        });
        let key = inline_dns_cache_key(&config).unwrap().unwrap();
        let encoded = serde_json::to_vec(&config["dns"]).unwrap();
        let expected: InlineDnsCacheKey = Sha256::digest(encoded).into();

        assert_eq!(std::mem::size_of_val(&key), 32);
        assert_eq!(key, expected);
        assert!(!format!("{key:?}").contains(secret));
        assert_eq!(inline_dns_cache_key(&json!({})).unwrap(), None);
        assert_eq!(inline_dns_cache_key(&json!({"dns": null})).unwrap(), None);
    }

    #[tokio::test]
    async fn identical_inline_dns_sections_share_one_resolver_graph() {
        let first = validate_inbound_config(inbound_with_dns("udp://127.0.0.1:5353"))
            .await
            .unwrap();
        let second = validate_inbound_config(inbound_with_dns("udp://127.0.0.1:5353"))
            .await
            .unwrap();
        let dns = build_dns_registry(Vec::new()).await.unwrap();
        let mut control = ControlState {
            client_chain_groups: ClientChainGroupRegistry::default(),
            dns,
            inline_dns: HashMap::new(),
            dns_policy_state: PolicyStateRegistry::default(),
            replay_lineages: ReplayLineages::new(MAX_REPLAY_LINEAGES),
        };

        let first_resolver = Engine::resolver_for(
            &mut control,
            &first.configs[0],
            &first.dns_groups,
            first.dns_cache_key.as_ref(),
        )
        .await
        .unwrap();
        let second_resolver = Engine::resolver_for(
            &mut control,
            &second.configs[0],
            &second.dns_groups,
            second.dns_cache_key.as_ref(),
        )
        .await
        .unwrap();

        assert!(Arc::ptr_eq(&first_resolver, &second_resolver));
        assert_eq!(control.inline_dns.len(), 1);
    }

    #[tokio::test]
    async fn canonical_urltest_probe_dns_is_not_reused_as_an_unleased_inbound_graph() {
        let probe = validate_urltest_probe_dns_config(Some(&json!({
            "servers": [{"tag": "default-dns", "url": "udp://127.0.0.1:5353"}],
            "final": "default-dns"
        })))
        .await
        .unwrap()
        .unwrap();
        let dns = build_dns_registry(Vec::new()).await.unwrap();
        let registry = ClientChainGroupRegistry::default();
        let mut control = ControlState {
            client_chain_groups: registry.clone(),
            dns,
            inline_dns: HashMap::new(),
            dns_policy_state: PolicyStateRegistry::default(),
            replay_lineages: ReplayLineages::new(MAX_REPLAY_LINEAGES),
        };

        Engine::ensure_urltest_probe_resolver(&mut control, &registry, Some(&probe))
            .await
            .unwrap();

        assert!(control.inline_dns.is_empty());
        assert!(registry.probe_resolver_is_bound());
    }

    #[tokio::test]
    async fn update_and_remove_prune_dead_inline_dns_entries() {
        let engine = Engine::bootstrap().await.unwrap();
        let address = free_tcp_address();
        let initial_config = inbound_with_dns_at(address, "udp://127.0.0.1:5353");
        let initial_key = inline_dns_cache_key(&initial_config).unwrap().unwrap();
        engine
            .add_inbound(InboundSpec {
                tag: "dns-cache-prune".to_string(),
                config: initial_config,
                users: None,
            })
            .await
            .unwrap();
        let (cache_len, key_size, contains_initial) = {
            let control = engine.inner.control.lock().await;
            (
                control.inline_dns.len(),
                std::mem::size_of_val(control.inline_dns.keys().next().unwrap()),
                control.inline_dns.contains_key(&initial_key),
            )
        };
        assert_eq!(cache_len, 1);
        assert_eq!(key_size, 32);
        assert!(contains_initial);

        let updated_config = inbound_with_dns_at(address, "udp://127.0.0.1:5354");
        let updated_key = inline_dns_cache_key(&updated_config).unwrap().unwrap();
        engine
            .update_inbound(InboundSpec {
                tag: "dns-cache-prune".to_string(),
                config: updated_config,
                users: None,
            })
            .await
            .unwrap();
        let (cache_len, contains_initial, contains_updated) = {
            let control = engine.inner.control.lock().await;
            (
                control.inline_dns.len(),
                control.inline_dns.contains_key(&initial_key),
                control.inline_dns.contains_key(&updated_key),
            )
        };
        assert_eq!(cache_len, 1);
        assert!(!contains_initial);
        assert!(contains_updated);

        engine.remove_inbound("dns-cache-prune").await.unwrap();
        let cache_is_empty = {
            let control = engine.inner.control.lock().await;
            control.inline_dns.is_empty()
        };
        assert!(cache_is_empty);
    }

    #[tokio::test]
    async fn removal_after_update_snapshot_is_a_retryable_concurrent_modification() {
        let engine = Engine::bootstrap().await.unwrap();
        let spec = InboundSpec {
            tag: "removed-during-update-preparation".to_string(),
            config: inbound_with_dns_at(free_tcp_address(), "udp://127.0.0.1:5353"),
            users: None,
        };
        engine.add_inbound(spec.clone()).await.unwrap();
        let expected = engine.get_inbound(&spec.tag).expect("inbound is live");
        let snapshot = InboundUpdateSnapshot::new(expected);

        engine.remove_inbound_hard(&spec.tag).await.unwrap();
        let raced = snapshot
            .verify(&engine.inner.inbounds)
            .expect_err("removal after the initial snapshot must fail the CAS fence");
        assert!(raced.is_concurrent_modification());
        assert!(matches!(
            raced,
            EngineError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));

        let initially_missing = engine
            .update_inbound(spec)
            .await
            .expect_err("a tag absent at the initial lookup is still UnknownTag");
        assert!(matches!(initially_missing, EngineError::UnknownTag(_)));
        assert!(!initially_missing.is_concurrent_modification());
    }

    #[tokio::test]
    async fn compiler_key_shares_reject_flood_state_across_distinct_inline_dns_graphs() {
        let key = format!("__acp_dns_reject_v1_{}", "a".repeat(64));
        let first = validate_inbound_config(inbound_with_dns_rules(
            "udp://127.0.0.1:5353",
            json!([{
                "action": "reject",
                "__acp_reject_flood_key": key,
            }]),
        ))
        .await
        .unwrap();
        let second = validate_inbound_config(inbound_with_dns_rules(
            "udp://127.0.0.1:5353",
            json!([
                {
                    "domain": ["other.example"],
                    "action": "predefined",
                    "answer": ["192.0.2.7"],
                },
                {
                    "action": "reject",
                    "__acp_reject_flood_key": key,
                }
            ]),
        ))
        .await
        .unwrap();
        assert_ne!(first.dns_cache_key, second.dns_cache_key);

        let dns = build_dns_registry(Vec::new()).await.unwrap();
        let mut control = ControlState {
            client_chain_groups: ClientChainGroupRegistry::default(),
            dns,
            inline_dns: HashMap::new(),
            dns_policy_state: PolicyStateRegistry::default(),
            replay_lineages: ReplayLineages::new(MAX_REPLAY_LINEAGES),
        };
        let first_resolver = Engine::resolver_for(
            &mut control,
            &first.configs[0],
            &first.dns_groups,
            first.dns_cache_key.as_ref(),
        )
        .await
        .unwrap();
        let second_resolver = Engine::resolver_for(
            &mut control,
            &second.configs[0],
            &second.dns_groups,
            second.dns_cache_key.as_ref(),
        )
        .await
        .unwrap();
        assert!(!Arc::ptr_eq(&first_resolver, &second_resolver));

        let target = NetLocation::new(Address::Hostname("blocked.example".to_string()), 53);
        for _ in 0..50 {
            let error = first_resolver.resolve_location(&target).await.unwrap_err();
            let failure = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .unwrap()
                .failure();
            assert_eq!(
                failure,
                DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
            );
        }
        let error = second_resolver.resolve_location(&target).await.unwrap_err();
        let failure = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<DnsPolicyError>())
            .unwrap()
            .failure();
        assert_eq!(failure, DnsPolicyFailure::Rejected(DnsRejectMethod::Drop));
    }

    #[tokio::test]
    async fn dns_client_rotation_does_not_reuse_a_live_inline_resolver_graph() {
        let key = format!("__acp_dns_reject_v1_{}", "c".repeat(64));
        let validated = validate_inbound_config(inbound_with_dns_rules(
            "udp://127.0.0.1:5353",
            json!([{
                "action": "reject",
                "__acp_reject_flood_key": key,
            }]),
        ))
        .await
        .unwrap();
        let engine = Engine::bootstrap().await.unwrap();
        let first_resolver = {
            let mut control = engine.inner.control.lock().await;
            Engine::resolver_for(
                &mut control,
                &validated.configs[0],
                &validated.dns_groups,
                validated.dns_cache_key.as_ref(),
            )
            .await
            .unwrap()
        };
        let target = NetLocation::new(Address::Hostname("blocked.example".to_string()), 53);
        for _ in 0..50 {
            let error = first_resolver.resolve_location(&target).await.unwrap_err();
            let failure = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .unwrap()
                .failure();
            assert_eq!(
                failure,
                DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
            );
        }

        assert_eq!(engine.rotate_dns_client_generation().await, 1);
        let second_resolver = {
            let mut control = engine.inner.control.lock().await;
            Engine::resolver_for(
                &mut control,
                &validated.configs[0],
                &validated.dns_groups,
                validated.dns_cache_key.as_ref(),
            )
            .await
            .unwrap()
        };
        assert!(!Arc::ptr_eq(&first_resolver, &second_resolver));
        let error = second_resolver.resolve_location(&target).await.unwrap_err();
        let failure = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<DnsPolicyError>())
            .unwrap()
            .failure();
        assert_eq!(
            failure,
            DnsPolicyFailure::Rejected(DnsRejectMethod::Default)
        );
    }

    #[tokio::test]
    async fn replay_lease_survives_candidate_and_rollback_and_is_tag_bound() {
        let engine = Engine::bootstrap().await.unwrap();
        let spec = InboundSpec {
            tag: "replay-replacement".to_string(),
            config: inbound_with_dns_at(free_tcp_address(), "udp://127.0.0.1:5353"),
            users: None,
        };
        engine.add_inbound(spec.clone()).await.unwrap();
        let before = engine
            .preserve_inbound_replay(&spec.tag)
            .expect("running inbound has replay state");

        engine.remove_inbound(&spec.tag).await.unwrap();
        engine
            .add_inbound_with_replay(spec.clone(), &before)
            .await
            .unwrap();
        let after = engine
            .preserve_inbound_replay(&spec.tag)
            .expect("replacement has replay state");
        assert_eq!(before, after);

        engine.remove_inbound_hard(&spec.tag).await.unwrap();
        engine
            .add_inbound_with_replay(spec.clone(), &before)
            .await
            .expect("the same lineage lease remains valid for rollback");
        assert_eq!(before, engine.preserve_inbound_replay(&spec.tag).unwrap());

        let mut wrong_tag = spec.clone();
        wrong_tag.tag = "another-inbound".to_string();
        let error = engine
            .add_inbound_with_replay(wrong_tag, &before)
            .await
            .expect_err("a replay lease must not cross inbound tags");
        assert!(error.to_string().contains("cannot start inbound"));

        engine.remove_inbound_hard(&spec.tag).await.unwrap();
    }

    #[tokio::test]
    async fn replay_lease_cannot_cross_engine_identity() {
        let first = Engine::bootstrap().await.unwrap();
        let second = Engine::bootstrap().await.unwrap();
        let spec = InboundSpec {
            tag: "engine-bound-replay".to_string(),
            config: inbound_with_dns_at(free_tcp_address(), "udp://127.0.0.1:5353"),
            users: None,
        };
        first.add_inbound(spec.clone()).await.unwrap();
        let lease = first.preserve_inbound_replay(&spec.tag).unwrap();

        let error = second
            .add_inbound_with_replay(spec.clone(), &lease)
            .await
            .expect_err("another engine must reject the lease");
        assert!(error.to_string().contains("another engine"));

        first.remove_inbound_hard(&spec.tag).await.unwrap();
    }

    #[tokio::test]
    async fn fresh_readd_invalidates_an_older_replay_lease() {
        let engine = Engine::bootstrap().await.unwrap();
        let spec = InboundSpec {
            tag: "fresh-replay-lineage".to_string(),
            config: inbound_with_dns_at(free_tcp_address(), "udp://127.0.0.1:5353"),
            users: None,
        };
        engine.add_inbound(spec.clone()).await.unwrap();
        let old = engine.preserve_inbound_replay(&spec.tag).unwrap();
        engine.remove_inbound_hard(&spec.tag).await.unwrap();

        engine
            .add_inbound(spec.clone())
            .await
            .expect("a normal add creates a fresh security lineage");
        let fresh = engine.preserve_inbound_replay(&spec.tag).unwrap();
        assert_ne!(old, fresh);
        engine.remove_inbound_hard(&spec.tag).await.unwrap();

        let error = engine
            .add_inbound_with_replay(spec.clone(), &old)
            .await
            .expect_err("a superseded lease must stay stale after removal");
        assert!(error.to_string().contains("is stale"));

        engine
            .add_inbound_with_replay(spec.clone(), &fresh)
            .await
            .expect("the current lineage lease remains recoverable");
        engine.remove_inbound_hard(&spec.tag).await.unwrap();
    }

    #[tokio::test]
    async fn failed_fresh_add_does_not_advance_replay_lineage() {
        let engine = Engine::bootstrap().await.unwrap();
        let spec = InboundSpec {
            tag: "failed-fresh-replay".to_string(),
            config: inbound_with_dns_at(free_tcp_address(), "udp://127.0.0.1:5353"),
            users: None,
        };
        engine.add_inbound(spec.clone()).await.unwrap();
        let lease = engine.preserve_inbound_replay(&spec.tag).unwrap();

        engine
            .add_inbound(spec.clone())
            .await
            .expect_err("duplicate fresh add fails before publishing a lineage");
        engine.remove_inbound_hard(&spec.tag).await.unwrap();
        engine
            .add_inbound_with_replay(spec.clone(), &lease)
            .await
            .expect("the failed fresh add must not invalidate the retained lease");
        engine.remove_inbound_hard(&spec.tag).await.unwrap();
    }
}
