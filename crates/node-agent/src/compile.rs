//! Compile ACP topology directly into native shoes inbound payloads.
//!
//! The Go provider registry is the validation authority. Its two adapters are
//! reproduced here; route/DNS/outbound semantics that shoes cannot preserve are
//! rejected before the runtime transaction begins. The deterministic warning
//! list is reserved for diagnostics that do not change traffic meaning.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::io;
use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use shoes_api::{InboundSpec, UserSpec};
use shoes_engine::Engine;

use crate::outbound_adapter::{
    MAX_OUTBOUND_REFERENCE_DEPTH, OutboundCatalog, OutboundRef, SelectorProjectionCache,
    compile_client_chains_cached, validate_client_outbound,
};
use crate::rule_set::{
    RuleSetLoader, RuleSetReference, RuleSetResource, plan_inline_resource, plan_resource,
};
use crate::runtime::{CompiledInbound, RuntimeConfig};
use crate::topology::provider::{
    CURRENT_CONFIG_VERSION, HYSTERIA2_SALAMANDER_ID, Hysteria2SalamanderConfig,
    VLESS_REALITY_VISION_ID, VlessRealityVisionConfig,
};
use crate::topology::{
    DEFAULT_DIRECT_OUTBOUND, DEFAULT_INBOUND_LISTEN, Dns, DnsRule, DnsServer, DomainResolveOptions,
    MachineTopology, NodeInstance, Outbound, Route, RouteRule, UserCredential,
    VLESS_FLOW_REALITY_VISION,
};

const SUPPORTED_OUTBOUND_TYPES: &[&str] = &[
    "direct",
    "selector",
    "urltest",
    "shadowsocks",
    "trojan",
    "vless",
    "hysteria2",
];

/// Maximum cumulative number of client-chain hops projected into one runtime
/// configuration, including repeated URLTest members and per-inbound copies.
pub const MAX_PROJECTED_CLIENT_CHAIN_HOPS: usize = 65_536;

/// Maximum cumulative serialized JSON size of client-chain values projected
/// into one runtime configuration.
pub const MAX_PROJECTED_CLIENT_CHAIN_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of distinct active URLTest outbounds in one runtime config.
/// Repeated references share one runtime identity and do not consume this twice.
pub const MAX_PROJECTED_URLTEST_GROUPS: usize = 256;

/// Maximum total number of unique candidates scheduled by active URLTest groups.
pub const MAX_PROJECTED_URLTEST_CANDIDATES: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(String);

impl CompileError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CompileError {}

/// Runtime payload plus warnings suitable for an APPLIED acknowledgement.
#[derive(Debug, Clone)]
pub struct CompileOutput {
    pub runtime: RuntimeConfig,
    pub warnings: Vec<String>,
}

/// Compile without opening sockets.  Use [`compile_and_preflight`] before apply
/// when an engine is available.
pub fn compile(topology: &MachineTopology) -> Result<RuntimeConfig, CompileError> {
    Ok(compile_with_warnings(topology)?.runtime)
}

pub fn compile_with_warnings(topology: &MachineTopology) -> Result<CompileOutput, CompileError> {
    if topology.machine_id.is_empty() {
        return Err(CompileError::new("machine_id is required"));
    }

    let mut warnings = BTreeSet::new();
    let mut nodes: Vec<&NodeInstance> = topology.nodes.iter().collect();
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let mut node_ids = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut sniff_enabled = BTreeMap::new();
    let mut inbounds = Vec::with_capacity(nodes.len());
    for node in nodes {
        if !node_ids.insert(node.node_id.clone()) {
            return Err(CompileError::new(format!(
                "duplicate node_id {:?}",
                node.node_id
            )));
        }
        let inbound = compile_inbound(node, &mut warnings)?;
        let effective_tag = inbound.spec.tag.trim();
        if effective_tag.is_empty() {
            return Err(CompileError::new(format!(
                "node {} inbound tag is required",
                node.node_id
            )));
        }
        if !tags.insert(effective_tag.to_string()) {
            return Err(CompileError::new(format!(
                "duplicate inbound tag {:?}",
                effective_tag
            )));
        }
        sniff_enabled.insert(
            effective_tag.to_string(),
            inbound_protocol_sniff_enabled(node)?,
        );
        inbounds.push(inbound);
    }

    // Go compiles providers before the global routing surface.  Keeping that
    // order makes a topology carrying multiple faults report the same primary
    // error to the panel.
    let mut outbounds = validate_outbounds(&topology.outbounds)?;
    validate_outbound_catalog(&outbounds)?;
    let (rule_sets, rule_set_resources) = compile_rule_set_catalog(topology.route.as_ref())?;
    validate_route(topology.route.as_ref(), &outbounds, &rule_sets)?;
    let dns_ip_strategies = validate_dns_resolution_projection(
        topology.route.as_ref(),
        topology.dns.as_ref(),
        &outbounds,
    )?;
    let outbound_dns_projection = project_outbound_dns_resolvers(
        topology.route.as_ref(),
        topology.dns.as_ref(),
        &mut outbounds,
        &dns_ip_strategies,
    )?;
    let mut client_chain_projection_budget = ClientChainProjectionBudget::default();
    // Go constructs the generation-global DNS/outbound graph before any
    // inbound-scoped projection. Keep this sidecar even when no current node
    // activates URLTest: a later apply may add a matching node without changing
    // the global DNS fingerprint, and must inherit the correct probe DNS.
    let urltest_probe_dns = compile_dns(
        topology.dns.as_ref(),
        &outbounds,
        &rule_sets,
        None,
        &dns_ip_strategies,
        &outbound_dns_projection,
        &mut client_chain_projection_budget,
    )?;

    for inbound in &mut inbounds {
        let rules = compile_rules_for_inbound(
            topology.route.as_ref(),
            &outbounds,
            &rule_sets,
            &inbound.spec.tag,
            sniff_enabled
                .get(&inbound.spec.tag)
                .copied()
                .unwrap_or(false),
            &mut client_chain_projection_budget,
        )?;
        inbound.spec.config["rules"] = Value::Array(rules);
        if let Some(dns) = compile_dns(
            topology.dns.as_ref(),
            &outbounds,
            &rule_sets,
            Some(&inbound.spec.tag),
            &dns_ip_strategies,
            &outbound_dns_projection,
            &mut client_chain_projection_budget,
        )? {
            inbound.spec.config["dns"] = dns;
        }
    }
    let warnings: Vec<String> = warnings.into_iter().collect();
    let diagnostic_yaml = diagnostic_yaml(topology, &inbounds, &outbounds, &warnings)?;
    let dns_client_fingerprint = Sha256::digest(
        serde_json::to_vec(&(&topology.dns, &topology.route, &topology.outbounds))
            .expect("typed global topology always serializes to JSON"),
    )
    .into();
    Ok(CompileOutput {
        runtime: RuntimeConfig {
            inbounds,
            rule_sets: rule_set_resources,
            diagnostic_yaml,
            dns_client_fingerprint,
            urltest_probe_dns,
        },
        warnings,
    })
}

/// Compile and run the same schema/user preflight used by a live engine.
pub async fn compile_and_preflight(
    topology: &MachineTopology,
    engine: &Engine,
) -> Result<CompileOutput, CompileError> {
    let output = compile_with_warnings(topology)?;
    let prepared = RuleSetLoader::new()
        .map_err(|error| CompileError::new(format!("build rule-set loader: {error}")))?
        .prepare(&output.runtime.rule_sets)
        .await
        .map_err(|error| CompileError::new(format!("prepare route rule-sets: {error}")))?;
    for inbound in &output.runtime.inbounds {
        let mut spec = inbound.spec.clone();
        prepared.rewrite_config(&mut spec.config);
        engine.validate_inbound(&spec).await.map_err(|error| {
            CompileError::new(format!(
                "node {} ({}) failed shoes preflight: {error}",
                inbound.node_id, inbound.spec.tag
            ))
        })?;
    }
    let mut urltest_probe_dns = output.runtime.urltest_probe_dns.clone();
    if let Some(probe_dns) = &mut urltest_probe_dns {
        prepared.rewrite_config(probe_dns);
    }
    engine
        .validate_urltest_probe_dns(urltest_probe_dns.as_ref())
        .await
        .map_err(|error| {
            CompileError::new(format!(
                "generation-global URLTest probe DNS failed shoes preflight: {error}"
            ))
        })?;
    Ok(output)
}

/// Go's `DirectOutboundIsEmpty` predicate, used by port-hopping planning to
/// reject a detour whose direct dialer has no effective settings.
pub fn direct_outbound_is_empty(options: &crate::topology::RawJson) -> Result<bool, CompileError> {
    let value = if options.is_empty() {
        json!({})
    } else {
        options.value().map_err(|error| {
            CompileError::new(format!("invalid Direct outbound options: {error}"))
        })?
    };
    let Some(fields) = value.as_object() else {
        return Err(CompileError::new(
            "invalid Direct outbound options: expected a JSON object",
        ));
    };
    validate_outbound_options("direct", "direct", fields)?;
    Ok(!fields.iter().any(|(name, value)| {
        // sing-box distinguishes an explicitly configured udp_fragment=false
        // from the absent default, even though ordinary bool zero values vanish.
        name == "udp_fragment" || json_value_is_effective(value)
    }))
}

fn json_value_is_effective(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => values.values().any(json_value_is_effective),
    }
}

#[derive(Debug, Clone)]
struct ValidatedOutbound {
    /// Stable identity within one immutable validated catalog. Projection
    /// caches use this instead of repeatedly hashing or comparing long tags.
    id: usize,
    kind: String,
    tag: String,
    /// Adapter-safe options. Panel-managed `domain_resolver` is consumed by
    /// the compiler before this value enters a shoes client chain.
    options: Value,
    /// Unmodified request used by diagnostics.
    requested_options: Value,
    domain_resolver: Option<OutboundDomainResolver>,
    /// Shoes DNS upstream tag selected only while this outbound's socket
    /// connector resolves a hostname. Populated after the DNS catalog is
    /// validated, so ordinary route and DNS consumers keep their own policy.
    shoes_dns_resolver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundDomainResolver {
    server: String,
    strategy: String,
    query: DnsServerQueryProfile,
}

fn outbound_inherits_default_domain_resolver(outbound: &ValidatedOutbound) -> bool {
    if matches!(outbound.kind.as_str(), "selector" | "urltest") {
        return false;
    }
    // Go's common dialer bypasses the current outbound's local dialer when a
    // detour is present. Only an explicitly attached resolver (handled by the
    // caller before this fallback) may resolve that current proxy hop.
    outbound
        .options
        .get("detour")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
}

impl OutboundCatalog for BTreeMap<String, ValidatedOutbound> {
    fn resolve(&self, tag: &str) -> Option<OutboundRef<'_>> {
        self.get(tag).map(ValidatedOutbound::as_outbound_ref)
    }

    fn dns_resolver(&self, tag: &str) -> Option<&str> {
        self.get(tag)?.shoes_dns_resolver.as_deref()
    }
}

impl ValidatedOutbound {
    fn as_outbound_ref(&self) -> OutboundRef<'_> {
        OutboundRef {
            id: self.id,
            kind: &self.kind,
            tag: &self.tag,
            options: &self.options,
            dns_resolver: self.shoes_dns_resolver.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ClientChainProjectionCost {
    hops: usize,
    bytes: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct ClientChainsProjection {
    hops: usize,
    chain_count: usize,
    chain_element_bytes: usize,
}

impl ClientChainsProjection {
    fn inspect(value: &Value) -> Result<Self, CompileError> {
        let chains = value.as_array().ok_or_else(|| {
            CompileError::new("compiled outbound did not produce a client-chain array")
        })?;
        let mut projection = Self::default();
        for chain in chains {
            let hops = chain
                .get("chain")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    CompileError::new("compiled outbound produced an invalid client-chain entry")
                })?
                .len();
            projection.hops = projection.hops.checked_add(hops).ok_or_else(|| {
                CompileError::new("projected client-chain hop count overflowed usize")
            })?;
            projection.chain_count = projection.chain_count.checked_add(1).ok_or_else(|| {
                CompileError::new("projected client-chain count overflowed usize")
            })?;
            projection.chain_element_bytes = projection
                .chain_element_bytes
                .checked_add(serialized_json_len(chain)?)
                .ok_or_else(|| {
                    CompileError::new("projected client-chain byte count overflowed usize")
                })?;
        }
        Ok(projection)
    }

    fn append(&mut self, other: Self) -> Result<(), CompileError> {
        self.hops = self.hops.checked_add(other.hops).ok_or_else(|| {
            CompileError::new("projected client-chain hop count overflowed usize")
        })?;
        self.chain_count = self
            .chain_count
            .checked_add(other.chain_count)
            .ok_or_else(|| CompileError::new("projected client-chain count overflowed usize"))?;
        self.chain_element_bytes = self
            .chain_element_bytes
            .checked_add(other.chain_element_bytes)
            .ok_or_else(|| {
                CompileError::new("projected client-chain byte count overflowed usize")
            })?;
        Ok(())
    }

    fn cost(self, selection: Option<&Value>) -> Result<ClientChainProjectionCost, CompileError> {
        let selection_bytes = selection.map(serialized_json_len).transpose()?.unwrap_or(0);
        self.cost_with_selection_bytes(selection_bytes)
    }

    fn cost_with_selection_bytes(
        self,
        selection_bytes: usize,
    ) -> Result<ClientChainProjectionCost, CompileError> {
        // JSON array brackets plus the commas between chain objects.
        let mut bytes = self
            .chain_element_bytes
            .checked_add(2)
            .and_then(|bytes| bytes.checked_add(self.chain_count.saturating_sub(1)))
            .ok_or_else(|| {
                CompileError::new("projected client-chain byte count overflowed usize")
            })?;
        bytes = bytes.checked_add(selection_bytes).ok_or_else(|| {
            CompileError::new("projected client-chain byte count overflowed usize")
        })?;
        Ok(ClientChainProjectionCost {
            hops: self.hops,
            bytes,
        })
    }
}

#[derive(Debug, Default)]
struct ClientChainProjectionBudget<'a> {
    used: ClientChainProjectionCost,
    selector_immediate: BTreeMap<usize, &'a ValidatedOutbound>,
    selector_terminals: BTreeMap<usize, &'a ValidatedOutbound>,
    compiled_samples: BTreeMap<usize, CompiledClientChainSample>,
    urltest_samples: BTreeMap<usize, CachedUrltestAction>,
    urltest_candidates: usize,
    adapter_cache: SelectorProjectionCache<'a>,
}

#[derive(Debug)]
struct CompiledClientChainSample {
    value: Value,
    projection: ClientChainsProjection,
}

#[derive(Debug, Clone)]
struct CachedUrltestAction {
    action: CompiledOutboundAction,
    cost: ClientChainProjectionCost,
}

impl ClientChainProjectionBudget<'_> {
    fn ensure_can_reserve(
        &self,
        additional: ClientChainProjectionCost,
        context: impl FnOnce() -> String,
    ) -> Result<(), CompileError> {
        let hops = self.used.hops.checked_add(additional.hops).ok_or_else(|| {
            CompileError::new("projected client-chain hop count overflowed usize")
        })?;
        let bytes = self
            .used
            .bytes
            .checked_add(additional.bytes)
            .ok_or_else(|| {
                CompileError::new("projected client-chain byte count overflowed usize")
            })?;
        if hops > MAX_PROJECTED_CLIENT_CHAIN_HOPS || bytes > MAX_PROJECTED_CLIENT_CHAIN_BYTES {
            let context = context();
            return Err(CompileError::new(format!(
                "client-chain projection budget exceeded while compiling {context}: RuntimeConfig would contain {hops} projected hops and {bytes} projected JSON bytes; maximums are {MAX_PROJECTED_CLIENT_CHAIN_HOPS} hops and {MAX_PROJECTED_CLIENT_CHAIN_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        additional: ClientChainProjectionCost,
        context: impl FnOnce() -> String,
    ) -> Result<(), CompileError> {
        self.ensure_can_reserve(additional, context)?;
        self.used.hops += additional.hops;
        self.used.bytes += additional.bytes;
        Ok(())
    }
}

#[derive(Default)]
struct JsonByteCounter {
    bytes: usize,
}

impl io::Write for JsonByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized JSON byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_json_len(value: &Value) -> Result<usize, CompileError> {
    let mut counter = JsonByteCounter::default();
    serde_json::to_writer(&mut counter, value).map_err(|error| {
        CompileError::new(format!("measure projected client-chain JSON: {error}"))
    })?;
    Ok(counter.bytes)
}

fn prepare_outbound_client_chains<'a>(
    outbound: &'a ValidatedOutbound,
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<(), CompileError> {
    if budget.compiled_samples.contains_key(&outbound.id) {
        return Ok(());
    }
    let compiled = compile_client_chains_cached(
        &outbound.kind,
        &outbound.tag,
        &outbound.options,
        catalog,
        &mut budget.adapter_cache,
    )
    .map_err(|error| CompileError::new(format!("compile outbound {:?}: {error}", outbound.tag)))?;
    let projection = ClientChainsProjection::inspect(&compiled)?;
    budget.compiled_samples.insert(
        outbound.id,
        CompiledClientChainSample {
            value: compiled,
            projection,
        },
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct CompiledOutboundAction {
    client_chains: Value,
    client_chain_selection: Option<Value>,
}

fn outbound_client_action<'a>(
    outbound: &'a ValidatedOutbound,
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<CompiledOutboundAction, CompileError> {
    let selected = resolve_static_selector_outbound(
        outbound,
        catalog,
        &mut budget.selector_terminals,
        &mut budget.selector_immediate,
        &mut budget.adapter_cache,
    )?;
    if selected.kind == "urltest" {
        return compile_urltest_action(selected, catalog, budget);
    }
    prepare_outbound_client_chains(selected, catalog, budget)?;
    let projection = budget
        .compiled_samples
        .get(&selected.id)
        .expect("prepared outbound chain sample is cached")
        .projection;
    budget.reserve(projection.cost(None)?, || {
        format!("outbound {:?}", outbound.tag)
    })?;
    Ok(CompiledOutboundAction {
        client_chains: budget
            .compiled_samples
            .get(&selected.id)
            .expect("reserved outbound chain sample is cached")
            .value
            .clone(),
        client_chain_selection: None,
    })
}

/// Validate every configured outbound before route and DNS references select a
/// subset of them.
///
/// The Go compiler strictly decodes the complete outbound list up front.  Doing
/// the same adapter pass here prevents an unused outbound, or a selector member
/// that is not currently selected, from becoming a latent apply-time failure.
fn validate_outbound_catalog(
    catalog: &BTreeMap<String, ValidatedOutbound>,
) -> Result<(), CompileError> {
    // Validate protocol-specific fields once without walking references. The
    // graph pass below owns reference completeness, cycle, and depth checks.
    for outbound in catalog.values() {
        if outbound.kind == "urltest" {
            let _ = parse_urltest_definition(outbound)?;
        } else {
            validate_client_outbound(&outbound.kind, &outbound.tag, &outbound.options, catalog)
                .map_err(|error| {
                    CompileError::new(format!("compile outbound {:?}: {error}", outbound.tag))
                })?;
        }
    }

    ReferenceGraphValidator::new(catalog).validate()?;
    OutboundActionShapeValidator::new(catalog).validate()?;
    Ok(())
}

#[derive(Debug)]
struct SelectorDefinition<'a> {
    members: Vec<&'a str>,
    selected: &'a str,
}

fn parse_selector_definition(
    outbound: &ValidatedOutbound,
) -> Result<SelectorDefinition<'_>, CompileError> {
    let fields = outbound.options.as_object().ok_or_else(|| {
        CompileError::new(format!(
            "selector outbound {:?} options must be an object",
            outbound.tag
        ))
    })?;
    let values = fields
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CompileError::new(format!(
                "selector outbound {:?} requires an outbounds string array",
                outbound.tag
            ))
        })?;
    if values.is_empty() {
        return Err(CompileError::new(format!(
            "selector outbound {:?} requires at least one member",
            outbound.tag
        )));
    }
    let mut members = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let member = value
            .as_str()
            .filter(|member| !member.is_empty())
            .ok_or_else(|| {
                CompileError::new(format!(
                    "selector outbound {:?} outbounds[{index}] must be a non-empty string",
                    outbound.tag
                ))
            })?;
        seen.insert(member);
        members.push(member);
    }

    let default = match fields.get("default") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.is_empty() => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(CompileError::new(format!(
                "selector outbound {:?} default must be a string",
                outbound.tag
            )));
        }
    };
    if let Some(default) = default
        && !seen.contains(default)
    {
        return Err(CompileError::new(format!(
            "selector outbound {:?} default {default:?} is not a member",
            outbound.tag
        )));
    }
    let selected = default.unwrap_or(members[0]);
    Ok(SelectorDefinition { members, selected })
}

#[derive(Debug)]
struct UrltestDefinition<'a> {
    members: Vec<&'a str>,
    selection: Value,
}

fn parse_urltest_definition(
    outbound: &ValidatedOutbound,
) -> Result<UrltestDefinition<'_>, CompileError> {
    const DEFAULT_INTERVAL_MILLIS: u64 = 3 * 60 * 1_000;
    const DEFAULT_IDLE_TIMEOUT_MILLIS: u64 = 30 * 60 * 1_000;

    let fields = outbound.options.as_object().ok_or_else(|| {
        CompileError::new(format!(
            "urltest outbound {:?} options must be an object",
            outbound.tag
        ))
    })?;
    const ALLOWED: &[&str] = &[
        "outbounds",
        "url",
        "interval",
        "tolerance",
        "idle_timeout",
        "interrupt_exist_connections",
    ];
    if let Some(field) = fields
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(CompileError::new(format!(
            "urltest outbound {:?} field {field:?} cannot be represented by shoes",
            outbound.tag
        )));
    }

    let values = fields
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CompileError::new(format!(
                "urltest outbound {:?} requires an outbounds string array",
                outbound.tag
            ))
        })?;
    if values.is_empty() {
        return Err(CompileError::new(format!(
            "urltest outbound {:?} requires at least one member",
            outbound.tag
        )));
    }
    let members = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|member| !member.is_empty())
                .ok_or_else(|| {
                    CompileError::new(format!(
                        "urltest outbound {:?} outbounds[{index}] must be a non-empty string",
                        outbound.tag
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let requested_url = match fields.get("url") {
        None | Some(Value::Null) => "",
        Some(Value::String(url)) => url.as_str(),
        Some(_) => {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} url must be a string",
                outbound.tag
            )));
        }
    };
    let interval_millis = parse_urltest_duration(
        &outbound.tag,
        fields.get("interval"),
        "interval",
        DEFAULT_INTERVAL_MILLIS,
    )?;
    let idle_timeout_millis = parse_urltest_duration(
        &outbound.tag,
        fields.get("idle_timeout"),
        "idle_timeout",
        DEFAULT_IDLE_TIMEOUT_MILLIS,
    )?;
    if interval_millis > idle_timeout_millis {
        return Err(CompileError::new(format!(
            "urltest outbound {:?} interval must be less than or equal to idle_timeout",
            outbound.tag
        )));
    }
    let tolerance = match fields.get("tolerance") {
        None | Some(Value::Null) => 50,
        Some(Value::Number(value)) => {
            let value = value
                .as_u64()
                .filter(|value| *value <= u64::from(u16::MAX))
                .ok_or_else(|| {
                    CompileError::new(format!(
                        "urltest outbound {:?} tolerance must be an unsigned 16-bit integer",
                        outbound.tag
                    ))
                })?;
            if value == 0 { 50 } else { value }
        }
        Some(_) => {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} tolerance must be an unsigned 16-bit integer",
                outbound.tag
            )));
        }
    };
    match fields.get("interrupt_exist_connections") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} requests interrupt_exist_connections; shoes cannot revoke already-established connections when the selected chain changes",
                outbound.tag
            )));
        }
        Some(_) => {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} interrupt_exist_connections must be a boolean",
                outbound.tag
            )));
        }
    }

    Ok(UrltestDefinition {
        members,
        selection: json!({
            "type": "urltest",
            // Replaced by compile_urltest_action after the member chains are
            // known. The final digest has the same fixed length, so projection
            // budget accounting remains exact while the graph is assembled.
            "shared_id": "node-agent-urltest-v1:0000000000000000000000000000000000000000000000000000000000000000",
            "url": requested_url,
            "use_native_roots": true,
            "reselect_on_connection_failure": false,
            "interval_millis": interval_millis,
            "idle_timeout_millis": idle_timeout_millis,
            "tolerance_millis": tolerance,
        }),
    })
}

#[derive(Debug)]
enum OutboundReference {
    SelectorMember(String),
    UrltestMember(String),
    Detour(String),
}

impl OutboundReference {
    fn target(&self) -> &str {
        match self {
            Self::SelectorMember(target) | Self::UrltestMember(target) | Self::Detour(target) => {
                target
            }
        }
    }
}

fn effective_detour(outbound: &ValidatedOutbound) -> Option<&str> {
    outbound
        .options
        .get("detour")
        .and_then(Value::as_str)
        .filter(|detour| !detour.is_empty())
}

fn outbound_references(
    outbound: &ValidatedOutbound,
) -> Result<Vec<OutboundReference>, CompileError> {
    match outbound.kind.as_str() {
        "selector" => Ok(parse_selector_definition(outbound)?
            .members
            .into_iter()
            .map(|member| OutboundReference::SelectorMember(member.to_string()))
            .collect()),
        "urltest" => Ok(parse_urltest_definition(outbound)?
            .members
            .into_iter()
            .map(|member| OutboundReference::UrltestMember(member.to_string()))
            .collect()),
        _ => Ok(effective_detour(outbound)
            .map(|detour| vec![OutboundReference::Detour(detour.to_string())])
            .unwrap_or_default()),
    }
}

#[derive(Debug, Clone, Copy)]
enum ReferenceVisitState {
    Visiting,
    Complete { depth: usize },
}

struct ReferenceGraphValidator<'a> {
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    states: BTreeMap<String, ReferenceVisitState>,
    stack: Vec<String>,
}

impl<'a> ReferenceGraphValidator<'a> {
    fn new(catalog: &'a BTreeMap<String, ValidatedOutbound>) -> Self {
        Self {
            catalog,
            states: BTreeMap::new(),
            stack: Vec::new(),
        }
    }

    fn validate(mut self) -> Result<(), CompileError> {
        let tags: Vec<String> = self.catalog.keys().cloned().collect();
        for tag in tags {
            let _ = self.visit(&tag)?;
        }
        Ok(())
    }

    fn visit(&mut self, tag: &str) -> Result<usize, CompileError> {
        match self.states.get(tag).copied() {
            Some(ReferenceVisitState::Complete { depth }) => return Ok(depth),
            Some(ReferenceVisitState::Visiting) => {
                let cycle_start = self
                    .stack
                    .iter()
                    .position(|active| active == tag)
                    .expect("a visiting outbound is present on the DFS stack");
                let mut cycle = self.stack[cycle_start..].to_vec();
                cycle.push(tag.to_string());
                return Err(CompileError::new(format!(
                    "outbound reference cycle: {}",
                    cycle.join(" -> ")
                )));
            }
            None => {}
        }

        // Bound the live recursion before descending. Complete-node depths are
        // also combined below so traversal order cannot hide a long shared suffix.
        if self.stack.len() >= MAX_OUTBOUND_REFERENCE_DEPTH {
            let mut path = self.stack.clone();
            path.push(tag.to_string());
            return Err(CompileError::new(format!(
                "outbound reference depth exceeds maximum {MAX_OUTBOUND_REFERENCE_DEPTH}: {}",
                path.join(" -> ")
            )));
        }

        let outbound = self
            .catalog
            .get(tag)
            .expect("graph traversal only starts from catalog tags");
        let references = outbound_references(outbound)?;
        self.states
            .insert(tag.to_string(), ReferenceVisitState::Visiting);
        self.stack.push(tag.to_string());

        let mut max_child_depth = 0;
        for reference in references {
            let target = reference.target();
            if !self.catalog.contains_key(target) {
                return Err(match reference {
                    OutboundReference::SelectorMember(member) => CompileError::new(format!(
                        "selector outbound {tag:?} references unknown member {member:?}"
                    )),
                    OutboundReference::UrltestMember(member) => CompileError::new(format!(
                        "urltest outbound {tag:?} references unknown member {member:?}"
                    )),
                    OutboundReference::Detour(detour) => CompileError::new(format!(
                        "outbound {tag:?} references unknown detour {detour:?}"
                    )),
                });
            }
            max_child_depth = max_child_depth.max(self.visit(target)?);
        }

        self.stack.pop();
        let depth = max_child_depth + 1;
        if depth > MAX_OUTBOUND_REFERENCE_DEPTH {
            return Err(CompileError::new(format!(
                "outbound reference depth from {tag:?} is {depth}, exceeding maximum {MAX_OUTBOUND_REFERENCE_DEPTH}"
            )));
        }
        self.states
            .insert(tag.to_string(), ReferenceVisitState::Complete { depth });
        Ok(depth)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundActionShape {
    Plain,
    Urltest,
}

struct OutboundActionShapeValidator<'a> {
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    completed: BTreeMap<String, OutboundActionShape>,
}

impl<'a> OutboundActionShapeValidator<'a> {
    fn new(catalog: &'a BTreeMap<String, ValidatedOutbound>) -> Self {
        Self {
            catalog,
            completed: BTreeMap::new(),
        }
    }

    fn validate(mut self) -> Result<(), CompileError> {
        let tags: Vec<String> = self.catalog.keys().cloned().collect();
        for tag in tags {
            let _ = self.shape(&tag)?;
        }
        Ok(())
    }

    fn shape(&mut self, tag: &str) -> Result<OutboundActionShape, CompileError> {
        if let Some(shape) = self.completed.get(tag).copied() {
            return Ok(shape);
        }
        let outbound = self
            .catalog
            .get(tag)
            .expect("action-shape validation follows a validated reference graph");
        let kind = outbound.kind.clone();
        let shape = match kind.as_str() {
            "selector" => {
                let selected = parse_selector_definition(outbound)?.selected.to_string();
                self.shape(&selected)?
            }
            "urltest" => {
                let members: Vec<String> = parse_urltest_definition(outbound)?
                    .members
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                for member in members {
                    if self.shape(&member)? == OutboundActionShape::Urltest {
                        return Err(CompileError::new(format!(
                            "urltest outbound {tag:?} contains nested active urltest through member {member:?}"
                        )));
                    }
                }
                OutboundActionShape::Urltest
            }
            _ => {
                let detour = effective_detour(outbound).map(str::to_string);
                if let Some(detour) = detour
                    && self.shape(&detour)? == OutboundActionShape::Urltest
                {
                    return Err(CompileError::new(format!(
                        "outbound {tag:?} detour {detour:?} selects urltest; shoes cannot embed active client-chain selection inside one proxy chain"
                    )));
                }
                OutboundActionShape::Plain
            }
        };
        self.completed.insert(tag.to_string(), shape);
        Ok(shape)
    }
}

fn cached_selector_outbound<'a>(
    id: usize,
    completed: &mut BTreeMap<usize, &'a ValidatedOutbound>,
    resolve: impl FnOnce() -> Result<&'a ValidatedOutbound, CompileError>,
) -> Result<(&'a ValidatedOutbound, bool), CompileError> {
    if let Some(selected) = completed.get(&id).copied() {
        return Ok((selected, false));
    }
    let selected = resolve()?;
    completed.insert(id, selected);
    Ok((selected, true))
}

fn immediate_selector_outbound<'a>(
    outbound: &ValidatedOutbound,
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    completed: &mut BTreeMap<usize, &'a ValidatedOutbound>,
    adapter_cache: &mut SelectorProjectionCache<'a>,
) -> Result<&'a ValidatedOutbound, CompileError> {
    let (selected, inserted) = cached_selector_outbound(outbound.id, completed, || {
        let selected_tag = parse_selector_definition(outbound)?.selected;
        catalog.get(selected_tag).ok_or_else(|| {
            CompileError::new(format!(
                "selector outbound {:?} references unknown member {selected_tag:?}",
                outbound.tag
            ))
        })
    })?;
    if inserted {
        adapter_cache.remember(outbound.id, selected.as_outbound_ref());
    }
    Ok(selected)
}

fn resolve_static_selector_outbound<'a>(
    outbound: &'a ValidatedOutbound,
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    completed: &mut BTreeMap<usize, &'a ValidatedOutbound>,
    immediate: &mut BTreeMap<usize, &'a ValidatedOutbound>,
    adapter_cache: &mut SelectorProjectionCache<'a>,
) -> Result<&'a ValidatedOutbound, CompileError> {
    let mut current = outbound;
    let mut path: Vec<&'a ValidatedOutbound> = Vec::new();
    loop {
        if let Some(terminal) = completed.get(&current.id).copied() {
            for outbound in path {
                completed.insert(outbound.id, terminal);
            }
            return Ok(terminal);
        }
        if let Some(cycle_start) = path.iter().position(|active| active.id == current.id) {
            let cycle = path[cycle_start..]
                .iter()
                .map(|outbound| outbound.tag.as_str())
                .chain(std::iter::once(current.tag.as_str()))
                .collect::<Vec<_>>();
            return Err(CompileError::new(format!(
                "outbound reference cycle: {}",
                cycle.join(" -> ")
            )));
        }
        if path.len() >= MAX_OUTBOUND_REFERENCE_DEPTH {
            path.push(current);
            return Err(CompileError::new(format!(
                "outbound reference depth exceeds maximum {MAX_OUTBOUND_REFERENCE_DEPTH}: {}",
                path.iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            )));
        }
        if current.kind != "selector" {
            completed.insert(current.id, current);
            for outbound in path {
                completed.insert(outbound.id, current);
            }
            return Ok(current);
        }
        path.push(current);
        current = immediate_selector_outbound(current, catalog, immediate, adapter_cache)?;
    }
}

fn compile_urltest_action<'a>(
    outbound: &'a ValidatedOutbound,
    catalog: &'a BTreeMap<String, ValidatedOutbound>,
    budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<CompiledOutboundAction, CompileError> {
    if let Some(cost) = budget
        .urltest_samples
        .get(&outbound.id)
        .map(|sample| sample.cost)
    {
        budget.reserve(cost, || format!("urltest outbound {:?}", outbound.tag))?;
        return Ok(budget
            .urltest_samples
            .get(&outbound.id)
            .expect("reserved URLTest action sample is cached")
            .action
            .clone());
    }

    if budget.urltest_samples.len() >= MAX_PROJECTED_URLTEST_GROUPS {
        return Err(CompileError::new(format!(
            "active URLTest group budget exceeded while compiling {:?}: maximum is {MAX_PROJECTED_URLTEST_GROUPS} distinct groups per RuntimeConfig",
            outbound.tag
        )));
    }

    let definition = parse_urltest_definition(outbound)?;
    let mut selected_ids = BTreeSet::new();
    let mut resolved_members = Vec::new();
    let mut history_keys = Vec::new();
    let mut failure_history_keys = Vec::new();
    let mut compiled_members = Vec::new();
    let mut projection = ClientChainsProjection::default();

    // Go probes each selected RealTag once. RealTag calls OutboundGroup.Now()
    // exactly once, so a selector contributes its immediate selected tag while
    // a non-selector contributes its own tag. Keep recursive selector folding
    // below for the actual projected chain, but do not use its terminal tag as
    // the deduplication identity: A -> B(selector) -> X and direct B -> X have
    // distinct Go RealTags B and X.
    // Resolve and deduplicate immediate RealTags first. Their identities are
    // serialized into the selection, so doing this pass up front keeps byte
    // accounting exact rather than retroactively growing every cached action.
    for member_tag in definition.members {
        let member = catalog.get(member_tag).ok_or_else(|| {
            CompileError::new(format!(
                "urltest outbound {:?} references unknown member {member_tag:?}",
                outbound.tag
            ))
        })?;
        // A repeated URLTest member must not reparse all M members of the same
        // selector N times. Cache its immediate identity and discard duplicate
        // RealTags before any recursive selector resolution or chain compile.
        let real_outbound = if member.kind == "selector" {
            immediate_selector_outbound(
                member,
                catalog,
                &mut budget.selector_immediate,
                &mut budget.adapter_cache,
            )?
        } else {
            member
        };
        if !selected_ids.insert(real_outbound.id) {
            continue;
        }
        let projected_candidates = budget
            .urltest_candidates
            .checked_add(selected_ids.len())
            .ok_or_else(|| CompileError::new("active URLTest candidate count overflowed usize"))?;
        if projected_candidates > MAX_PROJECTED_URLTEST_CANDIDATES {
            return Err(CompileError::new(format!(
                "active URLTest candidate budget exceeded while compiling {:?}: RuntimeConfig would schedule {projected_candidates} candidates; maximum is {MAX_PROJECTED_URLTEST_CANDIDATES}",
                outbound.tag
            )));
        }
        history_keys.push(real_outbound.tag.clone());
        failure_history_keys.push(member.tag.clone());
        resolved_members.push(member);
    }

    let mut selection = definition.selection;
    selection
        .as_object_mut()
        .expect("URLTest selection is constructed as an object")
        .insert("history_keys".to_string(), json!(history_keys));
    selection
        .as_object_mut()
        .expect("URLTest selection is constructed as an object")
        .insert(
            "failure_history_keys".to_string(),
            json!(failure_history_keys),
        );
    let selection_bytes = serialized_json_len(&selection)?;

    // Preflight the complete unique expansion before moving it into the final
    // array so a shared detour suffix cannot trigger unbounded N-by-D output.
    for member in resolved_members {
        let selected = resolve_static_selector_outbound(
            member,
            catalog,
            &mut budget.selector_terminals,
            &mut budget.selector_immediate,
            &mut budget.adapter_cache,
        )?;
        if selected.kind == "urltest" {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} contains nested active urltest through member {:?}",
                outbound.tag, member.tag
            )));
        }
        prepare_outbound_client_chains(selected, catalog, budget)?;
        let sample = budget
            .compiled_samples
            .get(&selected.id)
            .expect("prepared URLTest chain sample is cached");
        projection.append(sample.projection)?;
        budget.ensure_can_reserve(
            projection.cost_with_selection_bytes(selection_bytes)?,
            || format!("urltest outbound {:?}", outbound.tag),
        )?;
        compiled_members.push(sample.value.clone());
    }

    let cost = projection.cost_with_selection_bytes(selection_bytes)?;
    budget.reserve(cost, || format!("urltest outbound {:?}", outbound.tag))?;

    let mut chains = Vec::with_capacity(projection.chain_count);
    for compiled in compiled_members {
        let Value::Array(member_chains) = compiled else {
            unreachable!("compiled URLTest member chains were inspected above");
        };
        chains.extend(member_chains);
    }

    let identity_source =
        serde_json::to_vec(&(&outbound.tag, &chains, &selection)).map_err(|error| {
            CompileError::new(format!(
                "urltest outbound {:?} could not derive its runtime identity: {error}",
                outbound.tag
            ))
        })?;
    let mut shared_id = String::from("node-agent-urltest-v1:");
    for byte in Sha256::digest(identity_source) {
        write!(&mut shared_id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    selection
        .as_object_mut()
        .expect("URLTest selection is constructed as an object")
        .insert("shared_id".to_string(), Value::String(shared_id));

    let action = CompiledOutboundAction {
        client_chains: Value::Array(chains),
        client_chain_selection: Some(selection),
    };
    budget.urltest_samples.insert(
        outbound.id,
        CachedUrltestAction {
            action: action.clone(),
            cost,
        },
    );
    budget.urltest_candidates = budget
        .urltest_candidates
        .checked_add(selected_ids.len())
        .expect("URLTest candidate capacity was checked above");
    Ok(action)
}

fn parse_urltest_duration(
    tag: &str,
    value: Option<&Value>,
    field: &str,
    default_millis: u64,
) -> Result<u64, CompileError> {
    let Some(value) = value else {
        return Ok(default_millis);
    };
    let Value::String(value) = value else {
        return Err(CompileError::new(format!(
            "urltest outbound {tag:?} {field} must be a Go duration string"
        )));
    };
    let duration = shoes::config::parse_go_duration(value).map_err(|error| {
        CompileError::new(format!(
            "urltest outbound {tag:?} has invalid {field} {value:?}: {error}"
        ))
    })?;
    if duration.is_zero() {
        return Ok(default_millis);
    }
    if duration.subsec_nanos() % 1_000_000 != 0 {
        return Err(CompileError::new(format!(
            "urltest outbound {tag:?} {field} {value:?} has sub-millisecond precision that shoes cannot preserve"
        )));
    }
    u64::try_from(duration.as_millis()).map_err(|_| {
        CompileError::new(format!(
            "urltest outbound {tag:?} {field} {value:?} is too large"
        ))
    })
}

fn apply_outbound_action(target: &mut Value, chain_field: &str, action: CompiledOutboundAction) {
    target[chain_field] = action.client_chains;
    if let Some(selection) = action.client_chain_selection {
        target["client_chain_selection"] = selection;
    }
}

fn reserve_embedded_outbound_action(
    source: &Value,
    chain_field: &str,
    budget: &mut ClientChainProjectionBudget,
    context: impl FnOnce() -> String,
) -> Result<(), CompileError> {
    let Some(client_chains) = source.get(chain_field) else {
        return Ok(());
    };
    let projection = ClientChainsProjection::inspect(client_chains)?;
    budget.reserve(
        projection.cost(source.get("client_chain_selection"))?,
        context,
    )
}

type CompiledRuleSet = RuleSetReference;

fn compile_rule_set_catalog(
    route: Option<&Route>,
) -> Result<(BTreeMap<String, CompiledRuleSet>, Vec<RuleSetResource>), CompileError> {
    let Some(route) = route else {
        return Ok((BTreeMap::new(), Vec::new()));
    };
    let mut catalog = BTreeMap::new();
    let mut resources = Vec::new();
    for rule_set in &route.rule_sets {
        if rule_set.tag.trim().is_empty() {
            return Err(CompileError::new("route rule_set tag is required"));
        }
        let (compiled, resource) = match rule_set.kind.trim() {
            "" | "inline" => {
                if rule_set.rules.is_empty() {
                    return Err(CompileError::new(format!(
                        "inline route rule-set {:?} rules are required",
                        rule_set.tag
                    )));
                }
                let bytes = serde_json::to_vec(&json!({
                    "version": 4,
                    "rules": &rule_set.rules,
                }))
                .map_err(|error| {
                    CompileError::new(format!(
                        "encode inline route rule-set {:?}: {error}",
                        rule_set.tag
                    ))
                })?;
                let resource = plan_inline_resource(&rule_set.tag, bytes)
                    .map_err(|error| CompileError::new(error.to_string()))?;
                (resource.reference(), resource)
            }
            "local" | "remote" => {
                let resource = plan_resource(
                    &rule_set.tag,
                    &rule_set.kind,
                    &rule_set.format,
                    &rule_set.path,
                    &rule_set.url,
                    &rule_set.download_detour,
                    &rule_set.update_interval,
                )
                .map_err(|error| CompileError::new(error.to_string()))?;
                let reference = resource.reference();
                (reference, resource)
            }
            other => {
                return Err(CompileError::new(format!(
                    "route rule-set {:?} has unsupported type {other:?}",
                    rule_set.tag
                )));
            }
        };
        resources.push(resource);
        if catalog.insert(rule_set.tag.clone(), compiled).is_some() {
            return Err(CompileError::new(format!(
                "duplicate route rule-set tag {:?}",
                rule_set.tag
            )));
        }
    }
    resources.sort_by(|left, right| left.tag.cmp(&right.tag));
    Ok((catalog, resources))
}

fn validate_outbounds(
    values: &[Outbound],
) -> Result<BTreeMap<String, ValidatedOutbound>, CompileError> {
    if values.is_empty() {
        return Ok(BTreeMap::from([(
            DEFAULT_DIRECT_OUTBOUND.to_string(),
            ValidatedOutbound {
                id: 0,
                kind: "direct".to_string(),
                tag: DEFAULT_DIRECT_OUTBOUND.to_string(),
                options: json!({}),
                requested_options: json!({}),
                domain_resolver: None,
                shoes_dns_resolver: None,
            },
        )]));
    }

    let mut result = BTreeMap::new();
    for (id, outbound) in values.iter().enumerate() {
        if outbound.kind.is_empty() {
            return Err(CompileError::new("outbound type is required"));
        }
        if outbound.tag.is_empty() {
            return Err(CompileError::new(format!(
                "outbound {} tag is required",
                outbound.kind
            )));
        }
        if !SUPPORTED_OUTBOUND_TYPES.contains(&outbound.kind.as_str()) {
            return Err(CompileError::new(format!(
                "unknown outbound type {:?}",
                outbound.kind
            )));
        }
        let options = if outbound.options.is_empty() {
            json!({})
        } else {
            outbound.options.value().map_err(|error| {
                CompileError::new(format!(
                    "outbound {:?} options must be a JSON object: {error}",
                    outbound.tag
                ))
            })?
        };
        let requested_options = options.clone();
        let Some(fields) = options.as_object() else {
            return Err(CompileError::new(format!(
                "outbound {:?} options must be a JSON object",
                outbound.tag
            )));
        };
        if let Some(field) = fields
            .keys()
            .find(|field| field.eq_ignore_ascii_case("type") || field.eq_ignore_ascii_case("tag"))
        {
            return Err(CompileError::new(format!(
                "outbound {:?} options must not contain managed field {:?}",
                outbound.tag, field
            )));
        }
        validate_outbound_options(&outbound.kind, &outbound.tag, fields)?;
        let mut options = options;
        let domain_resolver = extract_outbound_domain_resolver(
            &outbound.kind,
            &outbound.tag,
            options
                .as_object_mut()
                .expect("outbound options object was validated above"),
        )?;
        if result
            .insert(
                outbound.tag.clone(),
                ValidatedOutbound {
                    id,
                    kind: outbound.kind.clone(),
                    tag: outbound.tag.clone(),
                    options,
                    requested_options,
                    domain_resolver,
                    shoes_dns_resolver: None,
                },
            )
            .is_some()
        {
            return Err(CompileError::new(format!(
                "duplicate outbound tag {:?}",
                outbound.tag
            )));
        }
    }
    Ok(result)
}

fn validate_outbound_options(
    kind: &str,
    tag: &str,
    fields: &Map<String, Value>,
) -> Result<(), CompileError> {
    // sing-box applies strict unknown-field decoding.  Direct is the important
    // zero-config case and has the full DialerOptions surface from topology.go.
    if kind == "direct" {
        const DIRECT_FIELDS: &[&str] = &[
            "detour",
            "bind_interface",
            "inet4_bind_address",
            "inet6_bind_address",
            "routing_mark",
            "reuse_addr",
            "connect_timeout",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
            "udp_timeout",
            "domain_strategy",
            "bind_address_no_port",
            "protect_path",
            "netns",
            "disable_tcp_keep_alive",
            "tcp_keep_alive",
            "tcp_keep_alive_interval",
            "domain_resolver",
            "network_strategy",
            "network_type",
            "fallback_network_type",
            "fallback_delay",
            "override_address",
            "override_port",
        ];
        if let Some(field) = fields
            .keys()
            .find(|field| !DIRECT_FIELDS.contains(&field.as_str()))
        {
            return Err(CompileError::new(format!(
                "invalid direct outbound {:?} options: unknown field {:?}",
                tag, field
            )));
        }
    }
    Ok(())
}

fn extract_outbound_domain_resolver(
    kind: &str,
    tag: &str,
    fields: &mut Map<String, Value>,
) -> Result<Option<OutboundDomainResolver>, CompileError> {
    let Some(value) = fields.remove("domain_resolver") else {
        return Ok(None);
    };
    if matches!(kind, "selector" | "urltest") {
        return Err(CompileError::new(format!(
            "outbound {tag:?} ({kind}) does not have sing-box dialer options and cannot declare domain_resolver"
        )));
    }
    let resolver = match value {
        Value::Null => return Ok(None),
        Value::String(server) => {
            if server.is_empty() {
                // sing-box decodes the empty string to an empty options pointer;
                // its dialer then follows route.default_domain_resolver/default.
                return Ok(None);
            }
            if server.trim() != server {
                return Err(CompileError::new(format!(
                    "outbound {tag:?} ({kind}) domain_resolver must be a non-empty trimmed DNS server tag"
                )));
            }
            return Ok(Some(OutboundDomainResolver {
                server,
                strategy: String::new(),
                query: DnsServerQueryProfile::default(),
            }));
        }
        Value::Object(resolver) => resolver,
        _ => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver must be a string, object, or null"
            )));
        }
    };
    if let Some(field) = resolver.keys().find(|field| {
        !matches!(
            field.as_str(),
            "server" | "strategy" | "disable_cache" | "rewrite_ttl" | "client_subnet"
        )
    }) {
        return Err(CompileError::new(format!(
            "outbound {tag:?} ({kind}) domain_resolver field {field:?} cannot be represented by shoes"
        )));
    }
    let server = match resolver.get("server") {
        Some(Value::String(server)) if !server.trim().is_empty() && server.trim() == server => {
            server.clone()
        }
        _ => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver.server must be a non-empty trimmed string"
            )));
        }
    };
    let strategy = match resolver.get("strategy") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(strategy)) if strategy.trim() == strategy => {
            if strategy == "as_is" {
                String::new()
            } else {
                strategy.clone()
            }
        }
        Some(_) => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver.strategy must be a string"
            )));
        }
    };
    if !matches!(
        strategy.as_str(),
        "" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
    ) {
        return Err(CompileError::new(format!(
            "outbound {tag:?} ({kind}) domain_resolver strategy {strategy:?} is unsupported"
        )));
    }
    let disable_cache = match resolver.get("disable_cache") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver.disable_cache must be a boolean"
            )));
        }
    };
    let rewrite_ttl = match resolver.get("rewrite_ttl") {
        None | Some(Value::Null) => None,
        Some(Value::Number(value)) => {
            let value = value.as_u64().and_then(|value| u32::try_from(value).ok());
            Some(value.ok_or_else(|| {
                CompileError::new(format!(
                    "outbound {tag:?} ({kind}) domain_resolver.rewrite_ttl must be a uint32"
                ))
            })?)
        }
        Some(_) => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver.rewrite_ttl must be a uint32"
            )));
        }
    };
    let client_subnet = match resolver.get("client_subnet") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            normalize_dns_client_subnet_value(value).map_err(|reason| {
                CompileError::new(format!(
                    "outbound {tag:?} ({kind}) domain_resolver.client_subnet {value:?} {reason}"
                ))
            })?
        }
        Some(_) => {
            return Err(CompileError::new(format!(
                "outbound {tag:?} ({kind}) domain_resolver.client_subnet must be a string"
            )));
        }
    };
    Ok(Some(OutboundDomainResolver {
        server,
        strategy,
        query: DnsServerQueryProfile {
            disable_cache,
            rewrite_ttl,
            client_subnet,
        },
    }))
}

fn compile_domain_resolve_options(
    resolver: &DomainResolveOptions,
    context: &str,
) -> Result<OutboundDomainResolver, CompileError> {
    if resolver.server.is_empty() || resolver.server.trim() != resolver.server {
        return Err(CompileError::new(format!(
            "{context}.server must be a non-empty trimmed string"
        )));
    }
    if resolver.strategy.trim() != resolver.strategy {
        return Err(CompileError::new(format!(
            "{context}.strategy must be a trimmed string"
        )));
    }
    let strategy = if resolver.strategy == "as_is" {
        String::new()
    } else {
        resolver.strategy.clone()
    };
    outbound_dns_ip_strategy(&strategy).map_err(|_| {
        CompileError::new(format!(
            "{context} strategy {:?} is unsupported",
            resolver.strategy
        ))
    })?;
    let client_subnet =
        normalize_dns_client_subnet_value(&resolver.client_subnet).map_err(|reason| {
            CompileError::new(format!(
                "{context}.client_subnet {:?} {reason}",
                resolver.client_subnet
            ))
        })?;
    Ok(OutboundDomainResolver {
        server: resolver.server.clone(),
        strategy,
        query: DnsServerQueryProfile {
            disable_cache: resolver.disable_cache,
            rewrite_ttl: resolver.rewrite_ttl,
            client_subnet,
        },
    })
}

fn same_egress_dns_ip_strategy(strategy: &str) -> Result<&'static str, &'static str> {
    match strategy {
        // The panel runtime-clone generator emits only these values. For the
        // dual-stack empty strategy, both implementations perform parallel A
        // and AAAA lookup and return IPv4 first.
        "" => Ok("ipv4_and_ipv6"),
        "ipv4_only" => Ok("ipv4_only"),
        "ipv6_only" => Ok("ipv6_only"),
        _ => Err("is not emitted for a panel same-egress runtime Direct clone"),
    }
}

fn validate_dns_resolution_projection(
    route: Option<&Route>,
    dns: Option<&Dns>,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
) -> Result<BTreeMap<String, &'static str>, CompileError> {
    const DEFAULT_DNS_TAG: &str = "default-dns";

    let configured_servers = dns.map(|dns| dns.servers.as_slice()).unwrap_or_default();
    let implicit_default = configured_servers.is_empty();
    let mut servers = BTreeMap::new();
    if implicit_default {
        servers.insert(DEFAULT_DNS_TAG.to_string(), None);
    } else {
        for server in configured_servers {
            if servers.insert(server.tag.clone(), Some(server)).is_some() {
                return Err(CompileError::new(format!(
                    "duplicate dns server tag {:?}",
                    server.tag
                )));
            }
        }
    }

    let requested_final = dns.map(|dns| dns.final_.as_str()).unwrap_or_default();
    let final_tag = if requested_final.is_empty() {
        DEFAULT_DNS_TAG
    } else {
        requested_final
    };
    if !servers.contains_key(final_tag) {
        return Err(CompileError::new(format!(
            "dns final references unknown server {final_tag:?}"
        )));
    }

    let default_resolver = route
        .and_then(|route| route.default_domain_resolver.as_ref())
        .map(|resolver| compile_domain_resolve_options(resolver, "route.default_domain_resolver"))
        .transpose()?;
    if let Some(resolver) = &default_resolver
        && !servers.contains_key(&resolver.server)
    {
        return Err(CompileError::new(format!(
            "route.default_domain_resolver references unknown DNS server {:?}",
            resolver.server
        )));
    }

    let mut strategies = BTreeMap::new();

    let route_rules = route
        .map(|route| route.rules.as_slice())
        .unwrap_or_default();
    let dns_rules = dns.map(|dns| dns.rules.as_slice()).unwrap_or_default();

    for outbound in outbounds.values() {
        let resolver = outbound.domain_resolver.as_ref().or_else(|| {
            outbound_inherits_default_domain_resolver(outbound)
                .then_some(default_resolver.as_ref())
                .flatten()
        });
        let Some(resolver) = resolver else {
            continue;
        };
        if !servers.contains_key(&resolver.server) {
            return Err(CompileError::new(format!(
                "outbound {:?} domain_resolver references unknown DNS server {:?}",
                outbound.tag, resolver.server
            )));
        }
        if !outbound.tag.starts_with("__acp_direct_") || !outbound.tag.ends_with("_same_egress") {
            continue;
        }
        if !resolver.server.starts_with("__acp_dns_") {
            return Err(CompileError::new(format!(
                "same-egress runtime Direct {:?} must resolve through a reserved synthetic DNS server",
                outbound.tag
            )));
        }
        let server = servers
            .get(&resolver.server)
            .and_then(|server| *server)
            .ok_or_else(|| {
                CompileError::new(format!(
                    "same-egress runtime Direct {:?} references missing synthetic DNS server {:?}",
                    outbound.tag, resolver.server
                ))
            })?;
        if server.detour.is_empty() {
            return Err(CompileError::new(format!(
                "synthetic DNS server {:?} must detour through the original Direct outbound",
                resolver.server
            )));
        }
        let original = outbounds.get(&server.detour).ok_or_else(|| {
            CompileError::new(format!(
                "synthetic DNS server {:?} references unknown original Direct {:?}",
                resolver.server, server.detour
            ))
        })?;
        if original.kind != "direct" || original.options != outbound.options {
            return Err(CompileError::new(format!(
                "same-egress runtime Direct {:?} does not preserve the original Direct {:?} local dialer options",
                outbound.tag, original.tag
            )));
        }
        if server.server.parse::<std::net::IpAddr>().is_err() {
            return Err(CompileError::new(format!(
                "synthetic DNS server {:?} must use a literal IP address so stripping the original Direct resolver is lossless",
                resolver.server
            )));
        }
        if route.is_some_and(|route| route.final_ == outbound.tag) {
            return Err(CompileError::new(format!(
                "same-egress runtime Direct {:?} cannot be route.final",
                outbound.tag
            )));
        }
        let linked_route_rules: Vec<&RouteRule> = route_rules
            .iter()
            .filter(|rule| rule.outbound == outbound.tag)
            .collect();
        if linked_route_rules.is_empty()
            || linked_route_rules.iter().any(|rule| {
                !same_egress_route_match_supported(rule)
                    || !dns_rules.iter().any(|dns_rule| {
                        dns_rule.action == "route"
                            && dns_rule.server == resolver.server
                            && same_egress_rule_matches_dns(rule, dns_rule)
                    })
            })
        {
            return Err(CompileError::new(format!(
                "same-egress runtime Direct {:?} requires a matching panel-generated route and DNS rule pair",
                outbound.tag
            )));
        }
        if dns_rules
            .iter()
            .filter(|rule| rule.server == resolver.server)
            .any(|dns_rule| {
                dns_rule.action != "route"
                    || !linked_route_rules
                        .iter()
                        .any(|route_rule| same_egress_rule_matches_dns(route_rule, dns_rule))
            })
        {
            return Err(CompileError::new(format!(
                "synthetic DNS server {:?} is referenced outside its same-egress rule pair",
                resolver.server
            )));
        }
        let strategy = same_egress_dns_ip_strategy(&resolver.strategy).map_err(|reason| {
            CompileError::new(format!(
                "same-egress runtime Direct {:?} domain_resolver strategy {:?} {reason}",
                outbound.tag, resolver.strategy
            ))
        })?;
        if let Some(existing) = strategies.insert(resolver.server.clone(), strategy)
            && existing != strategy
        {
            return Err(CompileError::new(format!(
                "DNS server {:?} is required with conflicting IP strategies {existing:?} and {strategy:?}",
                resolver.server
            )));
        }
    }
    Ok(strategies)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsServerVariant {
    tag: String,
    source_tag: String,
    ip_strategy: &'static str,
    query: DnsServerQueryProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DnsServerVariantKey {
    source_tag: String,
    ip_strategy: &'static str,
    query: DnsServerQueryProfile,
}

impl DnsServerVariant {
    fn key(&self) -> DnsServerVariantKey {
        DnsServerVariantKey {
            source_tag: self.source_tag.clone(),
            ip_strategy: self.ip_strategy,
            query: self.query.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct DnsServerQueryProfile {
    disable_cache: bool,
    rewrite_ttl: Option<u32>,
    client_subnet: Option<String>,
}

impl DnsServerQueryProfile {
    fn is_default(&self) -> bool {
        !self.disable_cache && self.rewrite_ttl.is_none() && self.client_subnet.is_none()
    }
}

#[derive(Debug, Default)]
struct OutboundDnsProjection {
    variants: Vec<DnsServerVariant>,
}

fn outbound_dns_ip_strategy(strategy: &str) -> Result<Option<&'static str>, CompileError> {
    match strategy {
        "" => Ok(None),
        // sing-box issues A and AAAA concurrently for both prefer modes, then
        // imposes stable family order on the combined answer.
        "prefer_ipv4" => Ok(Some("ipv4_and_ipv6")),
        "prefer_ipv6" => Ok(Some("ipv6_and_ipv4")),
        "ipv4_only" => Ok(Some("ipv4_only")),
        "ipv6_only" => Ok(Some("ipv6_only")),
        other => Err(CompileError::new(format!(
            "unsupported outbound domain_resolver strategy {other:?}"
        ))),
    }
}

fn dns_profile_variant_tag(
    source_tag: &str,
    ip_strategy: &str,
    query: &DnsServerQueryProfile,
) -> String {
    let rewrite_ttl = query.rewrite_ttl.map(|value| value.to_string());
    let digest = Sha256::digest(format!(
        "{source_tag}\0{ip_strategy}\0{}\0{}\0{}",
        query.disable_cache,
        rewrite_ttl.as_deref().unwrap_or_default(),
        query.client_subnet.as_deref().unwrap_or_default(),
    ));
    let mut tag = String::from("__acp_dns_profile_");
    for byte in digest {
        write!(&mut tag, "{byte:02x}").expect("writing to a String cannot fail");
    }
    tag
}

fn dns_reject_flood_state_key(rule: &DnsRule, index: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"node-agent/acp-dns-reject-flood/v1\0");
    hasher.update((index as u64).to_be_bytes());
    hasher.update(
        serde_json::to_vec(rule).expect("the typed ACP DNS rule always serializes to JSON"),
    );
    let mut key = String::from("__acp_dns_reject_v1_");
    for byte in hasher.finalize() {
        write!(&mut key, "{byte:02x}").expect("writing to a String cannot fail");
    }
    key
}

/// Assign an exact named DNS transport to each outbound without changing the
/// policy/final resolver seen by any other consumer. A strategy override gets a
/// private clone of the source server unless the source already has identical
/// lookup behavior.
fn project_outbound_dns_resolvers(
    route: Option<&Route>,
    dns: Option<&Dns>,
    outbounds: &mut BTreeMap<String, ValidatedOutbound>,
    base_strategies: &BTreeMap<String, &'static str>,
) -> Result<OutboundDnsProjection, CompileError> {
    const DEFAULT_DNS_TAG: &str = "default-dns";

    let mut configured_tags = BTreeSet::new();
    let configured = dns.map(|dns| dns.servers.as_slice()).unwrap_or_default();
    if configured.is_empty() {
        configured_tags.insert(DEFAULT_DNS_TAG.to_string());
    } else {
        configured_tags.extend(configured.iter().map(|server| server.tag.clone()));
    }
    let default_resolver = route
        .and_then(|route| route.default_domain_resolver.as_ref())
        .map(|resolver| compile_domain_resolve_options(resolver, "route.default_domain_resolver"))
        .transpose()?;

    let mut variants = BTreeMap::<DnsServerVariantKey, DnsServerVariant>::new();
    for outbound in outbounds.values_mut() {
        let resolver = outbound.domain_resolver.as_ref().or_else(|| {
            outbound_inherits_default_domain_resolver(outbound)
                .then_some(default_resolver.as_ref())
                .flatten()
        });
        let Some(resolver) = resolver else {
            continue;
        };
        if !configured_tags.contains(&resolver.server) {
            return Err(CompileError::new(format!(
                "outbound {:?} domain_resolver references unknown DNS server {:?}",
                outbound.tag, resolver.server
            )));
        }

        let desired = outbound_dns_ip_strategy(&resolver.strategy)?;
        let source_strategy = base_strategies
            .get(&resolver.server)
            .copied()
            .unwrap_or("ipv4_and_ipv6");
        let effective_strategy = desired.unwrap_or(source_strategy);
        let selected_tag = if effective_strategy == source_strategy && resolver.query.is_default() {
            resolver.server.clone()
        } else {
            let key = DnsServerVariantKey {
                source_tag: resolver.server.clone(),
                ip_strategy: effective_strategy,
                query: resolver.query.clone(),
            };
            let tag = dns_profile_variant_tag(&key.source_tag, key.ip_strategy, &key.query);
            if configured_tags.contains(&tag) {
                return Err(CompileError::new(format!(
                    "configured DNS server tag {tag:?} collides with a reserved DNS profile tag"
                )));
            }
            variants.entry(key).or_insert_with(|| DnsServerVariant {
                tag: tag.clone(),
                source_tag: resolver.server.clone(),
                ip_strategy: effective_strategy,
                query: resolver.query.clone(),
            });
            tag
        };
        outbound.shoes_dns_resolver = Some(selected_tag);
    }

    Ok(OutboundDnsProjection {
        variants: variants.into_values().collect(),
    })
}

fn same_egress_route_match_supported(rule: &RouteRule) -> bool {
    let full_network = rule.network.len() == 2
        && rule.network.iter().any(|value| value == "tcp")
        && rule.network.iter().any(|value| value == "udp");
    let hostname_scope = !rule.domain.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty()
        || !rule.domain_regex.is_empty()
        || !rule.rule_set.is_empty()
        || !rule.inbound.is_empty();
    rule.action == "route"
        && !rule.invert
        && unsupported_route_rule_fields(rule).is_empty()
        && (rule.network.is_empty() || full_network)
        && (hostname_scope || full_network)
        && rule.ip_version == 0
        && rule.ip_cidr.is_empty()
        && rule.port.is_empty()
        && rule.port_range.is_empty()
        && rule.protocol.is_empty()
}

fn same_egress_rule_matches_dns(route: &RouteRule, dns: &DnsRule) -> bool {
    route.inbound == dns.inbound
        && route.domain == dns.domain
        && route.domain_suffix == dns.domain_suffix
        && route.domain_keyword == dns.domain_keyword
        && route.domain_regex == dns.domain_regex
        && route.rule_set == dns.rule_set
}

fn compile_inbound(
    node: &NodeInstance,
    warnings: &mut BTreeSet<String>,
) -> Result<CompiledInbound, CompileError> {
    if node.node_id.trim().is_empty() {
        return Err(CompileError::new("node_id is required"));
    }
    match node.provider_id.as_str() {
        VLESS_REALITY_VISION_ID | HYSTERIA2_SALAMANDER_ID
            if node.provider_config_version != CURRENT_CONFIG_VERSION =>
        {
            Err(CompileError::new(format!(
                "node {} provider {} config version {} is unsupported",
                node.node_id, node.provider_id, node.provider_config_version
            )))
        }
        VLESS_REALITY_VISION_ID => compile_vless(node),
        HYSTERIA2_SALAMANDER_ID => compile_hysteria2(node, warnings),
        _ => Err(CompileError::new(format!(
            "node {} has unsupported provider {:?}",
            node.node_id, node.provider_id
        ))),
    }
}

fn inbound_protocol_sniff_enabled(node: &NodeInstance) -> Result<bool, CompileError> {
    match node.provider_id.as_str() {
        VLESS_REALITY_VISION_ID => {
            let config: VlessRealityVisionConfig =
                node.provider_config.parse().map_err(|error| {
                    CompileError::new(format!(
                        "node {} decode vless provider config: {error}",
                        node.node_id
                    ))
                })?;
            Ok(config.sniff)
        }
        // The panel's Hysteria2 provider has no sniff switch. The Rust engine
        // performs bounded, demand-driven sniffing whenever a protocol matcher is
        // present, so there is no provider option to gate here.
        HYSTERIA2_SALAMANDER_ID => Ok(true),
        _ => Ok(false),
    }
}

fn active_users(users: &[UserCredential]) -> impl Iterator<Item = &UserCredential> {
    users.iter().filter(|user| user.status != "disabled")
}

fn compile_vless(node: &NodeInstance) -> Result<CompiledInbound, CompileError> {
    let cfg: VlessRealityVisionConfig = node.provider_config.parse().map_err(|error| {
        CompileError::new(format!(
            "node {} decode vless provider config: {error}",
            node.node_id
        ))
    })?;
    if cfg.listen_port == 0
        || cfg.tls.reality.private_key.is_empty()
        || cfg.tls.reality.short_id.is_empty()
    {
        return Err(CompileError::new(format!(
            "node {} vless provider config is incomplete",
            node.node_id
        )));
    }
    if !cfg.tls.enabled || !cfg.tls.reality.enabled {
        return Err(CompileError::new(format!(
            "node {} vless provider requires tls.enabled and tls.reality.enabled: tls={} reality={}",
            node.node_id, cfg.tls.enabled, cfg.tls.reality.enabled
        )));
    }
    if cfg.tls.reality.handshake.server.is_empty() || cfg.tls.reality.handshake.server_port == 0 {
        return Err(CompileError::new(format!(
            "node {} vless provider requires a reality handshake server and port",
            node.node_id
        )));
    }
    if !cfg.flow.is_empty() && cfg.flow != VLESS_FLOW_REALITY_VISION {
        return Err(CompileError::new(format!(
            "node {} vless provider has unsupported flow {:?}",
            node.node_id, cfg.flow
        )));
    }

    let tag = defaulted(&cfg.tag, &node.node_id);
    let listen = defaulted(&cfg.listen, DEFAULT_INBOUND_LISTEN);
    let sni = defaulted(&cfg.tls.server_name, &cfg.tls.reality.handshake.server);
    let users = compile_users(node, "vless")?;
    if cfg.tcp_fast_open {
        return Err(CompileError::new(format!(
            "node {} enables tcp_fast_open, which is not configurable on a shoes inbound",
            node.node_id
        )));
    }
    let dest = socket_address(
        &cfg.tls.reality.handshake.server,
        cfg.tls.reality.handshake.server_port,
    );
    let config = json!({
        "address": socket_address(&listen, cfg.listen_port),
        "sniff": cfg.sniff,
        "protocol": {
            "type": "tls",
            "reality_targets": {
                sni: {
                    "private_key": cfg.tls.reality.private_key,
                    "short_ids": cfg.tls.reality.short_id,
                    "dest": dest,
                    "vision": cfg.flow == VLESS_FLOW_REALITY_VISION,
                    "protocol": {"type": "vless", "udp_enabled": true}
                }
            }
        }
    });
    Ok(CompiledInbound {
        node_id: node.node_id.clone(),
        protocol: "vless".to_string(),
        spec: InboundSpec {
            tag,
            config,
            users: Some(users),
        },
    })
}

fn compile_hysteria2(
    node: &NodeInstance,
    warnings: &mut BTreeSet<String>,
) -> Result<CompiledInbound, CompileError> {
    let cfg: Hysteria2SalamanderConfig = node.provider_config.parse().map_err(|error| {
        CompileError::new(format!(
            "node {} decode hysteria2 provider config: {error}",
            node.node_id
        ))
    })?;
    if cfg.listen_port == 0
        || cfg.tls.certificate_pem.is_empty()
        || cfg.tls.private_key_pem.is_empty()
    {
        return Err(CompileError::new(format!(
            "node {} hysteria2 provider config is incomplete",
            node.node_id
        )));
    }
    if cfg.up_mbps < 0 || cfg.down_mbps < 0 {
        return Err(CompileError::new(format!(
            "node {} hysteria2 bandwidth must not be negative: up_mbps={} down_mbps={}",
            node.node_id, cfg.up_mbps, cfg.down_mbps
        )));
    }
    match cfg.obfs.kind.as_str() {
        "salamander" => {
            if cfg.obfs.password.is_empty() {
                return Err(CompileError::new(format!(
                    "node {} hysteria2 salamander password is required",
                    node.node_id
                )));
            }
            if cfg.masquerade.is_some() {
                return Err(CompileError::new(format!(
                    "node {} hysteria2 masquerade requires obfs to be disabled",
                    node.node_id
                )));
            }
        }
        "" | "none" => {
            if !cfg.obfs.password.is_empty() {
                return Err(CompileError::new(format!(
                    "node {} hysteria2 obfs password requires salamander",
                    node.node_id
                )));
            }
        }
        other => {
            return Err(CompileError::new(format!(
                "node {} has unsupported hysteria2 obfs type {:?}",
                node.node_id, other
            )));
        }
    }
    if let Some(masquerade) = &cfg.masquerade {
        match masquerade.kind.as_str() {
            "proxy" if masquerade.url.is_empty() => {
                return Err(CompileError::new(format!(
                    "node {} hysteria2 proxy masquerade config is incomplete",
                    node.node_id
                )));
            }
            "string" if masquerade.content.is_empty() => {
                return Err(CompileError::new(format!(
                    "node {} hysteria2 fixed response masquerade content is required",
                    node.node_id
                )));
            }
            "proxy" | "string" => {}
            other => {
                return Err(CompileError::new(format!(
                    "node {} has unsupported hysteria2 masquerade type {:?}",
                    node.node_id, other
                )));
            }
        }
    }

    let tag = defaulted(&cfg.tag, &node.node_id);
    let listen = defaulted(&cfg.listen, DEFAULT_INBOUND_LISTEN);
    let users = compile_users(node, "hysteria2")?;
    if !cfg.port_hopping.is_empty() {
        warnings.insert(format!(
            "node {} port_hopping {:?} is retained for the nftables phase and is not represented by the shoes listener",
            node.node_id, cfg.port_hopping
        ));
    }
    let mut protocol = Map::from_iter([
        ("type".to_string(), json!("hysteria2")),
        ("udp_enabled".to_string(), json!(true)),
        ("up_mbps".to_string(), json!(cfg.up_mbps as u64)),
        ("down_mbps".to_string(), json!(cfg.down_mbps as u64)),
        (
            "ignore_client_bandwidth".to_string(),
            json!(cfg.ignore_client_bandwidth),
        ),
    ]);
    if cfg.obfs.kind == "salamander" {
        protocol.insert(
            "obfs".to_string(),
            json!({"type": "salamander", "password": cfg.obfs.password}),
        );
    }
    if let Some(masquerade) = cfg.masquerade {
        let value = match masquerade.kind.as_str() {
            "proxy" => json!({
                "type": "proxy",
                "url": masquerade.url,
                "rewrite_host": masquerade.rewrite_host,
                "use_native_roots": true
            }),
            "string" => json!({
                "type": "string",
                "content": masquerade.content,
                "content_type": "text/html; charset=utf-8"
            }),
            _ => unreachable!("validated above"),
        };
        protocol.insert("masquerade".to_string(), value);
    }
    let config = json!({
        "address": socket_address(&listen, cfg.listen_port),
        "transport": "quic",
        "quic_settings": {
            "cert": cfg.tls.certificate_pem,
            "key": cfg.tls.private_key_pem,
            "alpn_protocols": "h3"
        },
        "protocol": Value::Object(protocol)
    });
    Ok(CompiledInbound {
        node_id: node.node_id.clone(),
        protocol: "hysteria2".to_string(),
        spec: InboundSpec {
            tag,
            config,
            users: Some(users),
        },
    })
}

fn compile_users(node: &NodeInstance, protocol: &str) -> Result<Vec<UserSpec>, CompileError> {
    let mut identities = BTreeSet::new();
    let mut users = Vec::new();
    for user in active_users(&node.users) {
        if user.credential.is_empty() {
            return Err(CompileError::new(format!(
                "node {} user {} credential is required",
                node.node_id, user.user_id
            )));
        }
        let reported_id = if user.user_id.is_empty() {
            user.name.clone()
        } else {
            user.user_id.clone()
        };
        let identity = if reported_id.is_empty() && protocol == "vless" {
            user.credential.clone()
        } else {
            reported_id.clone()
        };
        if identity.is_empty() {
            return Err(CompileError::new(format!(
                "node {} hysteria2 user identity is required",
                node.node_id
            )));
        }
        if !identities.insert(identity.clone()) {
            return Err(CompileError::new(format!(
                "node {} lists user {:?} twice",
                node.node_id, identity
            )));
        }
        users.push(UserSpec {
            id: (!reported_id.is_empty()).then_some(reported_id),
            uuid: (protocol == "vless").then(|| user.credential.clone()),
            password: (protocol == "hysteria2").then(|| user.credential.clone()),
            enabled: true,
            max_conns: None,
            upload_limit_bps: (user.upload_speed_limit_bps != 0)
                .then_some(user.upload_speed_limit_bps),
            download_limit_bps: (user.download_speed_limit_bps != 0)
                .then_some(user.download_speed_limit_bps),
        });
    }
    Ok(users)
}

fn defaulted(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn socket_address(host: &str, port: u16) -> String {
    if host.starts_with('[') || host.matches(':').count() <= 1 {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}

fn unsupported_route_top_level_fields(route: &Route) -> Vec<&'static str> {
    let mut unsupported = Vec::new();
    if route.auto_detect_interface {
        unsupported.push("auto_detect_interface");
    }
    if !route.default_interface.is_empty() {
        unsupported.push("default_interface");
    }
    if route.default_mark != 0 {
        unsupported.push("default_mark");
    }
    if route.find_process {
        unsupported.push("find_process");
    }
    if route.geoip.is_some() {
        unsupported.push("geoip");
    }
    if route.geosite.is_some() {
        unsupported.push("geosite");
    }
    if route.override_android_vpn {
        unsupported.push("override_android_vpn");
    }
    if route.default_network_strategy.is_some() {
        unsupported.push("default_network_strategy");
    }
    if !route.default_network_type.is_empty() {
        unsupported.push("default_network_type");
    }
    if !route.default_fallback_network_type.is_empty() {
        unsupported.push("default_fallback_network_type");
    }
    if !route.default_fallback_delay.is_empty() {
        unsupported.push("default_fallback_delay");
    }
    unsupported
}

fn validate_route(
    route: Option<&Route>,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
) -> Result<(), CompileError> {
    let Some(route) = route else {
        return Ok(());
    };
    let unsupported = unsupported_route_top_level_fields(route);
    if !unsupported.is_empty() {
        return Err(CompileError::new(format!(
            "route contains unsupported top-level fields: {}",
            unsupported.join(", ")
        )));
    }
    if !route.final_.is_empty() && !outbounds.contains_key(&route.final_) {
        return Err(CompileError::new(format!(
            "route final references unknown outbound {:?}",
            route.final_
        )));
    }
    for rule in &route.rules {
        validate_route_rule_references(rule, outbounds, rule_sets)?;
    }
    Ok(())
}

fn validate_route_rule_references(
    rule: &RouteRule,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
) -> Result<(), CompileError> {
    if !rule.outbound.is_empty() && !outbounds.contains_key(&rule.outbound) {
        return Err(CompileError::new(format!(
            "route rule references unknown outbound {:?}",
            rule.outbound
        )));
    }
    for tag in &rule.rule_set {
        if !rule_sets.contains_key(tag) {
            return Err(CompileError::new(format!(
                "route rule references unknown rule-set {tag:?}"
            )));
        }
    }
    for nested in &rule.rules {
        validate_route_rule_references(nested, outbounds, rule_sets)?;
    }
    Ok(())
}

fn compile_rules_for_inbound<'a>(
    route: Option<&Route>,
    outbounds: &'a BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
    inbound_tag: &str,
    sniff_enabled: bool,
    projection_budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<Vec<Value>, CompileError> {
    let mut rules = Vec::new();
    if let Some(route) = route {
        for (index, rule) in route.rules.iter().enumerate() {
            if !rule.inbound.is_empty() && !rule.inbound.iter().any(|tag| tag == inbound_tag) {
                continue;
            }
            if !rule.protocol.is_empty() && !sniff_enabled {
                return Err(CompileError::new(format!(
                    "route.rules[{index}] uses protocol matching on inbound {inbound_tag:?}, but that provider does not enable sniff; enable sniff on the VLESS inbound"
                )));
            }
            rules.push(compile_route_rule(
                rule,
                index,
                outbounds,
                rule_sets,
                projection_budget,
            )?);
        }
    }

    let final_tag = route.map(|route| route.final_.as_str()).unwrap_or_default();
    let final_outbound = if final_tag.is_empty() {
        Some(outbounds.get(DEFAULT_DIRECT_OUTBOUND).ok_or_else(|| {
            CompileError::new("route has no final outbound and no direct outbound named \"direct\"")
        })?)
    } else {
        Some(outbounds.get(final_tag).ok_or_else(|| {
            CompileError::new(format!(
                "route final references unknown outbound {final_tag:?}"
            ))
        })?)
    };
    if let Some(outbound) = final_outbound {
        let mut rule = json!({
            "masks": "0.0.0.0/0",
            "action": "allow",
        });
        apply_outbound_action(
            &mut rule,
            "client_chains",
            outbound_client_action(outbound, outbounds, projection_budget)?,
        );
        rules.push(rule);
    }
    Ok(rules)
}

fn compile_route_rule<'a>(
    rule: &RouteRule,
    index: usize,
    outbounds: &'a BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
    projection_budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<Value, CompileError> {
    let unsupported = unsupported_route_rule_fields(rule);
    if !unsupported.is_empty() {
        return Err(CompileError::new(format!(
            "route.rules[{index}] contains unsupported fields: {}",
            unsupported.join(", ")
        )));
    }

    let (action, outbound) = match rule.action.as_str() {
        "reject" | "reject-drop" => {
            if !rule.outbound.is_empty() {
                return Err(CompileError::new(format!(
                    "route.rules[{index}] reject action must not contain outbound"
                )));
            }
            ("block", None)
        }
        "" | "route" => {
            if rule.action == "route" && rule.outbound.is_empty() {
                return Err(CompileError::new(format!(
                    "route.rules[{index}] route action requires outbound"
                )));
            }
            if rule.outbound.is_empty() {
                ("allow", None)
            } else {
                let outbound = outbounds.get(&rule.outbound).ok_or_else(|| {
                    CompileError::new(format!(
                        "route rule references unknown outbound {:?}",
                        rule.outbound
                    ))
                })?;
                ("allow", Some(outbound))
            }
        }
        other => {
            return Err(CompileError::new(format!(
                "route.rules[{index}] action {other:?} is not supported by shoes"
            )));
        }
    };
    let match_config = compile_route_match(rule, rule_sets)?;
    let mut compiled = json!({"masks": "0.0.0.0/0", "action": action});
    if let Some(outbound) = outbound {
        apply_outbound_action(
            &mut compiled,
            "client_chains",
            outbound_client_action(outbound, outbounds, projection_budget)?,
        );
    }
    if !match_config
        .as_object()
        .expect("route matcher is an object")
        .is_empty()
    {
        compiled["match"] = match_config;
    }
    Ok(compiled)
}

fn compile_route_match(
    rule: &RouteRule,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
) -> Result<Value, CompileError> {
    let has_direct_match = !rule.domain.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty()
        || !rule.domain_regex.is_empty()
        || !rule.ip_cidr.is_empty()
        || rule.ip_version != 0
        || !rule.port.is_empty()
        || !rule.port_range.is_empty()
        || !rule.network.is_empty()
        || !rule.protocol.is_empty();
    // `inbound` is projected by compiling one shoes selector per inbound and
    // therefore does not appear in the second-stage matcher.
    if rule.inbound.is_empty() && !has_direct_match && rule.rule_set.is_empty() {
        return Err(CompileError::new("route rule has no match conditions"));
    }

    let mut matcher = Map::new();
    insert_non_empty(&mut matcher, "domain", &rule.domain);
    insert_non_empty(&mut matcher, "domain_suffix", &rule.domain_suffix);
    insert_non_empty(&mut matcher, "domain_keyword", &rule.domain_keyword);
    insert_non_empty(&mut matcher, "domain_regex", &rule.domain_regex);
    insert_non_empty(&mut matcher, "ip_cidr", &rule.ip_cidr);
    if rule.ip_version != 0 {
        if !matches!(rule.ip_version, 4 | 6) {
            return Err(CompileError::new(format!(
                "route ip_version {} must be 4 or 6",
                rule.ip_version
            )));
        }
        matcher.insert("ip_version".into(), json!([rule.ip_version]));
    }
    insert_ports(&mut matcher, "port", &rule.port)?;
    insert_port_ranges(&mut matcher, "port_range", &rule.port_range)?;
    insert_networks(&mut matcher, &rule.network)?;
    insert_protocols(&mut matcher, &rule.protocol)?;

    if !rule.rule_set.is_empty() {
        let mut referenced = Vec::with_capacity(rule.rule_set.len());
        for tag in &rule.rule_set {
            let rule_set = rule_sets.get(tag).ok_or_else(|| {
                CompileError::new(format!("route rule references unknown rule-set {tag:?}"))
            })?;
            referenced.push(json!({
                "format": rule_set.format,
                "path": rule_set.path,
            }));
        }
        matcher.insert("rule_set".into(), Value::Array(referenced));
    }
    if rule.invert {
        matcher.insert("invert".into(), Value::Bool(true));
    }
    Ok(Value::Object(matcher))
}

fn insert_non_empty<T: Serialize>(matcher: &mut Map<String, Value>, name: &str, values: &[T]) {
    if !values.is_empty() {
        matcher.insert(
            name.into(),
            serde_json::to_value(values).expect("serializing a rule field cannot fail"),
        );
    }
}

fn insert_ports(
    matcher: &mut Map<String, Value>,
    name: &str,
    ports: &[u32],
) -> Result<(), CompileError> {
    let ports = ports
        .iter()
        .map(|port| {
            let port = u16::try_from(*port).map_err(|_| {
                CompileError::new(format!("route port {port} must be in 1..=65535"))
            })?;
            if port == 0 {
                return Err(CompileError::new("route port 0 must be in 1..=65535"));
            }
            Ok(port)
        })
        .collect::<Result<Vec<_>, _>>()?;
    insert_non_empty(matcher, name, &ports);
    Ok(())
}

fn insert_port_ranges(
    matcher: &mut Map<String, Value>,
    name: &str,
    ranges: &[String],
) -> Result<(), CompileError> {
    for range in ranges {
        validate_port_range(range)?;
    }
    insert_non_empty(matcher, name, ranges);
    Ok(())
}

fn insert_networks(
    matcher: &mut Map<String, Value>,
    networks: &[String],
) -> Result<(), CompileError> {
    for network in networks {
        if !matches!(network.as_str(), "tcp" | "udp") {
            return Err(CompileError::new(format!(
                "route network {network:?} must be tcp or udp"
            )));
        }
    }
    insert_non_empty(matcher, "network", networks);
    Ok(())
}

fn insert_protocols(
    matcher: &mut Map<String, Value>,
    protocols: &[String],
) -> Result<(), CompileError> {
    for protocol in protocols {
        if !matches!(protocol.as_str(), "http" | "tls") {
            return Err(CompileError::new(format!(
                "route protocol {protocol:?} is not supported; panel-compatible TCP sniffing currently supports http and tls"
            )));
        }
    }
    insert_non_empty(matcher, "protocol", protocols);
    Ok(())
}

fn unsupported_route_rule_fields(rule: &RouteRule) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if !matches!(rule.kind.as_str(), "" | "default") {
        fields.push("type");
    }
    if !rule.source_ip_cidr.is_empty() {
        fields.push("source_ip_cidr");
    }
    if rule.source_ip_is_private.is_some() {
        fields.push("source_ip_is_private");
    }
    if rule.ip_is_private.is_some() {
        fields.push("ip_is_private");
    }
    if !rule.source_port.is_empty() {
        fields.push("source_port");
    }
    if !rule.source_port_range.is_empty() {
        fields.push("source_port_range");
    }
    if !rule.method.is_empty() {
        fields.push("method");
    }
    if rule.no_drop {
        fields.push("no_drop");
    }
    if !rule.mode.is_empty() {
        fields.push("mode");
    }
    if !rule.rules.is_empty() {
        fields.push("rules");
    }
    if !rule.auth_user.is_empty() {
        fields.push("auth_user");
    }
    if !rule.client.is_empty() {
        fields.push("client");
    }
    if !rule.geosite.is_empty() {
        fields.push("geosite");
    }
    if !rule.source_geoip.is_empty() {
        fields.push("source_geoip");
    }
    if !rule.geoip.is_empty() {
        fields.push("geoip");
    }
    if !rule.process_name.is_empty() {
        fields.push("process_name");
    }
    if !rule.process_path.is_empty() {
        fields.push("process_path");
    }
    if !rule.process_path_regex.is_empty() {
        fields.push("process_path_regex");
    }
    if !rule.package_name.is_empty() {
        fields.push("package_name");
    }
    if !rule.user.is_empty() {
        fields.push("user");
    }
    if !rule.user_id.is_empty() {
        fields.push("user_id");
    }
    if !rule.clash_mode.is_empty() {
        fields.push("clash_mode");
    }
    if !rule.network_type.is_empty() {
        fields.push("network_type");
    }
    if rule.network_is_expensive.is_some() {
        fields.push("network_is_expensive");
    }
    if rule.network_is_constrained.is_some() {
        fields.push("network_is_constrained");
    }
    if !rule.wifi_ssid.is_empty() {
        fields.push("wifi_ssid");
    }
    if !rule.wifi_bssid.is_empty() {
        fields.push("wifi_bssid");
    }
    if !rule.default_interface_address.is_empty() {
        fields.push("default_interface_address");
    }
    if !rule.preferred_by.is_empty() {
        fields.push("preferred_by");
    }
    if rule.rule_set_ip_cidr_match_source {
        fields.push("rule_set_ip_cidr_match_source");
    }
    if rule.route_options.is_some() {
        fields.push("route_options");
    }
    if rule.direct_options.is_some() {
        fields.push("direct_options");
    }
    if rule.sniff_options.is_some() {
        fields.push("sniff_options");
    }
    if rule.resolve_options.is_some() {
        fields.push("resolve_options");
    }
    fields
}

fn validate_port_range(value: &str) -> Result<(), CompileError> {
    let separator = if value.contains(':') { ':' } else { '-' };
    let Some((start, end)) = value.split_once(separator) else {
        return Err(CompileError::new(format!(
            "route port_range {value:?} must be START:END"
        )));
    };
    let start: u16 = start.trim().parse().map_err(|error| {
        CompileError::new(format!("invalid route port_range {value:?}: {error}"))
    })?;
    let end: u16 = end.trim().parse().map_err(|error| {
        CompileError::new(format!("invalid route port_range {value:?}: {error}"))
    })?;
    if start > end {
        return Err(CompileError::new(format!(
            "route port_range {value:?} has descending bounds"
        )));
    }
    if start == 0 {
        return Err(CompileError::new(format!(
            "route port_range {value:?} must start at 1 or greater"
        )));
    }
    Ok(())
}

fn compile_dns<'a>(
    dns: Option<&Dns>,
    outbounds: &'a BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
    inbound_tag: Option<&str>,
    ip_strategies: &BTreeMap<String, &'static str>,
    outbound_projection: &OutboundDnsProjection,
    projection_budget: &mut ClientChainProjectionBudget<'a>,
) -> Result<Option<Value>, CompileError> {
    const DEFAULT_DNS_TAG: &str = "default-dns";

    let default_server = DnsServer {
        kind: "https".to_string(),
        tag: DEFAULT_DNS_TAG.to_string(),
        server: "1.1.1.1".to_string(),
        detour: String::new(),
    };
    let configured = dns.map(|dns| dns.servers.as_slice()).unwrap_or_default();
    let server_list = if configured.is_empty() {
        std::slice::from_ref(&default_server)
    } else {
        configured
    };

    let mut servers = BTreeMap::new();
    let mut compiled_servers =
        Vec::with_capacity(server_list.len() + outbound_projection.variants.len());
    let mut compiled_by_tag = BTreeMap::new();
    for server in server_list {
        validate_dns_server(server)?;
        if servers.insert(server.tag.clone(), server).is_some() {
            return Err(CompileError::new(format!(
                "duplicate dns server tag {:?}",
                server.tag
            )));
        }
        let mut compiled_server = json!({
            "tag": server.tag,
            "url": dns_server_url(server)?,
            "use_native_roots": matches!(
                server.kind.as_str(),
                "tls" | "quic" | "https" | "h3"
            ),
        });
        // sing-box's address lookup issues A and AAAA concurrently when no
        // strategy is specified, returning IPv4 answers first. Shoes' generic
        // config default is intentionally different, so the ACP adapter makes
        // the Go behavior explicit.
        let strategy = ip_strategies
            .get(&server.tag)
            .copied()
            .unwrap_or("ipv4_and_ipv6");
        compiled_server["ip_strategy"] = Value::String(strategy.to_string());
        if !server.detour.is_empty() {
            if matches!(server.kind.as_str(), "local" | "system") {
                return Err(CompileError::new(format!(
                    "dns server {} cannot apply detour {:?} to the system resolver",
                    server.tag, server.detour
                )));
            }
            let outbound = outbounds.get(&server.detour).ok_or_else(|| {
                CompileError::new(format!(
                    "dns server {} references unknown detour outbound {:?}",
                    server.tag, server.detour
                ))
            })?;
            // DnsServerSpec intentionally uses the singular `client_chain`
            // field (whose value may still be one or many complete chains).
            // Emitting the route-rule `client_chains` spelling here used to be
            // ignored by serde and silently turned a requested DNS detour into
            // a direct transport.
            apply_outbound_action(
                &mut compiled_server,
                "client_chain",
                outbound_client_action(outbound, outbounds, projection_budget)?,
            );
        }
        compiled_by_tag.insert(server.tag.clone(), compiled_server.clone());
        compiled_servers.push(compiled_server);
    }

    let mut profile_variants = BTreeMap::<DnsServerVariantKey, String>::new();
    for variant in &outbound_projection.variants {
        let source_server = compiled_by_tag.get(&variant.source_tag).ok_or_else(|| {
            CompileError::new(format!(
                "DNS profile variant {:?} references unknown source server {:?}",
                variant.tag, variant.source_tag
            ))
        })?;
        reserve_embedded_outbound_action(source_server, "client_chain", projection_budget, || {
            format!("DNS profile variant {:?}", variant.tag)
        })?;
        let mut compiled_server = source_server.clone();
        compiled_server["tag"] = Value::String(variant.tag.clone());
        compiled_server["__acp_source_tag"] = Value::String(variant.source_tag.clone());
        compiled_server["ip_strategy"] = Value::String(variant.ip_strategy.to_string());
        apply_dns_server_query_profile(&mut compiled_server, &variant.query);
        compiled_servers.push(compiled_server);
        if let Some(existing) = profile_variants.insert(variant.key(), variant.tag.clone())
            && existing != variant.tag
        {
            return Err(CompileError::new(format!(
                "DNS profile variant {:?} conflicts with existing tag {existing:?}",
                variant.tag
            )));
        }
    }

    let requested_final = dns.map(|dns| dns.final_.as_str()).unwrap_or_default();
    let final_tag = if requested_final.is_empty() {
        if servers.contains_key(DEFAULT_DNS_TAG) {
            DEFAULT_DNS_TAG
        } else {
            return Err(CompileError::new(format!(
                "dns final is empty but no server is tagged {DEFAULT_DNS_TAG:?}"
            )));
        }
    } else {
        if !servers.contains_key(requested_final) {
            return Err(CompileError::new(format!(
                "dns final references unknown server {requested_final:?}"
            )));
        }
        requested_final
    };

    let mut compiled_rules = Vec::new();
    let mut emitted_tags = servers.keys().cloned().collect::<BTreeSet<_>>();
    emitted_tags.extend(
        outbound_projection
            .variants
            .iter()
            .map(|variant| variant.tag.clone()),
    );
    if let Some(dns) = dns {
        for (index, rule) in dns.rules.iter().enumerate() {
            let (mut compiled, route_query) = compile_dns_rule(rule, index, &servers, rule_sets)?;
            if rule.inbound.is_empty()
                || inbound_tag
                    .is_some_and(|inbound_tag| rule.inbound.iter().any(|tag| tag == inbound_tag))
            {
                if let Some(query) = route_query {
                    let strategy = ip_strategies
                        .get(&rule.server)
                        .copied()
                        .unwrap_or("ipv4_and_ipv6");
                    let key = DnsServerVariantKey {
                        source_tag: rule.server.clone(),
                        ip_strategy: strategy,
                        query: query.clone(),
                    };
                    let variant_tag = if let Some(tag) = profile_variants.get(&key) {
                        tag.clone()
                    } else {
                        let tag =
                            dns_profile_variant_tag(&key.source_tag, key.ip_strategy, &key.query);
                        if !emitted_tags.insert(tag.clone()) {
                            return Err(CompileError::new(format!(
                                "dns.rules[{index}] private DNS server tag {tag:?} collides with another DNS server"
                            )));
                        }
                        let variant = DnsServerVariant {
                            tag: tag.clone(),
                            source_tag: key.source_tag.clone(),
                            ip_strategy: key.ip_strategy,
                            query: key.query.clone(),
                        };
                        let source_server = compiled_by_tag
                            .get(&variant.source_tag)
                            .ok_or_else(|| {
                                CompileError::new(format!(
                                    "dns.rules[{index}] private DNS variant references unknown source server {:?}",
                                    variant.source_tag
                                ))
                            })?;
                        reserve_embedded_outbound_action(
                            source_server,
                            "client_chain",
                            projection_budget,
                            || format!("dns.rules[{index}] private DNS profile variant"),
                        )?;
                        let mut compiled_server = source_server.clone();
                        compiled_server["tag"] = Value::String(variant.tag.clone());
                        compiled_server["__acp_source_tag"] =
                            Value::String(variant.source_tag.clone());
                        compiled_server["ip_strategy"] =
                            Value::String(variant.ip_strategy.to_string());
                        apply_dns_server_query_profile(&mut compiled_server, &variant.query);
                        compiled_servers.push(compiled_server);
                        profile_variants.insert(key, tag.clone());
                        tag
                    };
                    compiled["server"] = Value::String(variant_tag);
                }
                compiled_rules.push(compiled);
            }
        }
    }

    let mut compiled = json!({
        "servers": compiled_servers,
        "final": final_tag,
    });
    if !compiled_rules.is_empty() {
        compiled["rules"] = Value::Array(compiled_rules);
    }
    Ok(Some(compiled))
}

fn apply_dns_server_query_profile(server: &mut Value, query: &DnsServerQueryProfile) {
    if query.disable_cache {
        server["disable_cache"] = Value::Bool(true);
    }
    if let Some(rewrite_ttl) = query.rewrite_ttl {
        server["rewrite_ttl"] = Value::from(rewrite_ttl);
    }
    if let Some(client_subnet) = &query.client_subnet {
        server["client_subnet"] = Value::String(client_subnet.clone());
    }
}

fn compile_dns_rule(
    rule: &DnsRule,
    index: usize,
    servers: &BTreeMap<String, &DnsServer>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
) -> Result<(Value, Option<DnsServerQueryProfile>), CompileError> {
    if rule.action.is_empty() {
        return Err(CompileError::new(format!(
            "dns.rules[{index}] action is required"
        )));
    }

    let mut compiled = Map::new();
    insert_non_empty(&mut compiled, "domain", &rule.domain);
    insert_non_empty(&mut compiled, "domain_suffix", &rule.domain_suffix);
    insert_non_empty(&mut compiled, "domain_keyword", &rule.domain_keyword);
    insert_non_empty(&mut compiled, "domain_regex", &rule.domain_regex);

    if !rule.rule_set.is_empty() {
        let mut references = Vec::with_capacity(rule.rule_set.len());
        for tag in &rule.rule_set {
            let rule_set = rule_sets.get(tag).ok_or_else(|| {
                CompileError::new(format!(
                    "dns.rules[{index}] references unknown rule-set {tag:?}"
                ))
            })?;
            references.push(json!({
                "format": rule_set.format,
                "path": rule_set.path,
            }));
        }
        compiled.insert("rule_set".into(), Value::Array(references));
    }

    let route_query = match rule.action.as_str() {
        "route" => {
            if rule.no_drop {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] route action must not contain no_drop"
                )));
            }
            let query = parse_dns_server_query_profile(rule, index)?;
            if rule.server.is_empty() {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] route action requires server"
                )));
            }
            if !servers.contains_key(&rule.server) {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] route references unknown server {:?}",
                    rule.server
                )));
            }
            if !rule.rcode.is_empty()
                || !rule.method.is_empty()
                || !rule.answer.is_empty()
                || !rule.ns.is_empty()
                || !rule.extra.is_empty()
            {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] route action must not contain rcode, method, answer, ns, or extra"
                )));
            }
            compiled.insert("action".into(), Value::String("route".into()));
            compiled.insert("server".into(), Value::String(rule.server.clone()));
            if !rule.timeout.is_empty() {
                compiled.insert(
                    "timeout_millis".into(),
                    Value::from(parse_dns_timeout_millis(&rule.timeout, index)?),
                );
            }
            (!query.is_default()).then_some(query)
        }
        "reject" => {
            if !rule.server.is_empty()
                || !rule.rcode.is_empty()
                || !rule.answer.is_empty()
                || !rule.ns.is_empty()
                || !rule.extra.is_empty()
                || !rule.timeout.is_empty()
                || rule.disable_cache
                || !rule.rewrite_ttl.trim().is_empty()
                || !rule.client_subnet.trim().is_empty()
            {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] reject action must not contain server, rcode, answer, ns, extra, timeout, disable_cache, rewrite_ttl, or client_subnet"
                )));
            }
            let method = shoes::dns::DnsRejectMethod::parse(&rule.method).ok_or_else(|| {
                CompileError::new(format!(
                    "dns.rules[{index}] reject method must be default or drop, got {:?}",
                    rule.method
                ))
            })?;
            if rule.no_drop && method == shoes::dns::DnsRejectMethod::Drop {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] reject method drop conflicts with no_drop"
                )));
            }
            compiled.insert("action".into(), Value::String("reject".into()));
            if !rule.method.is_empty() {
                compiled.insert("method".into(), Value::String(method.as_str().into()));
            }
            if rule.no_drop {
                compiled.insert("no_drop".into(), Value::Bool(true));
            }
            if method == shoes::dns::DnsRejectMethod::Default && !rule.no_drop {
                compiled.insert(
                    "__acp_reject_flood_key".into(),
                    Value::String(dns_reject_flood_state_key(rule, index)),
                );
            }
            None
        }
        "predefined" => {
            if !rule.server.is_empty()
                || !rule.method.is_empty()
                || !rule.timeout.is_empty()
                || rule.no_drop
                || rule.disable_cache
                || !rule.rewrite_ttl.trim().is_empty()
                || !rule.client_subnet.trim().is_empty()
            {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] predefined action must not contain server, method, timeout, no_drop, disable_cache, rewrite_ttl, or client_subnet"
                )));
            }
            let _rcode = shoes::dns::DnsRcode::parse(&rule.rcode).ok_or_else(|| {
                CompileError::new(format!(
                    "dns.rules[{index}] predefined rcode must be an exact miekg/dns response-code name, got {:?}",
                    rule.rcode
                ))
            })?;
            shoes::dns::parse_predefined_lookup_addresses(&rule.answer, &rule.ns, &rule.extra)
                .map_err(|error| CompileError::new(format!("dns.rules[{index}] {error}")))?;
            compiled.insert("action".into(), Value::String("predefined".into()));
            if !rule.rcode.is_empty() {
                compiled.insert("rcode".into(), Value::String(rule.rcode.clone()));
            }
            compiled.insert("answer".into(), json!(rule.answer));
            insert_non_empty(&mut compiled, "ns", &rule.ns);
            insert_non_empty(&mut compiled, "extra", &rule.extra);
            None
        }
        other => {
            return Err(CompileError::new(format!(
                "dns.rules[{index}] action {other:?} is not supported by shoes"
            )));
        }
    };
    Ok((Value::Object(compiled), route_query))
}

fn parse_dns_server_query_profile(
    rule: &DnsRule,
    index: usize,
) -> Result<DnsServerQueryProfile, CompileError> {
    let rewrite_ttl = match rule.rewrite_ttl.trim() {
        "" => None,
        value => Some(value.parse::<u32>().map_err(|error| {
            CompileError::new(format!(
                "dns.rules[{index}] rewrite_ttl {:?} must be a uint32: {error}",
                rule.rewrite_ttl
            ))
        })?),
    };
    let client_subnet = normalize_dns_client_subnet(&rule.client_subnet, index)?;
    Ok(DnsServerQueryProfile {
        disable_cache: rule.disable_cache,
        rewrite_ttl,
        client_subnet,
    })
}

fn normalize_dns_client_subnet(value: &str, index: usize) -> Result<Option<String>, CompileError> {
    normalize_dns_client_subnet_value(value).map_err(|reason| {
        CompileError::new(format!(
            "dns.rules[{index}] client_subnet {value:?} {reason}"
        ))
    })
}

fn normalize_dns_client_subnet_value(value: &str) -> Result<Option<String>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let (address, prefix_len) = match value.split_once('/') {
        Some((address, prefix)) => {
            if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
                return Err("must be an IP address or CIDR prefix".into());
            }
            let address = address
                .parse::<IpAddr>()
                .map_err(|error| format!("has invalid address {address:?}: {error}"))?;
            if !prefix.bytes().all(|byte| byte.is_ascii_digit())
                || (prefix.len() > 1 && prefix.starts_with('0'))
            {
                return Err(format!("has invalid prefix {prefix:?}"));
            }
            let prefix_len = prefix
                .parse::<u8>()
                .map_err(|error| format!("has invalid prefix {prefix:?}: {error}"))?;
            (address, prefix_len)
        }
        None => {
            let address = value
                .parse::<IpAddr>()
                .map_err(|error| format!("has invalid address: {error}"))?;
            let prefix_len = if address.is_ipv4() { 32 } else { 128 };
            (address, prefix_len)
        }
    };
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_prefix {
        return Err(format!(
            "has prefix length {prefix_len}, which exceeds {max_prefix} for {address}"
        ));
    }
    let network = match address {
        IpAddr::V4(address) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            IpAddr::V6((u128::from(address) & mask).into())
        }
    };
    Ok(Some(format!("{network}/{prefix_len}")))
}

fn parse_dns_timeout_millis(value: &str, index: usize) -> Result<u64, CompileError> {
    let duration = shoes::config::parse_go_duration(value).map_err(|error| {
        CompileError::new(format!(
            "dns.rules[{index}] timeout {value:?} is not a valid Go duration: {error}"
        ))
    })?;
    if duration.is_zero() {
        return Err(CompileError::new(format!(
            "dns.rules[{index}] timeout must be greater than zero"
        )));
    }
    let nanos = duration.as_nanos();
    if !nanos.is_multiple_of(1_000_000) {
        return Err(CompileError::new(format!(
            "dns.rules[{index}] timeout {value:?} cannot be represented exactly in milliseconds"
        )));
    }
    u64::try_from(nanos / 1_000_000).map_err(|_| {
        CompileError::new(format!(
            "dns.rules[{index}] timeout {value:?} exceeds the millisecond representation"
        ))
    })
}

fn validate_dns_server(server: &DnsServer) -> Result<(), CompileError> {
    if server.kind.is_empty() {
        return Err(CompileError::new("dns server type is required"));
    }
    if server.tag.is_empty() {
        return Err(CompileError::new("dns server tag is required"));
    }
    if server.server.is_empty() {
        return Err(CompileError::new("dns server address is required"));
    }
    Ok(())
}

fn dns_server_url(server: &DnsServer) -> Result<String, CompileError> {
    let address = server.server.trim();
    let authority = if address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{address}]")
    } else {
        address.to_string()
    };
    let url = match server.kind.as_str() {
        "local" | "system" => "system".to_string(),
        "udp" | "tcp" | "tls" | "quic" => format!("{}://{authority}", server.kind),
        "https" => {
            if address.starts_with("https://") {
                address.to_string()
            } else if address.contains('/') {
                format!("https://{address}")
            } else {
                format!("https://{authority}/dns-query")
            }
        }
        "h3" => {
            if address.starts_with("h3://") {
                address.to_string()
            } else if address.contains('/') {
                format!("h3://{address}")
            } else {
                format!("h3://{authority}/dns-query")
            }
        }
        other => {
            return Err(CompileError::new(format!(
                "dns server {} has unsupported type {other:?}",
                server.tag
            )));
        }
    };
    Ok(url)
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    format: &'static str,
    machine_id: &'a str,
    revision: u64,
    inbounds: Vec<DiagnosticInbound>,
    requested_outbounds: Value,
    requested_route: Value,
    requested_dns: Value,
    warnings: &'a [String],
}

#[derive(Serialize)]
struct DiagnosticInbound {
    node_id: String,
    protocol: String,
    tag: String,
    config: Value,
    users: Vec<DiagnosticUser>,
}

#[derive(Serialize)]
struct DiagnosticUser {
    id: String,
    enabled: bool,
    upload_limit_bps: u64,
    download_limit_bps: u64,
}

fn diagnostic_yaml(
    topology: &MachineTopology,
    inbounds: &[CompiledInbound],
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    warnings: &[String],
) -> Result<Vec<u8>, CompileError> {
    let inbounds = inbounds
        .iter()
        .map(|inbound| {
            let mut users: Vec<DiagnosticUser> = inbound
                .spec
                .users
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|user| DiagnosticUser {
                    id: user
                        .resolved_id()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    enabled: user.enabled,
                    upload_limit_bps: user.upload_limit_bps.unwrap_or_default(),
                    download_limit_bps: user.download_limit_bps.unwrap_or_default(),
                })
                .collect();
            users.sort_by(|left, right| left.id.cmp(&right.id));
            DiagnosticInbound {
                node_id: inbound.node_id.clone(),
                protocol: inbound.protocol.clone(),
                tag: inbound.spec.tag.clone(),
                config: redact(inbound.spec.config.clone()),
                users,
            }
        })
        .collect();
    let requested_outbounds = Value::Array(
        outbounds
            .values()
            .map(|outbound| {
                redact(json!({
                    "type": outbound.kind,
                    "tag": outbound.tag,
                    "options": outbound.requested_options
                }))
            })
            .collect(),
    );
    let requested_route = topology
        .route
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| CompileError::new(format!("encode diagnostic route: {error}")))?
        .unwrap_or(Value::Null);
    let requested_dns = topology
        .dns
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| CompileError::new(format!("encode diagnostic dns: {error}")))?
        .unwrap_or(Value::Null);
    let diagnostic = Diagnostic {
        format: "shoes-equivalent-v1",
        machine_id: &topology.machine_id,
        revision: topology.revision,
        inbounds,
        requested_outbounds,
        requested_route,
        requested_dns,
        warnings,
    };
    serde_yaml::to_string(&diagnostic)
        .map(String::into_bytes)
        .map_err(|error| CompileError::new(format!("encode diagnostic YAML: {error}")))
}

fn redact(mut value: Value) -> Value {
    redact_in_place(&mut value);
    value
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.sort_keys();
            for (key, value) in map {
                let key = key.to_ascii_lowercase();
                if matches!(
                    key.as_str(),
                    "password"
                        | "credential"
                        | "uuid"
                        | "private_key"
                        | "private_key_pem"
                        | "key"
                        | "secret"
                        | "token"
                ) {
                    *value = Value::String("<redacted>".to_string());
                } else {
                    redact_in_place(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_in_place),
        _ => {}
    }
}

#[cfg(test)]
mod projection_budget_tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn test_outbound(kind: &str, tag: impl Into<String>, options: Value) -> ValidatedOutbound {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

        let tag = tag.into();
        ValidatedOutbound {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            kind: kind.to_string(),
            tag,
            requested_options: options.clone(),
            options,
            domain_resolver: None,
            shoes_dns_resolver: None,
        }
    }

    #[test]
    fn repeated_urltest_member_resolves_its_large_selector_identity_once() {
        const MEMBER_COUNT: usize = 4_096;
        const OCCURRENCE_COUNT: usize = 8_192;

        let large_selector_members = vec!["terminal"; MEMBER_COUNT];
        let terminal = test_outbound("direct", "terminal", json!({}));
        let mut immediate = BTreeMap::new();
        let visited_selector_members = Cell::new(0);
        let mut retained = 0;
        let mut selected_ids = BTreeSet::new();

        for _ in 0..OCCURRENCE_COUNT {
            let (real_outbound, _) = cached_selector_outbound(usize::MAX, &mut immediate, || {
                for selector_member in &large_selector_members {
                    assert_eq!(*selector_member, "terminal");
                    visited_selector_members.set(visited_selector_members.get() + 1);
                }
                Ok(&terminal)
            })
            .unwrap();
            if selected_ids.insert(real_outbound.id) {
                retained += 1;
            }
        }

        assert_eq!(visited_selector_members.get(), MEMBER_COUNT);
        assert_eq!(retained, 1);
        assert_eq!(selected_ids, BTreeSet::from([terminal.id]));
        assert!(std::ptr::eq(immediate[&usize::MAX], &terminal));
    }

    #[test]
    fn distinct_urltest_actions_share_one_immediate_selector_parse() {
        const MEMBER_COUNT: usize = 4_096;
        const ACTION_COUNT: usize = 8_192;

        let large_selector_members = vec!["terminal"; MEMBER_COUNT];
        let terminal = test_outbound("direct", "terminal", json!({}));
        let mut immediate = BTreeMap::new();
        let visited_selector_members = Cell::new(0);
        let mut retained_actions = 0;

        for _ in 0..ACTION_COUNT {
            let mut selected_ids = BTreeSet::new();
            let (real_outbound, _) = cached_selector_outbound(usize::MAX, &mut immediate, || {
                for selector_member in &large_selector_members {
                    assert_eq!(*selector_member, "terminal");
                    visited_selector_members.set(visited_selector_members.get() + 1);
                }
                Ok(&terminal)
            })
            .unwrap();
            if selected_ids.insert(real_outbound.id) {
                retained_actions += 1;
            }
        }

        assert_eq!(visited_selector_members.get(), MEMBER_COUNT);
        assert_eq!(retained_actions, ACTION_COUNT);
        assert!(std::ptr::eq(immediate[&usize::MAX], &terminal));
    }

    #[test]
    fn distinct_aliases_path_compress_a_shared_wide_selector_suffix() {
        const MEMBER_COUNT: usize = 4_096;
        const ALIAS_COUNT: usize = 2_048;

        let mut catalog = BTreeMap::new();
        catalog.insert(
            "terminal".to_string(),
            test_outbound("direct", "terminal", json!({})),
        );
        catalog.insert(
            "shared".to_string(),
            test_outbound(
                "selector",
                "shared",
                json!({
                    "outbounds": vec!["terminal"; MEMBER_COUNT],
                    "default": "terminal",
                }),
            ),
        );
        for index in 0..ALIAS_COUNT {
            let inner = format!("inner-{index:04}");
            let outer = format!("outer-{index:04}");
            catalog.insert(
                inner.clone(),
                test_outbound(
                    "selector",
                    &inner,
                    json!({"outbounds": ["shared"], "default": "shared"}),
                ),
            );
            catalog.insert(
                outer.clone(),
                test_outbound(
                    "selector",
                    &outer,
                    json!({"outbounds": [&inner], "default": inner}),
                ),
            );
        }

        let mut completed = BTreeMap::new();
        let mut immediate = BTreeMap::new();
        let mut selector_cache = SelectorProjectionCache::default();
        for index in 0..ALIAS_COUNT {
            let outer = format!("outer-{index:04}");
            let terminal = resolve_static_selector_outbound(
                catalog.get(&outer).unwrap(),
                &catalog,
                &mut completed,
                &mut immediate,
                &mut selector_cache,
            )
            .unwrap();
            assert_eq!(terminal.tag, "terminal");
        }

        assert_eq!(
            completed
                .get(&catalog["shared"].id)
                .map(|outbound| outbound.tag.as_str()),
            Some("terminal")
        );
        assert_eq!(
            completed.len(),
            ALIAS_COUNT * 2 + 2,
            "every alias and the shared suffix are compressed exactly once"
        );
    }

    #[test]
    fn selector_terminal_and_immediate_caches_reuse_long_tag_handles() {
        const ALIAS_COUNT: usize = 1_024;

        let terminal_tag = format!("terminal-{}", "x".repeat(256 * 1024));
        let mut catalog = BTreeMap::new();
        catalog.insert(
            terminal_tag.clone(),
            test_outbound("direct", &terminal_tag, json!({})),
        );
        catalog.insert(
            "shared".to_string(),
            test_outbound(
                "selector",
                "shared",
                json!({"outbounds": [&terminal_tag], "default": &terminal_tag}),
            ),
        );
        for index in 0..ALIAS_COUNT {
            let alias = format!("alias-{index:04}");
            catalog.insert(
                alias.clone(),
                test_outbound(
                    "selector",
                    &alias,
                    json!({"outbounds": ["shared"], "default": "shared"}),
                ),
            );
            let direct_alias = format!("direct-alias-{index:04}");
            catalog.insert(
                direct_alias.clone(),
                test_outbound(
                    "selector",
                    &direct_alias,
                    json!({"outbounds": [&terminal_tag], "default": &terminal_tag}),
                ),
            );
        }

        let mut completed = BTreeMap::new();
        let mut immediate = BTreeMap::new();
        let mut selector_cache = SelectorProjectionCache::default();
        for index in 0..ALIAS_COUNT {
            let alias = format!("alias-{index:04}");
            resolve_static_selector_outbound(
                catalog.get(&alias).unwrap(),
                &catalog,
                &mut completed,
                &mut immediate,
                &mut selector_cache,
            )
            .unwrap();
            let direct_alias = format!("direct-alias-{index:04}");
            resolve_static_selector_outbound(
                catalog.get(&direct_alias).unwrap(),
                &catalog,
                &mut completed,
                &mut immediate,
                &mut selector_cache,
            )
            .unwrap();
        }

        let terminal = catalog.get(terminal_tag.as_str()).unwrap();
        assert!(
            completed
                .values()
                .all(|candidate| std::ptr::eq(*candidate, terminal)),
            "path-compressed aliases must share one terminal outbound handle"
        );
        assert!(std::ptr::eq(immediate[&catalog["shared"].id], terminal));
        let shared_adapter_ref = selector_cache.selected(catalog["shared"].id).unwrap();
        assert!(std::ptr::eq(shared_adapter_ref.options, &terminal.options));

        for index in 0..ALIAS_COUNT {
            let alias = format!("direct-alias-{index:04}");
            let alias_id = catalog[&alias].id;
            assert!(
                std::ptr::eq(immediate[&alias_id], terminal),
                "different selector aliases must reuse the terminal outbound handle"
            );
            assert_eq!(immediate[&alias_id].id, terminal.id);
            let adapter_ref = selector_cache.selected(alias_id).unwrap();
            assert!(std::ptr::eq(adapter_ref.options, &terminal.options));
        }
    }

    #[test]
    fn repeated_actions_reuse_one_compiled_urltest_sample_but_charge_each_copy() {
        const MEMBER_COUNT: usize = 4_096;
        const OCCURRENCE_COUNT: usize = 8_192;

        let mut catalog = BTreeMap::new();
        catalog.insert(
            "terminal".to_string(),
            test_outbound(
                "shadowsocks",
                "terminal",
                json!({
                    "server": "192.0.2.10",
                    "server_port": 8388,
                    "method": "aes-128-gcm",
                    "password": "secret",
                    "network": "tcp",
                }),
            ),
        );
        catalog.insert(
            "choice".to_string(),
            test_outbound(
                "selector",
                "choice",
                json!({
                    "outbounds": vec!["terminal"; MEMBER_COUNT],
                    "default": "terminal",
                }),
            ),
        );
        catalog.insert(
            "automatic".to_string(),
            test_outbound(
                "urltest",
                "automatic",
                json!({"outbounds": vec!["choice"; OCCURRENCE_COUNT]}),
            ),
        );

        let automatic = catalog.get("automatic").unwrap();
        let mut budget = ClientChainProjectionBudget::default();
        let first = compile_urltest_action(automatic, &catalog, &mut budget).unwrap();
        let first_cost = budget.used;
        let second = compile_urltest_action(automatic, &catalog, &mut budget).unwrap();

        assert_eq!(first.client_chains, second.client_chains);
        assert_eq!(first.client_chain_selection, second.client_chain_selection);
        assert_eq!(budget.urltest_samples.len(), 1);
        assert_eq!(budget.compiled_samples.len(), 1);
        assert_eq!(budget.used.hops, first_cost.hops * 2);
        assert_eq!(budget.used.bytes, first_cost.bytes * 2);
    }

    #[test]
    fn repeated_selector_actions_reuse_a_long_tag_urltest_without_formatting_its_tag() {
        const ACTION_COUNT: usize = 4_096;
        const LONG_TAG_BYTES: usize = 64 * 1024;

        let urltest_tag = format!("urltest-{}", "x".repeat(LONG_TAG_BYTES));
        let mut catalog = BTreeMap::new();
        catalog.insert(
            "terminal".to_string(),
            test_outbound("direct", "terminal", json!({})),
        );
        catalog.insert(
            urltest_tag.clone(),
            test_outbound("urltest", &urltest_tag, json!({"outbounds": ["terminal"]})),
        );
        catalog.insert(
            "choice".to_string(),
            test_outbound(
                "selector",
                "choice",
                json!({"outbounds": [&urltest_tag], "default": &urltest_tag}),
            ),
        );

        let choice = catalog.get("choice").unwrap();
        let mut budget = ClientChainProjectionBudget::default();
        for _ in 0..ACTION_COUNT {
            let action = outbound_client_action(choice, &catalog, &mut budget).unwrap();
            assert_eq!(
                action.client_chain_selection.as_ref().unwrap()["type"],
                "urltest"
            );
        }

        assert_eq!(budget.urltest_samples.len(), 1);
        assert_eq!(budget.compiled_samples.len(), 1);
        assert_eq!(budget.used.hops, ACTION_COUNT);
    }

    #[test]
    fn projection_cost_counts_hops_json_and_selection_without_allocating_bytes() {
        let chains = json!([
            {"chain": [{"protocol": {"type": "direct"}}]},
            {"chain": [
                {"protocol": {"type": "direct"}},
                {"protocol": {"type": "direct"}}
            ]}
        ]);
        let selection = json!({"type": "urltest", "url": "https://example.com/"});
        let projection = ClientChainsProjection::inspect(&chains).unwrap();
        let cost = projection.cost(Some(&selection)).unwrap();
        assert_eq!(cost.hops, 3);
        assert_eq!(
            cost.bytes,
            serde_json::to_vec(&chains).unwrap().len()
                + serde_json::to_vec(&selection).unwrap().len()
        );
    }

    #[test]
    fn projection_budget_is_cumulative_and_fails_loudly_on_each_boundary() {
        let mut hop_budget = ClientChainProjectionBudget::default();
        let context_calls = Cell::new(0);
        hop_budget
            .reserve(
                ClientChainProjectionCost {
                    hops: MAX_PROJECTED_CLIENT_CHAIN_HOPS,
                    bytes: 0,
                },
                || {
                    context_calls.set(context_calls.get() + 1);
                    "first action".to_string()
                },
            )
            .unwrap();
        assert_eq!(context_calls.get(), 0);
        let error = hop_budget
            .reserve(ClientChainProjectionCost { hops: 1, bytes: 0 }, || {
                context_calls.set(context_calls.get() + 1);
                "second action".to_string()
            })
            .unwrap_err();
        assert_eq!(context_calls.get(), 1);
        assert!(error.to_string().contains("projection budget exceeded"));
        assert!(error.to_string().contains("second action"));

        let mut byte_budget = ClientChainProjectionBudget::default();
        byte_budget
            .reserve(
                ClientChainProjectionCost {
                    hops: 0,
                    bytes: MAX_PROJECTED_CLIENT_CHAIN_BYTES,
                },
                || "first action".to_string(),
            )
            .unwrap();
        let error = byte_budget
            .reserve(ClientChainProjectionCost { hops: 0, bytes: 1 }, || {
                "second action".to_string()
            })
            .unwrap_err();
        assert!(error.to_string().contains("projection budget exceeded"));
        assert!(error.to_string().contains("67108865 projected JSON bytes"));
    }

    #[test]
    fn dns_profile_variant_reserves_its_embedded_chain_copy() {
        let source = json!({
            "client_chain": [{"chain": [{"protocol": {"type": "direct"}}]}],
            "client_chain_selection": {"type": "urltest"}
        });
        let mut budget = ClientChainProjectionBudget::default();
        reserve_embedded_outbound_action(&source, "client_chain", &mut budget, || {
            "DNS profile variant".to_string()
        })
        .unwrap();
        assert_eq!(budget.used.hops, 1);
        assert!(budget.used.bytes > 0);
    }
}
