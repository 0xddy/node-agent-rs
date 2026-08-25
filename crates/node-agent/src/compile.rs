//! Compile ACP topology directly into native shoes inbound payloads.
//!
//! The Go provider registry is the validation authority. Its two adapters are
//! reproduced here; route/DNS/outbound semantics that shoes cannot preserve are
//! rejected before the runtime transaction begins. The deterministic warning
//! list is reserved for diagnostics that do not change traffic meaning.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use shoes_api::{InboundSpec, UserSpec};
use shoes_engine::Engine;

use crate::outbound_adapter::{OutboundCatalog, OutboundRef, compile_client_chains};
use crate::rule_set::{
    RuleSetLoader, RuleSetReference, RuleSetResource, plan_inline_resource, plan_resource,
};
use crate::runtime::{CompiledInbound, RuntimeConfig};
use crate::topology::provider::{
    CURRENT_CONFIG_VERSION, HYSTERIA2_SALAMANDER_ID, Hysteria2SalamanderConfig,
    VLESS_REALITY_VISION_ID, VlessRealityVisionConfig,
};
use crate::topology::{
    DEFAULT_DIRECT_OUTBOUND, DEFAULT_INBOUND_LISTEN, Dns, DnsRule, DnsServer, MachineTopology,
    NodeInstance, Outbound, Route, RouteRule, UserCredential, VLESS_FLOW_REALITY_VISION,
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
    let (rule_sets, rule_set_resources) = compile_rule_set_catalog(topology.route.as_ref())?;
    validate_route(topology.route.as_ref(), &outbounds, &rule_sets)?;
    let dns_ip_strategies = validate_dns_resolution_projection(
        topology.route.as_ref(),
        topology.dns.as_ref(),
        &outbounds,
    )?;
    let outbound_dns_projection =
        project_outbound_dns_resolvers(topology.dns.as_ref(), &mut outbounds, &dns_ip_strategies)?;

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
        )?;
        inbound.spec.config["rules"] = Value::Array(rules);
        if let Some(dns) = compile_dns(
            topology.dns.as_ref(),
            &outbounds,
            &rule_sets,
            &inbound.spec.tag,
            &dns_ip_strategies,
            &outbound_dns_projection,
        )? {
            inbound.spec.config["dns"] = dns;
        }
    }

    let warnings: Vec<String> = warnings.into_iter().collect();
    let diagnostic_yaml = diagnostic_yaml(topology, &inbounds, &outbounds, &warnings)?;
    Ok(CompileOutput {
        runtime: RuntimeConfig {
            inbounds,
            rule_sets: rule_set_resources,
            diagnostic_yaml,
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
}

impl OutboundCatalog for BTreeMap<String, ValidatedOutbound> {
    fn resolve(&self, tag: &str) -> Option<OutboundRef<'_>> {
        self.get(tag).map(|outbound| OutboundRef {
            kind: &outbound.kind,
            tag: &outbound.tag,
            options: &outbound.options,
        })
    }

    fn dns_resolver(&self, tag: &str) -> Option<&str> {
        self.get(tag)?.shoes_dns_resolver.as_deref()
    }
}

fn outbound_client_chains(
    outbound: &ValidatedOutbound,
    catalog: &BTreeMap<String, ValidatedOutbound>,
) -> Result<Value, CompileError> {
    compile_client_chains(&outbound.kind, &outbound.tag, &outbound.options, catalog)
        .map_err(|error| CompileError::new(format!("compile outbound {:?}: {error}", outbound.tag)))
}

#[derive(Debug, Clone)]
struct CompiledOutboundAction {
    client_chains: Value,
    client_chain_selection: Option<Value>,
}

fn outbound_client_action(
    outbound: &ValidatedOutbound,
    catalog: &BTreeMap<String, ValidatedOutbound>,
) -> Result<CompiledOutboundAction, CompileError> {
    if outbound.kind == "urltest" {
        return compile_urltest_action(outbound, catalog);
    }
    Ok(CompiledOutboundAction {
        client_chains: outbound_client_chains(outbound, catalog)?,
        client_chain_selection: None,
    })
}

fn compile_urltest_action(
    outbound: &ValidatedOutbound,
    catalog: &BTreeMap<String, ValidatedOutbound>,
) -> Result<CompiledOutboundAction, CompileError> {
    const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
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

    let members = fields
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CompileError::new(format!(
                "urltest outbound {:?} requires an outbounds string array",
                outbound.tag
            ))
        })?;
    if members.is_empty() {
        return Err(CompileError::new(format!(
            "urltest outbound {:?} requires at least one member",
            outbound.tag
        )));
    }

    let mut chains = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let member = member
            .as_str()
            .filter(|member| !member.is_empty())
            .ok_or_else(|| {
                CompileError::new(format!(
                    "urltest outbound {:?} outbounds[{index}] must be a non-empty string",
                    outbound.tag
                ))
            })?;
        let member = catalog.get(member).ok_or_else(|| {
            CompileError::new(format!(
                "urltest outbound {:?} references unknown member {member:?}",
                outbound.tag
            ))
        })?;
        if member.kind == "urltest" {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} contains nested urltest member {:?}; shoes exposes one cross-chain selection layer and cannot preserve both active selectors",
                outbound.tag, member.tag
            )));
        }
        let compiled = outbound_client_chains(member, catalog)?;
        let member_chains = compiled.as_array().ok_or_else(|| {
            CompileError::new(format!(
                "compiled urltest member {:?} did not produce client chains",
                member.tag
            ))
        })?;
        chains.extend(member_chains.iter().cloned());
    }

    let requested_url = match fields.get("url") {
        None => "",
        Some(Value::String(url)) => url.as_str(),
        Some(_) => {
            return Err(CompileError::new(format!(
                "urltest outbound {:?} url must be a string",
                outbound.tag
            )));
        }
    };
    let effective_url = if requested_url.is_empty() {
        DEFAULT_URL
    } else {
        requested_url
    };
    let parsed_url = url::Url::parse(effective_url).map_err(|error| {
        CompileError::new(format!(
            "urltest outbound {:?} has invalid URL {effective_url:?}: {error}",
            outbound.tag
        ))
    })?;
    if !matches!(parsed_url.scheme(), "http" | "https")
        || parsed_url.host_str().is_none()
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
    {
        return Err(CompileError::new(format!(
            "urltest outbound {:?} URL must be an absolute HTTP or HTTPS URL without user info",
            outbound.tag
        )));
    }

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
        None => 50,
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
        None | Some(Value::Bool(false)) => {}
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

    Ok(CompiledOutboundAction {
        client_chains: Value::Array(chains),
        client_chain_selection: Some(json!({
            "type": "urltest",
            "url": requested_url,
            "use_native_roots": true,
            "reselect_on_connection_failure": false,
            "interval_millis": interval_millis,
            "idle_timeout_millis": idle_timeout_millis,
            "tolerance_millis": tolerance,
        })),
    })
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
    for outbound in values {
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
    let resolver = value.as_object().ok_or_else(|| {
        CompileError::new(format!(
            "outbound {tag:?} ({kind}) domain_resolver must be an object"
        ))
    })?;
    if let Some(field) = resolver
        .keys()
        .find(|field| !matches!(field.as_str(), "server" | "strategy"))
    {
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
        None => String::new(),
        Some(Value::String(strategy)) if strategy.trim() == strategy => strategy.clone(),
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
    Ok(Some(OutboundDomainResolver { server, strategy }))
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

    let mut strategies = BTreeMap::new();
    if let Some(default_resolver) = route.and_then(|route| route.default_domain_resolver.as_ref()) {
        if default_resolver.server != final_tag {
            return Err(CompileError::new(format!(
                "route.default_domain_resolver server {:?} is not equivalent to dns.final {final_tag:?}",
                default_resolver.server
            )));
        }
        if !default_resolver.strategy.is_empty()
            || default_resolver.disable_cache
            || default_resolver.rewrite_ttl.is_some()
            || !default_resolver.client_subnet.is_empty()
        {
            return Err(CompileError::new(
                "route.default_domain_resolver is equivalent to dns.final only with an empty strategy and no cache, TTL, or client_subnet controls",
            ));
        }
    }

    let route_rules = route
        .map(|route| route.rules.as_slice())
        .unwrap_or_default();
    let dns_rules = dns.map(|dns| dns.rules.as_slice()).unwrap_or_default();

    for outbound in outbounds.values() {
        let Some(resolver) = &outbound.domain_resolver else {
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

fn dns_variant_tag(source_tag: &str, ip_strategy: &str) -> String {
    let digest = Sha256::digest(format!("{source_tag}\0{ip_strategy}"));
    let mut tag = String::from("__acp_outbound_dns_");
    for byte in digest {
        write!(&mut tag, "{byte:02x}").expect("writing to a String cannot fail");
    }
    tag
}

/// Assign an exact named DNS transport to each outbound without changing the
/// policy/final resolver seen by any other consumer. A strategy override gets a
/// private clone of the source server unless the source already has identical
/// lookup behavior.
fn project_outbound_dns_resolvers(
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

    let mut variants = BTreeMap::<String, DnsServerVariant>::new();
    for outbound in outbounds.values_mut() {
        let Some(resolver) = outbound.domain_resolver.as_ref() else {
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
        let selected_tag = match desired {
            None => resolver.server.clone(),
            Some(desired) if desired == source_strategy => resolver.server.clone(),
            Some(desired) => {
                let tag = dns_variant_tag(&resolver.server, desired);
                if configured_tags.contains(&tag) {
                    return Err(CompileError::new(format!(
                        "configured DNS server tag {tag:?} collides with a reserved per-outbound resolver tag"
                    )));
                }
                variants
                    .entry(tag.clone())
                    .or_insert_with(|| DnsServerVariant {
                        tag: tag.clone(),
                        source_tag: resolver.server.clone(),
                        ip_strategy: desired,
                    });
                tag
            }
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
        VLESS_REALITY_VISION_ID => compile_vless(node, warnings),
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

fn compile_vless(
    node: &NodeInstance,
    warnings: &mut BTreeSet<String>,
) -> Result<CompiledInbound, CompileError> {
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
    if !cfg.outbounds.is_empty() {
        warnings.insert(format!(
            "node {} provider-local outbounds are not consumed by either provider adapter",
            node.node_id
        ));
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
    if !cfg.outbounds.is_empty() {
        warnings.insert(format!(
            "node {} provider-local outbounds are not consumed by either provider adapter",
            node.node_id
        ));
    }

    let mut protocol = Map::from_iter([
        ("type".to_string(), json!("hysteria2")),
        ("udp_enabled".to_string(), json!(true)),
        ("up_mbps".to_string(), json!(cfg.up_mbps as u64)),
        ("down_mbps".to_string(), json!(cfg.down_mbps as u64)),
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

fn compile_rules_for_inbound(
    route: Option<&Route>,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
    inbound_tag: &str,
    sniff_enabled: bool,
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
            rules.push(compile_route_rule(rule, index, outbounds, rule_sets)?);
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
            outbound_client_action(outbound, outbounds)?,
        );
        rules.push(rule);
    }
    Ok(rules)
}

fn compile_route_rule(
    rule: &RouteRule,
    index: usize,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
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
            outbound_client_action(outbound, outbounds)?,
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

fn compile_dns(
    dns: Option<&Dns>,
    outbounds: &BTreeMap<String, ValidatedOutbound>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
    inbound_tag: &str,
    ip_strategies: &BTreeMap<String, &'static str>,
    outbound_projection: &OutboundDnsProjection,
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
                outbound_client_action(outbound, outbounds)?,
            );
        }
        compiled_by_tag.insert(server.tag.clone(), compiled_server.clone());
        compiled_servers.push(compiled_server);
    }

    for variant in &outbound_projection.variants {
        let mut compiled_server = compiled_by_tag
            .get(&variant.source_tag)
            .cloned()
            .ok_or_else(|| {
                CompileError::new(format!(
                    "per-outbound DNS variant {:?} references unknown source server {:?}",
                    variant.tag, variant.source_tag
                ))
            })?;
        compiled_server["tag"] = Value::String(variant.tag.clone());
        compiled_server["ip_strategy"] = Value::String(variant.ip_strategy.to_string());
        compiled_servers.push(compiled_server);
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
    if let Some(dns) = dns {
        for (index, rule) in dns.rules.iter().enumerate() {
            let compiled = compile_dns_rule(rule, index, &servers, rule_sets)?;
            if rule.inbound.is_empty() || rule.inbound.iter().any(|tag| tag == inbound_tag) {
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

fn compile_dns_rule(
    rule: &DnsRule,
    index: usize,
    servers: &BTreeMap<String, &DnsServer>,
    rule_sets: &BTreeMap<String, CompiledRuleSet>,
) -> Result<Value, CompileError> {
    if rule.action.is_empty() {
        return Err(CompileError::new(format!(
            "dns.rules[{index}] action is required"
        )));
    }
    let unsupported = dns_rule_unsupported_fields(rule);
    if !unsupported.is_empty() {
        return Err(CompileError::new(format!(
            "dns.rules[{index}] contains unsupported fields: {}",
            unsupported.join(", ")
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

    match rule.action.as_str() {
        "route" => {
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
        }
        "reject" => {
            if !rule.server.is_empty()
                || !rule.rcode.is_empty()
                || !rule.answer.is_empty()
                || !rule.ns.is_empty()
                || !rule.extra.is_empty()
                || !rule.timeout.is_empty()
            {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] reject action must not contain server, rcode, answer, ns, extra, or timeout"
                )));
            }
            let method = shoes::dns::DnsRejectMethod::parse(&rule.method).ok_or_else(|| {
                CompileError::new(format!(
                    "dns.rules[{index}] reject method must be default or drop, got {:?}",
                    rule.method
                ))
            })?;
            compiled.insert("action".into(), Value::String("reject".into()));
            if !rule.method.is_empty() {
                compiled.insert("method".into(), Value::String(method.as_str().into()));
            }
        }
        "predefined" => {
            if !rule.server.is_empty() || !rule.method.is_empty() || !rule.timeout.is_empty() {
                return Err(CompileError::new(format!(
                    "dns.rules[{index}] predefined action must not contain server, method, or timeout"
                )));
            }
            let rcode = shoes::dns::DnsRcode::parse(&rule.rcode).ok_or_else(|| {
                CompileError::new(format!(
                    "dns.rules[{index}] predefined rcode must be NOERROR, NXDOMAIN, REFUSED, or SERVFAIL, got {:?}",
                    rule.rcode
                ))
            })?;
            shoes::dns::parse_predefined_lookup_addresses(&rule.answer, &rule.ns, &rule.extra)
                .map_err(|error| CompileError::new(format!("dns.rules[{index}] {error}")))?;
            compiled.insert("action".into(), Value::String("predefined".into()));
            if !rule.rcode.is_empty() {
                compiled.insert("rcode".into(), Value::String(rcode.as_str().into()));
            }
            compiled.insert("answer".into(), json!(rule.answer));
            insert_non_empty(&mut compiled, "ns", &rule.ns);
            insert_non_empty(&mut compiled, "extra", &rule.extra);
        }
        other => {
            return Err(CompileError::new(format!(
                "dns.rules[{index}] action {other:?} is not supported by shoes"
            )));
        }
    }
    Ok(Value::Object(compiled))
}

fn dns_rule_unsupported_fields(rule: &DnsRule) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if rule.no_drop {
        fields.push("no_drop");
    }
    if rule.disable_cache {
        fields.push("disable_cache");
    }
    if !rule.rewrite_ttl.trim().is_empty() {
        fields.push("rewrite_ttl");
    }
    if !rule.client_subnet.trim().is_empty() {
        fields.push("client_subnet");
    }
    fields
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
