//! Strict adapter from panel/sing-box outbound objects to shoes client chains.
//!
//! This module deliberately depends only on `serde_json`.  It is the compatibility
//! boundary between ACP topology data and shoes, so protocol-specific projection
//! stays outside the shoes source tree.
//!
//! The returned value is the value of a shoes `RuleConfig.client_chains` field:
//!
//! ```text
//! [{ "chain": [<hop>, ...] }]
//! ```
//!
//! Supported, lossless subset:
//!
//! - Direct with the panel-managed local dialer fields supported by shoes;
//! - Shadowsocks TCP, native SIP003 UDP, or explicitly selected UoT v2;
//! - Trojan TCP/UDP-over-TCP, optionally wrapped in ordinary TLS;
//! - VLESS TCP and all panel packet encodings (`xudp`, `packetaddr`, or the
//!   legacy single-destination encoding), optionally wrapped in ordinary TLS
//!   or TLS Vision;
//! - Hysteria2 TCP/UDP over its native QUIC transport, including Salamander
//!   obfuscation and Brutal bandwidth negotiation;
//! - selector as its configured default member (or first member when no default
//!   is configured), matching sing-box when no selector-switching control API is
//!   present;
//! - proxy `detour` as an ordered multi-hop shoes chain.
//!
//! A field is never silently copied or discarded.  Unsupported sing-box features
//! produce [`OutboundAdapterError`], rather than accidentally turning traffic into
//! a direct connection.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use serde_json::{Map, Value, json};

/// A borrowed outbound returned by an [`OutboundCatalog`].
#[derive(Debug, Clone, Copy)]
pub struct OutboundRef<'a> {
    pub kind: &'a str,
    pub tag: &'a str,
    pub options: &'a Value,
}

/// Lookup used to resolve selector members and detours.
///
/// The compiler can implement this trait for its validated outbound catalog
/// without exposing the compiler's internal catalog type.
pub trait OutboundCatalog {
    fn resolve(&self, tag: &str) -> Option<OutboundRef<'_>>;

    /// Optional shoes DNS upstream selected only for this outbound's socket
    /// lookup. Catalogs that do not need per-outbound resolution keep the
    /// historical behavior through this default.
    fn dns_resolver(&self, _tag: &str) -> Option<&str> {
        None
    }
}

/// Convenience owned catalog entry, primarily useful to callers and tests.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboundDefinition {
    pub kind: String,
    pub tag: String,
    pub options: Value,
}

impl OutboundDefinition {
    pub fn new(kind: impl Into<String>, tag: impl Into<String>, options: Value) -> Self {
        Self {
            kind: kind.into(),
            tag: tag.into(),
            options,
        }
    }
}

impl OutboundCatalog for BTreeMap<String, OutboundDefinition> {
    fn resolve(&self, tag: &str) -> Option<OutboundRef<'_>> {
        self.get(tag).map(|outbound| OutboundRef {
            kind: &outbound.kind,
            tag: &outbound.tag,
            options: &outbound.options,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAdapterError {
    message: String,
}

impl OutboundAdapterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OutboundAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for OutboundAdapterError {}

/// Compile one topology outbound into a value suitable for the shoes
/// `RuleConfig.client_chains` field.
pub fn compile_client_chains<C: OutboundCatalog + ?Sized>(
    kind: &str,
    tag: &str,
    options: &Value,
    catalog: &C,
) -> Result<Value, OutboundAdapterError> {
    let mut adapter = Adapter {
        catalog,
        active_tags: Vec::new(),
    };
    let hops = adapter.compile(kind, tag, options)?;
    Ok(Value::Array(vec![json!({ "chain": hops.into_values() })]))
}

#[derive(Debug, Clone)]
struct Chain(Vec<Value>);

impl Chain {
    fn one(config: Value) -> Self {
        Self(vec![config])
    }

    fn append(&mut self, config: Value) {
        self.0.push(config);
    }

    fn into_values(self) -> Vec<Value> {
        self.0
    }
}

struct Adapter<'a, C: OutboundCatalog + ?Sized> {
    catalog: &'a C,
    active_tags: Vec<String>,
}

impl<C: OutboundCatalog + ?Sized> Adapter<'_, C> {
    fn compile(
        &mut self,
        kind: &str,
        tag: &str,
        options: &Value,
    ) -> Result<Chain, OutboundAdapterError> {
        let kind = kind.trim();
        let tag = tag.trim();
        if kind.is_empty() {
            return Err(OutboundAdapterError::new("outbound type is required"));
        }
        if tag.is_empty() {
            return Err(OutboundAdapterError::new(format!(
                "outbound {kind:?} tag is required"
            )));
        }
        if let Some(cycle_start) = self.active_tags.iter().position(|active| active == tag) {
            let mut cycle = self.active_tags[cycle_start..].to_vec();
            cycle.push(tag.to_string());
            return Err(OutboundAdapterError::new(format!(
                "outbound reference cycle: {}",
                cycle.join(" -> ")
            )));
        }

        let fields = options.as_object().ok_or_else(|| {
            OutboundAdapterError::new(format!(
                "outbound {tag:?} ({kind}) options must be a JSON object"
            ))
        })?;

        self.active_tags.push(tag.to_string());
        let result = match kind {
            "direct" => self.compile_direct(tag, fields),
            "shadowsocks" => self.compile_shadowsocks(tag, fields),
            "trojan" => self.compile_trojan(tag, fields),
            "vless" => self.compile_vless(tag, fields),
            "selector" => self.compile_selector(tag, fields),
            "urltest" => Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} uses urltest; shoes has no equivalent active health-check and latency-selection client"
            ))),
            "hysteria2" => self.compile_hysteria2(tag, fields),
            other => Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} has unsupported type {other:?}"
            ))),
        };
        self.active_tags.pop();
        result
    }

    fn compile_direct(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(tag, "direct", fields, DIALER_FIELD_NAMES)?;
        let dialer = DialerProjection::parse(tag, fields)?;
        Ok(Chain::one(client_config(
            None,
            json!({ "type": "direct" }),
            &dialer,
            self.catalog.dns_resolver(tag),
        )))
    }

    fn compile_shadowsocks(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(
            tag,
            "shadowsocks",
            fields,
            &[
                "server",
                "server_port",
                "method",
                "password",
                "network",
                "udp_over_tcp",
                "detour",
                "bind_interface",
                "inet4_bind_address",
                "inet6_bind_address",
                "routing_mark",
                "connect_timeout",
                "bind_address_no_port",
            ],
        )?;
        let address = server_address(tag, fields)?;
        let method = required_nonempty_string(tag, fields, "method")?;
        let password = required_nonempty_string(tag, fields, "password")?;
        let network = parse_network(tag, fields)?;
        if network == NetworkMode::UdpOnly {
            return Err(OutboundAdapterError::new(format!(
                "shadowsocks outbound {tag:?} is UDP-only; shoes client chains cannot disable TCP on a proxy hop"
            )));
        }
        let uot = parse_uot(tag, fields.get("udp_over_tcp"))?;
        let udp_enabled = network == NetworkMode::Both;
        let native_udp = udp_enabled && !uot;
        if native_udp && optional_nonempty_string(tag, fields, "detour")?.is_some() {
            return Err(OutboundAdapterError::new(format!(
                "shadowsocks outbound {tag:?} combines native UDP with detour; shoes native datagram proxying currently requires Shadowsocks to be the first and final hop (use UoT v2 or remove detour)"
            )));
        }
        let mut protocol = json!({
            "type": "shadowsocks",
            "cipher": method,
            "password": password,
            "udp_enabled": udp_enabled,
        });
        if native_udp {
            protocol["udp_mode"] = Value::String("native".into());
        }
        self.compile_proxy_chain(tag, fields, address, protocol)
    }

    fn compile_trojan(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(
            tag,
            "trojan",
            fields,
            &[
                "server",
                "server_port",
                "password",
                "network",
                "tls",
                "detour",
                "bind_interface",
                "inet4_bind_address",
                "inet6_bind_address",
                "routing_mark",
                "connect_timeout",
                "bind_address_no_port",
            ],
        )?;
        let network = parse_network(tag, fields)?;
        if network == NetworkMode::UdpOnly {
            return Err(OutboundAdapterError::new(format!(
                "trojan outbound {tag:?} is UDP-only; shoes client chains cannot disable TCP on a proxy hop"
            )));
        }
        let address = server_address(tag, fields)?;
        let password = required_nonempty_string(tag, fields, "password")?;
        let inner = json!({
            "type": "trojan",
            "password": password,
            "udp_enabled": network == NetworkMode::Both,
        });
        let protocol = wrap_tls(tag, fields.get("tls"), false, inner)?;
        self.compile_proxy_chain(tag, fields, address, protocol)
    }

    fn compile_vless(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(
            tag,
            "vless",
            fields,
            &[
                "server",
                "server_port",
                "uuid",
                "flow",
                "network",
                "packet_encoding",
                "tls",
                "detour",
                "bind_interface",
                "inet4_bind_address",
                "inet6_bind_address",
                "routing_mark",
                "connect_timeout",
                "bind_address_no_port",
            ],
        )?;
        let network = parse_network(tag, fields)?;
        if network == NetworkMode::UdpOnly {
            return Err(OutboundAdapterError::new(format!(
                "vless outbound {tag:?} is UDP-only; shoes client chains cannot disable TCP on a proxy hop"
            )));
        }

        let packet_encoding = optional_string(tag, fields, "packet_encoding")?;
        if let Some(value) = packet_encoding
            && !matches!(value, "" | "xudp" | "packetaddr")
        {
            return Err(OutboundAdapterError::new(format!(
                "vless outbound {tag:?} has unsupported packet_encoding {value:?}"
            )));
        }

        let flow = optional_string(tag, fields, "flow")?.unwrap_or("");
        let vision = match flow {
            "" => false,
            "xtls-rprx-vision" => true,
            other => {
                return Err(OutboundAdapterError::new(format!(
                    "vless outbound {tag:?} has unsupported flow {other:?}"
                )));
            }
        };
        let address = server_address(tag, fields)?;
        let uuid = required_nonempty_string(tag, fields, "uuid")?;
        let mut inner = json!({
            "type": "vless",
            "user_id": uuid,
            "udp_enabled": network == NetworkMode::Both,
        });
        if network == NetworkMode::Both {
            // sing-box defaults an omitted packet_encoding to XUDP.  An explicit
            // empty string selects the historical VLESS CommandUDP framing.
            match packet_encoding {
                None | Some("xudp") => {
                    inner["packet_encoding"] = Value::String("xudp".into());
                }
                Some("packetaddr") => {
                    inner["packet_encoding"] = Value::String("packetaddr".into());
                }
                Some("") => {}
                Some(_) => unreachable!("packet encoding was validated above"),
            }
        }
        let protocol = wrap_tls(tag, fields.get("tls"), vision, inner)?;
        self.compile_proxy_chain(tag, fields, address, protocol)
    }

    fn compile_hysteria2(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(
            tag,
            "hysteria2",
            fields,
            &[
                "server",
                "server_port",
                "server_ports",
                "hop_interval",
                "up_mbps",
                "down_mbps",
                "obfs",
                "password",
                "network",
                "tls",
                "brutal_debug",
                "detour",
                "bind_interface",
                "inet4_bind_address",
                "inet6_bind_address",
                "routing_mark",
                "connect_timeout",
                "bind_address_no_port",
            ],
        )?;

        if optional_nonempty_string(tag, fields, "detour")?.is_some() {
            return Err(OutboundAdapterError::new(format!(
                "hysteria2 outbound {tag:?} uses detour; shoes Hysteria2 owns its UDP/QUIC socket and must be the first client-chain hop"
            )));
        }
        reject_hysteria2_port_hopping(tag, fields)?;
        if optional_bool(tag, fields, "brutal_debug")?.unwrap_or(false) {
            return Err(OutboundAdapterError::new(format!(
                "hysteria2 outbound {tag:?} enables brutal_debug, which shoes does not expose"
            )));
        }
        if optional_nonempty_string(tag, fields, "connect_timeout")?.is_some() {
            return Err(OutboundAdapterError::new(format!(
                "hysteria2 outbound {tag:?} configures connect_timeout; shoes does not yet apply that timeout to the underlying UDP dial without changing Hysteria2's separate 15-second QUIC/authentication budget"
            )));
        }

        let network = parse_network(tag, fields)?;
        if network == NetworkMode::UdpOnly {
            return Err(OutboundAdapterError::new(format!(
                "hysteria2 outbound {tag:?} is UDP-only; shoes client chains cannot disable TCP on a proxy hop"
            )));
        }

        let address = server_address(tag, fields)?;
        let password = optional_string(tag, fields, "password")?.unwrap_or("");
        let up_mbps = optional_hysteria2_mbps(tag, fields, "up_mbps")?;
        let down_mbps = optional_hysteria2_mbps(tag, fields, "down_mbps")?;
        let obfs = compile_hysteria2_obfs(tag, fields.get("obfs"))?;
        let quic_settings = compile_hysteria2_tls(tag, fields.get("tls"))?;

        let dialer = DialerProjection::parse(tag, fields)?;
        if dialer.bind_address_no_port {
            return Err(OutboundAdapterError::new(format!(
                "hysteria2 outbound {tag:?} enables bind_address_no_port, which shoes has not implemented on the Hysteria2 UDP socket"
            )));
        }

        let mut protocol = json!({
            "type": "hysteria2",
            "password": password,
            "udp_enabled": network == NetworkMode::Both,
            "up_mbps": up_mbps,
            "down_mbps": down_mbps,
        });
        if let Some(obfs) = obfs {
            protocol["obfs"] = obfs;
        }

        let mut config = client_config(
            Some(address),
            protocol,
            &dialer,
            self.catalog.dns_resolver(tag),
        );
        config["transport"] = Value::String("quic".to_string());
        config["quic_settings"] = quic_settings;
        Ok(Chain::one(config))
    }

    fn compile_selector(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
    ) -> Result<Chain, OutboundAdapterError> {
        reject_unknown_fields(tag, "selector", fields, &["outbounds", "default"])?;
        let members = required_string_array(tag, fields, "outbounds")?;
        if members.is_empty() {
            return Err(OutboundAdapterError::new(format!(
                "selector outbound {tag:?} requires at least one member"
            )));
        }
        let mut seen = BTreeSet::new();
        for member in &members {
            if !seen.insert(member.as_str()) {
                return Err(OutboundAdapterError::new(format!(
                    "selector outbound {tag:?} contains duplicate member {member:?}"
                )));
            }
        }

        let default = optional_nonempty_string(tag, fields, "default")?;
        if let Some(default) = default
            && !seen.contains(default)
        {
            return Err(OutboundAdapterError::new(format!(
                "selector outbound {tag:?} default {default:?} is not a member"
            )));
        }

        // Validate every reference, even though only the selected member is used.
        // This keeps an inactive typo from being accepted merely because it is not
        // currently the selector default.
        for member in &members {
            let outbound = self.catalog.resolve(member).ok_or_else(|| {
                OutboundAdapterError::new(format!(
                    "selector outbound {tag:?} references unknown member {member:?}"
                ))
            })?;
            if outbound.tag != member {
                return Err(OutboundAdapterError::new(format!(
                    "outbound catalog resolved {member:?} as mismatched tag {:?}",
                    outbound.tag
                )));
            }
        }

        // sing-box's selector is static in this node-agent: there is no Clash API or
        // other selector-switching control plane. It therefore selects `default`, or
        // the first member when `default` is absent. A shoes round-robin pool would
        // change that behavior on every connection and is intentionally not used.
        let selected = default.unwrap_or(&members[0]);
        let outbound = self
            .catalog
            .resolve(selected)
            .expect("all selector members were validated above");
        let kind = outbound.kind.to_string();
        let resolved_tag = outbound.tag.to_string();
        let options = outbound.options.clone();
        self.compile(&kind, &resolved_tag, &options)
    }

    fn compile_proxy_chain(
        &mut self,
        tag: &str,
        fields: &Map<String, Value>,
        address: String,
        protocol: Value,
    ) -> Result<Chain, OutboundAdapterError> {
        let detour = optional_nonempty_string(tag, fields, "detour")?;
        let dialer = DialerProjection::parse(tag, fields)?;
        if detour.is_some() && dialer.has_effective_fields() {
            return Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} combines detour with local dialer field(s) {}; sing-box bypasses the current outbound's local dialer on detour, so applying them to shoes hop zero would change behavior",
                dialer.effective_field_names().join(", ")
            )));
        }
        let current = client_config(
            Some(address),
            protocol,
            &dialer,
            self.catalog.dns_resolver(tag),
        );
        let Some(detour) = detour else {
            return Ok(Chain::one(current));
        };

        let outbound = self.catalog.resolve(detour).ok_or_else(|| {
            OutboundAdapterError::new(format!(
                "outbound {tag:?} references unknown detour {detour:?}"
            ))
        })?;
        if outbound.tag != detour {
            return Err(OutboundAdapterError::new(format!(
                "outbound catalog resolved detour {detour:?} as mismatched tag {:?}",
                outbound.tag
            )));
        }
        let kind = outbound.kind.to_string();
        let resolved_tag = outbound.tag.to_string();
        let options = outbound.options.clone();
        let mut chain = self.compile(&kind, &resolved_tag, &options)?;
        chain.append(current);
        Ok(chain)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkMode {
    Both,
    TcpOnly,
    UdpOnly,
}

fn parse_network(
    tag: &str,
    fields: &Map<String, Value>,
) -> Result<NetworkMode, OutboundAdapterError> {
    let Some(value) = fields.get("network") else {
        return Ok(NetworkMode::Both);
    };
    if value.is_null() {
        return Ok(NetworkMode::Both);
    }
    let values = match value {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    OutboundAdapterError::new(format!(
                        "outbound {tag:?} network entries must be strings"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} field \"network\" must be a string or string array"
            )));
        }
    };
    if values.is_empty() {
        return Ok(NetworkMode::Both);
    }
    let mut tcp = false;
    let mut udp = false;
    for network in values {
        match network {
            "tcp" => tcp = true,
            "udp" => udp = true,
            other => {
                return Err(OutboundAdapterError::new(format!(
                    "outbound {tag:?} has unsupported network {other:?}"
                )));
            }
        }
    }
    Ok(match (tcp, udp) {
        (true, true) => NetworkMode::Both,
        (true, false) => NetworkMode::TcpOnly,
        (false, true) => NetworkMode::UdpOnly,
        (false, false) => NetworkMode::Both,
    })
}

fn parse_uot(tag: &str, value: Option<&Value>) -> Result<bool, OutboundAdapterError> {
    let Some(value) = value else {
        return Ok(false);
    };
    if value.is_null() {
        return Ok(false);
    }
    match value {
        Value::Bool(enabled) => Ok(*enabled),
        Value::Object(fields) => {
            reject_unknown_fields(tag, "udp_over_tcp", fields, &["enabled", "version"])?;
            let enabled = match fields.get("enabled") {
                None => false,
                Some(Value::Bool(enabled)) => *enabled,
                Some(_) => {
                    return Err(OutboundAdapterError::new(format!(
                        "outbound {tag:?} udp_over_tcp.enabled must be a boolean"
                    )));
                }
            };
            let version = match fields.get("version") {
                None => 0,
                Some(Value::Number(version)) => version.as_u64().ok_or_else(|| {
                    OutboundAdapterError::new(format!(
                        "outbound {tag:?} udp_over_tcp.version must be an unsigned integer"
                    ))
                })?,
                Some(_) => {
                    return Err(OutboundAdapterError::new(format!(
                        "outbound {tag:?} udp_over_tcp.version must be an unsigned integer"
                    )));
                }
            };
            if enabled && !matches!(version, 0 | 2) {
                return Err(OutboundAdapterError::new(format!(
                    "outbound {tag:?} requests UoT version {version}; shoes implements UoT v2 only"
                )));
            }
            Ok(enabled)
        }
        _ => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field \"udp_over_tcp\" must be a boolean or object"
        ))),
    }
}

fn wrap_tls(
    tag: &str,
    value: Option<&Value>,
    vision: bool,
    inner: Value,
) -> Result<Value, OutboundAdapterError> {
    let Some(value) = value else {
        if vision {
            return Err(OutboundAdapterError::new(format!(
                "vless outbound {tag:?} enables Vision flow without TLS"
            )));
        }
        return Ok(inner);
    };
    let fields = value.as_object().ok_or_else(|| {
        OutboundAdapterError::new(format!("outbound {tag:?} field \"tls\" must be an object"))
    })?;
    reject_unknown_fields(tag, "tls", fields, &["enabled", "server_name", "insecure"])?;
    let enabled = optional_bool(tag, fields, "enabled")?.unwrap_or(false);
    let server_name = optional_nonempty_string(tag, fields, "server_name")?;
    let insecure = optional_bool(tag, fields, "insecure")?.unwrap_or(false);
    if !enabled {
        if vision {
            return Err(OutboundAdapterError::new(format!(
                "vless outbound {tag:?} enables Vision flow while tls.enabled is false"
            )));
        }
        if server_name.is_some() || insecure {
            return Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} configures TLS fields while tls.enabled is false"
            )));
        }
        return Ok(inner);
    }

    let mut tls = Map::from_iter([
        ("type".to_string(), Value::String("tls".to_string())),
        ("verify".to_string(), Value::Bool(!insecure)),
        ("use_native_roots".to_string(), Value::Bool(true)),
        ("protocol".to_string(), inner),
    ]);
    if let Some(server_name) = server_name {
        tls.insert(
            "sni_hostname".to_string(),
            Value::String(server_name.to_string()),
        );
    }
    if vision {
        tls.insert("vision".to_string(), Value::Bool(true));
    }
    Ok(Value::Object(tls))
}

fn compile_hysteria2_tls(tag: &str, value: Option<&Value>) -> Result<Value, OutboundAdapterError> {
    let Some(Value::Object(fields)) = value else {
        return Err(OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} requires tls.enabled=true"
        )));
    };
    reject_unknown_fields(
        tag,
        "hysteria2 tls",
        fields,
        &["enabled", "server_name", "insecure"],
    )?;
    if !optional_bool(tag, fields, "enabled")?.unwrap_or(false) {
        return Err(OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} requires tls.enabled=true"
        )));
    }

    let server_name = optional_nonempty_string(tag, fields, "server_name")?;
    let insecure = optional_bool(tag, fields, "insecure")?.unwrap_or(false);
    let mut tls = Map::from_iter([
        ("verify".to_string(), Value::Bool(!insecure)),
        ("use_native_roots".to_string(), Value::Bool(true)),
    ]);
    if let Some(server_name) = server_name {
        tls.insert(
            "sni_hostname".to_string(),
            Value::String(server_name.to_string()),
        );
    }
    Ok(Value::Object(tls))
}

fn compile_hysteria2_obfs(
    tag: &str,
    value: Option<&Value>,
) -> Result<Option<Value>, OutboundAdapterError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let fields = value.as_object().ok_or_else(|| {
        OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} field \"obfs\" must be an object"
        ))
    })?;
    reject_unknown_fields(tag, "hysteria2 obfs", fields, &["type", "password"])?;
    let kind = required_nonempty_string(tag, fields, "type")?;
    if kind != "salamander" {
        return Err(OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} has unsupported obfs type {kind:?}"
        )));
    }
    let password = required_nonempty_string(tag, fields, "password")?;
    Ok(Some(json!({
        "type": "salamander",
        "password": password,
    })))
}

fn reject_hysteria2_port_hopping(
    tag: &str,
    fields: &Map<String, Value>,
) -> Result<(), OutboundAdapterError> {
    let server_ports_enabled = match fields.get("server_ports") {
        None | Some(Value::Null) => false,
        Some(Value::Array(values)) => !values.is_empty(),
        Some(_) => true,
    };
    let hop_interval_enabled = !matches!(fields.get("hop_interval"), None | Some(Value::Null));
    if server_ports_enabled || hop_interval_enabled {
        return Err(OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} uses server_ports/hop_interval port hopping, which shoes does not implement"
        )));
    }
    Ok(())
}

fn optional_hysteria2_mbps(
    tag: &str,
    fields: &Map<String, Value>,
    name: &str,
) -> Result<u64, OutboundAdapterError> {
    const MBPS_TO_BYTES_PER_SECOND: u64 = 125_000;
    const MAX_SAFE_MBPS: u64 = u64::MAX / MBPS_TO_BYTES_PER_SECOND;

    let Some(value) = fields.get(name) else {
        return Ok(0);
    };
    if value.is_null() {
        return Ok(0);
    }
    let value = value.as_i64().filter(|value| *value >= 0).ok_or_else(|| {
        OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} field {name:?} must be a non-negative integer"
        ))
    })? as u64;
    if value > MAX_SAFE_MBPS {
        return Err(OutboundAdapterError::new(format!(
            "hysteria2 outbound {tag:?} field {name:?} exceeds the largest Mbps value whose Go bytes-per-second conversion does not overflow ({MAX_SAFE_MBPS})"
        )));
    }
    Ok(value)
}

fn server_address(tag: &str, fields: &Map<String, Value>) -> Result<String, OutboundAdapterError> {
    let server = required_nonempty_string(tag, fields, "server")?;
    if server.trim() != server || server.chars().any(char::is_whitespace) {
        return Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} server contains whitespace"
        )));
    }
    let port = match fields.get("server_port") {
        Some(Value::Number(port)) => port.as_u64().filter(|port| (1..=65535).contains(port)),
        _ => None,
    }
    .ok_or_else(|| {
        OutboundAdapterError::new(format!(
            "outbound {tag:?} field \"server_port\" must be an integer from 1 to 65535"
        ))
    })?;

    match server.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => Ok(format!("[{address}]:{port}")),
        Ok(IpAddr::V4(address)) => Ok(format!("{address}:{port}")),
        Err(_) if server.contains(':') => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} server {server:?} is not a valid hostname or IP address"
        ))),
        Err(_) => Ok(format!("{server}:{port}")),
    }
}

const DIALER_FIELD_NAMES: &[&str] = &[
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "bind_address_no_port",
];

#[derive(Debug, Default)]
struct DialerProjection<'a> {
    bind_interface: Option<&'a str>,
    inet4_bind_address: Option<&'a str>,
    inet6_bind_address: Option<&'a str>,
    routing_mark: Option<u32>,
    connect_timeout: Option<&'a str>,
    bind_address_no_port: bool,
}

impl<'a> DialerProjection<'a> {
    fn parse(tag: &str, fields: &'a Map<String, Value>) -> Result<Self, OutboundAdapterError> {
        let inet4_bind_address = optional_ip_address(tag, fields, "inet4_bind_address", false)?;
        let inet6_bind_address = optional_ip_address(tag, fields, "inet6_bind_address", true)?;
        let routing_mark = optional_u32(tag, fields, "routing_mark")?.filter(|value| *value != 0);
        let connect_timeout = optional_string(tag, fields, "connect_timeout")?;
        if connect_timeout == Some("") {
            return Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} field \"connect_timeout\" must be a non-empty Go duration string"
            )));
        }

        Ok(Self {
            bind_interface: optional_nonempty_string(tag, fields, "bind_interface")?,
            inet4_bind_address,
            inet6_bind_address,
            routing_mark,
            // Keep Go duration syntax byte-for-byte. shoes performs the duration
            // validation when it deserializes the generated ClientConfig.
            connect_timeout,
            bind_address_no_port: optional_bool(tag, fields, "bind_address_no_port")?
                .unwrap_or(false),
        })
    }

    fn has_effective_fields(&self) -> bool {
        !self.effective_field_names().is_empty()
    }

    fn effective_field_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.bind_interface.is_some() {
            names.push("bind_interface");
        }
        if self.inet4_bind_address.is_some() {
            names.push("inet4_bind_address");
        }
        if self.inet6_bind_address.is_some() {
            names.push("inet6_bind_address");
        }
        if self.routing_mark.is_some() {
            names.push("routing_mark");
        }
        if self.connect_timeout.is_some() {
            names.push("connect_timeout");
        }
        if self.bind_address_no_port {
            names.push("bind_address_no_port");
        }
        names
    }
}

fn client_config(
    address: Option<String>,
    protocol: Value,
    dialer: &DialerProjection<'_>,
    dns_resolver: Option<&str>,
) -> Value {
    let mut config = Map::new();
    if let Some(address) = address {
        config.insert("address".to_string(), Value::String(address));
    }
    if let Some(bind_interface) = dialer.bind_interface {
        config.insert(
            "bind_interface".to_string(),
            Value::String(bind_interface.to_string()),
        );
    }
    if let Some(inet4_bind_address) = dialer.inet4_bind_address {
        config.insert(
            "inet4_bind_address".to_string(),
            Value::String(inet4_bind_address.to_string()),
        );
    }
    if let Some(inet6_bind_address) = dialer.inet6_bind_address {
        config.insert(
            "inet6_bind_address".to_string(),
            Value::String(inet6_bind_address.to_string()),
        );
    }
    if let Some(routing_mark) = dialer.routing_mark {
        config.insert("routing_mark".to_string(), json!(routing_mark));
    }
    if let Some(connect_timeout) = dialer.connect_timeout {
        config.insert(
            "connect_timeout".to_string(),
            Value::String(connect_timeout.to_string()),
        );
    }
    if dialer.bind_address_no_port {
        config.insert("bind_address_no_port".to_string(), Value::Bool(true));
    }
    if let Some(dns_resolver) = dns_resolver {
        config.insert(
            "dns_resolver".to_string(),
            Value::String(dns_resolver.to_string()),
        );
    }
    config.insert("protocol".to_string(), protocol);
    Value::Object(config)
}

fn optional_ip_address<'a>(
    tag: &str,
    fields: &'a Map<String, Value>,
    name: &str,
    require_ipv6: bool,
) -> Result<Option<&'a str>, OutboundAdapterError> {
    let Some(value) = optional_nonempty_string(tag, fields, name)? else {
        return Ok(None);
    };
    let address = value.parse::<IpAddr>().map_err(|_| {
        OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be a valid {} address",
            if require_ipv6 { "IPv6" } else { "IPv4" }
        ))
    })?;
    if address.is_ipv6() != require_ipv6 {
        return Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be an {} address",
            if require_ipv6 { "IPv6" } else { "IPv4" }
        )));
    }
    Ok(Some(value))
}

fn optional_u32(
    tag: &str,
    fields: &Map<String, Value>,
    name: &str,
) -> Result<Option<u32>, OutboundAdapterError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                OutboundAdapterError::new(format!(
                    "outbound {tag:?} field {name:?} must be an unsigned 32-bit integer"
                ))
            }),
        Some(_) => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be an unsigned 32-bit integer"
        ))),
    }
}

fn reject_unknown_fields(
    tag: &str,
    kind: &str,
    fields: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), OutboundAdapterError> {
    if let Some(field) = fields
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} {kind} field {field:?} is not expressible by shoes"
        )));
    }
    Ok(())
}

fn required_nonempty_string<'a>(
    tag: &str,
    fields: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, OutboundAdapterError> {
    match fields.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value),
        _ => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be a non-empty string"
        ))),
    }
}

fn optional_string<'a>(
    tag: &str,
    fields: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, OutboundAdapterError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be a string"
        ))),
    }
}

fn optional_nonempty_string<'a>(
    tag: &str,
    fields: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, OutboundAdapterError> {
    Ok(optional_string(tag, fields, name)?.filter(|value| !value.is_empty()))
}

fn optional_bool(
    tag: &str,
    fields: &Map<String, Value>,
    name: &str,
) -> Result<Option<bool>, OutboundAdapterError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be a boolean"
        ))),
    }
}

fn required_string_array(
    tag: &str,
    fields: &Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, OutboundAdapterError> {
    let Some(Value::Array(values)) = fields.get(name) else {
        return Err(OutboundAdapterError::new(format!(
            "outbound {tag:?} field {name:?} must be a string array"
        )));
    };
    values
        .iter()
        .map(|value| match value {
            Value::String(value) if !value.is_empty() => Ok(value.clone()),
            _ => Err(OutboundAdapterError::new(format!(
                "outbound {tag:?} field {name:?} must contain non-empty strings"
            ))),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(entries: Vec<OutboundDefinition>) -> BTreeMap<String, OutboundDefinition> {
        entries
            .into_iter()
            .map(|entry| (entry.tag.clone(), entry))
            .collect()
    }

    fn assert_shoes_rule_accepts(client_chains: Value) {
        let rule = json!({
            "masks": "0.0.0.0/0",
            "action": "allow",
            "client_chains": client_chains,
        });
        serde_json::from_value::<shoes::config::RuleConfig>(rule)
            .expect("adapter output must deserialize as a shoes rule");
    }

    #[test]
    fn empty_direct_is_a_real_direct_chain() {
        let chains =
            compile_client_chains("direct", "direct", &json!({}), &catalog(vec![])).unwrap();
        assert_eq!(
            chains,
            json!([{ "chain": [{ "protocol": { "type": "direct" } }] }])
        );
        assert_shoes_rule_accepts(chains);
    }

    #[test]
    fn direct_projects_single_stack_and_linux_dialer_fields() {
        let chains = compile_client_chains(
            "direct",
            "bound-direct",
            &json!({
                "inet4_bind_address": "203.0.113.10",
                "routing_mark": 100,
                "connect_timeout": "1m2.5s",
                "bind_address_no_port": true,
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(
            chains,
            json!([{
                "chain": [{
                    "inet4_bind_address": "203.0.113.10",
                    "routing_mark": 100,
                    "connect_timeout": "1m2.5s",
                    "bind_address_no_port": true,
                    "protocol": { "type": "direct" },
                }]
            }])
        );
        assert_shoes_rule_accepts(chains);
    }

    #[test]
    fn proxy_projects_all_supported_local_dialer_fields() {
        let chains = compile_client_chains(
            "vless",
            "edge",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "uuid": "11111111-1111-4111-8111-111111111111",
                "network": "tcp",
                "bind_interface": "eth0",
                "inet6_bind_address": "2001:db8::10",
                "routing_mark": 7,
                "connect_timeout": "8s",
                "bind_address_no_port": true,
            }),
            &catalog(vec![]),
        )
        .unwrap();
        let hop = &chains[0]["chain"][0];
        assert_eq!(hop["bind_interface"], "eth0");
        assert_eq!(hop["inet6_bind_address"], "2001:db8::10");
        assert_eq!(hop["routing_mark"], 7);
        assert_eq!(hop["connect_timeout"], "8s");
        assert_eq!(hop["bind_address_no_port"], true);
        assert_shoes_rule_accepts(chains);
    }

    #[test]
    fn shadowsocks_tcp_native_udp_and_uot_v2_are_explicit() {
        let tcp = compile_client_chains(
            "shadowsocks",
            "ss-tcp",
            &json!({
                "server": "2001:db8::1",
                "server_port": 8388,
                "method": "aes-256-gcm",
                "password": "secret",
                "network": "tcp",
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(tcp[0]["chain"][0]["address"], "[2001:db8::1]:8388");
        assert_eq!(tcp[0]["chain"][0]["protocol"]["udp_enabled"], false);
        assert_shoes_rule_accepts(tcp);

        let native = compile_client_chains(
            "shadowsocks",
            "ss-native",
            &json!({
                "server": "ss.example.com",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(native[0]["chain"][0]["protocol"]["udp_enabled"], true);
        assert_eq!(native[0]["chain"][0]["protocol"]["udp_mode"], "native");
        assert_shoes_rule_accepts(native);

        let uot = compile_client_chains(
            "shadowsocks",
            "ss-uot",
            &json!({
                "server": "ss.example.com",
                "server_port": 8388,
                "method": "chacha20-ietf-poly1305",
                "password": "secret",
                "udp_over_tcp": { "enabled": true, "version": 2 },
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(uot[0]["chain"][0]["protocol"]["udp_enabled"], true);
        assert!(uot[0]["chain"][0]["protocol"].get("udp_mode").is_none());
        assert_shoes_rule_accepts(uot);
    }

    #[test]
    fn shadowsocks_native_udp_rejects_detour_before_apply() {
        let catalog = catalog(vec![OutboundDefinition::new("direct", "wan", json!({}))]);
        let error = compile_client_chains(
            "shadowsocks",
            "ss-native",
            &json!({
                "server": "ss.example.com",
                "server_port": 8388,
                "method": "aes-256-gcm",
                "password": "secret",
                "detour": "wan",
            }),
            &catalog,
        )
        .unwrap_err();
        assert!(error.to_string().contains("native UDP with detour"));
    }

    #[test]
    fn trojan_tls_and_vless_vision_use_shoes_nested_protocols() {
        let trojan = compile_client_chains(
            "trojan",
            "trojan-tls",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "password": "secret",
                "network": "tcp",
                "tls": { "enabled": true, "server_name": "sni.example.com", "insecure": true },
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(trojan[0]["chain"][0]["protocol"]["type"], "tls");
        assert_eq!(trojan[0]["chain"][0]["protocol"]["verify"], false);
        assert_eq!(trojan[0]["chain"][0]["protocol"]["use_native_roots"], true);
        assert_eq!(
            trojan[0]["chain"][0]["protocol"]["protocol"]["type"],
            "trojan"
        );
        assert_eq!(
            trojan[0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
            false
        );
        assert_shoes_rule_accepts(trojan);

        let trojan_udp = compile_client_chains(
            "trojan",
            "trojan-udp",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "password": "secret",
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(trojan_udp[0]["chain"][0]["protocol"]["udp_enabled"], true);
        assert_shoes_rule_accepts(trojan_udp);

        let vision = compile_client_chains(
            "vless",
            "vision",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "uuid": "11111111-1111-4111-8111-111111111111",
                "flow": "xtls-rprx-vision",
                "network": "tcp",
                "tls": { "enabled": true, "server_name": "edge.example.com" },
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(vision[0]["chain"][0]["protocol"]["vision"], true);
        assert_shoes_rule_accepts(vision);
    }

    #[test]
    fn vless_panel_udp_encodings_are_projected_explicitly() {
        for (requested, expected) in [
            (None, Some("xudp")),
            (Some("xudp"), Some("xudp")),
            (Some("packetaddr"), Some("packetaddr")),
            (Some(""), None),
        ] {
            let mut options = json!({
                "server": "edge.example.com",
                "server_port": 443,
                "uuid": "11111111-1111-4111-8111-111111111111",
            });
            if let Some(requested) = requested {
                options["packet_encoding"] = Value::String(requested.into());
            }
            let chains =
                compile_client_chains("vless", "edge", &options, &catalog(vec![])).unwrap();
            let protocol = &chains[0]["chain"][0]["protocol"];
            assert_eq!(protocol["udp_enabled"], true);
            match expected {
                Some(expected) => assert_eq!(protocol["packet_encoding"], expected),
                None => assert!(protocol.get("packet_encoding").is_none()),
            }
            assert_shoes_rule_accepts(chains);
        }
    }

    #[test]
    fn hysteria2_projects_native_quic_tls_obfs_and_bandwidth() {
        let chains = compile_client_chains(
            "hysteria2",
            "hy2-edge",
            &json!({
                "server": "2001:db8::20",
                "server_port": 443,
                "up_mbps": 100,
                "down_mbps": 200,
                "obfs": { "type": "salamander", "password": "obfs-secret" },
                "tls": {
                    "enabled": true,
                    "server_name": "edge.example.com",
                    "insecure": true
                },
                "bind_interface": "eth0",
                "server_ports": []
            }),
            &catalog(vec![]),
        )
        .unwrap();

        let hop = &chains[0]["chain"][0];
        assert_eq!(hop["address"], "[2001:db8::20]:443");
        assert_eq!(hop["transport"], "quic");
        assert_eq!(hop["bind_interface"], "eth0");
        assert_eq!(hop["quic_settings"]["verify"], false);
        assert_eq!(hop["quic_settings"]["use_native_roots"], true);
        assert_eq!(hop["quic_settings"]["sni_hostname"], "edge.example.com");
        assert_eq!(hop["protocol"]["type"], "hysteria2");
        assert_eq!(hop["protocol"]["password"], "");
        assert_eq!(hop["protocol"]["udp_enabled"], true);
        assert_eq!(hop["protocol"]["up_mbps"], 100);
        assert_eq!(hop["protocol"]["down_mbps"], 200);
        assert_eq!(hop["protocol"]["obfs"]["type"], "salamander");
        assert_eq!(hop["protocol"]["obfs"]["password"], "obfs-secret");
        assert_shoes_rule_accepts(chains);

        let tcp_only = compile_client_chains(
            "hysteria2",
            "hy2-tcp",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "password": "secret",
                "network": "tcp",
                "tls": { "enabled": true }
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(tcp_only[0]["chain"][0]["protocol"]["udp_enabled"], false);
        assert_shoes_rule_accepts(tcp_only);

        let null_network = compile_client_chains(
            "hysteria2",
            "hy2-null-network",
            &json!({
                "server": "edge.example.com",
                "server_port": 443,
                "network": null,
                "tls": { "enabled": true }
            }),
            &catalog(vec![]),
        )
        .unwrap();
        assert_eq!(null_network[0]["chain"][0]["protocol"]["udp_enabled"], true);
    }

    #[test]
    fn hysteria2_rejects_unimplemented_or_lossy_options_before_apply() {
        let base = json!({
            "server": "edge.example.com",
            "server_port": 443,
            "password": "secret",
            "tls": { "enabled": true }
        });
        for (field, value, expected) in [
            ("server_ports", json!(["443:445"]), "port hopping"),
            ("hop_interval", json!("30s"), "port hopping"),
            ("detour", json!("direct"), "must be the first"),
            ("network", json!("udp"), "UDP-only"),
            ("bind_address_no_port", json!(true), "Hysteria2 UDP socket"),
            ("connect_timeout", json!("8s"), "underlying UDP dial"),
            ("brutal_debug", json!(true), "brutal_debug"),
            ("up_mbps", json!(-1), "non-negative integer"),
            ("network", json!(""), "unsupported network"),
        ] {
            let mut options = base.clone();
            options[field] = value;
            let error = compile_client_chains("hysteria2", "hy2-edge", &options, &catalog(vec![]))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{field}: {error}");
        }

        for (options, expected) in [
            (
                json!({
                    "server": "edge.example.com", "server_port": 443,
                    "password": "secret"
                }),
                "requires tls.enabled=true",
            ),
            (
                json!({
                    "server": "edge.example.com", "server_port": 443,
                    "password": "secret", "tls": { "enabled": false }
                }),
                "requires tls.enabled=true",
            ),
            (
                json!({
                    "server": "edge.example.com", "server_port": 443,
                    "password": "secret", "tls": { "enabled": true },
                    "obfs": { "type": "salamander", "password": "" }
                }),
                "non-empty string",
            ),
            (
                json!({
                    "server": "edge.example.com", "server_port": 443,
                    "password": "secret", "tls": { "enabled": true },
                    "obfs": { "type": "unknown", "password": "secret" }
                }),
                "unsupported obfs type",
            ),
        ] {
            let error = compile_client_chains("hysteria2", "hy2-edge", &options, &catalog(vec![]))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn selector_resolves_to_static_default_instead_of_round_robin_pool() {
        let members = catalog(vec![
            OutboundDefinition::new("direct", "direct", json!({})),
            OutboundDefinition::new(
                "vless",
                "edge",
                json!({
                    "server": "edge.example.com",
                    "server_port": 443,
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "network": "tcp",
                }),
            ),
        ]);
        let chains = compile_client_chains(
            "selector",
            "manual",
            &json!({ "outbounds": ["direct", "edge"], "default": "edge" }),
            &members,
        )
        .unwrap();
        assert_eq!(chains[0]["chain"][0]["address"], "edge.example.com:443");
        assert_eq!(chains[0]["chain"].as_array().unwrap().len(), 1);
        assert_shoes_rule_accepts(chains);

        let first = compile_client_chains(
            "selector",
            "manual",
            &json!({ "outbounds": ["direct", "edge"] }),
            &members,
        )
        .unwrap();
        assert_eq!(first[0]["chain"][0]["protocol"]["type"], "direct");
    }

    #[test]
    fn detour_builds_ordered_chain_and_cycles_are_rejected() {
        let entries = catalog(vec![
            OutboundDefinition::new(
                "shadowsocks",
                "entry",
                json!({
                    "server": "entry.example.com",
                    "server_port": 8388,
                    "method": "aes-128-gcm",
                    "password": "secret",
                    "network": "tcp",
                }),
            ),
            OutboundDefinition::new(
                "vless",
                "exit",
                json!({
                    "server": "exit.example.com",
                    "server_port": 443,
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "network": "tcp",
                    "detour": "entry",
                }),
            ),
        ]);
        let exit = entries.get("exit").unwrap();
        let chains = compile_client_chains(&exit.kind, &exit.tag, &exit.options, &entries).unwrap();
        assert_eq!(chains[0]["chain"][0]["address"], "entry.example.com:8388");
        assert_eq!(chains[0]["chain"][1]["address"], "exit.example.com:443");
        assert_shoes_rule_accepts(chains);

        let cyclic = catalog(vec![
            OutboundDefinition::new(
                "vless",
                "a",
                json!({
                    "server": "a.example.com", "server_port": 443,
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "network": "tcp", "detour": "b",
                }),
            ),
            OutboundDefinition::new(
                "vless",
                "b",
                json!({
                    "server": "b.example.com", "server_port": 443,
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "network": "tcp", "detour": "a",
                }),
            ),
        ]);
        let a = cyclic.get("a").unwrap();
        let error = compile_client_chains(&a.kind, &a.tag, &a.options, &cyclic).unwrap_err();
        assert!(error.to_string().contains("a -> b -> a"), "{error}");
    }

    #[test]
    fn detour_rejects_current_outbound_local_dialer_fields() {
        for (field, value) in [
            ("bind_interface", json!("eth0")),
            ("inet4_bind_address", json!("203.0.113.10")),
            ("inet6_bind_address", json!("2001:db8::10")),
            ("routing_mark", json!(100)),
            ("connect_timeout", json!("8s")),
            ("bind_address_no_port", json!(true)),
        ] {
            let mut options = json!({
                "server": "exit.example.com",
                "server_port": 443,
                "uuid": "11111111-1111-4111-8111-111111111111",
                "network": "tcp",
                "detour": "entry",
            });
            options[field] = value;
            let error =
                compile_client_chains("vless", "exit", &options, &catalog(vec![])).unwrap_err();
            assert!(error.to_string().contains("combines detour"), "{error}");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn unsupported_or_lossy_features_fail_loudly() {
        let error = compile_client_chains(
            "urltest",
            "test",
            &json!({ "outbounds": ["direct"] }),
            &catalog(vec![]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("health-check"), "{error}");

        let error = compile_client_chains(
            "trojan",
            "test",
            &json!({
                "server": "example.com", "server_port": 443,
                "password": "secret", "network": "tcp",
                "multiplex": { "enabled": true },
            }),
            &catalog(vec![]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("multiplex"), "{error}");

        let error = compile_client_chains(
            "direct",
            "test",
            &json!({ "reuse_addr": true }),
            &catalog(vec![]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("reuse_addr"), "{error}");

        for (options, expected) in [
            (
                json!({ "inet4_bind_address": "2001:db8::10" }),
                "must be an IPv4 address",
            ),
            (
                json!({ "inet6_bind_address": "203.0.113.10" }),
                "must be an IPv6 address",
            ),
            (
                json!({ "routing_mark": 4_294_967_296_u64 }),
                "unsigned 32-bit integer",
            ),
            (json!({ "connect_timeout": 8 }), "must be a string"),
            (
                json!({ "connect_timeout": "" }),
                "non-empty Go duration string",
            ),
            (
                json!({ "bind_address_no_port": "true" }),
                "must be a boolean",
            ),
        ] {
            let error =
                compile_client_chains("direct", "test", &options, &catalog(vec![])).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}
