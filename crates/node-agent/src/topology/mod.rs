//! ACP topology model.
//!
//! The field names and defaults deliberately mirror the Go agent's
//! `internal/topology/types.go`.  Provider payloads and outbound options stay as
//! raw JSON bytes: this preserves the wire value until the compiler can report a
//! useful, node-scoped validation error.

pub mod manager;
mod proto;
pub mod provider;

use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use proto::{
    apply_node_mutation_to_snapshot, apply_route_patch_to_snapshot,
    apply_user_mutation_to_snapshot, clone_snapshot, digest, from_machine_config, from_snapshot,
    replace_node_users, to_snapshot,
};

pub const VLESS_FLOW_REALITY_VISION: &str = "xtls-rprx-vision";
pub const DEFAULT_INBOUND_LISTEN: &str = "::";
pub const OUTBOUND_TYPE_DIRECT: &str = "direct";
pub const DEFAULT_DIRECT_OUTBOUND: &str = "direct";

/// A JSON value whose original bytes are retained across protobuf conversion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawJson(Arc<[u8]>);

impl RawJson {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Arc::from(bytes.into()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn parse<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.0)
    }

    pub fn value(&self) -> serde_json::Result<serde_json::Value> {
        self.parse()
    }
}

impl From<serde_json::Value> for RawJson {
    fn from(value: serde_json::Value) -> Self {
        Self(Arc::from(
            serde_json::to_vec(&value).expect("serializing a JSON value cannot fail"),
        ))
    }
}

impl Serialize for RawJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value: serde_json::Value =
            serde_json::from_slice(&self.0).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RawJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        serde_json::to_vec(&value)
            .map(Arc::from)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MachineTopology {
    pub machine_id: String,
    pub revision: u64,
    #[serde(default)]
    pub nodes: Vec<NodeInstance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    #[serde(skip, default)]
    pub snapshot: Option<acp_proto::TopologySnapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeInstance {
    pub node_id: String,
    pub provider_id: String,
    pub provider_config_version: u32,
    pub provider_config: RawJson,
    #[serde(default)]
    pub users: Vec<UserCredential>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserCredential {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub upload_speed_limit_bps: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub download_speed_limit_bps: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "RawJson::is_empty")]
    pub options: RawJson,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DialerOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detour: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bind_interface: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inet4_bind_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inet6_bind_address: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub routing_mark: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_addr: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub connect_timeout: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_fast_open: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_multi_path: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_fragment: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub udp_timeout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain_strategy: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub bind_address_no_port: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protect_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub netns: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_tcp_keep_alive: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tcp_keep_alive: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tcp_keep_alive_interval: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolveOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fallback_delay: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainResolveOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub strategy: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_subnet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkStrategy {
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "type")]
    pub kind: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_type: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fallback_delay: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<RouteRuleSet>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[serde(rename = "final")]
    pub final_: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_detect_interface: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_interface: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_mark: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub find_process: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoIpOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite: Option<GeositeOptions>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub override_android_vpn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolveOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_strategy: Option<NetworkStrategy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_fallback_network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_fallback_delay: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dns {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[serde(rename = "final")]
    pub final_: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServer {
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detour: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rcode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rewrite_ttl: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timeout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_subnet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoIpOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeositeOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteRule {
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub ip_version: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip_is_private: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_is_private: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub outbound: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_geoip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geoip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_path_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_id: Vec<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub clash_mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_is_expensive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_is_constrained: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_interface_address: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferred_by: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ip_cidr_match_source: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_options: Option<RouteActionOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_options: Option<DialerOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniff_options: Option<SniffActionOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_options: Option<ResolveActionOptions>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteRuleSet {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub format: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_detour: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub update_interval: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteActionOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub override_address: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub override_port: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fallback_delay: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_disable_domain_unmapping: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_connect: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub udp_timeout: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_fragment: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls_fragment_fallback_delay: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_record_fragment: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SniffActionOptions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sniffer: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timeout: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolveActionOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub strategy: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_subnet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HeadlessRule {
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_path_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_is_expensive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_is_constrained: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_interface_address: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod memory_tests {
    use super::*;

    #[test]
    fn cloning_raw_json_shares_its_payload() {
        let original = RawJson::new(vec![b'x'; 128 * 1024]);
        let cloned = original.clone();
        assert!(Arc::ptr_eq(&original.0, &cloned.0));
    }
}
