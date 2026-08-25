//! The two provider payloads accepted by the panel and Go agent.

use serde::{Deserialize, Serialize};

pub const VLESS_REALITY_VISION_ID: &str = "vless-reality-vision@1";
pub const HYSTERIA2_SALAMANDER_ID: &str = "hysteria2-salamander@1";
pub const CURRENT_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VlessRealityVisionConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    pub flow: String,
    pub tcp_fast_open: bool,
    pub sniff: bool,
    pub tls: VlessRealityVisionTlsConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<OutboundConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VlessRealityVisionTlsConfig {
    pub enabled: bool,
    pub server_name: String,
    pub reality: VlessRealityConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VlessRealityConfig {
    pub enabled: bool,
    pub handshake: RealityHandshake,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    pub short_id: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RealityHandshake {
    pub server: String,
    pub server_port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hysteria2SalamanderConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub port_hopping: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub up_mbps: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub down_mbps: i64,
    pub obfs: Hysteria2ObfsConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masquerade: Option<Hysteria2MasqueradeConfig>,
    pub tls: Hysteria2TlsConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<OutboundConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hysteria2ObfsConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hysteria2MasqueradeConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub rewrite_host: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hysteria2TlsConfig {
    pub enabled: bool,
    pub server_name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate_pem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key_pem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate_sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate_public_key_sha256: String,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}
