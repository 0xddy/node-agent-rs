//! Wire types for the shoes dynamic engine management API.
//!
//! This crate is deliberately dependency-light: it knows nothing about `shoes`
//! itself, so it can be shared with external control planes and clients.
//!
//! The inbound payload is carried as an opaque [`serde_json::Value`] rather than
//! a mirrored config struct. `shoes` already has a complete, well-tested set of
//! `serde` config types (`shoes::config`), and duplicating them here would mean
//! re-doing that work on every upstream merge. Because YAML 1.2 is a superset of
//! JSON, the engine can feed the JSON payload straight into the same
//! `serde_yaml` deserializers the YAML config files use.

use serde::{Deserialize, Serialize};

/// Request body for `POST /inbounds`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSpec {
    /// Caller-assigned identity, unique within the engine. Used as the handle
    /// for `DELETE /inbounds/{tag}`.
    pub tag: String,
    /// A native shoes server config object, i.e. one element of the top-level
    /// YAML config list, expressed as JSON.
    pub config: serde_json::Value,
}

/// A registered inbound as reported by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundInfo {
    pub tag: String,
    /// Protocol discriminant, e.g. `"vless"`, `"trojan"`, `"hysteria2"`.
    pub protocol: String,
    /// Transport discriminant, e.g. `"tcp"`, `"quic"`.
    pub transport: String,
    /// Resolved bind addresses actually being listened on.
    pub bind: Vec<String>,
    /// Number of live listener tasks backing this inbound.
    pub listeners: usize,
}

/// Response body for `GET /status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub version: String,
    pub inbounds: usize,
    /// Bind addresses currently claimed by the engine.
    pub bound_addresses: Vec<String>,
}

/// Error envelope returned with every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}
