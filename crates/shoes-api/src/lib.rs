//! Argument and report types for the shoes dynamic engine.
//!
//! These are the values [`shoes_engine::Engine`]'s methods take and return. They
//! describe *what* a control plane asks for, and nothing about how it was asked:
//! there is no transport, no status code and no error envelope here, because the
//! transport is not this repository's business. A gRPC, HTTP or FFI layer converts
//! its own request types into these at its boundary.
//!
//! The crate is deliberately dependency-light -- it knows nothing about `shoes`
//! itself -- so that conversion code can depend on the types without pulling in
//! the proxy engine.
//!
//! The inbound payload is carried as an opaque [`serde_json::Value`] rather than
//! a mirrored config struct. `shoes` already has a complete, well-tested set of
//! `serde` config types (`shoes::config`), and duplicating them here would mean
//! re-doing that work on every upstream merge. Because YAML 1.2 is a superset of
//! JSON, the engine can feed the JSON payload straight into the same
//! `serde_yaml` deserializers the YAML config files use.
//!
//! [`shoes_engine::Engine`]: https://docs.rs/shoes-engine

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// A user to authenticate against an inbound.
///
/// Which credential field applies is decided by the inbound's protocol, not by
/// this type: a VLESS inbound reads `uuid`, a Trojan inbound reads `password`. A
/// spec that carries neither, or carries the wrong one for the protocol, is
/// rejected rather than silently accepted, because a credential that is quietly
/// dropped reads to the caller as a user who was added.
///
/// `deny_unknown_fields` is deliberate for the same reason. This payload carries
/// secrets, and a typo in a field name must be an error, not a user with no
/// credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    /// Stable identity for reporting, and the handle for
    /// [`Engine::remove_user`](https://docs.rs/shoes-engine). Defaults to `uuid`
    /// when one is given, since that is already how operators refer to a VLESS or
    /// VMess user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Canonical uuid, with or without dashes. Used by VLESS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Cleartext password. Used by Trojan, which hashes it before it goes on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// A disabled user keeps their counters and their established connections but
    /// cannot authenticate again.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl UserSpec {
    /// The identity this user will be reported under.
    pub fn resolved_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.uuid.as_deref())
    }
}

/// A registered user as reported by the engine.
///
/// Credentials are never echoed back. The engine holds them only as index keys,
/// and re-serving them would turn a status report into a credential dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub enabled: bool,
    /// Bytes sent to this user, as they went on the wire.
    pub tx: u64,
    /// Bytes received from this user, as they came off the wire.
    pub rx: u64,
    /// Connections currently open.
    pub conns: u64,
    /// Successful authentications since the user was added.
    pub total_conns: u64,
}

/// Argument to [`Engine::add_inbound`] and [`Engine::update_inbound`].
///
/// [`Engine::add_inbound`]: https://docs.rs/shoes-engine
/// [`Engine::update_inbound`]: https://docs.rs/shoes-engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSpec {
    /// Caller-assigned identity, unique within the engine. Every later operation
    /// on this inbound names it by this tag.
    ///
    /// Required by `add_inbound`. `update_inbound` also reads it, so a caller that
    /// already knows the tag from elsewhere -- a URL path, a gRPC field -- must
    /// still put it here rather than leaving the engine to guess.
    #[serde(default)]
    pub tag: String,
    /// A native shoes server config object, i.e. one element of the top-level
    /// YAML config list, expressed as JSON.
    pub config: serde_json::Value,
    /// Users to authenticate with, opting this inbound into dynamic mode.
    ///
    /// Absent means the classic file-config behaviour: the credential written in
    /// `config` is the authority, and the engine does not manage users for this
    /// inbound.
    ///
    /// Present -- **including an empty list** -- hands authority to the engine's
    /// in-memory registry instead. Any credential in `config` is then rejected as
    /// misleading rather than ignored, and an empty registry means nobody can
    /// connect until users are added with [`Engine::add_user`]. An empty list is
    /// the normal way to bring an inbound up first and populate it after.
    ///
    /// The distinction is why this is an `Option` and not a plain `Vec`: a `Vec`
    /// cannot tell "no users section" from "deliberately no users yet", and those
    /// two mean opposite things for who may connect.
    ///
    /// [`Engine::add_user`]: https://docs.rs/shoes-engine
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserSpec>>,
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
    /// How many times this inbound's rules and protocol settings have been
    /// swapped since it started, i.e. how many [`Engine::update_inbound`] calls
    /// have been applied. `0` for a freshly added inbound.
    ///
    /// Reported so a caller can tell an applied reload from a rejected one without
    /// inspecting traffic, and can spot one it did not make.
    ///
    /// [`Engine::update_inbound`]: https://docs.rs/shoes-engine
    #[serde(default)]
    pub revision: u64,
    /// Users registered against this inbound. `None` when the protocol does not
    /// authenticate through the engine's user registry, which is not the same as
    /// zero users: zero means nobody can connect, `None` means the question does
    /// not apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<usize>,
}

/// Engine-wide summary, as reported by [`Engine::status`].
///
/// [`Engine::status`]: https://docs.rs/shoes-engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub version: String,
    pub inbounds: usize,
    /// Bind addresses currently claimed by the engine.
    pub bound_addresses: Vec<String>,
}
