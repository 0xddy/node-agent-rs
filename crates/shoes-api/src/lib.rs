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

const fn default_true() -> bool {
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
    /// `VMess` user.
    ///
    /// Normally a label and nothing more. **`NaiveProxy` is the exception**: its
    /// credential is HTTP Basic, i.e. base64 of `username:password`, and this field
    /// is the username half -- so on such an inbound the id is part of the
    /// credential, and renaming a user rotates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Canonical uuid, with or without dashes.
    ///
    /// Read by **VLESS**, **`VMess`** and **TUIC**. TUIC needs `password` alongside
    /// it: the uuid crosses the wire in cleartext and names the user, the password
    /// keys the token beside it, and a user carrying only one of the two is refused
    /// when added rather than left unable to connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// The user's secret, in the form an operator writes it. Which form that is
    /// depends on the inbound's protocol, not on this type:
    ///
    /// - **Trojan** hashes it (SHA-224, hex) before it goes on the wire;
    /// - **Hysteria2** compares it as cleartext;
    /// - **`AnyTLS`** sends raw SHA-256 of it;
    /// - **`NaiveProxy`** sends it base64'd beside the user's id;
    /// - **TUIC** keys its authentication token with it;
    /// - **Shadowsocks 2022** reads it as a *base64 PSK*, not as a password, and
    ///   rejects one whose decoded length the inbound's cipher cannot use.
    ///
    /// One inbound can serve several of these at once -- Trojan and Hysteria2 on two
    /// SNIs share this one cleartext value, indexed twice. What it cannot do is mean
    /// two *different* things at once, such as a cleartext password on one target and
    /// a base64 PSK on another; that combination is refused when the inbound is added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// A disabled user keeps their counters and their established connections but
    /// cannot authenticate again.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Most connections this user may have open at once. `0`, and the absent
    /// default, mean no ceiling.
    ///
    /// This is the only bound on what one valid credential can cost the host.
    /// Every protocol's per-connection state is a multiplier on it -- a hysteria2 or
    /// TUIC connection may hold hundreds of UDP sessions, a `NaiveProxy` one hundreds
    /// of multiplexed tunnels -- so on a shared inbound this is what stops one user
    /// exhausting sockets or memory for all the others. An inbound serving users who
    /// do not need many parallel connections is worth capping.
    ///
    /// Lowering it, or setting it on a user who is already over it, does not
    /// disconnect anybody: it governs new connections, and the live count drains to
    /// the new ceiling as existing ones end. Removing the user is what disconnects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns: Option<u64>,
    /// Ceiling on how fast this user may *send*, in bits per second. `None` and
    /// `0` both mean unlimited.
    ///
    /// Directions are named from the client's point of view, the way a control
    /// plane states them: `upload` is the client sending to the proxy. Getting
    /// the pair the wrong way round is a quiet failure -- traffic still flows,
    /// just capped in the direction nobody complained about -- so the two fields
    /// say whose upload and whose download they mean.
    ///
    /// The bucket belongs to the user, not to a connection, so opening a second
    /// connection does not buy a second allowance. Like `max_conns`, changing
    /// this governs what happens next and disconnects nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_limit_bps: Option<u64>,
    /// Ceiling on how fast this user may *receive*, in bits per second. `None`
    /// and `0` both mean unlimited. See [`upload_limit_bps`](Self::upload_limit_bps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_limit_bps: Option<u64>,
}

impl UserSpec {
    /// The identity this user will be reported under.
    #[must_use]
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
    /// Unix milliseconds of the most recent non-zero byte observation.
    ///
    /// This belongs to the byte counters rather than to a later control-plane
    /// snapshot.  Consumers that periodically take the counters can therefore
    /// retain the minute in which the traffic actually flowed. `0` means that
    /// this accounting generation has not observed any bytes yet.
    #[serde(default)]
    pub last_traffic_observed_at_unix_millis: u64,
    /// Connections currently open.
    pub conns: u64,
    /// Successful authentications since the user was added. A connection refused
    /// for exceeding `max_conns` is not counted here: the credential was good but
    /// no connection came of it.
    pub total_conns: u64,
    /// The ceiling `conns` is admitted against, or `0` for no ceiling.
    #[serde(default)]
    pub max_conns: u64,
    /// Client-upload ceiling in bits per second, or `0` for none.
    #[serde(default)]
    pub upload_limit_bps: u64,
    /// Client-download ceiling in bits per second, or `0` for none.
    #[serde(default)]
    pub download_limit_bps: u64,
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
    /// Everything the engine currently holds exclusively, one entry per claim.
    ///
    /// A claim names the *socket*, not just the address -- `"127.0.0.1:443 (tcp)"` --
    /// because `:443` over TCP and `:443` over QUIC are two different sockets and
    /// holding both at once is ordinary. A unix socket appears as its path.
    pub bound_addresses: Vec<String>,
}
