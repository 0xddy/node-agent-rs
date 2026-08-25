//! Shared harness for the engine's end-to-end tests.
//!
//! Every test here drives [`shoes_engine::Engine`] **in process**: it bootstraps an
//! engine, injects the inbounds it needs, and speaks socks5 to them over loopback.
//! There is no management API and no child process. That is deliberate -- the
//! surface under test is the one an embedder actually links against, so a test that
//! passes here says something about the library rather than about a shell in front
//! of it.
//!
//! # The chain every traffic test builds
//!
//! ```text
//! test client --socks5--> socks inbound --vless--> vless inbound --direct--> Sink
//!                         (static, no auth)        (dynamic users)
//! ```
//!
//! Both inbounds live in the *same* engine. The socks leg exists only to speak the
//! client half of VLESS, which is otherwise a great deal of crypto to reimplement in
//! a test; giving each user their own socks port is what makes "alice's traffic" and
//! "bob's traffic" separable at the client end. Nothing leaves loopback, so no test
//! needs network access.
//!
//! # Why the checks are soft
//!
//! [`Checks`] accumulates instead of panicking on the first failure, and
//! [`Checks::finish`] reports them all at once. An acceptance test that stops at the
//! first bad assertion hides how much else broke, which is exactly the information
//! needed to tell "one property regressed" from "the chain is not up at all".

#![allow(dead_code)]

use std::fmt::{Debug, Display};
use std::io;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

// Named through `shoes_engine` rather than `shoes_api` on purpose: these tests stand
// in for an embedder, and an embedder should not need a second dependency to write
// down the types the engine's own methods take.
use shoes_engine::{Engine, InboundSpec, UserInfo, UserSpec};

/// The client half of the Hysteria2 suite, which shoes cannot supply.
pub mod hysteria2;
/// Likewise for TUIC.
pub mod tuic;

/// Ceiling on every individual read in the harness.
///
/// Generous, because it exists to turn a hung chain into a reported failure rather
/// than to measure anything. A test that legitimately needs to wait polls instead.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// How long [`wait_for`] keeps polling before it gives up.
const POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// Self-signed leaf for `CN=e2e.test`, used by the TLS legs.
///
/// Inlined rather than referenced by path: `shoes::config::pem` passes any value
/// starting with `-----BEGIN` straight through (`shoes/src/config/pem.rs:418`), so
/// this keeps the tests independent of the directory they were launched from. The
/// newline normalisation is for `core.autocrlf` checkouts.
const TEST_CRT: &str = include_str!("../fixtures/test.crt");
const TEST_KEY: &str = include_str!("../fixtures/test.key");

pub fn test_cert() -> String {
    TEST_CRT.replace("\r\n", "\n")
}

pub fn test_key() -> String {
    TEST_KEY.replace("\r\n", "\n")
}

// ------------------------------------------------------------------------- checks

/// Soft assertion accumulator, printing a `PASS`/`FAIL` trace as it goes.
///
/// Run with `cargo test -- --nocapture` to watch it.
pub struct Checks {
    name: &'static str,
    passed: usize,
    failures: Vec<String>,
}

impl Checks {
    pub fn new(name: &'static str) -> Self {
        println!("\n=== {name} ===");
        Self {
            name,
            passed: 0,
            failures: Vec::new(),
        }
    }

    /// Marks the start of a numbered section, purely for readable output.
    pub fn section(&self, title: &str) {
        println!("{title}");
    }

    pub fn that(&mut self, label: &str, ok: bool) {
        self.record(label, ok, String::new());
    }

    pub fn detail(&mut self, label: &str, ok: bool, detail: impl Display) {
        self.record(label, ok, detail.to_string());
    }

    pub fn eq<T: PartialEq + Debug>(&mut self, label: &str, actual: T, expected: T) {
        let ok = actual == expected;
        self.record(label, ok, format!("{actual:?}, expected {expected:?}"));
    }

    /// Range assertion. The *upper* bound is the interesting half for byte
    /// accounting: a lower bound only says bytes were counted somewhere, while an
    /// upper bound is what catches counting them twice.
    pub fn within(&mut self, label: &str, value: u64, low: u64, high: u64) {
        let ok = (low..=high).contains(&value);
        self.record(label, ok, format!("{value}, expected {low}..{high}"));
    }

    /// Asserts a lower bound.
    ///
    /// For timing assertions this is the half worth trusting: a rate limiter
    /// cannot deliver faster than its rate however fast the machine is, whereas
    /// an upper bound is only as reliable as the runner's scheduling.
    pub fn at_least<T: PartialOrd + Debug>(&mut self, label: &str, value: T, floor: T) {
        let ok = value >= floor;
        self.record(label, ok, format!("{value:?}, expected at least {floor:?}"));
    }

    /// Asserts an upper bound. Use only where the margin is wide enough that a
    /// slow runner cannot turn a pass into a failure.
    pub fn at_most<T: PartialOrd + Debug>(&mut self, label: &str, value: T, ceiling: T) {
        let ok = value <= ceiling;
        self.record(
            label,
            ok,
            format!("{value:?}, expected at most {ceiling:?}"),
        );
    }

    /// Asserts an operation was refused, and that the reason mentions `needle`.
    ///
    /// The message matters as much as the rejection: a refusal a caller cannot act
    /// on is barely better than a silent failure.
    pub fn refused<T: Debug>(
        &mut self,
        label: &str,
        result: Result<T, shoes_engine::EngineError>,
        needle: &str,
    ) {
        match result {
            Ok(value) => self.record(label, false, format!("unexpectedly succeeded: {value:?}")),
            Err(e) => {
                let message = e.to_string();
                let ok = message.contains(needle);
                self.record(
                    label,
                    ok,
                    if ok {
                        message
                    } else {
                        format!("{message:?} does not mention {needle:?}")
                    },
                );
            }
        }
    }

    fn record(&mut self, label: &str, ok: bool, detail: String) {
        let shown = if detail.is_empty() {
            String::new()
        } else {
            format!("  {detail}")
        };
        println!("  {}  {label}{shown}", if ok { "PASS" } else { "FAIL" });
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(label.to_string());
        }
    }

    /// Panics with every failure listed, or prints the tally and returns.
    pub fn finish(self) {
        let total = self.passed + self.failures.len();
        if self.failures.is_empty() {
            println!("  {} -- {}/{} checks passed", self.name, self.passed, total);
            return;
        }
        panic!(
            "{}: {}/{} checks failed:\n  - {}",
            self.name,
            self.failures.len(),
            total,
            self.failures.join("\n  - ")
        );
    }
}

// ------------------------------------------------------------------------- engine

/// Bootstraps an engine with logging wired to `RUST_LOG`.
pub async fn engine() -> Engine {
    static LOGGING: Once = Once::new();
    LOGGING.call_once(|| {
        shoes::logging::init_multi_logger(
            vec![Box::new(shoes::logging::StderrWriter)],
            shoes::logging::resolve_directives(),
        );
    });

    Engine::bootstrap()
        .await
        .expect("engine should bootstrap with no config")
}

/// A loopback address on a port the OS says is free **for both TCP and UDP**.
///
/// Both, because the caller does not say which it wants and the QUIC inbounds want
/// UDP. TCP and UDP port spaces are independent, so a port the TCP probe found idle
/// can still be in use by a UDP socket -- which showed up as an intermittent
/// `WSAEACCES` from a hysteria2 or TUIC listener when the whole workspace suite ran
/// at once and enough ephemeral ports were in play.
///
/// Both sockets are opened and dropped, so there is still a window in which something
/// else could take the port. Nothing better is available without teaching shoes to
/// bind `:0` and report back what it got, and in practice the OS does not hand the
/// same ephemeral port to two live sockets.
pub fn free_addr() -> SocketAddr {
    // UDP first, deliberately. Windows reserves whole blocks of UDP ports for
    // Hyper-V, WSL and Docker -- `netsh int ipv4 show excludedportrange protocol=udp`
    // lists them -- and those blocks overlap the ephemeral range the OS hands out for
    // TCP. Asking for a TCP port and then binding UDP on it therefore fails with
    // `WSAEACCES` for entire runs of ports, which is what made the hysteria2 and TUIC
    // suites fail intermittently once the workspace run had enough listeners in play.
    // The OS never hands out an excluded port for a UDP socket, so starting there
    // gives a port that works for both.
    // Rejected candidates stay bound for a while rather than being dropped at once:
    // dropping one immediately lets the OS hand the same port straight back, and a
    // port whose TCP side is blocked would then be retried instead of moved past.
    //
    // Only a window of them, though. The excluded blocks are a few hundred ports wide
    // and several suites search at the same time, so pinning every rejected port until
    // the search ended could tie up a large share of the 16k dynamic range.
    const WINDOW: usize = 64;
    let mut rejected: Vec<std::net::UdpSocket> = Vec::with_capacity(WINDOW);
    for _ in 0..1024 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral udp port");
        let address = socket.local_addr().expect("read back the bound port");
        // Probed while the UDP side is still held, so the OS cannot hand this port to
        // the next caller in between. The reverse collision is rarer than the excluded
        // ranges but real: a port the UDP probe found idle can still be held for TCP.
        let listener = std::net::TcpListener::bind(address);
        if listener.is_ok() {
            drop(listener);
            drop(socket);
            return address;
        }
        if rejected.len() == WINDOW {
            rejected.remove(0);
        }
        rejected.push(socket);
    }
    panic!("could not find a port free for both udp and tcp after 1024 tries");
}

// ------------------------------------------------------------------ config builders

pub fn vless_inbound(address: SocketAddr, udp_enabled: bool) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {"type": "vless", "udp_enabled": udp_enabled},
    })
}

/// `cipher: "any"` lets each client pick its own data cipher.
///
/// That is the upstream default for a server and it keeps the two halves of a VMess
/// connection independent: which cipher a user negotiates has nothing to do with how
/// the server worked out who they are.
pub fn vmess_inbound(address: SocketAddr, udp_enabled: bool) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {"type": "vmess", "cipher": "any", "udp_enabled": udp_enabled},
    })
}

pub fn vless_inbound_with_rules(address: SocketAddr, udp_enabled: bool, rules: Value) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {"type": "vless", "udp_enabled": udp_enabled},
        "rules": rules,
    })
}

/// A TLS inbound wrapping VLESS, using the bundled self-signed cert.
pub fn tls_vless_inbound(address: SocketAddr) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {
            "type": "tls",
            "default_target": {
                "cert": test_cert(),
                "key": test_key(),
                "protocol": {"type": "vless", "udp_enabled": true},
            },
        },
    })
}

pub fn allow_all() -> Value {
    json!([{"masks": "0.0.0.0/0", "action": "allow"}])
}

/// Allow everything, but send it to `dest` regardless of what the client asked for.
///
/// This is what makes a rules swap *positively* observable: the destination that
/// answers tells you which generation of rules the connection is running under.
pub fn redirect_to(dest: SocketAddr) -> Value {
    json!([{
        "masks": "0.0.0.0/0",
        "action": "allow",
        "override_address": dest.to_string(),
    }])
}

pub fn vless_chain(server: SocketAddr, uuid: &str) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {"type": "vless", "user_id": uuid},
    })
}

/// A VMess leg, speaking `cipher` for its payload.
///
/// The cipher is a parameter because it is the one part of a VMess client the tests
/// vary: the auth id that identifies the user is derived from the uuid alone, so two
/// users on different ciphers are the sharpest way to show the two are unrelated.
pub fn vmess_chain(server: SocketAddr, uuid: &str, cipher: &str) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {"type": "vmess", "cipher": cipher, "user_id": uuid},
    })
}

/// A Shadowsocks 2022 inbound.
///
/// Its `password` is the *identity PSK*. Unlike a VLESS `user_id`, that value stays
/// live in dynamic mode: it names the inbound rather than a user, every client has to
/// know it to be understood at all, and the engine neither replaces nor rejects it.
pub fn ss_inbound(
    address: SocketAddr,
    cipher: &str,
    identity_psk: &str,
    udp_enabled: bool,
) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {
            "type": "ss",
            "cipher": format!("2022-blake3-{cipher}"),
            "password": identity_psk,
            "udp_enabled": udp_enabled,
        },
    })
}

/// A Shadowsocks 2022 leg for one user.
///
/// The colon-joined password is how a 2022 client says which server *and* which user
/// it is: it seals one identity header per leading key, each naming the next, and the
/// last segment is its own session key.
pub fn ss_chain(
    server: SocketAddr,
    cipher: &str,
    identity_psk: &str,
    user_psk: &str,
    udp_enabled: bool,
) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {
            "type": "ss",
            "cipher": format!("2022-blake3-{cipher}"),
            "password": format!("{identity_psk}:{user_psk}"),
            "udp_enabled": udp_enabled,
        },
    })
}

/// A Shadowsocks leg with no identity header at all -- a plain single-user client.
///
/// What an old client, or one pointed at the wrong server, actually sends. A
/// multi-user inbound has to refuse it rather than fall back to its own key.
pub fn ss_chain_without_identity(
    server: SocketAddr,
    cipher: &str,
    user_psk: &str,
    udp_enabled: bool,
) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {
            "type": "ss",
            "cipher": format!("2022-blake3-{cipher}"),
            "password": user_psk,
            "udp_enabled": udp_enabled,
        },
    })
}

/// A Hysteria2 inbound over QUIC for **dynamic** mode, using the bundled self-signed
/// cert.
///
/// No `password` field, which is not an omission: Hysteria2's password names nothing on
/// the wire beyond the one user it belongs to, so an inbound with a registry has no use
/// for one and the engine refuses a config that declares it. Shoes' schema still
/// requires the field, so the engine fills in a throwaway -- see `PLACEHOLDER_FIELDS`
/// in `shoes-engine`'s `protocol` module.
///
/// `alpn_protocols: ["h3"]` is not optional: Hysteria2 authenticates over HTTP/3, and a
/// client offering `h3` to a server that does not is a failed handshake with nothing to
/// do with credentials.
pub fn hysteria2_inbound(address: SocketAddr, udp_enabled: bool) -> Value {
    json!({
        "address": address.to_string(),
        "transport": "quic",
        "quic_settings": {
            "cert": test_cert(),
            "key": test_key(),
            "alpn_protocols": ["h3"],
        },
        "protocol": {"type": "hysteria2", "udp_enabled": udp_enabled},
    })
}

/// As [`hysteria2_inbound`], with independently negotiated Brutal bandwidths.
pub fn hysteria2_inbound_with_bandwidth(
    address: SocketAddr,
    up_mbps: u64,
    down_mbps: u64,
    udp_enabled: bool,
) -> Value {
    let mut config = hysteria2_inbound(address, udp_enabled);
    config["protocol"]["up_mbps"] = json!(up_mbps);
    config["protocol"]["down_mbps"] = json!(down_mbps);
    config
}

/// As [`hysteria2_inbound`], but with Salamander obfuscation switched on.
pub fn hysteria2_inbound_obfuscated(
    address: SocketAddr,
    obfs_password: &str,
    udp_enabled: bool,
) -> Value {
    let mut config = hysteria2_inbound(address, udp_enabled);
    config["protocol"]["obfs"] = json!({"type": "salamander", "password": obfs_password});
    config
}

/// As [`hysteria2_inbound`], but declaring the password a classic-mode inbound
/// authenticates against.
pub fn hysteria2_inbound_with_password(
    address: SocketAddr,
    password: &str,
    udp_enabled: bool,
) -> Value {
    let mut config = hysteria2_inbound(address, udp_enabled);
    config["protocol"]["password"] = json!(password);
    config
}

/// A TUIC v5 inbound over QUIC for **dynamic** mode, using the bundled self-signed
/// cert.
///
/// Neither `uuid` nor `password`, and for the same reason `hysteria2_inbound` omits
/// its password: with a registry injected, both are dead config, and the engine
/// refuses a payload that declares one. Shoes' schema requires both fields, so the
/// engine fills in throwaways -- see `PLACEHOLDER_FIELDS` in `shoes-engine`'s
/// `protocol` module, which is why that table maps a protocol to a *list*.
///
/// `alpn_protocols: ["h3"]` is not a TUIC requirement the way it is for Hysteria2 --
/// TUIC does not speak HTTP/3 -- but a server that names an ALPN and a client that
/// offers a different one fail the handshake, so the two halves have to agree and
/// this is the value the test client offers.
pub fn tuic_inbound(address: SocketAddr) -> Value {
    json!({
        "address": address.to_string(),
        "transport": "quic",
        "quic_settings": {
            "cert": test_cert(),
            "key": test_key(),
            "alpn_protocols": ["h3"],
        },
        "protocol": {"type": "tuic"},
    })
}

/// As [`tuic_inbound`], but routing by `rules` instead of the default.
///
/// The reload suite's way of making a rules swap visible on a QUIC-native inbound:
/// an `override_address` rule names which generation a connection is running under.
pub fn tuic_inbound_with_rules(address: SocketAddr, rules: Value) -> Value {
    let mut config = tuic_inbound(address);
    config["rules"] = rules;
    config
}

/// As [`tuic_inbound`], but declaring the credential a classic-mode inbound
/// authenticates against.
pub fn tuic_inbound_with_credential(address: SocketAddr, uuid: &str, password: &str) -> Value {
    let mut config = tuic_inbound(address);
    config["protocol"]["uuid"] = json!(uuid);
    config["protocol"]["password"] = json!(password);
    config
}

/// An AnyTLS inbound for **dynamic** mode, wrapped in TLS as every real one is.
///
/// No `users` list, which is not an omission: with a registry injected the config's
/// own users are dead, and the engine refuses a payload that declares them. Shoes'
/// schema still requires the field -- its `OneOrSome` even refuses an empty list --
/// so the engine stands in a one-element throwaway. See `PLACEHOLDER_USER_LISTS` in
/// `shoes-engine`'s `protocol` module.
pub fn tls_anytls_inbound(address: SocketAddr, udp_enabled: bool) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {
            "type": "tls",
            "default_target": {
                "cert": test_cert(),
                "key": test_key(),
                "protocol": {"type": "anytls", "udp_enabled": udp_enabled},
            },
        },
    })
}

/// As [`tls_anytls_inbound`], but declaring the users a classic-mode inbound
/// authenticates against.
///
/// Takes several, because AnyTLS is the first protocol here whose *config* is already
/// multi-user: without a registry all of them go into a static one, and a test that
/// only ever declared one would not notice if that stopped being true.
pub fn tls_anytls_inbound_with_users(
    address: SocketAddr,
    users: &[(&str, &str)],
    udp_enabled: bool,
) -> Value {
    let declared: Vec<Value> = users
        .iter()
        .map(|(name, password)| json!({"name": name, "password": password}))
        .collect();
    let mut config = tls_anytls_inbound(address, udp_enabled);
    config["protocol"]["default_target"]["protocol"]["users"] = json!(declared);
    config
}

/// An AnyTLS leg for one user, through TLS.
///
/// `verify: false` for the same reason [`tls_vless_chain`] gives: the bundled cert is
/// self-signed for `CN=e2e.test` and no CA store knows it.
pub fn tls_anytls_chain(server: SocketAddr, password: &str, udp_enabled: bool) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {
            "type": "tls",
            "verify": false,
            "sni_hostname": "e2e.test",
            "protocol": {
                "type": "anytls",
                "password": password,
                "udp_enabled": udp_enabled,
            },
        },
    })
}

/// A NaiveProxy inbound for **dynamic** mode, wrapped in TLS as every real one is.
///
/// No `users`, for the same reason [`tls_anytls_inbound`] omits its list: with a
/// registry injected the config's users are dead, the engine refuses a payload that
/// declares them, and shoes' schema still requires the field -- so a one-element
/// throwaway is filled in. NaiveProxy's throwaway needs two fields rather than one.
pub fn tls_naive_inbound(address: SocketAddr, udp_enabled: bool) -> Value {
    json!({
        "address": address.to_string(),
        "protocol": {
            "type": "tls",
            "default_target": {
                "cert": test_cert(),
                "key": test_key(),
                // Not optional: NaiveProxy proxies over HTTP/2 and serves static
                // files over HTTP/1.1, so without `h2` negotiated the inbound comes
                // up and quietly refuses to proxy anything.
                "alpn_protocols": ["h2"],
                "protocol": {"type": "naive", "udp_enabled": udp_enabled},
            },
        },
    })
}

/// As [`tls_naive_inbound`], but declaring the users a classic-mode inbound
/// authenticates against.
pub fn tls_naive_inbound_with_users(
    address: SocketAddr,
    users: &[(&str, &str, &str)],
    udp_enabled: bool,
) -> Value {
    let declared: Vec<Value> = users
        .iter()
        .map(|(name, username, password)| {
            json!({"name": name, "username": username, "password": password})
        })
        .collect();
    let mut config = tls_naive_inbound(address, udp_enabled);
    config["protocol"]["default_target"]["protocol"]["users"] = json!(declared);
    config
}

/// A NaiveProxy leg for one user, through TLS.
///
/// In dynamic mode `username` is the user's `id`: that is the half of the HTTP Basic
/// credential `UserSpec` has no field of its own for.
pub fn tls_naive_chain(server: SocketAddr, username: &str, password: &str) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {
            "type": "tls",
            "verify": false,
            "sni_hostname": "e2e.test",
            "alpn_protocols": ["h2"],
            "protocol": {
                "type": "naive",
                "username": username,
                "password": password,
            },
        },
    })
}

/// A deterministic base64 PSK of `len` bytes, derived from `seed`.
///
/// Deterministic so a test can hand the same key to a client leg and to `add_user`
/// and know they match, and derived from the seed so no two named keys collide.
pub fn psk(seed: &str, len: usize) -> String {
    let bytes: Vec<u8> = seed.bytes().cycle().take(len).collect();
    shoes::dynamic::credential::encode_shadowsocks_psk(&bytes)
}

/// `verify: false` because the bundled cert is self-signed for `CN=e2e.test` and no
/// CA store knows it. These tests are about accounting and reloads, not about
/// certificate validation.
pub fn tls_vless_chain(server: SocketAddr, uuid: &str, sni: &str) -> Value {
    json!({
        "address": server.to_string(),
        "protocol": {
            "type": "tls",
            "verify": false,
            "sni_hostname": sni,
            "protocol": {"type": "vless", "user_id": uuid},
        },
    })
}

// ------------------------------------------------------------------ inbound helpers

pub fn dynamic(tag: &str, config: Value) -> InboundSpec {
    InboundSpec {
        tag: tag.to_string(),
        config,
        users: Some(vec![]),
    }
}

/// An inbound in classic mode: no registry, so its config's own credential -- if the
/// protocol has one -- stays the authority.
pub fn classic(tag: &str, config: Value) -> InboundSpec {
    InboundSpec {
        tag: tag.to_string(),
        config,
        users: None,
    }
}

pub fn user(id: &str, uuid: &str) -> UserSpec {
    UserSpec {
        id: Some(id.to_string()),
        uuid: Some(uuid.to_string()),
        password: None,
        enabled: true,
        max_conns: None,
        upload_limit_bps: None,
        download_limit_bps: None,
    }
}

pub fn disabled_user(id: &str, uuid: &str) -> UserSpec {
    UserSpec {
        enabled: false,
        ..user(id, uuid)
    }
}

/// A user whose credential is a base64 Shadowsocks 2022 PSK.
pub fn psk_user(id: &str, psk: &str) -> UserSpec {
    UserSpec {
        id: Some(id.to_string()),
        uuid: None,
        password: Some(psk.to_string()),
        enabled: true,
        max_conns: None,
        upload_limit_bps: None,
        download_limit_bps: None,
    }
}

/// A user whose credential is a cleartext password, as Hysteria2 wants.
///
/// The same `UserSpec` shape as [`psk_user`], deliberately named apart: what the
/// inbound's protocol does with the value is the whole difference between a password
/// and key material, and a test reads better for saying which it meant.
pub fn password_user(id: &str, password: &str) -> UserSpec {
    UserSpec {
        id: Some(id.to_string()),
        uuid: None,
        password: Some(password.to_string()),
        enabled: true,
        max_conns: None,
        upload_limit_bps: None,
        download_limit_bps: None,
    }
}

pub fn disabled_password_user(id: &str, password: &str) -> UserSpec {
    UserSpec {
        enabled: false,
        ..password_user(id, password)
    }
}

/// A user whose credential is a uuid *and* a password, as TUIC wants.
///
/// The only helper here that fills in both. Neither half stands alone: a TUIC user
/// missing either one is refused when they are added, rather than accepted and left
/// unable to connect.
pub fn tuic_user(id: &str, uuid: &str, password: &str) -> UserSpec {
    UserSpec {
        id: Some(id.to_string()),
        uuid: Some(uuid.to_string()),
        password: Some(password.to_string()),
        enabled: true,
        max_conns: None,
        upload_limit_bps: None,
        download_limit_bps: None,
    }
}

pub fn disabled_tuic_user(id: &str, uuid: &str, password: &str) -> UserSpec {
    UserSpec {
        enabled: false,
        ..tuic_user(id, uuid, password)
    }
}

/// Starts the client half of the chain: a plain socks5 inbound that speaks `chain`
/// onward. Returns the socks address a test client should connect to.
pub async fn start_leg(engine: &Engine, tag: &str, chain: Value) -> SocketAddr {
    let address = free_addr();
    let config = json!({
        "address": address.to_string(),
        "protocol": {"type": "socks"},
        "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": chain}],
    });
    engine
        .add_inbound(classic(tag, config))
        .await
        .unwrap_or_else(|e| panic!("could not start socks leg {tag}: {e}"));
    address
}

/// The engine's current view of one inbound.
pub fn info(engine: &Engine, tag: &str) -> shoes_engine::InboundInfo {
    engine
        .get_inbound(tag)
        .unwrap_or_else(|| panic!("inbound {tag} should be registered"))
        .describe()
}

// -------------------------------------------------------------------------- polling

/// Polls `predicate` until it holds or [`POLL_TIMEOUT`] elapses.
///
/// VLESS puts its header in front of the first payload byte, so a user's
/// authentication is observable only once data has actually flowed. Polling is what
/// keeps the tests independent of that timing.
pub async fn wait_for(what: &str, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + POLL_TIMEOUT;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    println!("      timed out waiting for {what}");
    false
}

/// The user's counters once none of their connections are still open.
///
/// Bytes are counted as they move, so a snapshot taken mid-transfer is a race. A
/// user with no live connections has no meter left to run: the context holding the
/// counters is dropped when the last holder of the connection goes, and dropping it
/// is what decrements `conns`. So `conns == 0` is the barrier that makes the totals
/// final.
pub async fn quiet(engine: &Engine, tag: &str, id: &str) -> UserInfo {
    let settled = wait_for(&format!("{id}'s connections to close"), || {
        engine
            .get_user(tag, id)
            .map(|u| u.conns == 0)
            .unwrap_or(false)
    })
    .await;

    let info = engine
        .get_user(tag, id)
        .unwrap_or_else(|e| panic!("user {id} should exist on {tag}: {e}"));
    if !settled {
        println!(
            "      warning: {id} still reports {} open connection(s)",
            info.conns
        );
    }
    info
}

/// `(tx, rx)` moved between two snapshots.
pub fn delta(before: &UserInfo, after: &UserInfo) -> (u64, u64) {
    (after.tx - before.tx, after.rx - before.rx)
}

// ---------------------------------------------------------------------- test peers

/// A TCP peer for the far end of the chain.
///
/// Speaks three commands, each a single line:
///
/// | command | behaviour |
/// |---|---|
/// | `who` | replies `<name>\n` -- says *which* peer the connection reached |
/// | `hold` | reads until the client closes -- keeps a connection countable |
/// | `<up> <down>` | reads `up` bytes, writes `down` -- makes both directions known |
///
/// `who` is what makes a rules swap observable, and splitting the request across two
/// writes is what lets a test establish a connection under one generation of rules
/// and complete it under the next.
pub struct Sink {
    pub address: SocketAddr,
    pub name: String,
}

impl Sink {
    pub async fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the sink");
        let address = listener.local_addr().expect("read back the sink address");
        let name = name.to_string();

        let served = name.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let name = served.clone();
                tokio::spawn(async move {
                    let _ = Self::serve(stream, name).await;
                });
            }
        });

        Self { address, name }
    }

    async fn serve(mut stream: TcpStream, name: String) -> io::Result<()> {
        let command = read_line(&mut stream).await?;

        if command == "who" {
            stream.write_all(format!("{name}\n").as_bytes()).await?;
            return Ok(());
        }
        if command == "hold" {
            let mut scratch = vec![0u8; 65536];
            while stream.read(&mut scratch).await? > 0 {}
            return Ok(());
        }

        let mut sizes = command.split_whitespace();
        let upload: usize = sizes
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| io::Error::other(format!("bad command {command:?}")))?;
        let download: usize = sizes
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| io::Error::other(format!("bad command {command:?}")))?;

        let mut remaining = upload;
        let mut scratch = vec![0u8; 65536];
        while remaining > 0 {
            let n = stream.read(&mut scratch[..remaining.min(65536)]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("wanted {upload} bytes, {remaining} short"),
                ));
            }
            remaining -= n;
        }
        stream.write_all(&vec![b'y'; download]).await?;
        stream.flush().await
    }
}

/// A UDP peer that returns whatever it is sent.
pub struct UdpEcho {
    pub address: SocketAddr,
}

impl UdpEcho {
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the udp echo");
        let address = socket.local_addr().expect("read back the echo address");

        tokio::spawn(async move {
            let mut scratch = vec![0u8; 65535];
            while let Ok((n, peer)) = socket.recv_from(&mut scratch).await {
                if socket.send_to(&scratch[..n], peer).await.is_err() {
                    return;
                }
            }
        });

        Self { address }
    }
}

// --------------------------------------------------------------------------- socks5

/// Minimal socks5 client. IPv4 destinations only, which is all loopback needs.
pub struct Socks;

impl Socks {
    /// `CONNECT` through `proxy` to `dest`.
    ///
    /// Success here does **not** mean the user was authenticated: shoes writes the
    /// socks reply before the upstream VLESS handshake completes, so a denied user
    /// shows up later as a connection that closes without answering.
    pub async fn connect(proxy: SocketAddr, dest: SocketAddr) -> io::Result<TcpStream> {
        let mut stream = Self::greet(proxy).await?;

        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&ipv4_octets(dest)?);
        request.extend_from_slice(&dest.port().to_be_bytes());
        stream.write_all(&request).await?;

        let reply = read_exact_n(&mut stream, 10).await?;
        if reply[1] != 0x00 {
            return Err(io::Error::other(format!(
                "socks5 connect refused: rep={}",
                reply[1]
            )));
        }
        Ok(stream)
    }

    /// `UDP ASSOCIATE`. Returns the control stream and the relay to send datagrams to.
    ///
    /// The control stream has to stay alive: per RFC 1928 the association dies with
    /// it, and shoes implements that.
    pub async fn associate(proxy: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
        let mut stream = Self::greet(proxy).await?;
        stream
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let reply = read_exact_n(&mut stream, 10).await?;
        if reply[1] != 0x00 {
            return Err(io::Error::other(format!(
                "socks5 udp associate refused: rep={}",
                reply[1]
            )));
        }
        let relay = SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ));
        Ok((stream, relay))
    }

    async fn greet(proxy: SocketAddr) -> io::Result<TcpStream> {
        let mut stream = timeout(TcpStream::connect(proxy)).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        if read_exact_n(&mut stream, 2).await? != [0x05, 0x00] {
            return Err(io::Error::other("socks5 method negotiation failed"));
        }
        Ok(stream)
    }
}

/// Wraps `payload` in a socks5 UDP request header for `dest`.
pub fn udp_wrap(dest: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x00, 0x00, 0x00, 0x01];
    packet.extend_from_slice(&ipv4_octets(dest)?);
    packet.extend_from_slice(&dest.port().to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// The payload of a socks5 UDP reply, or `None` if it is not an IPv4 datagram.
pub fn udp_unwrap(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 10 || packet[3] != 0x01 {
        return None;
    }
    Some(&packet[10..])
}

fn ipv4_octets(address: SocketAddr) -> io::Result<[u8; 4]> {
    match address {
        SocketAddr::V4(v4) => Ok(v4.ip().octets()),
        SocketAddr::V6(_) => Err(io::Error::other("the harness only speaks ipv4")),
    }
}

// ------------------------------------------------------------------------- stream io

async fn timeout<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the chain did not answer in time"))?
}

pub async fn read_exact_n(stream: &mut TcpStream, count: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    timeout(async {
        stream.read_exact(&mut buffer).await?;
        Ok(())
    })
    .await?;
    Ok(buffer)
}

/// Reads up to the next `\n`, trimmed. An EOF before one is an error, which is how a
/// refused user is detected.
pub async fn read_line(stream: &mut TcpStream) -> io::Result<String> {
    let mut line = Vec::new();
    timeout(async {
        let mut byte = [0u8; 1];
        loop {
            if stream.read(&mut byte).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("connection closed after {} byte(s)", line.len()),
                ));
            }
            if byte[0] == b'\n' {
                return Ok(());
            }
            line.push(byte[0]);
        }
    })
    .await?;
    Ok(String::from_utf8_lossy(&line).trim().to_string())
}

// --------------------------------------------------------------------- chain probes

/// Asks `dest` who it is, through the chain, and returns the name that answered.
///
/// Which sink answers is the observable: the inbound's rules decide where the
/// connection actually goes, and `override_address` can send it somewhere other than
/// the address the client asked for.
pub async fn reach(proxy: SocketAddr, dest: SocketAddr) -> io::Result<String> {
    let mut stream = Socks::connect(proxy, dest).await?;
    stream.write_all(b"who\n").await?;
    let answer = read_line(&mut stream).await?;
    let _ = stream.shutdown().await;
    Ok(answer)
}

/// True if the chain refuses to carry traffic for this leg's user.
///
/// Refusal shows up as a closed connection rather than a socks error: shoes answers
/// the socks request as soon as it has the upstream TCP connection, and the VLESS
/// handshake that rejects the user happens after that. So what a denied client sees
/// is an EOF where the sink's answer should have been.
///
/// The short deadline is deliberate. A refusal is immediate, so anything slower is
/// worth reporting as its own symptom instead of being absorbed into the generous
/// [`IO_TIMEOUT`].
pub async fn denied(proxy: SocketAddr, dest: SocketAddr) -> bool {
    match tokio::time::timeout(Duration::from_secs(5), reach(proxy, dest)).await {
        Ok(Ok(name)) => {
            println!("      reached {name} when the user should have been refused");
            false
        }
        Ok(Err(_)) => true,
        Err(_) => {
            println!("      the chain neither answered nor closed -- treating as refused");
            true
        }
    }
}

/// Moves `upload` bytes up and `download` bytes down, returning how much came back.
pub async fn transfer(
    proxy: SocketAddr,
    dest: SocketAddr,
    upload: usize,
    download: usize,
) -> io::Result<usize> {
    let mut stream = Socks::connect(proxy, dest).await?;
    stream
        .write_all(format!("{upload} {download}\n").as_bytes())
        .await?;
    stream.write_all(&vec![b'x'; upload]).await?;

    let mut received = 0usize;
    let mut scratch = vec![0u8; 65536];
    while received < download {
        let n = timeout(stream.read(&mut scratch)).await?;
        if n == 0 {
            break;
        }
        received += n;
    }
    let _ = stream.shutdown().await;
    Ok(received)
}

/// True if a datagram makes it through the chain and back.
pub async fn udp_roundtrip(proxy: SocketAddr, dest: SocketAddr, wait: Duration) -> bool {
    let Ok((control, relay)) = Socks::associate(proxy).await else {
        return false;
    };
    let Ok(client) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    let Ok(packet) = udp_wrap(dest, b"ping") else {
        return false;
    };
    if client.send_to(&packet, relay).await.is_err() {
        return false;
    }

    let mut scratch = vec![0u8; 65535];
    let echoed = match tokio::time::timeout(wait, client.recv_from(&mut scratch)).await {
        Ok(Ok((n, _))) => udp_unwrap(&scratch[..n]) == Some(b"ping".as_slice()),
        _ => false,
    };

    drop(control);
    echoed
}

/// Sends `count` datagrams of `size` bytes through the chain, returning how many came
/// back.
///
/// The control stream is held for the whole exchange and dropped on return, which is
/// what lets the caller wait for the association to close before reading counters.
pub async fn udp_burst(
    proxy: SocketAddr,
    dest: SocketAddr,
    size: usize,
    count: usize,
) -> io::Result<usize> {
    let (control, relay) = Socks::associate(proxy).await?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let payload = vec![b'u'; size];
    let packet = udp_wrap(dest, &payload)?;

    let mut echoed = 0usize;
    let mut scratch = vec![0u8; 65535];
    for _ in 0..count {
        client.send_to(&packet, relay).await?;
        // One in flight at a time: UDP may reorder or drop, and a test that cannot
        // tell "lost" from "late" cannot put an upper bound on the byte count.
        match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut scratch)).await {
            Ok(Ok((n, _))) if udp_unwrap(&scratch[..n]) == Some(payload.as_slice()) => echoed += 1,
            Ok(Ok((n, _))) => println!("      unexpected {n}-byte reply"),
            Ok(Err(e)) => return Err(e),
            Err(_) => println!("      a datagram did not come back"),
        }
    }

    drop(control);
    Ok(echoed)
}
