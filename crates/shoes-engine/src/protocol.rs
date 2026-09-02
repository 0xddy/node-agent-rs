//! Working out how an inbound authenticates, from its config.
//!
//! Two questions are answered here, both by walking the same config tree:
//!
//! 1. Which credential forms does this inbound need a registry to answer for?
//! 2. Where in the payload does shoes' schema demand a leaf credential that a
//!    registry is about to take over?
//!
//! The walk exists because a proxy inbound is a tree, not a flat protocol name. A
//! VLESS inbound is almost always written as `{type: tls, protocol: {type: vless}}`
//! and can also sit under Reality, ShadowTLS, or a Websocket path. Looking only at
//! the outermost protocol would classify every real-world VLESS inbound as one that
//! does not authenticate -- and then quietly accept a `users` list it would never
//! consult, which is a fail-open bug rather than a cosmetic one.

use serde_json::{Map, Value};
use shoes::config::{ServerProxyConfig, ShadowsocksConfig};
use shoes::dynamic::credential;

use crate::error::{EngineError, EngineResult};
use crate::users::CredentialKinds;

/// The credential forms this inbound, including everything nested inside it, needs
/// the engine's user registry to answer.
///
/// Empty means the inbound authenticates some other way, or not at all.
///
/// The match is exhaustive on purpose: no wildcard arm. Adding registry support for
/// another protocol is a deliberate decision, and so is absorbing a new protocol
/// from upstream, so both should stop the build here rather than silently classify
/// as "no users".
pub(crate) fn credential_kinds(protocol: &ServerProxyConfig) -> CredentialKinds {
    let mut kinds = CredentialKinds::NONE;

    match protocol {
        // Registry-backed today.
        ServerProxyConfig::Vless { .. } => kinds.merge(CredentialKinds::UUID),
        ServerProxyConfig::Trojan { .. } => kinds.merge(CredentialKinds::TROJAN_PASSWORD),
        // VMess identifies users by the same uuid VLESS does, so it needs no credential
        // form of its own -- only a different lookup, which the registry provides.
        ServerProxyConfig::Vmess { .. } => kinds.merge(CredentialKinds::UUID),

        // Shadowsocks tells users apart only under 2022 with an AES cipher, where each
        // client prefixes an identity header naming its own PSK. Legacy shadowsocks has
        // no such header and the 2022 chacha20 cipher has no way to build one, so an
        // inbound using either stays single-user and is refused a `users` list.
        //
        // The key length travels with the kind: a PSK is raw key material, so a 16 byte
        // key is not a short aes-256-gcm key, it is one that cipher can never use.
        //
        // Note that such an inbound's own `password` stays live in dynamic mode, unlike
        // VLESS' `user_id` -- it is the identity PSK every client must know to reach the
        // inbound at all, and it names no user. Hence no `PLACEHOLDER_FIELDS` entry.
        ServerProxyConfig::Shadowsocks { config, .. } => {
            if let ShadowsocksConfig::Aead2022 { cipher, .. } = config
                && credential::shadowsocks_supports_multi_user(cipher)
            {
                kinds.merge(CredentialKinds::shadowsocks_psk(cipher.key_len()));
            }
        }

        // Containers. Each target names its own inner protocol, so one inbound can
        // need more than one credential form -- e.g. VLESS on one SNI and Trojan on
        // another.
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for target in tls_targets.values() {
                kinds.merge(credential_kinds(&target.protocol));
            }
            if let Some(target) = default_tls_target {
                kinds.merge(credential_kinds(&target.protocol));
            }
            for target in shadowtls_targets.values() {
                kinds.merge(credential_kinds(&target.protocol));
            }
            for target in reality_targets.values() {
                kinds.merge(credential_kinds(&target.protocol));
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter() {
                kinds.merge(credential_kinds(&target.protocol));
            }
        }

        // Hysteria2 sends its password in cleartext in an HTTP/3 header, so a registry
        // lookup is the whole of authentication. It authenticates in its own QUIC
        // accept loop rather than through a `TcpServerHandler`, which is why it takes
        // the registry as a parameter instead of getting one from
        // `create_tcp_server_handler`.
        ServerProxyConfig::Hysteria2 { .. } => kinds.merge(CredentialKinds::PLAIN_PASSWORD),

        // TUIC needs a uuid and a password together: the uuid arrives in cleartext and
        // names the user, the password keys the 32 byte token beside it. Like
        // Hysteria2 it authenticates in its own QUIC accept loop rather than through a
        // `TcpServerHandler`, so it takes the registry as a parameter.
        ServerProxyConfig::TuicV5 { .. } => kinds.merge(CredentialKinds::TUIC),

        // AnyTLS sends the raw SHA-256 of its password, so the registry answers two
        // questions for it: which user a full hash belongs to, and whether an 8-byte
        // prefix is worth reading the rest of. The second is what keeps its
        // probe-resistant fallback fast, and it has to be answerable before the
        // credential is complete.
        ServerProxyConfig::Anytls { .. } => kinds.merge(CredentialKinds::ANYTLS_PASSWORD),

        // NaiveProxy authenticates with HTTP Basic. `UserSpec` has no `username`
        // field, so the user's `id` is the username half -- which means the id is
        // part of the credential here, and renaming a user rotates it.
        ServerProxyConfig::Naiveproxy { .. } => kinds.merge(CredentialKinds::NAIVE_BASIC),

        // Authenticates, but not through the registry. Snell has no multi-user
        // identity mechanism at all, so there is nothing for a registry to answer.
        ServerProxyConfig::Snell { .. } => {}

        // Either no credentials at all, or plain proxy credentials that identify a
        // client but not a billable user.
        ServerProxyConfig::Http { .. }
        | ServerProxyConfig::Socks { .. }
        | ServerProxyConfig::Mixed { .. }
        | ServerProxyConfig::PortForward { .. } => {}
    }

    kinds
}

/// Names a nested target that would leave a dynamic inbound admitting somebody the
/// caller's `users` list never mentions.
///
/// [`credential_kinds`] answers "does *anything* in this tree authenticate through a
/// registry", which is the right question for whether a `users` list is meaningful at
/// all. It is the wrong question for whether the list actually governs the inbound: a
/// tree can answer yes on one target and leave another wide open, and the caller is
/// then told they configured access control that half the inbound never consults.
///
/// Two shapes end up there, and both are fail-open:
///
/// 1. **A target that cannot act on a registry it is handed.** Shadowsocks is the only
///    protocol whose handler *branches* on whether a registry was injected, so it is
///    the only one that can be given one it has no way to consult -- a 2022 chacha20
///    target has no identity header to name a user with. That combination cannot even
///    start.
/// 2. **A target that authenticates nobody at all.** A plain HTTP, SOCKS or mixed
///    target with neither `username` nor `password`, or a port-forward, admits every
///    client that reaches it. Sharing an inbound with VLESS does not change that, and
///    it is exactly the case where a `users` list reads as protection it is not.
///
/// What is deliberately *not* named here is a target that authenticates on its own
/// terms without the registry: legacy shadowsocks, Snell, or an HTTP target with a
/// username and password. Those keep the credential the operator actually wrote --
/// nothing invented one for them, since only [`PLACEHOLDER_FIELDS`] protocols get a
/// throwaway -- so the inbound is not open, it is simply not per-user on that target.
pub(crate) fn unservable_registry_target(protocol: &ServerProxyConfig) -> Option<String> {
    match protocol {
        ServerProxyConfig::Shadowsocks { config, .. } => match config {
            ShadowsocksConfig::Aead2022 { cipher, .. }
                if !credential::shadowsocks_supports_multi_user(cipher) =>
            {
                Some(format!(
                    "a shadowsocks target using {} cannot serve a `users` list, so \
                     neither can the inbound carrying it: only the aes ciphers carry \
                     the identity header that names which user a connection belongs \
                     to, which is what the engine's user registry is consulted with",
                    cipher.name()
                ))
            }
            _ => None,
        },

        // `create_auth_credentials` treats "neither field" as "no authentication at
        // all", so that is exactly the condition here -- either field alone still
        // produces a credential to compare against.
        ServerProxyConfig::Http { username, password } => {
            unauthenticated_target("http", username, password)
        }
        ServerProxyConfig::Socks {
            username, password, ..
        } => unauthenticated_target("socks", username, password),
        ServerProxyConfig::Mixed {
            username, password, ..
        } => unauthenticated_target("mixed", username, password),

        ServerProxyConfig::PortForward { .. } => Some(
            "a port-forward target forwards every client that reaches it, so an \
             inbound carrying one cannot be governed by a `users` list: add it as its \
             own inbound if that is what you meant"
                .to_string(),
        ),

        // Containers: ask every target they nest.
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            // Iterated separately rather than chained: the four collections hold
            // four different target types, exactly as in `credential_kinds`.
            for target in tls_targets.values() {
                if let Some(reason) = unservable_registry_target(&target.protocol) {
                    return Some(reason);
                }
            }
            if let Some(target) = default_tls_target
                && let Some(reason) = unservable_registry_target(&target.protocol)
            {
                return Some(reason);
            }
            for target in shadowtls_targets.values() {
                if let Some(reason) = unservable_registry_target(&target.protocol) {
                    return Some(reason);
                }
            }
            for target in reality_targets.values() {
                if let Some(reason) = unservable_registry_target(&target.protocol) {
                    return Some(reason);
                }
            }
            None
        }
        ServerProxyConfig::Websocket { targets } => targets
            .iter()
            .find_map(|target| unservable_registry_target(&target.protocol)),

        // Every one of these authenticates: through the registry, or -- for Snell --
        // on a credential of its own that nothing here replaced.
        //
        // Exhaustive for the same reason `credential_kinds` is: absorbing a new
        // protocol from upstream should stop the build here rather than default to
        // "nothing to worry about".
        ServerProxyConfig::Vless { .. }
        | ServerProxyConfig::Vmess { .. }
        | ServerProxyConfig::Trojan { .. }
        | ServerProxyConfig::Hysteria2 { .. }
        | ServerProxyConfig::TuicV5 { .. }
        | ServerProxyConfig::Anytls { .. }
        | ServerProxyConfig::Naiveproxy { .. }
        | ServerProxyConfig::Snell { .. } => None,
    }
}

/// The message for a plain-proxy target that was configured with no credential.
fn unauthenticated_target(
    kind: &str,
    username: &Option<String>,
    password: &Option<String>,
) -> Option<String> {
    if username.is_some() || password.is_some() {
        return None;
    }
    Some(format!(
        "a {kind} target with no `username` or `password` admits every client that \
         reaches it, so a `users` list would not govern this inbound: give the target \
         a credential, or add it as its own inbound"
    ))
}

/// A human-readable label for an inbound's protocol, for logs and API responses.
///
/// This exists only to guarantee the label is non-empty. Upstream's `Display` builds a
/// `Tls` label from its populated target maps and never consults `default_tls_target`
/// (`../shoes-plus/src/config/types/server.rs:794`), so a TLS inbound configured with only a
/// default target renders as the empty string -- which then surfaced as an empty
/// `InboundInfo::protocol`. Substituting a label here keeps the fix on the
/// engine's side of the boundary; patching upstream's `Display` would mean carrying a
/// cosmetic diff through every merge of `../shoes-plus/`.
pub(crate) fn display_name(protocol: &ServerProxyConfig) -> String {
    let label = protocol.to_string();
    if !label.is_empty() {
        return label;
    }
    match protocol {
        // The only variant whose `Display` can produce nothing.
        ServerProxyConfig::Tls { .. } => "TLS".to_string(),
        // Unreachable today: every other arm writes a literal. A future upstream
        // variant that renders empty lands here, and a vague label beats a blank one.
        _ => "unknown".to_string(),
    }
}

/// The leaf credential fields each registry-backed protocol declares in its config.
///
/// A list per protocol rather than a single field, because TUIC declares two. Both
/// spellings of its tag appear: `rename_all = "lowercase"` makes the variant
/// `tuicv5`, and shoes accepts `tuic` as an alias, so listing only one would leave
/// configs written the other way demanding a credential the registry has taken over.
const PLACEHOLDER_FIELDS: &[(&str, &[&str])] = &[
    ("vless", &["user_id"]),
    ("vmess", &["user_id"]),
    ("trojan", &["password"]),
    ("hysteria2", &["password"]),
    ("tuicv5", &["uuid", "password"]),
    ("tuic", &["uuid", "password"]),
];

/// Protocols whose credential is a *list* of user objects rather than a leaf field,
/// and the fields a throwaway member of that list needs.
///
/// AnyTLS is the first of these. Its `users` is a `OneOrSome`, which refuses an empty
/// list, so such an inbound cannot simply omit the field the way a leaf credential
/// can be omitted -- the placeholder has to be a one-element list.
const PLACEHOLDER_USER_LISTS: &[(&str, &[&str])] = &[
    ("anytls", &["password"]),
    // Both spellings of the tag, as with TUIC: `rename_all = "lowercase"` makes the
    // variant `naiveproxy`, and shoes accepts `naive` as an alias.
    ("naiveproxy", &["username", "password"]),
    ("naive", &["username", "password"]),
];
/// Fills in the credential fields shoes' schema requires but a registry supersedes.
///
/// `ServerProxyConfig::Vless` has a non-optional `user_id`, so a payload without one
/// will not deserialize -- yet in dynamic mode that value is dead, because
/// `resolve_uuid_users` hands the injected registry to the handler and never looks
/// at it. Rather than make the caller invent a credential, or make the field
/// optional upstream and carry that diff forever, the engine supplies a random
/// throwaway.
///
/// A credential the caller *did* write is rejected instead of overwritten. It would
/// otherwise be silently ignored, and a credential that stops working without any
/// error is the worst way to learn about this rule.
///
/// This walks raw JSON rather than the typed config because it has to run *before*
/// deserialization, which is also why it cannot lean on serde to tell it which
/// objects are protocols.
///
/// It descends only through the positions where a *server* protocol nests another
/// one, and deliberately does not search the payload for `type: vless` at large. An
/// inbound's `rules` carry a `client_chain`, whose protocol objects look identical
/// but describe an **outbound** -- and there a `user_id` is a real, required
/// credential belonging to the far end. A blind search would reject those configs
/// for carrying a field they need, or worse, overwrite a missing one with a
/// throwaway and dial out with a credential nobody granted.
///
/// The tradeoff of being structural is that an unrecognised shape gets no
/// placeholder, and shoes' own deserializer then reports the missing field. That is
/// a confusing error message in an odd corner, never a credential that goes
/// unchecked.
pub(crate) fn install_placeholder_credentials(config: &mut Value) -> EngineResult<()> {
    // Absent `protocol` is not this pass's problem: `ServerConfig`'s deserializer
    // reports it far better than anything guessable from here.
    let Some(protocol) = config.get_mut("protocol") else {
        return Ok(());
    };
    visit_protocol(protocol)
}

/// Keys under which a protocol nests a *collection* of targets, each naming its own
/// inner protocol. The aliases matter: shoes accepts all of these spellings, so
/// missing one would silently skip a whole subtree.
const TARGET_COLLECTION_KEYS: &[&str] = &[
    // `Tls::tls_targets`, plus its `sni_targets`/`targets` aliases.
    "tls_targets",
    "sni_targets",
    "shadowtls_targets",
    "reality_targets",
    // `Websocket::targets` and `Tls`'s `targets` alias share a spelling, as does
    // `PortForward::targets` -- which holds addresses, not protocols, and so simply
    // has nothing for the walk to find.
    "targets",
    "target",
];

/// Keys under which a protocol nests exactly one target.
const SINGLE_TARGET_KEYS: &[&str] = &["default_tls_target", "default_target"];

/// One server-protocol object and every server protocol nested beneath it.
fn visit_protocol(value: &mut Value) -> EngineResult<()> {
    let Value::Object(map) = value else {
        return Ok(());
    };

    fill_protocol_object(map)?;

    for key in TARGET_COLLECTION_KEYS {
        if let Some(entry) = map.get_mut(*key) {
            visit_target_collection(entry)?;
        }
    }
    for key in SINGLE_TARGET_KEYS {
        if let Some(entry) = map.get_mut(*key) {
            visit_target(entry)?;
        }
    }
    Ok(())
}

/// A list of targets, an SNI-keyed map of them, or -- since `OneOrSome` accepts a
/// bare value where a list is allowed -- a single one.
fn visit_target_collection(value: &mut Value) -> EngineResult<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                visit_target(item)?;
            }
            Ok(())
        }
        // A target carries `protocol`; a map of targets carries SNI names. That is
        // the only thing distinguishing `OneOrSome::One` from a keyed map here.
        Value::Object(map) if map.contains_key("protocol") => visit_target(value),
        Value::Object(map) => {
            for target in map.values_mut() {
                visit_target(target)?;
            }
            Ok(())
        }
        // `PortForward` targets are addresses, so there is nothing to descend into.
        _ => Ok(()),
    }
}

fn visit_target(value: &mut Value) -> EngineResult<()> {
    let Value::Object(map) = value else {
        return Ok(());
    };
    match map.get_mut("protocol") {
        Some(protocol) => visit_protocol(protocol),
        None => Ok(()),
    }
}

fn fill_protocol_object(map: &mut Map<String, Value>) -> EngineResult<()> {
    // Cloned so the immutable borrow of `map` ends before the insert below.
    let kind = match map.get("type") {
        Some(Value::String(kind)) => kind.clone(),
        _ => return Ok(()),
    };

    // A protocol whose credential is a list of user objects. Same rule, different
    // shape: reject one the caller wrote, and stand in a throwaway otherwise.
    if let Some((_, member_fields)) = PLACEHOLDER_USER_LISTS
        .iter()
        .find(|(name, _)| *name == kind)
    {
        // Both spellings shoes accepts for the field, or the alias would slip past.
        for key in ["users", "user"] {
            if map.contains_key(key) {
                return Err(EngineError::InvalidConfig(format!(
                    "remove `{key}` from the {kind} protocol: this inbound has a `users` \
                     list of its own, which is its only authority, so credentials in the \
                     config would be ignored"
                )));
            }
        }

        let mut member = Map::new();
        for field in *member_fields {
            member.insert(
                (*field).to_string(),
                Value::String(credential::random_uuid()),
            );
        }
        map.insert(
            "users".to_string(),
            Value::Array(vec![Value::Object(member)]),
        );
        return Ok(());
    }

    let Some((_, fields)) = PLACEHOLDER_FIELDS.iter().find(|(name, _)| *name == kind) else {
        return Ok(());
    };

    for field in *fields {
        if map.contains_key(*field) {
            return Err(EngineError::InvalidConfig(format!(
                "remove `{field}` from the {kind} protocol: this inbound has a `users` \
                 list, which is its only authority, so a credential in the config would \
                 be ignored"
            )));
        }
    }

    // Every field gets a uuid, password fields included. The value is dead either way
    // -- nothing reads it once a registry is injected -- and an unguessable throwaway
    // is a better failure mode than a fixed one, should a path ever be found that does.
    for field in *fields {
        map.insert(
            (*field).to_string(),
            Value::String(credential::random_uuid()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> ServerProxyConfig {
        // Same route the engine takes: JSON is valid YAML 1.2, so shoes' own
        // deserializers accept it unchanged.
        serde_yaml::from_str(json).unwrap()
    }

    const VLESS: &str = r#"{"type":"vless","user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}"#;
    const TROJAN: &str = r#"{"type":"trojan","password":"hunter2"}"#;

    fn tls_wrapping(inner: &str) -> String {
        format!(
            r#"{{"type":"tls","tls_targets":{{"example.com":{{"cert":"c","key":"k","protocol":{inner}}}}}}}"#
        )
    }

    /// A base64 key of `len` bytes, for a 2022 cipher's `password`.
    fn base64_of(len: usize) -> String {
        credential::encode_shadowsocks_psk(&vec![7u8; len])
    }

    /// The placeholder pass takes a whole inbound, not a bare protocol, because
    /// `rules` sit alongside `protocol` and must be left alone.
    fn inbound(protocol: &str) -> String {
        format!(r#"{{"address":"127.0.0.1:18443","protocol":{protocol}}}"#)
    }

    #[test]
    fn classifies_a_bare_vless_inbound() {
        assert_eq!(credential_kinds(&parse(VLESS)), CredentialKinds::UUID);
    }

    #[test]
    fn classifies_a_bare_trojan_inbound() {
        assert_eq!(
            credential_kinds(&parse(TROJAN)),
            CredentialKinds::TROJAN_PASSWORD
        );
    }

    #[test]
    fn looks_through_tls_to_the_inner_protocol() {
        // The shape every real VLESS inbound actually uses.
        assert_eq!(
            credential_kinds(&parse(&tls_wrapping(VLESS))),
            CredentialKinds::UUID
        );
    }

    #[test]
    fn looks_through_a_default_tls_target() {
        let json = format!(
            r#"{{"type":"tls","default_tls_target":{{"cert":"c","key":"k","protocol":{VLESS}}}}}"#
        );
        assert_eq!(credential_kinds(&parse(&json)), CredentialKinds::UUID);
    }

    #[test]
    fn looks_through_reality_and_shadowtls() {
        let reality = format!(
            r#"{{"type":"tls","reality_targets":{{"example.com":{{"private_key":"k","dest":"example.com:443","protocol":{VLESS}}}}}}}"#
        );
        assert_eq!(credential_kinds(&parse(&reality)), CredentialKinds::UUID);

        let shadowtls = format!(
            r#"{{"type":"tls","shadowtls_targets":{{"example.com":{{"password":"p","handshake":{{"address":"example.com:443"}},"protocol":{TROJAN}}}}}}}"#
        );
        assert_eq!(
            credential_kinds(&parse(&shadowtls)),
            CredentialKinds::TROJAN_PASSWORD
        );
    }

    #[test]
    fn looks_through_websocket_and_nested_containers() {
        let json = format!(
            r#"{{"type":"ws","targets":[{{"matching_path":"/p","protocol":{}}}]}}"#,
            tls_wrapping(VLESS)
        );
        assert_eq!(credential_kinds(&parse(&json)), CredentialKinds::UUID);
    }

    #[test]
    fn unions_the_kinds_across_sni_targets() {
        let json = format!(
            r#"{{"type":"tls","tls_targets":{{"a.example":{{"cert":"c","key":"k","protocol":{VLESS}}},"b.example":{{"cert":"c","key":"k","protocol":{TROJAN}}}}}}}"#
        );
        let kinds = credential_kinds(&parse(&json));
        assert!(kinds.uuid && kinds.trojan_password);
    }

    #[test]
    fn reports_no_kinds_for_protocols_not_wired_up_yet() {
        for json in [
            r#"{"type":"http"}"#,
            r#"{"type":"socks"}"#,
            r#"{"type":"snell","cipher":"aes-256-gcm","password":"p"}"#,
            r#"{"type":"forward","targets":"127.0.0.1:80"}"#,
        ] {
            assert!(
                credential_kinds(&parse(json)).is_empty(),
                "expected no registry credentials for {json}"
            );
        }
    }

    #[test]
    fn classifies_hysteria2_as_a_cleartext_password() {
        // Its password arrives in an HTTP/3 header as sent, so unlike trojan there is
        // nothing to hash before the lookup -- a distinct kind, not a shared one.
        let kinds = credential_kinds(&parse(r#"{"type":"hysteria2","password":"p"}"#));
        assert_eq!(kinds, CredentialKinds::PLAIN_PASSWORD);
        assert!(!kinds.trojan_password, "the password is not hashed");
    }

    #[test]
    fn classifies_tuic_as_a_uuid_and_a_password_together() {
        // The one kind that needs two fields. `uuid` is set as well as `tuic` because
        // the uuid really is the index key the lookup hits; `tuic` is what says the
        // password beside it is required rather than optional.
        for json in [
            r#"{"type":"tuic","uuid":"b85798ef-e9dc-46a4-9a87-8da4499d36d0","password":"p"}"#,
            r#"{"type":"tuicv5","uuid":"b85798ef-e9dc-46a4-9a87-8da4499d36d0","password":"p"}"#,
        ] {
            let kinds = credential_kinds(&parse(json));
            assert_eq!(kinds, CredentialKinds::TUIC, "for {json}");
            assert!(kinds.uuid);
            assert!(kinds.tuic);
            // Not a plain-password inbound: the password never authenticates alone.
            assert!(!kinds.plain_password);
            assert!(kinds.conflict().is_none());
        }
    }

    #[test]
    fn classifies_anytls_as_its_own_hashed_password() {
        // The same cleartext value trojan and hysteria2 start from, hashed a third
        // way. A distinct kind, not a shared one -- and not a conflict with either,
        // because one `password` field still serves all three.
        let kinds = credential_kinds(&parse(
            r#"{"type":"anytls","users":[{"name":"alice","password":"p"}]}"#,
        ));
        assert_eq!(kinds, CredentialKinds::ANYTLS_PASSWORD);
        assert!(!kinds.trojan_password && !kinds.plain_password);

        let mut with_trojan = kinds;
        with_trojan.merge(CredentialKinds::TROJAN_PASSWORD);
        assert!(with_trojan.conflict().is_none());

        // But a base64 PSK and a cleartext password still cannot share a field.
        let mut with_ss = kinds;
        with_ss.merge(CredentialKinds::shadowsocks_psk(16));
        assert!(with_ss.conflict().is_some());
    }

    #[test]
    fn classifies_naiveproxy_as_an_http_basic_credential() {
        for json in [
            r#"{"type":"naiveproxy","users":[{"username":"u","password":"p"}]}"#,
            r#"{"type":"naive","users":[{"username":"u","password":"p"}]}"#,
        ] {
            let kinds = credential_kinds(&parse(json));
            assert_eq!(kinds, CredentialKinds::NAIVE_BASIC, "for {json}");
            // The password is half a credential here, never one on its own.
            assert!(!kinds.plain_password && !kinds.trojan_password);
        }
    }

    #[test]
    fn classifies_shadowsocks_only_where_identity_headers_exist() {
        // The two AES 2022 ciphers can name a user, and the length travels with them.
        for (cipher, len) in [("aes-128-gcm", 16), ("aes-256-gcm", 32)] {
            let json = format!(
                r#"{{"type":"ss","cipher":"2022-blake3-{cipher}","password":"{}"}}"#,
                base64_of(len)
            );
            assert_eq!(
                credential_kinds(&parse(&json)),
                CredentialKinds::shadowsocks_psk(len),
                "{cipher} should be registry-backed with a {len} byte psk"
            );
        }

        // chacha20 has no way to build an identity header, and legacy shadowsocks has
        // no header at all -- both stay single-user.
        for json in [
            &format!(
                r#"{{"type":"ss","cipher":"2022-blake3-chacha20-ietf-poly1305","password":"{}"}}"#,
                base64_of(32)
            ),
            &r#"{"type":"ss","cipher":"aes-256-gcm","password":"hunter2"}"#.to_string(),
        ] {
            assert!(
                credential_kinds(&parse(json)).is_empty(),
                "expected no registry credentials for {json}"
            );
        }
    }

    #[test]
    fn looks_through_tls_to_a_shadowsocks_target() {
        let inner = format!(
            r#"{{"type":"ss","cipher":"2022-blake3-aes-128-gcm","password":"{}"}}"#,
            base64_of(16)
        );
        assert_eq!(
            credential_kinds(&parse(&tls_wrapping(&inner))),
            CredentialKinds::shadowsocks_psk(16)
        );
    }

    #[test]
    fn a_target_that_cannot_serve_a_registry_is_named() {
        // A tree mixing a registry-backed target with one that cannot act on a
        // registry. `credential_kinds` is non-empty because of the VLESS half, so
        // this is the check that has to catch the other half -- otherwise the
        // shadowsocks handler is built with a registry and no identity header to
        // consult it with, which is not a listener that can start.
        let mixed = format!(
            r#"{{"type":"tls","tls_targets":{{
                 "a.example.com":{{"cert":"c","key":"k","protocol":{VLESS}}},
                 "b.example.com":{{"cert":"c","key":"k","protocol":{{
                    "type":"ss","cipher":"2022-blake3-chacha20-ietf-poly1305","password":"{}"
                 }}}}
               }}}}"#,
            base64_of(32)
        );
        let reason = unservable_registry_target(&parse(&mixed))
            .expect("the chacha20 target cannot serve a user list");
        assert!(reason.contains("chacha20"), "unexpected reason: {reason}");
        assert!(
            !credential_kinds(&parse(&mixed)).is_empty(),
            "the vless half is what makes this tree look servable"
        );

        // The aes ciphers can, and nothing else in the tree objects.
        let aes = format!(
            r#"{{"type":"ss","cipher":"2022-blake3-aes-128-gcm","password":"{}"}}"#,
            base64_of(16)
        );
        assert!(unservable_registry_target(&parse(&tls_wrapping(&aes))).is_none());
        assert!(unservable_registry_target(&parse(VLESS)).is_none());

        // Legacy shadowsocks keeps the credential the operator wrote, the same as a
        // snell or http target sharing the inbound would, so it is not refused.
        let legacy = r#"{"type":"ss","cipher":"aes-256-gcm","password":"hunter2"}"#;
        assert!(unservable_registry_target(&parse(legacy)).is_none());
    }

    #[test]
    fn a_shadowsocks_inbound_keeps_its_own_password() {
        // Unlike VLESS' `user_id`, an SS2022 inbound's `password` is its identity PSK:
        // it names the inbound, every client must know it, and it is still consulted in
        // dynamic mode. So it must not be rejected or replaced.
        let original = inbound(&format!(
            r#"{{"type":"ss","cipher":"2022-blake3-aes-128-gcm","password":"{}"}}"#,
            base64_of(16)
        ));
        let mut config: Value = serde_json::from_str(&original).unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        assert_eq!(config, serde_json::from_str::<Value>(&original).unwrap());
    }

    #[test]
    fn installs_a_placeholder_at_every_depth() {
        let mut config: Value = serde_json::from_str(
            r#"{"address":"0.0.0.0:443","protocol":{"type":"tls","tls_targets":{"a":{"cert":"c","key":"k","protocol":{"type":"vless"}}}}}"#,
        )
        .unwrap();

        install_placeholder_credentials(&mut config).unwrap();

        let filled = config["protocol"]["tls_targets"]["a"]["protocol"]["user_id"]
            .as_str()
            .expect("placeholder uuid installed");
        assert!(credential::parse_uuid(filled).is_ok());
    }

    #[test]
    fn reaches_every_nesting_position_shoes_accepts() {
        // One case per container key, including the aliases, since a spelling the
        // walk does not know would skip that subtree and leave `user_id` missing.
        let cases: &[(&str, &str)] = &[
            (
                r#"{"type":"tls","tls_targets":{"a":{"cert":"c","key":"k","protocol":{"type":"vless"}}}}"#,
                "/protocol/tls_targets/a/protocol/user_id",
            ),
            (
                r#"{"type":"tls","sni_targets":{"a":{"cert":"c","key":"k","protocol":{"type":"vless"}}}}"#,
                "/protocol/sni_targets/a/protocol/user_id",
            ),
            (
                r#"{"type":"tls","targets":{"a":{"cert":"c","key":"k","protocol":{"type":"vless"}}}}"#,
                "/protocol/targets/a/protocol/user_id",
            ),
            (
                r#"{"type":"tls","default_tls_target":{"cert":"c","key":"k","protocol":{"type":"vless"}}}"#,
                "/protocol/default_tls_target/protocol/user_id",
            ),
            (
                r#"{"type":"tls","default_target":{"cert":"c","key":"k","protocol":{"type":"vless"}}}"#,
                "/protocol/default_target/protocol/user_id",
            ),
            (
                r#"{"type":"tls","reality_targets":{"a":{"private_key":"k","dest":"a:443","protocol":{"type":"vless"}}}}"#,
                "/protocol/reality_targets/a/protocol/user_id",
            ),
            (
                r#"{"type":"tls","shadowtls_targets":{"a":{"password":"p","handshake":{"address":"a:443"},"protocol":{"type":"trojan"}}}}"#,
                "/protocol/shadowtls_targets/a/protocol/password",
            ),
            // Websocket's `targets` is `OneOrSome`, so it takes a list...
            (
                r#"{"type":"ws","targets":[{"matching_path":"/p","protocol":{"type":"vless"}}]}"#,
                "/protocol/targets/0/protocol/user_id",
            ),
            // ...or a bare object, which shares a key with the SNI map above and is
            // told apart only by carrying `protocol` itself.
            (
                r#"{"type":"ws","target":{"matching_path":"/p","protocol":{"type":"vless"}}}"#,
                "/protocol/target/protocol/user_id",
            ),
        ];

        for (protocol, pointer) in cases {
            let mut config: Value = serde_json::from_str(&format!(
                r#"{{"address":"0.0.0.0:443","protocol":{protocol}}}"#
            ))
            .unwrap();
            install_placeholder_credentials(&mut config).unwrap();
            assert!(
                config.pointer(pointer).and_then(Value::as_str).is_some(),
                "no placeholder at {pointer} for {protocol}"
            );
        }
    }

    #[test]
    fn leaves_outbound_credentials_in_the_rules_untouched() {
        // The `client_chain` protocol object is indistinguishable from an inbound's,
        // but its `user_id` belongs to the far end and is genuinely required. A walk
        // that searched the payload for `type: vless` would reject this config for
        // carrying a field it needs -- and this is the shape a chained inbound
        // actually uses, not a corner case.
        let original = r#"{
            "address":"127.0.0.1:18443",
            "protocol":{"type":"vless"},
            "rules":[{"masks":"0.0.0.0/0","action":"allow","client_chain":{
                "address":"127.0.0.1:19443",
                "protocol":{"type":"vless","user_id":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}
            }}]
        }"#;
        let mut config: Value = serde_json::from_str(original).unwrap();
        install_placeholder_credentials(&mut config).unwrap();

        let before: Value = serde_json::from_str(original).unwrap();
        assert_eq!(
            config["rules"], before["rules"],
            "the outbound credential must survive verbatim"
        );
        // The inbound's own credential is still filled in.
        assert!(config["protocol"]["user_id"].as_str().is_some());
    }

    #[test]
    fn a_missing_outbound_credential_is_not_papered_over() {
        // The other half of the same rule: injecting a throwaway here would dial out
        // with a credential nobody granted, instead of failing to parse.
        let mut config: Value = serde_json::from_str(
            r#"{"address":"127.0.0.1:18443","protocol":{"type":"vless"},
                "rules":[{"masks":"0.0.0.0/0","action":"allow",
                          "client_chain":{"address":"127.0.0.1:19443","protocol":{"type":"vless"}}}]}"#,
        )
        .unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        assert!(
            config["rules"][0]["client_chain"]["protocol"]
                .get("user_id")
                .is_none()
        );
    }

    #[test]
    fn placeholders_are_not_a_fixed_constant() {
        let template = inbound(r#"{"type":"vless"}"#);
        let mut first: Value = serde_json::from_str(&template).unwrap();
        let mut second: Value = serde_json::from_str(&template).unwrap();
        install_placeholder_credentials(&mut first).unwrap();
        install_placeholder_credentials(&mut second).unwrap();
        assert_ne!(first["protocol"]["user_id"], second["protocol"]["user_id"]);
    }

    #[test]
    fn rejects_a_config_credential_in_dynamic_mode() {
        let mut config: Value = serde_json::from_str(&inbound(VLESS)).unwrap();
        let err = install_placeholder_credentials(&mut config).unwrap_err();
        assert!(matches!(err, EngineError::InvalidConfig(_)));
        assert!(err.to_string().contains("user_id"));

        // Including one buried in a nested target, which is where it is easiest to
        // believe a credential is still doing something.
        let mut config: Value = serde_json::from_str(&inbound(&tls_wrapping(TROJAN))).unwrap();
        assert!(install_placeholder_credentials(&mut config).is_err());
    }

    #[test]
    fn leaves_other_protocols_alone() {
        // Snell has no multi-user identity mechanism, so its password is a real
        // credential and this pass must not touch it.
        let original = inbound(r#"{"type":"snell","cipher":"aes-256-gcm","password":"p"}"#);
        let mut config: Value = serde_json::from_str(&original).unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        assert_eq!(config, serde_json::from_str::<Value>(&original).unwrap());
    }

    #[test]
    fn fills_in_a_hysteria2_password() {
        // Its `password` is non-optional in shoes' schema but dead in dynamic mode, so
        // it gets a throwaway like vless' `user_id` does -- and a declared one is an
        // error rather than a value that quietly stops being consulted.
        let mut config: Value = serde_json::from_str(&inbound(r#"{"type":"hysteria2"}"#)).unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        let filled = config["protocol"]["password"]
            .as_str()
            .expect("hysteria2 should get a placeholder password");
        assert!(!filled.is_empty());

        let mut declared: Value =
            serde_json::from_str(&inbound(r#"{"type":"hysteria2","password":"p"}"#)).unwrap();
        let err = install_placeholder_credentials(&mut declared).unwrap_err();
        assert!(err.to_string().contains("password"));
    }

    #[test]
    fn fills_in_both_halves_of_a_tuic_credential() {
        // The case `PLACEHOLDER_FIELDS` became a list for. Filling only one of the two
        // would leave shoes' deserializer reporting the other as missing.
        for tag in ["tuic", "tuicv5"] {
            let mut config: Value =
                serde_json::from_str(&inbound(&format!(r#"{{"type":"{tag}"}}"#))).unwrap();
            install_placeholder_credentials(&mut config).unwrap();
            let uuid = config["protocol"]["uuid"]
                .as_str()
                .unwrap_or_else(|| panic!("{tag} should get a placeholder uuid"));
            let password = config["protocol"]["password"]
                .as_str()
                .unwrap_or_else(|| panic!("{tag} should get a placeholder password"));
            assert!(!uuid.is_empty() && !password.is_empty());
            assert_ne!(uuid, password, "two throwaways, not one value twice");

            // Either half being declared is an error, and nothing is filled in on the
            // way to reporting it.
            for declared in [
                format!(r#"{{"type":"{tag}","uuid":"b85798ef-e9dc-46a4-9a87-8da4499d36d0"}}"#),
                format!(r#"{{"type":"{tag}","password":"p"}}"#),
            ] {
                let mut config: Value = serde_json::from_str(&inbound(&declared)).unwrap();
                let err = install_placeholder_credentials(&mut config).unwrap_err();
                assert!(
                    matches!(err, EngineError::InvalidConfig(_)),
                    "for {declared}"
                );
            }
        }
    }

    #[test]
    fn fills_in_an_anytls_user_list() {
        // The list-shaped case. `users` is a `OneOrSome`, which refuses an empty
        // list, so the placeholder has to be a one-element list rather than a value.
        let mut config: Value = serde_json::from_str(&inbound(r#"{"type":"anytls"}"#)).unwrap();
        install_placeholder_credentials(&mut config).unwrap();

        let users = config["protocol"]["users"]
            .as_array()
            .expect("anytls should get a placeholder user list");
        assert_eq!(users.len(), 1);
        assert!(
            users[0]["password"].as_str().is_some_and(|p| !p.is_empty()),
            "the throwaway user needs a password"
        );

        // Declared credentials are refused rather than overwritten, under either
        // spelling of the field.
        for declared in [
            r#"{"type":"anytls","users":[{"name":"alice","password":"p"}]}"#,
            r#"{"type":"anytls","user":{"password":"p"}}"#,
        ] {
            let mut config: Value = serde_json::from_str(&inbound(declared)).unwrap();
            let err = install_placeholder_credentials(&mut config).unwrap_err();
            assert!(
                matches!(err, EngineError::InvalidConfig(_)),
                "for {declared}"
            );
        }
    }

    #[test]
    fn fills_in_a_naiveproxy_user_list() {
        // Two fields per member rather than one, and both spellings of the tag.
        for tag in ["naiveproxy", "naive"] {
            let mut config: Value =
                serde_json::from_str(&inbound(&format!(r#"{{"type":"{tag}"}}"#))).unwrap();
            install_placeholder_credentials(&mut config).unwrap();

            let users = config["protocol"]["users"].as_array().unwrap();
            assert_eq!(users.len(), 1, "for {tag}");
            let username = users[0]["username"].as_str().unwrap();
            let password = users[0]["password"].as_str().unwrap();
            assert!(!username.is_empty() && !password.is_empty());
            assert_ne!(username, password, "two throwaways, not one value twice");

            let mut declared: Value = serde_json::from_str(&inbound(&format!(
                r#"{{"type":"{tag}","users":[{{"username":"u","password":"p"}}]}}"#
            )))
            .unwrap();
            assert!(install_placeholder_credentials(&mut declared).is_err());
        }
    }

    #[test]
    fn a_filled_payload_still_deserializes() {
        // The point of the placeholder: the payload must survive shoes' own schema.
        let mut config: Value =
            serde_json::from_str(&inbound(&tls_wrapping(r#"{"type":"vless"}"#))).unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        let text = serde_json::to_string(&config["protocol"]).unwrap();
        let parsed: ServerProxyConfig = serde_yaml::from_str(&text).unwrap();
        assert_eq!(credential_kinds(&parsed), CredentialKinds::UUID);
    }

    #[test]
    fn labels_a_tls_inbound_that_upstream_renders_as_empty() {
        // A default target and nothing else: `Display` yields "", which used to reach
        // the API as `"protocol": ""`.
        let only_default = parse(&format!(
            r#"{{"type":"tls","default_tls_target":{{"cert":"c","key":"k","protocol":{VLESS}}}}}"#
        ));
        assert_eq!(only_default.to_string(), "", "upstream behaviour changed");
        assert_eq!(display_name(&only_default), "TLS");

        // Where upstream does produce a label, it is passed through unchanged.
        assert_eq!(display_name(&parse(VLESS)), "Vless");
        assert_eq!(display_name(&parse(&tls_wrapping(VLESS))), "TLS");
    }
}
