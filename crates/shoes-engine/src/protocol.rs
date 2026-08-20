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

        // Authenticates, but not through the registry yet. Snell has no multi-user
        // identity mechanism at all, AnyTLS and NaiveProxy already have their own
        // multi-user tables, and Hysteria2 and TUIC authenticate inside their QUIC
        // accept loops rather than through a `TcpServerHandler`.
        ServerProxyConfig::Snell { .. }
        | ServerProxyConfig::Anytls { .. }
        | ServerProxyConfig::Naiveproxy { .. }
        | ServerProxyConfig::Hysteria2 { .. }
        | ServerProxyConfig::TuicV5 { .. } => {}

        // Either no credentials at all, or plain proxy credentials that identify a
        // client but not a billable user.
        ServerProxyConfig::Http { .. }
        | ServerProxyConfig::Socks { .. }
        | ServerProxyConfig::Mixed { .. }
        | ServerProxyConfig::PortForward { .. } => {}
    }

    kinds
}

/// A human-readable label for an inbound's protocol, for logs and API responses.
///
/// This exists only to guarantee the label is non-empty. Upstream's `Display` builds a
/// `Tls` label from its populated target maps and never consults `default_tls_target`
/// (`shoes/src/config/types/server.rs:794`), so a TLS inbound configured with only a
/// default target renders as the empty string -- which then surfaced as an empty
/// `InboundInfo::protocol`. Substituting a label here keeps the fix on the
/// engine's side of the boundary; patching upstream's `Display` would mean carrying a
/// cosmetic diff through every merge of `shoes/`.
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

/// The leaf credential field each registry-backed protocol declares in its config.
const PLACEHOLDER_FIELDS: &[(&str, &str)] = &[
    ("vless", "user_id"),
    ("vmess", "user_id"),
    ("trojan", "password"),
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

    let Some((_, field)) = PLACEHOLDER_FIELDS.iter().find(|(name, _)| *name == kind) else {
        return Ok(());
    };

    if map.contains_key(*field) {
        return Err(EngineError::InvalidConfig(format!(
            "remove `{field}` from the {kind} protocol: this inbound has a `users` list, \
             which is its only authority, so a credential in the config would be ignored"
        )));
    }

    map.insert(
        (*field).to_string(),
        Value::String(credential::random_uuid()),
    );
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
            r#"{"type":"hysteria2","password":"p"}"#,
            r#"{"type":"forward","targets":"127.0.0.1:80"}"#,
        ] {
            assert!(
                credential_kinds(&parse(json)).is_empty(),
                "expected no registry credentials for {json}"
            );
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
        let mut config: Value = serde_json::from_str(&format!(
            r#"{{"address":"0.0.0.0:443","protocol":{{"type":"tls","tls_targets":{{"a":{{"cert":"c","key":"k","protocol":{{"type":"vless"}}}}}}}}}}"#
        ))
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
        let original = inbound(r#"{"type":"hysteria2","password":"p"}"#);
        let mut config: Value = serde_json::from_str(&original).unwrap();
        install_placeholder_credentials(&mut config).unwrap();
        assert_eq!(config, serde_json::from_str::<Value>(&original).unwrap());
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
