//! Bootstrap configuration loaded before an ACP session can be opened.
//!
//! The wire-facing topology is supplied by the panel; this deliberately small
//! TOML file only says how to reach and authenticate that panel and where local
//! diagnostics should go.  Its validation mirrors Go's `internal/config` so a
//! file can be moved between the two agents without changing its meaning.

use std::fmt;
use std::path::Path;

use serde::Deserialize;
use url::Url;

pub const PANEL_GRPC_SCHEME_PLAINTEXT: &str = "grpc";
pub const PANEL_GRPC_SCHEME_TLS: &str = "grpcs";
pub const DEFAULT_TRAFFIC_REPORT_MIN_DELTA_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub panel_grpc_endpoint: String,
    pub panel_grpc_address: String,
    pub panel_grpc_scheme: String,
    pub panel_grpc_server_name: String,
    pub machine_id: String,
    pub node_id: String,
    pub machine_secret: String,
    pub ca_cert_path: String,
    pub tls_insecure_skip_verify: bool,
    pub debug: bool,
    pub log_file_path: String,
    pub traffic_report_min_delta_bytes: u64,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(std::io::Error),
    Decode(toml::de::Error),
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "{error}"),
            Self::Decode(error) => write!(f, "{error}"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    panel_grpc_endpoint: String,
    #[serde(default)]
    machine_id: String,
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    machine_secret: String,
    #[serde(default)]
    ca_cert_path: String,
    #[serde(default)]
    tls_insecure_skip_verify: bool,
    #[serde(default)]
    debug: bool,
    #[serde(default)]
    log_file_path: String,
    traffic_report_min_delta_bytes: Option<u64>,
}

pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let source = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
    parse(&source)
}

pub fn parse(source: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(source).map_err(ConfigError::Decode)?;
    let traffic_report_min_delta_bytes = match raw.traffic_report_min_delta_bytes {
        Some(0) => {
            return Err(ConfigError::Invalid(
                "traffic_report_min_delta_bytes must be greater than 0",
            ));
        }
        Some(value) => value,
        None => DEFAULT_TRAFFIC_REPORT_MIN_DELTA_BYTES,
    };

    if raw.panel_grpc_endpoint.is_empty() {
        return Err(ConfigError::Invalid("panel_grpc_endpoint is required"));
    }
    let endpoint = parse_panel_grpc_endpoint(&raw.panel_grpc_endpoint)?;
    if endpoint.scheme == PANEL_GRPC_SCHEME_PLAINTEXT && !raw.ca_cert_path.is_empty() {
        return Err(ConfigError::Invalid(
            "ca_cert_path requires a grpcs:// panel_grpc_endpoint",
        ));
    }
    if raw.machine_id.is_empty() {
        return Err(ConfigError::Invalid("machine_id is required"));
    }
    if raw.node_id.is_empty() {
        return Err(ConfigError::Invalid("node_id is required"));
    }
    if raw.machine_secret.is_empty() {
        return Err(ConfigError::Invalid("machine_secret is required"));
    }

    Ok(Config {
        panel_grpc_endpoint: raw.panel_grpc_endpoint,
        panel_grpc_address: endpoint.address,
        panel_grpc_scheme: endpoint.scheme,
        panel_grpc_server_name: endpoint.server_name,
        machine_id: raw.machine_id,
        node_id: raw.node_id,
        machine_secret: raw.machine_secret,
        ca_cert_path: raw.ca_cert_path,
        tls_insecure_skip_verify: raw.tls_insecure_skip_verify,
        debug: raw.debug,
        log_file_path: raw.log_file_path,
        traffic_report_min_delta_bytes,
    })
}

struct ParsedEndpoint {
    address: String,
    scheme: String,
    server_name: String,
}

fn parse_panel_grpc_endpoint(raw: &str) -> Result<ParsedEndpoint, ConfigError> {
    if raw != raw.trim() {
        return Err(ConfigError::Invalid(
            "panel_grpc_endpoint must not contain leading or trailing whitespace",
        ));
    }
    if raw
        .as_bytes()
        .iter()
        .any(|byte| *byte < b' ' || *byte == 0x7f)
    {
        // WHATWG URL parsing removes tabs and newlines before parsing. Go's
        // net/url rejects every ASCII control byte instead, so accepting one
        // here could silently select a different host than the configured text.
        return Err(ConfigError::Invalid(
            "panel_grpc_endpoint must not contain ASCII control characters",
        ));
    }

    // Go's net/url records an empty trailing query via ForceQuery and discards
    // an empty fragment. The Go validator only inspects RawQuery/Fragment, so
    // these spellings are accepted even though `url::Url` exposes them as
    // `Some("")`.
    let parse_input = without_go_empty_query_or_fragment(raw);
    if let Some(endpoint) = parse_scoped_ipv6_endpoint(parse_input) {
        return endpoint;
    }
    validate_go_host_lexical_form(parse_input)?;

    let parsed = Url::parse(parse_input).map_err(|_| {
        ConfigError::Invalid("panel_grpc_endpoint must include a valid host and port")
    })?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != PANEL_GRPC_SCHEME_PLAINTEXT && scheme != PANEL_GRPC_SCHEME_TLS {
        return Err(ConfigError::Invalid(
            "panel_grpc_endpoint must use grpc:// or grpcs://",
        ));
    }
    // `url::Url` represents an explicitly empty userinfo (`//@host`) with an
    // empty username and no password. Go still sets URL.User in that case, so
    // inspect the lexical authority as well as the decoded fields.
    if authority(parse_input).is_some_and(|authority| authority.contains('@'))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !parsed.path().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "panel_grpc_endpoint must contain only a scheme, host, and port",
        ));
    }
    let port = parsed
        .port()
        .filter(|port| *port != 0)
        .ok_or(ConfigError::Invalid(
            "panel_grpc_endpoint must include a valid host and port",
        ))?;
    let (address, server_name) = match parsed.host() {
        Some(url::Host::Ipv6(host)) => (format!("[{host}]:{port}"), host.to_string()),
        Some(url::Host::Ipv4(host)) => (format!("{host}:{port}"), host.to_string()),
        Some(url::Host::Domain(host)) if !host.is_empty() => {
            (format!("{host}:{port}"), host.to_owned())
        }
        None => {
            return Err(ConfigError::Invalid(
                "panel_grpc_endpoint must include a valid host and port",
            ));
        }
        Some(url::Host::Domain(_)) => {
            return Err(ConfigError::Invalid(
                "panel_grpc_endpoint must include a valid host and port",
            ));
        }
    };

    Ok(ParsedEndpoint {
        address,
        scheme,
        server_name,
    })
}

fn without_go_empty_query_or_fragment(raw: &str) -> &str {
    if let Some(raw) = raw.strip_suffix("?#") {
        raw
    } else if let Some(without_query) = raw.strip_suffix('?') {
        // A question mark inside the fragment is fragment data, not an empty
        // query (for example `host:443#?`).
        if without_query.contains('#') {
            raw
        } else {
            without_query
        }
    } else if let Some(raw) = raw.strip_suffix('#') {
        raw
    } else {
        raw
    }
}

fn authority(raw: &str) -> Option<&str> {
    let (_, remainder) = raw.split_once("://")?;
    let end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    Some(&remainder[..end])
}

fn validate_go_host_lexical_form(raw: &str) -> Result<(), ConfigError> {
    let Some(raw_authority) = authority(raw) else {
        return Ok(());
    };
    // Go finds userinfo using the last '@' and applies host escaping rules only
    // to the suffix. Userinfo is rejected separately by our endpoint shape
    // check, but it must not hide malformed host text from this preflight.
    let host = raw_authority
        .rsplit_once('@')
        .map_or(raw_authority, |(_, host)| host);
    let bytes = host.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(high) = bytes.get(index + 1).and_then(|value| decode_hex(*value)) else {
                return Err(invalid_panel_host());
            };
            let Some(low) = bytes.get(index + 2).and_then(|value| decode_hex(*value)) else {
                return Err(invalid_panel_host());
            };
            let decoded = (high << 4) | low;
            // net/url's encodeHost permits percent-encoding only for
            // non-ASCII bytes, with RFC 6874's literal `%25` as the sole ASCII
            // exception. In particular `%41` must not turn into `A` here.
            if decoded < 0x80 && &bytes[index..index + 3] != b"%25" {
                return Err(invalid_panel_host());
            }
            index += 3;
            continue;
        }
        if byte.is_ascii() && !go_url_host_byte_is_allowed(byte) {
            return Err(invalid_panel_host());
        }
        index += 1;
    }
    Ok(())
}

fn invalid_panel_host() -> ConfigError {
    ConfigError::Invalid("panel_grpc_endpoint must include a valid host and port")
}

/// Parses the RFC 6874 spelling accepted by Go's `net/url`.
///
/// The WHATWG-oriented `url` crate intentionally rejects scoped IPv6 address
/// literals. Keep the common endpoint path on that mature parser and handle
/// only the bracketed `%25zone` form here.
fn parse_scoped_ipv6_endpoint(raw: &str) -> Option<Result<ParsedEndpoint, ConfigError>> {
    let (raw_scheme, remainder) = raw.split_once("://")?;
    let raw_authority = authority(raw)?;
    if !raw_authority.starts_with('[') || !raw_authority.contains("%25") {
        return None;
    }

    let invalid_shape =
        || ConfigError::Invalid("panel_grpc_endpoint must contain only a scheme, host, and port");
    let invalid_host =
        || ConfigError::Invalid("panel_grpc_endpoint must include a valid host and port");

    let scheme = raw_scheme.to_ascii_lowercase();
    if scheme != PANEL_GRPC_SCHEME_PLAINTEXT && scheme != PANEL_GRPC_SCHEME_TLS {
        return Some(Err(ConfigError::Invalid(
            "panel_grpc_endpoint must use grpc:// or grpcs://",
        )));
    }
    if remainder != raw_authority || raw_authority.contains('@') {
        return Some(Err(invalid_shape()));
    }

    let Some(close_bracket) = raw_authority.rfind(']') else {
        return Some(Err(invalid_host()));
    };
    let Some(host_literal) = raw_authority.get(1..close_bracket) else {
        return Some(Err(invalid_host()));
    };
    let Some(port) = raw_authority
        .get(close_bracket + 1..)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return Some(Err(invalid_host()));
    };
    if port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
        return Some(Err(invalid_host()));
    }

    let (ipv6, encoded_zone) = host_literal.split_once("%25")?;
    if ipv6.parse::<std::net::Ipv6Addr>().is_err() || encoded_zone.is_empty() {
        return Some(Err(invalid_host()));
    }
    let Some(zone) = decode_rfc6874_zone(encoded_zone) else {
        return Some(Err(invalid_host()));
    };
    if zone.is_empty() {
        return Some(Err(invalid_host()));
    }

    let server_name = format!("{ipv6}%{zone}");
    let address = format!("[{server_name}]:{port}");
    // Tonic stores the destination as an HTTP URI. Go's net/url permits a
    // broader set of zone bytes (notably an escaped space in Windows interface
    // names), but accepting one of those would only defer a deterministic
    // InvalidUriChar failure until PanelClient starts. Keep the useful RFC 6874
    // subset and reject addresses the actual Rust transport cannot represent.
    if tonic::transport::Endpoint::from_shared(format!("http://{address}")).is_err() {
        return Some(Err(invalid_host()));
    }
    Some(Ok(ParsedEndpoint {
        address,
        scheme,
        server_name,
    }))
}

fn decode_rfc6874_zone(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            if bytes[index].is_ascii() && !go_url_host_byte_is_allowed(bytes[index]) {
                return None;
            }
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = decode_hex(*bytes.get(index + 1)?)?;
        let low = decode_hex(*bytes.get(index + 2)?)?;
        let value = (high << 4) | low;
        // Go makes two RFC 6874 exceptions here: an escaped percent starts or
        // appears inside a zone, and Windows interface names may contain an
        // escaped space. Other escaped bytes must be legal host bytes.
        if value != b'%' && value != b' ' && !go_url_host_byte_is_allowed(value) {
            return None;
        }
        decoded.push(value);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

fn go_url_host_byte_is_allowed(value: u8) -> bool {
    value.is_ascii_alphanumeric()
        || matches!(
            value,
            b'!' | b'"'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'['
                | b']'
                | b'_'
                | b'~'
        )
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(endpoint: &str) -> String {
        format!(
            r#"panel_grpc_endpoint = "{endpoint}"
machine_id = "machine-1"
node_id = "node-1"
machine_secret = "secret"
"#,
        )
    }

    #[test]
    fn defaults_and_plaintext_endpoint_match_go() {
        let config = parse(&required("grpc://127.0.0.1:9090")).unwrap();
        assert_eq!(config.panel_grpc_address, "127.0.0.1:9090");
        assert_eq!(config.panel_grpc_scheme, PANEL_GRPC_SCHEME_PLAINTEXT);
        assert_eq!(config.panel_grpc_server_name, "127.0.0.1");
        assert_eq!(
            config.traffic_report_min_delta_bytes,
            DEFAULT_TRAFFIC_REPORT_MIN_DELTA_BYTES
        );
    }

    #[test]
    fn complete_production_flat_toml_preserves_every_go_field() {
        let config = parse(
            r#"panel_grpc_endpoint = "grpcs://panel.example.com:443"
machine_id = "machine-production"
node_id = "node-production"
machine_secret = "shared-secret"
ca_cert_path = "C:/acp/private-ca.pem"
tls_insecure_skip_verify = true
debug = true
log_file_path = "C:/acp/node-agent.log"
traffic_report_min_delta_bytes = 4194304
unknown_future_field = "ignored-by-both-agents"
"#,
        )
        .unwrap();

        assert_eq!(config.panel_grpc_endpoint, "grpcs://panel.example.com:443");
        assert_eq!(config.panel_grpc_address, "panel.example.com:443");
        assert_eq!(config.panel_grpc_scheme, PANEL_GRPC_SCHEME_TLS);
        assert_eq!(config.panel_grpc_server_name, "panel.example.com");
        assert_eq!(config.machine_id, "machine-production");
        assert_eq!(config.node_id, "node-production");
        assert_eq!(config.machine_secret, "shared-secret");
        assert_eq!(config.ca_cert_path, "C:/acp/private-ca.pem");
        assert!(config.tls_insecure_skip_verify);
        assert!(config.debug);
        assert_eq!(config.log_file_path, "C:/acp/node-agent.log");
        assert_eq!(config.traffic_report_min_delta_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn secure_and_ipv6_endpoints_are_normalized_for_tonic() {
        let secure = parse(&required("grpcs://panel.example.com:443")).unwrap();
        assert_eq!(secure.panel_grpc_address, "panel.example.com:443");
        assert_eq!(secure.panel_grpc_server_name, "panel.example.com");
        assert_eq!(secure.panel_grpc_scheme, PANEL_GRPC_SCHEME_TLS);

        let ipv6 = parse(&required("grpcs://[2001:db8::1]:8443")).unwrap();
        assert_eq!(ipv6.panel_grpc_address, "[2001:db8::1]:8443");
        assert_eq!(ipv6.panel_grpc_server_name, "2001:db8::1");
    }

    #[test]
    fn scoped_ipv6_endpoint_matches_go_rfc6874_decoding() {
        let config = parse(&required("grpcs://[fe80::1%25eth0]:8443")).unwrap();
        assert_eq!(config.panel_grpc_address, "[fe80::1%eth0]:8443");
        assert_eq!(config.panel_grpc_server_name, "fe80::1%eth0");
        assert_eq!(config.panel_grpc_scheme, PANEL_GRPC_SCHEME_TLS);

        let numeric = parse(&required("grpc://[fe80::1%253]:9090")).unwrap();
        assert_eq!(numeric.panel_grpc_address, "[fe80::1%3]:9090");

        for endpoint in [
            "grpc://[fe80::1%eth0]:9090",
            "grpc://[fe80::1%25]:9090",
            "grpc://[not-ipv6%25eth0]:9090",
            // Go accepts this spelling and decodes the interface name to
            // `Ethernet 2`; tonic cannot represent that authority as a URI.
            "grpc://[fe80::1%25Ethernet%202]:9090",
        ] {
            let error = parse(&required(endpoint)).unwrap_err();
            assert!(
                error.to_string().contains("panel_grpc_endpoint"),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn empty_query_and_fragment_match_go_but_empty_userinfo_does_not() {
        for endpoint in [
            "grpc://panel.example.com:9090?",
            "grpc://panel.example.com:9090#",
            "grpc://panel.example.com:9090?#",
            "grpcs://[2001:db8::1]:8443?#",
            "grpc://[fe80::1%25eth0]:9090?",
        ] {
            let config = parse(&required(endpoint)).unwrap();
            assert!(!config.panel_grpc_address.is_empty(), "{endpoint}");
        }

        for endpoint in [
            "grpc://@panel.example.com:9090",
            "grpc://:@panel.example.com:9090",
            "grpc://panel.example.com:9090#?",
        ] {
            let error = parse(&required(endpoint)).unwrap_err();
            assert!(
                error.to_string().contains("panel_grpc_endpoint"),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn go_lexical_preflight_rejects_whatwg_host_rewrites() {
        for endpoint in [
            "grpc://panel\texample.com:9090",
            "grpc://panel\rexample.com:9090",
            "grpc://panel\nexample.com:9090",
            "grpc://panel\0example.com:9090",
            "grpc://panel\u{7f}example.com:9090",
            "grpc://panel%ZZ.example.com:9090",
            "grpc://panel%.example.com:9090",
            "grpc://panel%2.example.com:9090",
            "grpc://%41.example.com:9090",
            "grpc://panel%2eexample.com:9090",
            "grpc://panel.example.com:%39%30%39%30",
            r"grpc://panel\example.com:9090",
            "grpc://panel^example.com:9090",
            "grpc://panel|example.com:9090",
            "grpc://panel example.com:9090",
        ] {
            let error = match parse_panel_grpc_endpoint(endpoint) {
                Err(error) => error,
                Ok(_) => panic!("Go-invalid endpoint {endpoint:?} was accepted"),
            };
            assert!(
                error.to_string().contains("panel_grpc_endpoint"),
                "{endpoint:?}: {error}"
            );
        }

        // Keep ordinary endpoints on their existing path while the lexical
        // guard protects it from WHATWG preprocessing.
        for endpoint in [
            "grpc://127.0.0.1:9090",
            "GRPC://Panel.Example.Com:09090",
            "grpcs://[2001:db8::1]:443",
            "grpc://[fe80::1%25eth0]:9090",
        ] {
            parse_panel_grpc_endpoint(endpoint).unwrap_or_else(|error| {
                panic!("ordinary endpoint {endpoint:?} regressed: {error}")
            });
        }
    }

    #[test]
    fn an_explicit_traffic_threshold_is_distinct_from_the_default() {
        let config = parse(
            &(required("grpc://127.0.0.1:9090") + "traffic_report_min_delta_bytes = 4194304\n"),
        )
        .unwrap();
        assert_eq!(config.traffic_report_min_delta_bytes, 4 * 1024 * 1024);

        let error =
            parse(&(required("grpc://127.0.0.1:9090") + "traffic_report_min_delta_bytes = 0\n"))
                .unwrap_err();
        assert!(error.to_string().contains("traffic_report_min_delta_bytes"));
    }

    #[test]
    fn invalid_endpoints_are_rejected_with_the_go_boundary() {
        for endpoint in [
            "127.0.0.1:9090",
            "https://panel.example.com:443",
            "grpcs://panel.example.com",
            "grpcs://panel.example.com:not-a-port",
            "grpcs://panel.example.com:65536",
            "grpcs://panel.example.com:443/api",
            " grpcs://panel.example.com:443",
            "grpcs://user@panel.example.com:443",
            "grpcs://panel.example.com:443?q=1",
        ] {
            let error = parse(&required(endpoint)).unwrap_err();
            assert!(
                error.to_string().contains("panel_grpc_endpoint"),
                "{endpoint}: {error}"
            );
        }
    }

    #[test]
    fn ca_file_requires_tls_but_insecure_is_ignored_for_plaintext() {
        let insecure =
            parse(&(required("grpc://127.0.0.1:9090") + "tls_insecure_skip_verify = true\n"))
                .unwrap();
        assert!(insecure.tls_insecure_skip_verify);

        let error = parse(&(required("grpc://127.0.0.1:9090") + "ca_cert_path = \"ca.pem\"\n"))
            .unwrap_err();
        assert!(error.to_string().contains("ca_cert_path"));
    }

    #[test]
    fn required_identity_fields_are_checked_in_go_order() {
        let missing_machine = r#"panel_grpc_endpoint = "grpc://127.0.0.1:9090"
node_id = "node-1"
machine_secret = "secret"
"#;
        assert_eq!(
            parse(missing_machine).unwrap_err().to_string(),
            "machine_id is required"
        );
    }
}
