//! Policy-aware DNS resolution.
//!
//! [`PolicyResolver`] selects an upstream resolver (or a local terminal action)
//! from the first hostname rule that matches. The implementation is deliberately
//! independent from configuration parsing so callers can resolve DNS server tags
//! first and then construct an immutable, cheaply shared resolver.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use regex::{Regex, RegexBuilder};

use crate::address::NetLocation;
use crate::resolver::Resolver;
use crate::routing::predicate::{
    RouteContext, RouteMatchConfig, RoutePredicate, RouteRuleSetConfig,
};

/// DNS response codes exposed by the ACP panel's predefined lookup action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError,
    NxDomain,
    Refused,
    ServFail,
}

impl DnsRcode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "" | "NOERROR" | "SUCCESS" => Some(Self::NoError),
            "NXDOMAIN" => Some(Self::NxDomain),
            "REFUSED" => Some(Self::Refused),
            "SERVFAIL" => Some(Self::ServFail),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::NxDomain => "NXDOMAIN",
            Self::Refused => "REFUSED",
            Self::ServFail => "SERVFAIL",
        }
    }
}

impl fmt::Display for DnsRcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Reject behavior supported by sing-box's DNS lookup path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRejectMethod {
    Default,
    Drop,
}

impl DnsRejectMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "default" => Some(Self::Default),
            "drop" => Some(Self::Drop),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Drop => "drop",
        }
    }
}

impl fmt::Display for DnsRejectMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The typed terminal failure selected by a DNS policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicyFailure {
    ResponseCode(DnsRcode),
    Rejected(DnsRejectMethod),
}

/// An address-resolver error that preserves DNS policy semantics for callers
/// which need to distinguish NXDOMAIN, REFUSED, SERVFAIL, and an explicit drop.
#[derive(Debug)]
pub struct DnsPolicyError {
    hostname: String,
    failure: DnsPolicyFailure,
}

impl DnsPolicyError {
    pub fn failure(&self) -> DnsPolicyFailure {
        self.failure
    }

    fn response_code(hostname: String, rcode: DnsRcode) -> Self {
        debug_assert_ne!(rcode, DnsRcode::NoError);
        Self {
            hostname,
            failure: DnsPolicyFailure::ResponseCode(rcode),
        }
    }

    fn rejected(hostname: String, method: DnsRejectMethod) -> Self {
        Self {
            hostname,
            failure: DnsPolicyFailure::Rejected(method),
        }
    }

    fn into_io_error(self) -> io::Error {
        let kind = match self.failure {
            DnsPolicyFailure::ResponseCode(DnsRcode::NxDomain) => io::ErrorKind::NotFound,
            DnsPolicyFailure::ResponseCode(DnsRcode::Refused) | DnsPolicyFailure::Rejected(_) => {
                io::ErrorKind::PermissionDenied
            }
            DnsPolicyFailure::ResponseCode(DnsRcode::ServFail) => io::ErrorKind::Other,
            DnsPolicyFailure::ResponseCode(DnsRcode::NoError) => {
                unreachable!("NOERROR is not a DNS policy failure")
            }
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for DnsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.failure {
            DnsPolicyFailure::ResponseCode(rcode) => {
                write!(
                    formatter,
                    "DNS policy returned {rcode} for {}",
                    self.hostname
                )
            }
            DnsPolicyFailure::Rejected(DnsRejectMethod::Default) => {
                write!(formatter, "DNS policy rejected {}", self.hostname)
            }
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop) => {
                write!(formatter, "DNS policy dropped lookup for {}", self.hostname)
            }
        }
    }
}

impl std::error::Error for DnsPolicyError {}

/// Validated predefined response projected onto the address-only lookup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPredefinedResponse {
    pub rcode: DnsRcode,
    pub addresses: Vec<IpAddr>,
}

impl DnsPredefinedResponse {
    pub fn new(rcode: DnsRcode, addresses: Vec<IpAddr>) -> Self {
        Self { rcode, addresses }
    }

    pub fn no_error(addresses: Vec<IpAddr>) -> Self {
        Self::new(DnsRcode::NoError, addresses)
    }
}

/// Conservative defaults for panel-provided DNS policy.
///
/// Rust's regex engine has linear-time matching, while its compiled programs can
/// still consume meaningful memory. These limits bound both the number of
/// programs and their individual compiled size before a policy becomes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub max_rules: usize,
    pub max_patterns_per_rule: usize,
    pub max_total_patterns: usize,
    pub max_regex_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub max_predefined_addresses_per_rule: usize,
    pub regex_size_limit: usize,
    pub regex_dfa_size_limit: usize,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_rules: 4_096,
            max_patterns_per_rule: 256,
            max_total_patterns: 16_384,
            max_regex_patterns: 512,
            max_pattern_bytes: 4_096,
            max_total_pattern_bytes: 4 * 1_024 * 1_024,
            max_predefined_addresses_per_rule: 256,
            regex_size_limit: 1_024 * 1_024,
            regex_dfa_size_limit: 2 * 1_024 * 1_024,
        }
    }
}

impl PolicyLimits {
    fn validate(self) -> io::Result<Self> {
        let non_zero = [
            ("max_rules", self.max_rules),
            ("max_patterns_per_rule", self.max_patterns_per_rule),
            ("max_total_patterns", self.max_total_patterns),
            ("max_regex_patterns", self.max_regex_patterns),
            ("max_pattern_bytes", self.max_pattern_bytes),
            ("max_total_pattern_bytes", self.max_total_pattern_bytes),
            (
                "max_predefined_addresses_per_rule",
                self.max_predefined_addresses_per_rule,
            ),
            ("regex_size_limit", self.regex_size_limit),
            ("regex_dfa_size_limit", self.regex_dfa_size_limit),
        ];
        if let Some((name, _)) = non_zero.into_iter().find(|(_, value)| *value == 0) {
            return Err(invalid_policy(format!(
                "policy limit {name} must be non-zero"
            )));
        }
        if self.max_patterns_per_rule > self.max_total_patterns {
            return Err(invalid_policy(
                "max_patterns_per_rule must not exceed max_total_patterns",
            ));
        }
        Ok(self)
    }
}

/// Terminal action selected by a DNS policy rule.
#[derive(Clone)]
pub enum PolicyAction {
    /// Resolve through the referenced upstream.
    Route(Arc<dyn Resolver>),
    /// Refuse the lookup without contacting an upstream.
    Reject(DnsRejectMethod),
    /// Return the configured A/AAAA address subset without contacting an upstream.
    /// An empty set is a successful NOERROR-style empty response.
    Predefined(DnsPredefinedResponse),
}

impl fmt::Debug for PolicyAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(resolver) => formatter.debug_tuple("Route").field(resolver).finish(),
            Self::Reject(method) => formatter.debug_tuple("Reject").field(method).finish(),
            Self::Predefined(response) => {
                formatter.debug_tuple("Predefined").field(response).finish()
            }
        }
    }
}

/// Uncompiled rule accepted by [`PolicyResolver::new`].
///
/// Pattern categories are ORed, matching sing-box's destination-domain group.
/// An empty pattern set is a catch-all rule. Rules are evaluated in input order.
#[derive(Debug, Clone)]
pub struct PolicyRuleSpec {
    pub exact: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
    pub regex: Vec<String>,
    /// Prevalidated local rule-set references. RoutePredicate evaluates these
    /// together with the direct hostname category using sing-box match-state
    /// merging (including nested invert semantics).
    pub rule_set: Vec<RouteRuleSetConfig>,
    pub action: PolicyAction,
    /// Optional timeout applied only to a matched route resolver call.
    pub timeout: Option<Duration>,
}

impl PolicyRuleSpec {
    pub fn new(action: PolicyAction) -> Self {
        Self {
            exact: Vec::new(),
            suffix: Vec::new(),
            keyword: Vec::new(),
            regex: Vec::new(),
            rule_set: Vec::new(),
            action,
            timeout: None,
        }
    }

    pub fn exact(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.exact.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn suffix(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.suffix.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn keyword(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.keyword.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn regex(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.regex.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn rule_set(mut self, values: impl IntoIterator<Item = RouteRuleSetConfig>) -> Self {
        self.rule_set.extend(values);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = (!timeout.is_zero()).then_some(timeout);
        self
    }
}

/// Immutable resolver that applies ordered hostname policy before its final
/// resolver.
#[derive(Debug)]
pub struct PolicyResolver {
    final_resolver: Arc<dyn Resolver>,
    named_upstreams: HashMap<String, Arc<dyn Resolver>>,
    rules: Box<[PolicyRule]>,
}

impl PolicyResolver {
    pub fn new(final_resolver: Arc<dyn Resolver>, rules: Vec<PolicyRuleSpec>) -> io::Result<Self> {
        Self::with_limits(final_resolver, rules, PolicyLimits::default())
    }

    /// Construct a policy resolver that also exposes its tagged transports for
    /// exact per-dialer resolution. Named lookups bypass hostname policy and do
    /// not mutate the final resolver used by ordinary consumers.
    pub fn with_named_upstreams(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        named_upstreams: impl IntoIterator<Item = (String, Arc<dyn Resolver>)>,
    ) -> io::Result<Self> {
        Self::with_limits_and_named_upstreams(
            final_resolver,
            rules,
            PolicyLimits::default(),
            named_upstreams,
        )
    }

    pub fn with_limits(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        limits: PolicyLimits,
    ) -> io::Result<Self> {
        Self::with_limits_and_named_upstreams(final_resolver, rules, limits, std::iter::empty())
    }

    fn with_limits_and_named_upstreams(
        final_resolver: Arc<dyn Resolver>,
        rules: Vec<PolicyRuleSpec>,
        limits: PolicyLimits,
        named_upstreams: impl IntoIterator<Item = (String, Arc<dyn Resolver>)>,
    ) -> io::Result<Self> {
        let limits = limits.validate()?;
        if rules.len() > limits.max_rules {
            return Err(invalid_policy(format!(
                "DNS policy has {} rules, limit is {}",
                rules.len(),
                limits.max_rules
            )));
        }

        let mut budget = CompileBudget::default();
        let rules = rules
            .into_iter()
            .enumerate()
            .map(|(index, spec)| PolicyRule::compile(index, spec, limits, &mut budget))
            .collect::<io::Result<Vec<_>>>()?;

        let mut named = HashMap::new();
        for (tag, resolver) in named_upstreams {
            if tag.trim().is_empty() || tag.trim() != tag {
                return Err(invalid_policy(
                    "DNS named upstream tags must be non-empty trimmed strings",
                ));
            }
            if named.insert(tag.clone(), resolver).is_some() {
                return Err(invalid_policy(format!(
                    "DNS policy has duplicate named upstream tag {tag:?}"
                )));
            }
        }

        Ok(Self {
            final_resolver,
            named_upstreams: named,
            rules: rules.into_boxed_slice(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Resolver for PolicyResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }

        let hostname = location
            .address()
            .hostname()
            .expect("a non-IP NetLocation must contain a hostname");
        let normalized_hostname = normalize_hostname(hostname);
        let selected = self
            .rules
            .iter()
            .find(|rule| rule.matches(&normalized_hostname, location))
            .map(|rule| (rule.action.clone(), rule.timeout));
        let final_resolver = self.final_resolver.clone();
        let location = location.clone();
        let port = location.port();

        Box::pin(async move {
            match selected {
                Some((PolicyAction::Route(resolver), timeout)) => {
                    let resolve = resolver.resolve_location(&location);
                    let addresses = match timeout {
                        Some(timeout) => tokio::time::timeout(timeout, resolve)
                            .await
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    format!(
                                        "DNS policy route for {normalized_hostname} timed out after {timeout:?}"
                                    ),
                                )
                            })??,
                        None => resolve.await?,
                    };
                    Ok(normalize_result_ports(addresses, port))
                }
                Some((PolicyAction::Reject(method), _)) => {
                    Err(DnsPolicyError::rejected(normalized_hostname, method).into_io_error())
                }
                Some((PolicyAction::Predefined(response), _)) => {
                    match response.rcode {
                        DnsRcode::NoError => Ok(response
                            .addresses
                            .into_iter()
                            .map(|address| SocketAddr::new(address, port))
                            .collect()),
                        rcode => Err(DnsPolicyError::response_code(normalized_hostname, rcode)
                            .into_io_error()),
                    }
                }
                None => Ok(normalize_result_ports(
                    final_resolver.resolve_location(&location).await?,
                    port,
                )),
            }
        })
    }

    fn resolve_location_via(
        &self,
        upstream_tag: &str,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
        if upstream_tag.is_empty() {
            return self.resolve_location(location);
        }
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }

        let resolver = self.named_upstreams.get(upstream_tag).cloned();
        let requested_tag = upstream_tag.to_string();
        let location = location.clone();
        let port = location.port();
        Box::pin(async move {
            let resolver = resolver.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("DNS policy references unknown named upstream {requested_tag:?}"),
                )
            })?;
            Ok(normalize_result_ports(
                resolver.resolve_location(&location).await?,
                port,
            ))
        })
    }
}

#[derive(Debug)]
struct PolicyRule {
    exact: Box<[String]>,
    suffix: Box<[String]>,
    keyword: Box<[String]>,
    regex: Box<[Regex]>,
    mixed_rule_set_matcher: Option<RoutePredicate>,
    action: PolicyAction,
    timeout: Option<Duration>,
}

impl PolicyRule {
    fn compile(
        index: usize,
        spec: PolicyRuleSpec,
        limits: PolicyLimits,
        budget: &mut CompileBudget,
    ) -> io::Result<Self> {
        let pattern_count = spec
            .exact
            .len()
            .checked_add(spec.suffix.len())
            .and_then(|count| count.checked_add(spec.keyword.len()))
            .and_then(|count| count.checked_add(spec.regex.len()))
            .ok_or_else(|| invalid_policy(format!("dns.rules[{index}] pattern count overflow")))?;
        if pattern_count > limits.max_patterns_per_rule {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] has {pattern_count} patterns, per-rule limit is {}",
                limits.max_patterns_per_rule
            )));
        }
        budget.patterns = budget.patterns.checked_add(pattern_count).ok_or_else(|| {
            invalid_policy(format!("dns.rules[{index}] total pattern count overflow"))
        })?;
        if budget.patterns > limits.max_total_patterns {
            return Err(invalid_policy(format!(
                "DNS policy has {} patterns, total limit is {}",
                budget.patterns, limits.max_total_patterns
            )));
        }

        budget.regex_patterns = budget
            .regex_patterns
            .checked_add(spec.regex.len())
            .ok_or_else(|| invalid_policy("DNS policy regex count overflow"))?;
        if budget.regex_patterns > limits.max_regex_patterns {
            return Err(invalid_policy(format!(
                "DNS policy has {} regex patterns, limit is {}",
                budget.regex_patterns, limits.max_regex_patterns
            )));
        }

        validate_action(index, &spec.action, limits)?;
        if spec.timeout.is_some() && !matches!(&spec.action, PolicyAction::Route(_)) {
            return Err(invalid_policy(format!(
                "dns.rules[{index}] timeout is only valid for route actions"
            )));
        }
        let exact = compile_literals(index, "domain", spec.exact, limits, budget, |value| {
            normalize_domain_literal(value, true)
        })?;
        let suffix = compile_literals(
            index,
            "domain_suffix",
            spec.suffix,
            limits,
            budget,
            |value| normalize_domain_literal(value, false),
        )?;
        let keyword = compile_literals(
            index,
            "domain_keyword",
            spec.keyword,
            limits,
            budget,
            |value| value.to_lowercase(),
        )?;
        let matcher_regex = spec.regex.clone();
        let mut regex = Vec::with_capacity(spec.regex.len());
        for (regex_index, pattern) in spec.regex.into_iter().enumerate() {
            account_pattern_bytes(index, "domain_regex", &pattern, limits, budget)?;
            if pattern.is_empty() {
                return Err(invalid_policy(format!(
                    "dns.rules[{index}].domain_regex[{regex_index}] must not be empty"
                )));
            }
            let compiled = RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .size_limit(limits.regex_size_limit)
                .dfa_size_limit(limits.regex_dfa_size_limit)
                .build()
                .map_err(|error| {
                    invalid_policy(format!(
                        "invalid dns.rules[{index}].domain_regex[{regex_index}] {pattern:?}: {error}"
                    ))
                })?;
            regex.push(compiled);
        }
        let mixed_rule_set_matcher = if spec.rule_set.is_empty() {
            None
        } else {
            let matcher = RoutePredicate::compile(&RouteMatchConfig {
                domain: exact.clone(),
                domain_suffix: suffix.clone(),
                domain_keyword: keyword.clone(),
                // Policy matching has historically treated regexes as
                // case-insensitive. Preserve that behavior in the shared
                // category matcher while the hostname itself is normalized.
                domain_regex: matcher_regex
                    .into_iter()
                    .map(|pattern| format!("(?i:{pattern})"))
                    .collect(),
                rule_set: spec.rule_set,
                ..RouteMatchConfig::default()
            })
            .map_err(|error| {
                invalid_policy(format!("invalid dns.rules[{index}].rule_set: {error}"))
            })?;
            if matcher.requires_ip() || matcher.uses_context() || matcher.uses_destination_port() {
                return Err(invalid_policy(format!(
                    "dns.rules[{index}].rule_set requires IP, port, network, or protocol metadata unavailable to DNS hostname lookup"
                )));
            }
            Some(matcher)
        };

        Ok(Self {
            exact: exact.into_boxed_slice(),
            suffix: suffix.into_boxed_slice(),
            keyword: keyword.into_boxed_slice(),
            regex: regex.into_boxed_slice(),
            mixed_rule_set_matcher,
            action: spec.action,
            timeout: spec.timeout.filter(|timeout| !timeout.is_zero()),
        })
    }

    fn matches(&self, hostname: &str, location: &NetLocation) -> bool {
        let catch_all = self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
            && self.mixed_rule_set_matcher.is_none();
        if let Some(matcher) = &self.mixed_rule_set_matcher {
            matcher.matches(location, None, &RouteContext::default())
        } else {
            catch_all
                || self.exact.iter().any(|pattern| pattern == hostname)
                || self
                    .suffix
                    .iter()
                    .any(|pattern| domain_has_suffix(hostname, pattern))
                || self
                    .keyword
                    .iter()
                    .any(|pattern| hostname.contains(pattern))
                || self.regex.iter().any(|pattern| pattern.is_match(hostname))
        }
    }
}

#[derive(Default)]
struct CompileBudget {
    patterns: usize,
    regex_patterns: usize,
    pattern_bytes: usize,
}

fn compile_literals(
    rule_index: usize,
    field: &str,
    values: Vec<String>,
    limits: PolicyLimits,
    budget: &mut CompileBudget,
    normalize: impl Fn(&str) -> String,
) -> io::Result<Vec<String>> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            account_pattern_bytes(rule_index, field, &value, limits, budget)?;
            let normalized = normalize(&value);
            if normalized.is_empty() {
                return Err(invalid_policy(format!(
                    "dns.rules[{rule_index}].{field}[{index}] must not be empty"
                )));
            }
            Ok(normalized)
        })
        .collect()
}

fn account_pattern_bytes(
    rule_index: usize,
    field: &str,
    value: &str,
    limits: PolicyLimits,
    budget: &mut CompileBudget,
) -> io::Result<()> {
    if value.len() > limits.max_pattern_bytes {
        return Err(invalid_policy(format!(
            "dns.rules[{rule_index}].{field} pattern is {} bytes, limit is {}",
            value.len(),
            limits.max_pattern_bytes
        )));
    }
    budget.pattern_bytes = budget
        .pattern_bytes
        .checked_add(value.len())
        .ok_or_else(|| invalid_policy("DNS policy pattern byte count overflow"))?;
    if budget.pattern_bytes > limits.max_total_pattern_bytes {
        return Err(invalid_policy(format!(
            "DNS policy patterns total {} bytes, limit is {}",
            budget.pattern_bytes, limits.max_total_pattern_bytes
        )));
    }
    Ok(())
}

fn validate_action(index: usize, action: &PolicyAction, limits: PolicyLimits) -> io::Result<()> {
    let PolicyAction::Predefined(response) = action else {
        return Ok(());
    };
    if response.addresses.len() > limits.max_predefined_addresses_per_rule {
        return Err(invalid_policy(format!(
            "dns.rules[{index}] has {} predefined addresses, limit is {}",
            response.addresses.len(),
            limits.max_predefined_addresses_per_rule
        )));
    }
    Ok(())
}

fn normalize_hostname(value: &str) -> String {
    value.trim_end_matches('.').to_lowercase()
}

fn normalize_domain_literal(value: &str, exact: bool) -> String {
    let value = normalize_hostname(value);
    if exact {
        value
    } else {
        value.trim_start_matches('.').to_string()
    }
}

fn domain_has_suffix(hostname: &str, suffix: &str) -> bool {
    hostname == suffix
        || hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_result_ports(mut addresses: Vec<SocketAddr>, port: u16) -> Vec<SocketAddr> {
    addresses
        .iter_mut()
        .for_each(|address| address.set_port(port));
    addresses
}

fn invalid_policy(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::NamedTempFile;

    use crate::address::Address;

    use super::*;

    fn source_rule_set(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[derive(Debug)]
    struct StaticResolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    impl StaticResolver {
        fn new(address: IpAddr, returned_port: u16) -> Arc<Self> {
            Arc::new(Self {
                addresses: vec![SocketAddr::new(address, returned_port)],
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolver for StaticResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[derive(Debug)]
    struct SlowResolver {
        delay: Duration,
        address: SocketAddr,
        calls: AtomicUsize,
    }

    impl SlowResolver {
        fn new(delay: Duration, address: SocketAddr) -> Arc<Self> {
            Arc::new(Self {
                delay,
                address,
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl Resolver for SlowResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let delay = self.delay;
            let address = self.address;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(vec![address])
            })
        }
    }

    fn location(hostname: &str, port: u16) -> NetLocation {
        NetLocation::new(Address::Hostname(hostname.to_string()), port)
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[tokio::test]
    async fn ordered_rules_match_all_hostname_pattern_kinds_case_insensitively() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let exact = StaticResolver::new(v4(1), 1);
        let suffix = StaticResolver::new(v4(2), 1);
        let keyword = StaticResolver::new(v4(3), 1);
        let regex = StaticResolver::new(v4(4), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(exact.clone())).exact(["Exact.Example"]),
                PolicyRuleSpec::new(PolicyAction::Route(suffix.clone())).suffix([".Example.NET"]),
                PolicyRuleSpec::new(PolicyAction::Route(keyword.clone())).keyword(["NeEdLe"]),
                PolicyRuleSpec::new(PolicyAction::Route(regex.clone()))
                    .regex([r"^api[0-9]+\.example\.org$"]),
            ],
        )
        .unwrap();

        for (hostname, expected) in [
            ("EXACT.EXAMPLE.", v4(1)),
            ("deep.Example.Net", v4(2)),
            ("has-NEEDLE-here.test", v4(3)),
            ("API42.EXAMPLE.ORG", v4(4)),
            ("unmatched.example", v4(99)),
        ] {
            let resolved = policy
                .resolve_location(&location(hostname, 8443))
                .await
                .unwrap();
            assert_eq!(resolved, vec![SocketAddr::new(expected, 8443)]);
        }
        assert_eq!(exact.calls(), 1);
        assert_eq!(suffix.calls(), 1);
        assert_eq!(keyword.calls(), 1);
        assert_eq!(regex.calls(), 1);
        assert_eq!(final_resolver.calls(), 1);
    }

    #[tokio::test]
    async fn named_upstream_bypasses_policy_without_changing_default_resolution() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let routed = StaticResolver::new(v4(1), 1);
        let named = StaticResolver::new(v4(7), 1);
        let policy = PolicyResolver::with_named_upstreams(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Route(routed.clone())).suffix(["example.com"])],
            [(
                "outbound-dns".to_string(),
                named.clone() as Arc<dyn Resolver>,
            )],
        )
        .unwrap();

        let target = location("api.example.com", 8443);
        assert_eq!(
            policy
                .resolve_location_via("outbound-dns", &target)
                .await
                .unwrap(),
            [SocketAddr::new(v4(7), 8443)]
        );
        assert_eq!(named.calls(), 1);
        assert_eq!(routed.calls(), 0);
        assert_eq!(final_resolver.calls(), 0);

        assert_eq!(
            policy.resolve_location(&target).await.unwrap(),
            [SocketAddr::new(v4(1), 8443)]
        );
        assert_eq!(routed.calls(), 1);

        let error = policy
            .resolve_location_via("missing", &target)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn first_match_wins_and_suffix_requires_a_label_boundary() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let first = StaticResolver::new(v4(1), 53);
        let second = StaticResolver::new(v4(2), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(first.clone())).suffix(["example.com"]),
                PolicyRuleSpec::new(PolicyAction::Route(second.clone())).keyword(["example.com"]),
            ],
        )
        .unwrap();

        let matched = policy
            .resolve_location(&location("www.example.com", 443))
            .await
            .unwrap();
        assert_eq!(matched[0].ip(), v4(1));
        let boundary_miss = policy
            .resolve_location(&location("notexample.com", 443))
            .await
            .unwrap();
        assert_eq!(boundary_miss[0].ip(), v4(2));
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1);
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn matched_route_timeout_is_per_rule_and_reports_timed_out() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let slow = SlowResolver::new(Duration::from_millis(200), SocketAddr::new(v4(1), 1));
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(slow.clone()))
                    .exact(["slow.example"])
                    .timeout(Duration::from_millis(10)),
            ],
        )
        .unwrap();

        let error = policy
            .resolve_location(&location("slow.example", 53))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(slow.calls.load(Ordering::Relaxed), 1);
        assert_eq!(final_resolver.calls(), 0);

        // An unmatched query still follows the unwrapped final resolver.
        let resolved = policy
            .resolve_location(&location("fast.example", 5353))
            .await
            .unwrap();
        assert_eq!(resolved, [SocketAddr::new(v4(99), 5353)]);
    }

    #[tokio::test]
    async fn zero_route_timeout_preserves_existing_resolver_behavior() {
        let slow = SlowResolver::new(Duration::from_millis(5), SocketAddr::new(v4(7), 1));
        let policy = PolicyResolver::new(
            StaticResolver::new(v4(99), 1),
            vec![
                PolicyRuleSpec::new(PolicyAction::Route(slow))
                    .exact(["slow.example"])
                    .timeout(Duration::ZERO),
            ],
        )
        .unwrap();
        assert_eq!(
            policy
                .resolve_location(&location("slow.example", 53))
                .await
                .unwrap(),
            [SocketAddr::new(v4(7), 53)]
        );
    }

    #[tokio::test]
    async fn reject_and_catch_all_rules_do_not_contact_an_upstream() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default))
                    .suffix(["blocked.example"]),
            ],
        )
        .unwrap();
        let error = policy
            .resolve_location(&location("BLOCKED.EXAMPLE", 53))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(final_resolver.calls(), 0);

        let catch_all = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        assert!(
            catch_all
                .resolve_location(&location("anything.example", 53))
                .await
                .is_err()
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn reject_drop_is_an_immediate_typed_terminal_failure() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Drop))
                    .exact(["drop.example"]),
            ],
        )
        .unwrap();

        let error = tokio::time::timeout(
            Duration::from_millis(50),
            policy.resolve_location(&location("drop.example", 53)),
        )
        .await
        .expect("drop must not leave an address lookup pending")
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<DnsPolicyError>())
            .expect("DNS policy error must preserve its typed failure");
        assert_eq!(
            typed.failure(),
            DnsPolicyFailure::Rejected(DnsRejectMethod::Drop)
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn predefined_response_codes_are_typed_terminal_outcomes() {
        for (rcode, kind) in [
            (DnsRcode::NxDomain, io::ErrorKind::NotFound),
            (DnsRcode::Refused, io::ErrorKind::PermissionDenied),
            (DnsRcode::ServFail, io::ErrorKind::Other),
        ] {
            let final_resolver = StaticResolver::new(v4(99), 53);
            let policy = PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::new(
                        rcode,
                        vec![v4(7)],
                    )))
                    .exact(["rcode.example"]),
                ],
            )
            .unwrap();

            let error = policy
                .resolve_location(&location("rcode.example", 53))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), kind);
            let typed = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<DnsPolicyError>())
                .expect("DNS policy error must preserve its response code");
            assert_eq!(typed.failure(), DnsPolicyFailure::ResponseCode(rcode));
            assert_eq!(final_resolver.calls(), 0);
        }
    }

    #[tokio::test]
    async fn predefined_answers_preserve_a_and_aaaa_and_target_port() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    vec![v4(7), ipv6],
                )))
                .exact(["static.example"]),
            ],
        )
        .unwrap();
        let resolved = policy
            .resolve_location(&location("static.example", 5353))
            .await
            .unwrap();
        assert_eq!(
            resolved,
            vec![SocketAddr::new(v4(7), 5353), SocketAddr::new(ipv6, 5353)]
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn empty_predefined_answer_is_a_successful_terminal_response() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    Vec::new(),
                )))
                .exact(["empty.example"]),
            ],
        )
        .unwrap();

        let resolved = policy
            .resolve_location(&location("empty.example", 53))
            .await
            .unwrap();
        assert!(resolved.is_empty());
        assert_eq!(final_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn direct_and_rule_set_domains_share_one_or_category() {
        let rule_set =
            source_rule_set(r#"{"version":4,"rules":[{"domain_suffix":["ads.example"]}]}"#);
        let final_resolver = StaticResolver::new(v4(1), 0);
        let resolver = PolicyResolver::new(
            final_resolver.clone(),
            vec![
                PolicyRuleSpec::new(PolicyAction::Predefined(DnsPredefinedResponse::no_error(
                    vec![v4(9)],
                )))
                .exact(["direct.example"])
                .rule_set([RouteRuleSetConfig {
                    format: "source".to_string(),
                    path: rule_set.path().to_path_buf(),
                }]),
            ],
        )
        .unwrap();

        let result = resolver
            .resolve_location(&location("track.ads.example", 5353))
            .await
            .unwrap();
        assert_eq!(result, [SocketAddr::new(v4(9), 5353)]);
        let direct = resolver
            .resolve_location(&location("direct.example", 5353))
            .await
            .unwrap();
        assert_eq!(direct, [SocketAddr::new(v4(9), 5353)]);
        let unrelated = resolver
            .resolve_location(&location("unrelated.example", 5353))
            .await
            .unwrap();
        assert_eq!(unrelated, [SocketAddr::new(v4(1), 5353)]);
        assert_eq!(final_resolver.calls(), 1);
    }

    #[tokio::test]
    async fn literal_ip_bypasses_policy_and_upstream() {
        let final_resolver = StaticResolver::new(v4(99), 1);
        let policy = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(
                DnsRejectMethod::Default,
            ))],
        )
        .unwrap();
        let literal = NetLocation::new(Address::Ipv4(Ipv4Addr::new(198, 51, 100, 3)), 8080);
        assert_eq!(
            policy.resolve_location(&literal).await.unwrap(),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)),
                8080
            )]
        );
        assert_eq!(final_resolver.calls(), 0);
    }

    #[test]
    fn constructor_rejects_invalid_and_oversized_policy() {
        let final_resolver = StaticResolver::new(v4(99), 53);
        let invalid_regex = PolicyResolver::new(
            final_resolver.clone(),
            vec![PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)).regex(["("])],
        )
        .unwrap_err();
        assert_eq!(invalid_regex.kind(), io::ErrorKind::InvalidInput);

        assert!(
            PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .exact([""])
                ]
            )
            .is_err()
        );
        assert!(
            PolicyResolver::new(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .timeout(Duration::from_millis(1))
                ]
            )
            .is_err()
        );
        let limits = PolicyLimits {
            max_rules: 1,
            max_patterns_per_rule: 1,
            max_total_patterns: 1,
            max_regex_patterns: 1,
            max_pattern_bytes: 4,
            max_total_pattern_bytes: 4,
            max_predefined_addresses_per_rule: 1,
            regex_size_limit: 1_024,
            regex_dfa_size_limit: 1_024,
        };
        assert!(
            PolicyResolver::with_limits(
                final_resolver.clone(),
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)),
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default)),
                ],
                limits,
            )
            .is_err()
        );
        assert!(
            PolicyResolver::with_limits(
                final_resolver,
                vec![
                    PolicyRuleSpec::new(PolicyAction::Reject(DnsRejectMethod::Default,))
                        .exact(["12345"])
                ],
                limits,
            )
            .is_err()
        );
    }
}
