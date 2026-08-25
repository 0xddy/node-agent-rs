//! DNS resolver module with configurable DNS servers.
//!
//! Supports:
//! - System resolver (NativeResolver)
//! - UDP DNS
//! - TCP DNS
//! - DNS-over-TLS (DoT) - requires `hickory-tls` feature
//! - DNS-over-HTTPS (DoH) - requires `hickory-https` feature
//!
//! TCP-based protocols (tcp://, tls://, https://) support routing through
//! proxy chains via the ProxyRuntimeProvider.

mod builder;
mod composite_resolver;
mod hickory_resolver;
mod parsed;
mod policy;
mod predefined;
mod proxy_runtime;

#[allow(unused_imports)]
pub use builder::{DnsRegistry, build_dns_registry};
pub use parsed::{IpStrategy, ParsedDnsUrl};
#[allow(unused_imports)]
pub use policy::{
    DnsPolicyError, DnsPolicyFailure, DnsPredefinedResponse, DnsRcode, DnsRejectMethod,
    PolicyAction, PolicyLimits, PolicyResolver, PolicyRuleSpec,
};
pub use predefined::parse_predefined_lookup_addresses;
