//! Resolver implementation using hickory-dns.
//!
//! Uses ProxyRuntimeProvider for all connections, which handles both direct
//! and proxied connections through ClientChainGroup.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::parsed::IpStrategy;
use crate::dns::proxy_runtime::ProxyRuntimeProvider;
use crate::resolver::Resolver as ShoesResolver;

/// Tuning options for hickory-backed resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HickoryResolverOptions {
    pub ip_strategy: IpStrategy,
    pub use_native_roots: bool,
    /// Per-request timeout passed to hickory's ResolverOpts.timeout.
    /// None means use hickory's default.
    pub request_timeout: Option<Duration>,
    /// Timeout for establishing TCP/TLS connections to DNS upstreams.
    pub connect_timeout: Duration,
    /// Number of retry attempts for failed queries.
    pub attempts: usize,
}

impl Default for HickoryResolverOptions {
    fn default() -> Self {
        Self {
            ip_strategy: IpStrategy::default(),
            use_native_roots: false,
            request_timeout: Some(Duration::from_secs(5)),
            connect_timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }
}

/// Resolver implementation using hickory-dns.
/// Uses ProxyRuntimeProvider for all connections (both direct and proxied).
pub struct HickoryResolver {
    inner: Resolver<ProxyRuntimeProvider>,
    description: String,
    ip_strategy: IpStrategy,
}

impl Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("description", &self.description)
            .field("ip_strategy", &self.ip_strategy)
            .finish()
    }
}

impl HickoryResolver {
    /// Create a UDP DNS resolver.
    /// Note: UDP uses the chain_group but only works with direct chains.
    pub fn udp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::udp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("udp://{}", addr),
        )
    }

    /// Create a TCP DNS resolver.
    pub fn tcp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tcp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tcp://{}", addr),
        )
    }

    /// Create a DNS-over-TLS resolver.
    pub fn tls(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tls(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tls://{}#{}", addr, server_name),
        )
    }

    /// Create a DNS-over-QUIC resolver (RFC 9250).
    ///
    /// Direct chains use a native UDP socket. Other UDP-capable chains are
    /// exposed to Quinn as a fixed-destination datagram socket, preserving one
    /// QUIC packet per proxy message.
    pub fn quic(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        if !chain_group.supports_udp() {
            return Err(std::io::Error::other(
                "DNS-over-QUIC client_chain has no UDP-capable chain",
            ));
        }

        let mut conn_config = ConnectionConfig::quic(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("quic://{}#{}", addr, server_name),
        )
    }

    /// Create a DNS-over-HTTPS resolver.
    pub fn https(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::https(server_name.clone(), Some(path));
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("https://{}", server_name),
        )
    }

    /// Create a DNS-over-HTTP/3 resolver.
    pub fn h3(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        if !chain_group.supports_udp() {
            return Err(std::io::Error::other(
                "DNS-over-HTTP/3 client_chain has no UDP-capable chain",
            ));
        }
        // Cloudflare has a broken GREASE implementation.
        // See: https://github.com/hyperium/h3/issues/206
        let protocol = ProtocolConfig::H3 {
            server_name: server_name.clone(),
            path,
            disable_grease: true,
        };
        let mut conn_config = ConnectionConfig::new(protocol);
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("h3://{}", server_name),
        )
    }

    /// Create a resolver with multiple nameservers in a single hickory pool.
    /// Hickory's NameServerPool handles ordering and parallelism internally,
    /// avoiding the sequential fallback behavior of CompositeResolver.
    pub fn build_pooled(
        servers: Vec<(std::net::IpAddr, ConnectionConfig)>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_configs: Vec<NameServerConfig> = servers
            .into_iter()
            .map(|(ip, conn_config)| NameServerConfig::new(ip, true, vec![conn_config]))
            .collect();

        Self::build_with_ns_configs(ns_configs, chain_group, bootstrap, options, description)
    }

    fn build(
        ip: std::net::IpAddr,
        conn_config: ConnectionConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_config = NameServerConfig::new(ip, true, vec![conn_config]);
        Self::build_with_ns_configs(
            vec![ns_config],
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    fn build_with_ns_configs(
        ns_configs: Vec<NameServerConfig>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        for connection in ns_configs
            .iter()
            .flat_map(|server| server.connections.iter())
        {
            match &connection.protocol {
                ProtocolConfig::Udp if !chain_group.is_direct_only() => {
                    return Err(std::io::Error::other(
                        "UDP DNS only supports a direct client_chain (optionally with bind_interface)",
                    ));
                }
                ProtocolConfig::Quic { .. } | ProtocolConfig::H3 { .. }
                    if !chain_group.supports_udp() =>
                {
                    return Err(std::io::Error::other(
                        "QUIC DNS client_chain has no UDP-capable chain",
                    ));
                }
                _ => {}
            }
        }

        let config = ResolverConfig::from_parts(None, vec![], ns_configs);
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, bootstrap, options.connect_timeout);

        let mut builder = Resolver::builder_with_config(config, provider);
        let resolver_opts = builder.options_mut();
        resolver_opts.ip_strategy = options.ip_strategy.to_hickory();
        if let Some(timeout) = options.request_timeout {
            resolver_opts.timeout = timeout;
        }
        resolver_opts.attempts = options.attempts;
        let builder = builder.with_tls_config(crate::rustls_config_util::create_dns_client_config(
            options.use_native_roots,
        ));
        let resolver = builder
            .build()
            .map_err(|e| std::io::Error::other(format!("failed to build resolver: {e}")))?;

        Ok(Self {
            inner: resolver,
            description,
            ip_strategy: options.ip_strategy,
        })
    }
}

impl ShoesResolver for HickoryResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        // Fast path: if already an IP address, return immediately without DNS lookup
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let name = location.address().to_string();
        let port = location.port();
        let description = self.description.clone();
        let resolver = self.inner.clone();
        let ip_strategy = self.ip_strategy;

        Box::pin(async move {
            let started = std::time::Instant::now();

            let response = resolver.lookup_ip(&name).await.map_err(|e| {
                let elapsed = started.elapsed();
                log::warn!(
                    "DNS lookup failed via {}: {}:{} in {:?}: {}",
                    description,
                    name,
                    port,
                    elapsed,
                    e
                );
                std::io::Error::other(format!("DNS lookup failed: {e}"))
            })?;

            let mut addrs: Vec<SocketAddr> = response
                .iter()
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| SocketAddr::new(ip, port))
                .collect();

            // Hickory exposes parallel A+AAAA lookup but not a parallel
            // IPv6-first variant. Keep the wire queries parallel and impose the
            // same stable family ordering used by sing-box afterwards.
            match ip_strategy {
                IpStrategy::Ipv4AndIpv6 => addrs.sort_by_key(SocketAddr::is_ipv6),
                IpStrategy::Ipv6AndIpv4 => addrs.sort_by_key(SocketAddr::is_ipv4),
                _ => {}
            }

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {name}"
                )));
            }

            let elapsed = started.elapsed();
            if elapsed > Duration::from_millis(500) {
                log::info!(
                    "slow DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            } else {
                log::debug!(
                    "DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            }
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection,
    };
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_client_chain_group;

    fn single_proxy_chain(protocol: ClientProxyConfig) -> Arc<ClientChainGroup> {
        let resolver: Arc<dyn ShoesResolver> = Arc::new(NativeResolver::new());
        let config = ClientConfig {
            address: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
            protocol,
            ..Default::default()
        };
        Arc::new(build_client_chain_group(
            NoneOrSome::One(ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
            }),
            resolver,
        ))
    }

    #[test]
    fn test_hickory_resolver_options_default() {
        let opts = HickoryResolverOptions::default();
        assert_eq!(opts.ip_strategy, IpStrategy::default());
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(5)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(5));
        assert_eq!(opts.attempts, 2);
    }

    #[test]
    fn test_hickory_resolver_options_zero_timeout() {
        let opts = HickoryResolverOptions {
            request_timeout: None,
            ..Default::default()
        };
        assert!(opts.request_timeout.is_none());
    }

    #[test]
    fn test_hickory_resolver_options_custom() {
        let opts = HickoryResolverOptions {
            ip_strategy: IpStrategy::Ipv4Only,
            use_native_roots: true,
            request_timeout: Some(Duration::from_secs(3)),
            connect_timeout: Duration::from_secs(1),
            attempts: 1,
        };
        assert_eq!(opts.ip_strategy, IpStrategy::Ipv4Only);
        assert!(opts.use_native_roots);
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(3)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(1));
        assert_eq!(opts.attempts, 1);
    }

    #[test]
    fn quic_dns_accepts_udp_capable_proxy_chain_and_rejects_tcp_only_chain() {
        let bootstrap: Arc<dyn ShoesResolver> = Arc::new(NativeResolver::new());
        let server_addr: SocketAddr = "127.0.0.1:853".parse().unwrap();
        let server_name: Arc<str> = Arc::from("dns.example.com");

        let vless = single_proxy_chain(ClientProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            udp_enabled: true,
            packet_encoding: None,
            h2mux: None,
        });
        HickoryResolver::quic(
            server_addr,
            server_name.clone(),
            vless,
            bootstrap.clone(),
            HickoryResolverOptions::default(),
        )
        .expect("UDP-capable proxy must be accepted for DoQ");

        let h3_vless = single_proxy_chain(ClientProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            udp_enabled: true,
            packet_encoding: None,
            h2mux: None,
        });
        HickoryResolver::h3(
            server_addr,
            server_name.clone(),
            Arc::from("/dns-query"),
            h3_vless,
            bootstrap.clone(),
            HickoryResolverOptions::default(),
        )
        .expect("UDP-capable proxy must be accepted for DoH3");

        let socks = single_proxy_chain(ClientProxyConfig::Socks {
            username: None,
            password: None,
        });
        let error = HickoryResolver::quic(
            server_addr,
            server_name,
            socks,
            bootstrap,
            HickoryResolverOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("no UDP-capable chain"));

        let h3_socks = single_proxy_chain(ClientProxyConfig::Socks {
            username: None,
            password: None,
        });
        let error = HickoryResolver::h3(
            server_addr,
            Arc::from("dns.example.com"),
            Arc::from("/dns-query"),
            h3_socks,
            Arc::new(NativeResolver::new()),
            HickoryResolverOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no UDP-capable chain"));
    }
}
