//! Lossless-enough ACP protobuf/model conversion and snapshot mutation helpers.
//!
//! Provider JSON bytes are copied verbatim.  Structured route/DNS messages are
//! mapped field-by-field so a protobuf field can never disappear merely because
//! a parallel serde schema forgot about it.

use acp_proto as pb;

use super::*;

pub fn from_machine_config(
    default_machine_id: impl Into<String>,
    config: Option<&pb::MachineConfig>,
) -> MachineTopology {
    let default_machine_id = default_machine_id.into();
    let Some(config) = config else {
        return MachineTopology {
            machine_id: default_machine_id,
            ..MachineTopology::default()
        };
    };

    let snapshot = pb::TopologySnapshot {
        machine_id: config.machine_id.clone(),
        revision: config.revision,
        nodes: config
            .nodes
            .iter()
            .map(|node| pb::NodeTopology {
                node_id: node.node_id.clone(),
                provider_id: node.provider_id.clone(),
                provider_config_version: node.provider_config_version,
                provider_config_json: node.provider_config_json.clone(),
                users: Vec::new(),
            })
            .collect(),
        outbounds: config.outbounds.clone(),
        route: config.route.clone(),
        dns: config.dns.clone(),
    };
    let mut topology = MachineTopology {
        machine_id: config.machine_id.clone(),
        revision: config.revision,
        nodes: config.nodes.iter().map(NodeInstance::from).collect(),
        outbounds: config.outbounds.iter().map(Outbound::from).collect(),
        route: config.route.as_ref().map(Route::from),
        dns: config.dns.as_ref().map(Dns::from),
        snapshot: Some(snapshot),
    };
    if topology.machine_id.is_empty() {
        topology.machine_id = default_machine_id;
    }
    topology
}

pub fn from_snapshot(
    default_machine_id: impl Into<String>,
    snapshot: Option<&pb::TopologySnapshot>,
) -> MachineTopology {
    let default_machine_id = default_machine_id.into();
    let Some(snapshot) = snapshot else {
        return MachineTopology {
            machine_id: default_machine_id,
            ..MachineTopology::default()
        };
    };

    let mut topology = MachineTopology {
        machine_id: snapshot.machine_id.clone(),
        revision: snapshot.revision,
        nodes: snapshot.nodes.iter().map(NodeInstance::from).collect(),
        outbounds: snapshot.outbounds.iter().map(Outbound::from).collect(),
        route: snapshot.route.as_ref().map(Route::from),
        dns: snapshot.dns.as_ref().map(Dns::from),
        snapshot: Some(snapshot.clone()),
    };
    if topology.machine_id.is_empty() {
        topology.machine_id = default_machine_id;
    }
    topology
}

pub fn to_snapshot(topology: &MachineTopology) -> pb::TopologySnapshot {
    pb::TopologySnapshot {
        machine_id: topology.machine_id.clone(),
        revision: topology.revision,
        nodes: topology.nodes.iter().map(pb::NodeTopology::from).collect(),
        outbounds: topology
            .outbounds
            .iter()
            .map(pb::OutboundConfig::from)
            .collect(),
        route: topology.route.as_ref().map(pb::RouteConfig::from),
        dns: topology.dns.as_ref().map(pb::DnsConfig::from),
    }
}

pub fn clone_snapshot(snapshot: Option<&pb::TopologySnapshot>) -> Option<pb::TopologySnapshot> {
    snapshot.cloned()
}

pub fn digest(topology: &MachineTopology) -> Option<String> {
    topology
        .snapshot
        .as_ref()
        .map(|snapshot| acp_proto::digest::sum(Some(snapshot)))
}

impl From<&pb::MachineConfig> for MachineTopology {
    fn from(config: &pb::MachineConfig) -> Self {
        from_machine_config(String::new(), Some(config))
    }
}

impl From<&pb::TopologySnapshot> for MachineTopology {
    fn from(snapshot: &pb::TopologySnapshot) -> Self {
        from_snapshot(String::new(), Some(snapshot))
    }
}

impl From<&MachineTopology> for pb::TopologySnapshot {
    fn from(topology: &MachineTopology) -> Self {
        to_snapshot(topology)
    }
}

pub fn replace_node_users(topology: &mut MachineTopology, node_id: &str, users: &[UserCredential]) {
    let Some(snapshot) = topology.snapshot.as_mut() else {
        return;
    };
    if let Some(node) = snapshot
        .nodes
        .iter_mut()
        .find(|node| node.node_id == node_id)
    {
        node.users = users.iter().map(pb::UserCredential::from).collect();
    }
}

pub fn apply_node_mutation_to_snapshot(
    topology: &mut MachineTopology,
    mutation: &pb::NodeMutation,
) {
    let Some(snapshot) = topology.snapshot.as_mut() else {
        return;
    };
    let node_id = if mutation.node_id.is_empty() {
        mutation
            .node
            .as_ref()
            .map(|node| node.node_id.as_str())
            .unwrap_or_default()
    } else {
        &mutation.node_id
    };
    if node_id.is_empty() {
        return;
    }

    match pb::MutationOperation::try_from(mutation.operation)
        .unwrap_or(pb::MutationOperation::Unspecified)
    {
        pb::MutationOperation::Delete | pb::MutationOperation::Disable => {
            snapshot.nodes.retain(|node| node.node_id != node_id);
        }
        pb::MutationOperation::Unspecified | pb::MutationOperation::Upsert => {
            let mut replacement = mutation.node.clone().unwrap_or_else(|| pb::NodeTopology {
                node_id: node_id.to_string(),
                ..pb::NodeTopology::default()
            });
            if replacement.node_id.is_empty() {
                replacement.node_id = node_id.to_string();
            }
            if let Some(existing) = snapshot
                .nodes
                .iter_mut()
                .find(|node| node.node_id == node_id)
            {
                *existing = replacement;
            } else {
                snapshot.nodes.push(replacement);
            }
        }
    }
}

pub fn apply_user_mutation_to_snapshot(
    topology: &mut MachineTopology,
    mutation: &pb::UserMutation,
) {
    let Some(snapshot) = topology.snapshot.as_mut() else {
        return;
    };
    let Some(node) = snapshot
        .nodes
        .iter_mut()
        .find(|node| node.node_id == mutation.node_id)
    else {
        return;
    };
    let Some(user) = mutation.user.as_ref() else {
        return;
    };
    let user_id = &user.user_id;
    let operation = pb::MutationOperation::try_from(mutation.operation)
        .unwrap_or(pb::MutationOperation::Unspecified);
    let disabled = pb::UserStatus::try_from(user.status).unwrap_or(pb::UserStatus::Unspecified)
        == pb::UserStatus::Disabled;
    if matches!(
        operation,
        pb::MutationOperation::Delete | pb::MutationOperation::Disable
    ) || disabled
    {
        node.users.retain(|candidate| candidate.user_id != *user_id);
        return;
    }
    if let Some(existing) = node
        .users
        .iter_mut()
        .find(|candidate| candidate.user_id == *user_id)
    {
        *existing = user.clone();
    } else {
        node.users.push(user.clone());
    }
}

pub fn apply_route_patch_to_snapshot(
    topology: &mut MachineTopology,
    patch: &pb::TopologyRoutePatch,
) {
    let Some(snapshot) = topology.snapshot.as_mut() else {
        return;
    };
    if !patch.machine_id.is_empty() {
        snapshot.machine_id.clone_from(&patch.machine_id);
    }
    snapshot.revision = patch.revision;
    snapshot.outbounds.clone_from(&patch.outbounds);
    snapshot.route.clone_from(&patch.route);
    snapshot.dns.clone_from(&patch.dns);
}

impl From<&pb::NodeConfig> for NodeInstance {
    fn from(node: &pb::NodeConfig) -> Self {
        Self {
            node_id: node.node_id.clone(),
            provider_id: node.provider_id.clone(),
            provider_config_version: node.provider_config_version,
            provider_config: RawJson::new(node.provider_config_json.clone()),
            users: Vec::new(),
        }
    }
}

impl From<&pb::NodeTopology> for NodeInstance {
    fn from(node: &pb::NodeTopology) -> Self {
        Self {
            node_id: node.node_id.clone(),
            provider_id: node.provider_id.clone(),
            provider_config_version: node.provider_config_version,
            provider_config: RawJson::new(node.provider_config_json.clone()),
            users: node.users.iter().map(UserCredential::from).collect(),
        }
    }
}

impl From<&NodeInstance> for pb::NodeTopology {
    fn from(node: &NodeInstance) -> Self {
        Self {
            node_id: node.node_id.clone(),
            provider_id: node.provider_id.clone(),
            provider_config_version: node.provider_config_version,
            provider_config_json: node.provider_config.as_bytes().to_vec(),
            users: node.users.iter().map(pb::UserCredential::from).collect(),
        }
    }
}

impl From<&pb::UserCredential> for UserCredential {
    fn from(user: &pb::UserCredential) -> Self {
        let status = if pb::UserStatus::try_from(user.status).unwrap_or(pb::UserStatus::Unspecified)
            == pb::UserStatus::Disabled
        {
            "disabled"
        } else {
            ""
        };
        Self {
            user_id: user.user_id.clone(),
            name: user.name.clone(),
            credential: user.credential.clone(),
            status: status.to_string(),
            upload_speed_limit_bps: user.upload_speed_limit_bps,
            download_speed_limit_bps: user.download_speed_limit_bps,
        }
    }
}

impl From<&UserCredential> for pb::UserCredential {
    fn from(user: &UserCredential) -> Self {
        Self {
            user_id: user.user_id.clone(),
            name: user.name.clone(),
            credential: user.credential.clone(),
            status: if user.status == "disabled" {
                pb::UserStatus::Disabled as i32
            } else {
                pb::UserStatus::Active as i32
            },
            upload_speed_limit_bps: user.upload_speed_limit_bps,
            download_speed_limit_bps: user.download_speed_limit_bps,
        }
    }
}

impl From<&pb::OutboundConfig> for Outbound {
    fn from(outbound: &pb::OutboundConfig) -> Self {
        Self {
            kind: outbound.r#type.clone(),
            tag: outbound.tag.clone(),
            options: RawJson::new(outbound.options_json.clone()),
        }
    }
}

impl From<&Outbound> for pb::OutboundConfig {
    fn from(outbound: &Outbound) -> Self {
        Self {
            r#type: outbound.kind.clone(),
            tag: outbound.tag.clone(),
            options_json: outbound.options.as_bytes().to_vec(),
        }
    }
}

impl From<&pb::DomainResolveOptions> for DomainResolveOptions {
    fn from(value: &pb::DomainResolveOptions) -> Self {
        Self {
            server: value.server.clone(),
            strategy: value.strategy.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl,
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&DomainResolveOptions> for pb::DomainResolveOptions {
    fn from(value: &DomainResolveOptions) -> Self {
        Self {
            server: value.server.clone(),
            strategy: value.strategy.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl,
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&pb::NetworkStrategy> for NetworkStrategy {
    fn from(value: &pb::NetworkStrategy) -> Self {
        Self {
            kind: value.r#type.clone(),
            fallback_type: value.fallback_type.clone(),
            fallback_delay: value.fallback_delay.clone(),
        }
    }
}

impl From<&NetworkStrategy> for pb::NetworkStrategy {
    fn from(value: &NetworkStrategy) -> Self {
        Self {
            r#type: value.kind.clone(),
            fallback_type: value.fallback_type.clone(),
            fallback_delay: value.fallback_delay.clone(),
        }
    }
}

impl From<&pb::DialerOptions> for DialerOptions {
    fn from(value: &pb::DialerOptions) -> Self {
        Self {
            detour: value.detour.clone(),
            bind_interface: value.bind_interface.clone(),
            inet4_bind_address: value.inet4_bind_address.clone(),
            inet6_bind_address: value.inet6_bind_address.clone(),
            routing_mark: value.routing_mark,
            reuse_addr: value.reuse_addr,
            connect_timeout: value.connect_timeout.clone(),
            tcp_fast_open: value.tcp_fast_open,
            tcp_multi_path: value.tcp_multi_path,
            udp_fragment: value.udp_fragment,
            udp_timeout: value.udp_timeout.clone(),
            domain_strategy: value.domain_strategy.clone(),
            bind_address_no_port: value.bind_address_no_port,
            protect_path: value.protect_path.clone(),
            netns: value.netns.clone(),
            disable_tcp_keep_alive: value.disable_tcp_keep_alive,
            tcp_keep_alive: value.tcp_keep_alive.clone(),
            tcp_keep_alive_interval: value.tcp_keep_alive_interval.clone(),
            domain_resolver: value
                .domain_resolver
                .as_ref()
                .map(DomainResolveOptions::from),
            network_strategy: value.network_strategy.as_ref().map(NetworkStrategy::from),
            network_type: value.network_type.clone(),
            fallback_network_type: value.fallback_network_type.clone(),
            fallback_delay: value.fallback_delay.clone(),
        }
    }
}

impl From<&DialerOptions> for pb::DialerOptions {
    fn from(value: &DialerOptions) -> Self {
        Self {
            detour: value.detour.clone(),
            bind_interface: value.bind_interface.clone(),
            inet4_bind_address: value.inet4_bind_address.clone(),
            inet6_bind_address: value.inet6_bind_address.clone(),
            routing_mark: value.routing_mark,
            reuse_addr: value.reuse_addr,
            connect_timeout: value.connect_timeout.clone(),
            tcp_fast_open: value.tcp_fast_open,
            tcp_multi_path: value.tcp_multi_path,
            udp_fragment: value.udp_fragment,
            udp_timeout: value.udp_timeout.clone(),
            domain_strategy: value.domain_strategy.clone(),
            bind_address_no_port: value.bind_address_no_port,
            protect_path: value.protect_path.clone(),
            netns: value.netns.clone(),
            disable_tcp_keep_alive: value.disable_tcp_keep_alive,
            tcp_keep_alive: value.tcp_keep_alive.clone(),
            tcp_keep_alive_interval: value.tcp_keep_alive_interval.clone(),
            domain_resolver: value
                .domain_resolver
                .as_ref()
                .map(pb::DomainResolveOptions::from),
            network_strategy: value
                .network_strategy
                .as_ref()
                .map(pb::NetworkStrategy::from),
            network_type: value.network_type.clone(),
            fallback_network_type: value.fallback_network_type.clone(),
            fallback_delay: value.fallback_delay.clone(),
        }
    }
}

impl From<&pb::RouteConfig> for Route {
    fn from(route: &pb::RouteConfig) -> Self {
        Self {
            rules: route.rules.iter().map(RouteRule::from).collect(),
            rule_sets: route.rule_sets.iter().map(RouteRuleSet::from).collect(),
            final_: route.r#final.clone(),
            auto_detect_interface: route.auto_detect_interface,
            default_interface: route.default_interface.clone(),
            default_mark: route.default_mark,
            find_process: route.find_process,
            geoip: route.geoip.as_ref().map(GeoIpOptions::from),
            geosite: route.geosite.as_ref().map(GeositeOptions::from),
            override_android_vpn: route.override_android_vpn,
            default_domain_resolver: route
                .default_domain_resolver
                .as_ref()
                .map(DomainResolveOptions::from),
            default_network_strategy: route
                .default_network_strategy
                .as_ref()
                .map(NetworkStrategy::from),
            default_network_type: route.default_network_type.clone(),
            default_fallback_network_type: route.default_fallback_network_type.clone(),
            default_fallback_delay: route.default_fallback_delay.clone(),
        }
    }
}

impl From<&Route> for pb::RouteConfig {
    fn from(route: &Route) -> Self {
        Self {
            rules: route.rules.iter().map(pb::RouteRule::from).collect(),
            rule_sets: route.rule_sets.iter().map(pb::RouteRuleSet::from).collect(),
            r#final: route.final_.clone(),
            auto_detect_interface: route.auto_detect_interface,
            default_interface: route.default_interface.clone(),
            default_mark: route.default_mark,
            find_process: route.find_process,
            geoip: route.geoip.as_ref().map(pb::GeoIpOptions::from),
            geosite: route.geosite.as_ref().map(pb::GeositeOptions::from),
            override_android_vpn: route.override_android_vpn,
            default_domain_resolver: route
                .default_domain_resolver
                .as_ref()
                .map(pb::DomainResolveOptions::from),
            default_network_strategy: route
                .default_network_strategy
                .as_ref()
                .map(pb::NetworkStrategy::from),
            default_network_type: route.default_network_type.clone(),
            default_fallback_network_type: route.default_fallback_network_type.clone(),
            default_fallback_delay: route.default_fallback_delay.clone(),
        }
    }
}

impl From<&pb::DnsConfig> for Dns {
    fn from(dns: &pb::DnsConfig) -> Self {
        Self {
            rules: dns.rules.iter().map(DnsRule::from).collect(),
            servers: dns.servers.iter().map(DnsServer::from).collect(),
            final_: dns.r#final.clone(),
        }
    }
}

impl From<&Dns> for pb::DnsConfig {
    fn from(dns: &Dns) -> Self {
        Self {
            rules: dns.rules.iter().map(pb::DnsRule::from).collect(),
            servers: dns.servers.iter().map(pb::DnsServer::from).collect(),
            r#final: dns.final_.clone(),
        }
    }
}

impl From<&pb::DnsServer> for DnsServer {
    fn from(value: &pb::DnsServer) -> Self {
        Self {
            kind: value.r#type.clone(),
            tag: value.tag.clone(),
            server: value.server.clone(),
            detour: value.detour.clone(),
        }
    }
}

impl From<&DnsServer> for pb::DnsServer {
    fn from(value: &DnsServer) -> Self {
        Self {
            r#type: value.kind.clone(),
            tag: value.tag.clone(),
            server: value.server.clone(),
            detour: value.detour.clone(),
        }
    }
}

impl From<&pb::DnsRule> for DnsRule {
    fn from(value: &pb::DnsRule) -> Self {
        Self {
            inbound: value.inbound.clone(),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            rule_set: value.rule_set.clone(),
            action: value.action.clone(),
            rcode: value.rcode.clone(),
            server: value.server.clone(),
            method: value.method.clone(),
            no_drop: value.no_drop,
            answer: value.answer.clone(),
            ns: value.ns.clone(),
            extra: value.extra.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl.clone(),
            timeout: value.timeout.clone(),
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&DnsRule> for pb::DnsRule {
    fn from(value: &DnsRule) -> Self {
        Self {
            inbound: value.inbound.clone(),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            rule_set: value.rule_set.clone(),
            action: value.action.clone(),
            rcode: value.rcode.clone(),
            server: value.server.clone(),
            method: value.method.clone(),
            no_drop: value.no_drop,
            answer: value.answer.clone(),
            ns: value.ns.clone(),
            extra: value.extra.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl.clone(),
            timeout: value.timeout.clone(),
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&pb::GeoIpOptions> for GeoIpOptions {
    fn from(value: &pb::GeoIpOptions) -> Self {
        Self {
            path: value.path.clone(),
            download_url: value.download_url.clone(),
            download_detour: value.download_detour.clone(),
        }
    }
}

impl From<&GeoIpOptions> for pb::GeoIpOptions {
    fn from(value: &GeoIpOptions) -> Self {
        Self {
            path: value.path.clone(),
            download_url: value.download_url.clone(),
            download_detour: value.download_detour.clone(),
        }
    }
}

impl From<&pb::GeositeOptions> for GeositeOptions {
    fn from(value: &pb::GeositeOptions) -> Self {
        Self {
            path: value.path.clone(),
            download_url: value.download_url.clone(),
            download_detour: value.download_detour.clone(),
        }
    }
}

impl From<&GeositeOptions> for pb::GeositeOptions {
    fn from(value: &GeositeOptions) -> Self {
        Self {
            path: value.path.clone(),
            download_url: value.download_url.clone(),
            download_detour: value.download_detour.clone(),
        }
    }
}

impl From<&pb::RouteRule> for RouteRule {
    fn from(value: &pb::RouteRule) -> Self {
        Self {
            kind: value.r#type.clone(),
            inbound: value.inbound.clone(),
            network: value.network.clone(),
            ip_version: u8::try_from(value.ip_version).unwrap_or_default(),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            source_ip_cidr: value.source_ip_cidr.clone(),
            ip_cidr: value.ip_cidr.clone(),
            source_ip_is_private: value.source_ip_is_private,
            ip_is_private: value.ip_is_private,
            port: value.port.clone(),
            port_range: value.port_range.clone(),
            source_port: value.source_port.clone(),
            source_port_range: value.source_port_range.clone(),
            protocol: value.protocol.clone(),
            rule_set: value.rule_set.clone(),
            invert: value.invert,
            action: value.action.clone(),
            outbound: value.outbound.clone(),
            method: value.method.clone(),
            no_drop: value.no_drop,
            mode: value.mode.clone(),
            rules: value.rules.iter().map(RouteRule::from).collect(),
            auth_user: value.auth_user.clone(),
            client: value.client.clone(),
            geosite: value.geosite.clone(),
            source_geoip: value.source_geoip.clone(),
            geoip: value.geoip.clone(),
            process_name: value.process_name.clone(),
            process_path: value.process_path.clone(),
            process_path_regex: value.process_path_regex.clone(),
            package_name: value.package_name.clone(),
            user: value.user.clone(),
            user_id: value.user_id.clone(),
            clash_mode: value.clash_mode.clone(),
            network_type: value.network_type.clone(),
            network_is_expensive: value.network_is_expensive,
            network_is_constrained: value.network_is_constrained,
            wifi_ssid: value.wifi_ssid.clone(),
            wifi_bssid: value.wifi_bssid.clone(),
            default_interface_address: value.default_interface_address.clone(),
            preferred_by: value.preferred_by.clone(),
            rule_set_ip_cidr_match_source: value.rule_set_ip_cidr_match_source,
            route_options: value.route_options.as_ref().map(RouteActionOptions::from),
            direct_options: value.direct_options.as_ref().map(DialerOptions::from),
            sniff_options: value.sniff_options.as_ref().map(SniffActionOptions::from),
            resolve_options: value
                .resolve_options
                .as_ref()
                .map(ResolveActionOptions::from),
        }
    }
}

impl From<&RouteRule> for pb::RouteRule {
    fn from(value: &RouteRule) -> Self {
        Self {
            r#type: value.kind.clone(),
            inbound: value.inbound.clone(),
            network: value.network.clone(),
            ip_version: u32::from(value.ip_version),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            source_ip_cidr: value.source_ip_cidr.clone(),
            ip_cidr: value.ip_cidr.clone(),
            source_ip_is_private: value.source_ip_is_private,
            ip_is_private: value.ip_is_private,
            port: value.port.clone(),
            port_range: value.port_range.clone(),
            source_port_range: value.source_port_range.clone(),
            protocol: value.protocol.clone(),
            rule_set: value.rule_set.clone(),
            invert: value.invert,
            action: value.action.clone(),
            outbound: value.outbound.clone(),
            method: value.method.clone(),
            no_drop: value.no_drop,
            mode: value.mode.clone(),
            rules: value.rules.iter().map(pb::RouteRule::from).collect(),
            auth_user: value.auth_user.clone(),
            client: value.client.clone(),
            geosite: value.geosite.clone(),
            source_geoip: value.source_geoip.clone(),
            geoip: value.geoip.clone(),
            source_port: value.source_port.clone(),
            process_name: value.process_name.clone(),
            process_path: value.process_path.clone(),
            process_path_regex: value.process_path_regex.clone(),
            package_name: value.package_name.clone(),
            user: value.user.clone(),
            user_id: value.user_id.clone(),
            clash_mode: value.clash_mode.clone(),
            network_type: value.network_type.clone(),
            network_is_expensive: value.network_is_expensive,
            network_is_constrained: value.network_is_constrained,
            wifi_ssid: value.wifi_ssid.clone(),
            wifi_bssid: value.wifi_bssid.clone(),
            default_interface_address: value.default_interface_address.clone(),
            preferred_by: value.preferred_by.clone(),
            rule_set_ip_cidr_match_source: value.rule_set_ip_cidr_match_source,
            route_options: value
                .route_options
                .as_ref()
                .map(pb::RouteActionOptions::from),
            direct_options: value.direct_options.as_ref().map(pb::DialerOptions::from),
            sniff_options: value
                .sniff_options
                .as_ref()
                .map(pb::SniffActionOptions::from),
            resolve_options: value
                .resolve_options
                .as_ref()
                .map(pb::ResolveActionOptions::from),
        }
    }
}

impl From<&pb::RouteRuleSet> for RouteRuleSet {
    fn from(value: &pb::RouteRuleSet) -> Self {
        Self {
            kind: value.r#type.clone(),
            tag: value.tag.clone(),
            format: value.format.clone(),
            path: value.path.clone(),
            url: value.url.clone(),
            download_detour: value.download_detour.clone(),
            update_interval: value.update_interval.clone(),
            rules: value.rules.iter().map(HeadlessRule::from).collect(),
        }
    }
}

impl From<&RouteRuleSet> for pb::RouteRuleSet {
    fn from(value: &RouteRuleSet) -> Self {
        Self {
            r#type: value.kind.clone(),
            tag: value.tag.clone(),
            format: value.format.clone(),
            path: value.path.clone(),
            url: value.url.clone(),
            download_detour: value.download_detour.clone(),
            update_interval: value.update_interval.clone(),
            rules: value.rules.iter().map(pb::HeadlessRule::from).collect(),
        }
    }
}

impl From<&pb::RouteActionOptions> for RouteActionOptions {
    fn from(value: &pb::RouteActionOptions) -> Self {
        Self {
            override_address: value.override_address.clone(),
            override_port: value.override_port,
            network_strategy: value.network_strategy.as_ref().map(NetworkStrategy::from),
            fallback_delay: value.fallback_delay,
            udp_disable_domain_unmapping: value.udp_disable_domain_unmapping,
            udp_connect: value.udp_connect,
            udp_timeout: value.udp_timeout.clone(),
            tls_fragment: value.tls_fragment,
            tls_fragment_fallback_delay: value.tls_fragment_fallback_delay.clone(),
            tls_record_fragment: value.tls_record_fragment,
        }
    }
}

impl From<&RouteActionOptions> for pb::RouteActionOptions {
    fn from(value: &RouteActionOptions) -> Self {
        Self {
            override_address: value.override_address.clone(),
            override_port: value.override_port,
            network_strategy: value
                .network_strategy
                .as_ref()
                .map(pb::NetworkStrategy::from),
            fallback_delay: value.fallback_delay,
            udp_disable_domain_unmapping: value.udp_disable_domain_unmapping,
            udp_connect: value.udp_connect,
            udp_timeout: value.udp_timeout.clone(),
            tls_fragment: value.tls_fragment,
            tls_fragment_fallback_delay: value.tls_fragment_fallback_delay.clone(),
            tls_record_fragment: value.tls_record_fragment,
        }
    }
}

impl From<&pb::SniffActionOptions> for SniffActionOptions {
    fn from(value: &pb::SniffActionOptions) -> Self {
        Self {
            sniffer: value.sniffer.clone(),
            timeout: value.timeout.clone(),
        }
    }
}

impl From<&SniffActionOptions> for pb::SniffActionOptions {
    fn from(value: &SniffActionOptions) -> Self {
        Self {
            sniffer: value.sniffer.clone(),
            timeout: value.timeout.clone(),
        }
    }
}

impl From<&pb::ResolveActionOptions> for ResolveActionOptions {
    fn from(value: &pb::ResolveActionOptions) -> Self {
        Self {
            server: value.server.clone(),
            strategy: value.strategy.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl,
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&ResolveActionOptions> for pb::ResolveActionOptions {
    fn from(value: &ResolveActionOptions) -> Self {
        Self {
            server: value.server.clone(),
            strategy: value.strategy.clone(),
            disable_cache: value.disable_cache,
            rewrite_ttl: value.rewrite_ttl,
            client_subnet: value.client_subnet.clone(),
        }
    }
}

impl From<&pb::HeadlessRule> for HeadlessRule {
    fn from(value: &pb::HeadlessRule) -> Self {
        Self {
            kind: value.r#type.clone(),
            network: value.network.clone(),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            source_ip_cidr: value.source_ip_cidr.clone(),
            ip_cidr: value.ip_cidr.clone(),
            source_port: value.source_port.clone(),
            source_port_range: value.source_port_range.clone(),
            port: value.port.clone(),
            port_range: value.port_range.clone(),
            process_name: value.process_name.clone(),
            process_path: value.process_path.clone(),
            process_path_regex: value.process_path_regex.clone(),
            package_name: value.package_name.clone(),
            network_type: value.network_type.clone(),
            network_is_expensive: value.network_is_expensive,
            network_is_constrained: value.network_is_constrained,
            wifi_ssid: value.wifi_ssid.clone(),
            wifi_bssid: value.wifi_bssid.clone(),
            default_interface_address: value.default_interface_address.clone(),
            invert: value.invert,
            mode: value.mode.clone(),
            rules: value.rules.iter().map(HeadlessRule::from).collect(),
        }
    }
}

impl From<&HeadlessRule> for pb::HeadlessRule {
    fn from(value: &HeadlessRule) -> Self {
        Self {
            r#type: value.kind.clone(),
            network: value.network.clone(),
            domain: value.domain.clone(),
            domain_suffix: value.domain_suffix.clone(),
            domain_keyword: value.domain_keyword.clone(),
            domain_regex: value.domain_regex.clone(),
            source_ip_cidr: value.source_ip_cidr.clone(),
            ip_cidr: value.ip_cidr.clone(),
            source_port: value.source_port.clone(),
            source_port_range: value.source_port_range.clone(),
            port: value.port.clone(),
            port_range: value.port_range.clone(),
            process_name: value.process_name.clone(),
            process_path: value.process_path.clone(),
            process_path_regex: value.process_path_regex.clone(),
            package_name: value.package_name.clone(),
            network_type: value.network_type.clone(),
            network_is_expensive: value.network_is_expensive,
            network_is_constrained: value.network_is_constrained,
            wifi_ssid: value.wifi_ssid.clone(),
            wifi_bssid: value.wifi_bssid.clone(),
            default_interface_address: value.default_interface_address.clone(),
            invert: value.invert,
            mode: value.mode.clone(),
            rules: value.rules.iter().map(pb::HeadlessRule::from).collect(),
        }
    }
}
