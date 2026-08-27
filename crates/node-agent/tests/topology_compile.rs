use acp_proto::{
    MutationOperation, NodeMutation, NodeTopology, TopologyRoutePatch, UserMutation, UserStatus,
};
use node_agent::compile::{
    MAX_PROJECTED_CLIENT_CHAIN_BYTES, MAX_PROJECTED_CLIENT_CHAIN_HOPS,
    MAX_PROJECTED_URLTEST_GROUPS, compile_and_preflight, compile_with_warnings,
    direct_outbound_is_empty,
};
use node_agent::outbound_adapter::MAX_OUTBOUND_REFERENCE_DEPTH;
use node_agent::topology::provider::{
    CURRENT_CONFIG_VERSION, HYSTERIA2_SALAMANDER_ID, Hysteria2MasqueradeConfig,
    Hysteria2ObfsConfig, Hysteria2SalamanderConfig, Hysteria2TlsConfig, RealityHandshake,
    VLESS_REALITY_VISION_ID, VlessRealityConfig, VlessRealityVisionConfig,
    VlessRealityVisionTlsConfig,
};
use node_agent::topology::*;
use serde::Serialize;
use serde_json::{Value, json};
use shoes_engine::Engine;
use std::io::Write;

const UUID: &str = "11111111-1111-4111-8111-111111111111";
const REALITY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CERT: &str = include_str!("../../shoes-engine/tests/fixtures/test.crt");
const KEY: &str = include_str!("../../shoes-engine/tests/fixtures/test.key");

fn raw(value: impl Serialize) -> RawJson {
    RawJson::from(serde_json::to_value(value).expect("encode provider"))
}

fn active_user(id: &str, credential: &str) -> UserCredential {
    UserCredential {
        user_id: id.to_string(),
        credential: credential.to_string(),
        ..UserCredential::default()
    }
}

fn vless_config(tag: &str, port: u16) -> VlessRealityVisionConfig {
    VlessRealityVisionConfig {
        kind: "vless".into(),
        tag: tag.into(),
        listen: "127.0.0.1".into(),
        listen_port: port,
        flow: VLESS_FLOW_REALITY_VISION.into(),
        tls: VlessRealityVisionTlsConfig {
            enabled: true,
            server_name: "example.com".into(),
            reality: VlessRealityConfig {
                enabled: true,
                handshake: RealityHandshake {
                    server: "example.com".into(),
                    server_port: 443,
                },
                private_key: REALITY_KEY.into(),
                short_id: vec!["0123456789abcdef".into()],
                ..VlessRealityConfig::default()
            },
        },
        ..VlessRealityVisionConfig::default()
    }
}

fn hysteria_config(tag: &str, port: u16) -> Hysteria2SalamanderConfig {
    Hysteria2SalamanderConfig {
        kind: "hysteria2".into(),
        tag: tag.into(),
        listen: "127.0.0.1".into(),
        listen_port: port,
        obfs: Hysteria2ObfsConfig {
            kind: "salamander".into(),
            password: "obfs-secret".into(),
        },
        tls: Hysteria2TlsConfig {
            enabled: true,
            server_name: "example.com".into(),
            certificate_pem: CERT.into(),
            private_key_pem: KEY.into(),
            ..Hysteria2TlsConfig::default()
        },
        ..Hysteria2SalamanderConfig::default()
    }
}

fn node(
    id: &str,
    provider: &str,
    config: impl Serialize,
    users: Vec<UserCredential>,
) -> NodeInstance {
    NodeInstance {
        node_id: id.into(),
        provider_id: provider.into(),
        provider_config_version: CURRENT_CONFIG_VERSION,
        provider_config: raw(config),
        users,
    }
}

fn topology(nodes: Vec<NodeInstance>) -> MachineTopology {
    MachineTopology {
        machine_id: "machine-a".into(),
        revision: 7,
        nodes,
        ..MachineTopology::default()
    }
}

fn outbound(kind: impl Into<String>, tag: impl Into<String>, options: Value) -> Outbound {
    Outbound {
        kind: kind.into(),
        tag: tag.into(),
        options: raw(options),
    }
}

fn layered_selector_diamond(levels: usize) -> Vec<Outbound> {
    let mut outbounds = Vec::with_capacity(2 * (levels + 1));
    for level in 0..levels {
        let next_a = format!("a{:03}", level + 1);
        let next_b = format!("b{:03}", level + 1);
        for prefix in ['a', 'b'] {
            outbounds.push(outbound(
                "selector",
                format!("{prefix}{level:03}"),
                json!({
                    "outbounds": [&next_a, &next_b],
                    "default": &next_a,
                }),
            ));
        }
    }
    outbounds.push(outbound("direct", format!("a{levels:03}"), json!({})));
    outbounds.push(outbound("direct", format!("b{levels:03}"), json!({})));
    outbounds
}

fn selector_reference_chain(node_count: usize) -> Vec<Outbound> {
    assert!(node_count > 0);
    let mut outbounds = Vec::with_capacity(node_count);
    for index in 0..node_count - 1 {
        let next = format!("depth-{:03}", index + 1);
        outbounds.push(outbound(
            "selector",
            format!("depth-{index:03}"),
            json!({"outbounds": [&next], "default": &next}),
        ));
    }
    outbounds.push(outbound(
        "direct",
        format!("depth-{:03}", node_count - 1),
        json!({}),
    ));
    outbounds
}

fn proxy_detour_chain(hop_count: usize) -> Vec<Outbound> {
    assert!(hop_count > 0);
    let mut outbounds = Vec::with_capacity(hop_count);
    for index in 0..hop_count {
        let mut options = json!({
            "server": format!("192.0.2.{}", index % 250 + 1),
            "server_port": 8388,
            "method": "aes-128-gcm",
            "password": "secret",
            "network": "tcp",
        });
        if index > 0 {
            options["detour"] = Value::String(format!("hop-{:03}", index - 1));
        }
        outbounds.push(outbound("shadowsocks", format!("hop-{index:03}"), options));
    }
    outbounds
}

fn append_shared_detour_candidates(
    outbounds: &mut Vec<Outbound>,
    candidate_count: usize,
    detour: &str,
) -> Vec<String> {
    let mut members = Vec::with_capacity(candidate_count);
    for index in 0..candidate_count {
        let tag = format!("candidate-{index:05}");
        outbounds.push(outbound(
            "shadowsocks",
            &tag,
            json!({
                "server": format!("198.51.100.{}", index % 250 + 1),
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
                "network": "tcp",
                "detour": detour,
            }),
        ));
        members.push(tag);
    }
    members
}

#[test]
fn serde_and_proto_round_trip_the_complete_topology_surface() {
    let nested = HeadlessRule {
        kind: "default".into(),
        network: vec!["tcp".into()],
        domain: vec!["exact.example".into()],
        domain_suffix: vec!["example".into()],
        domain_keyword: vec!["key".into()],
        domain_regex: vec!["^x".into()],
        source_ip_cidr: vec!["10.0.0.0/8".into()],
        ip_cidr: vec!["192.0.2.0/24".into()],
        source_port: vec![1],
        source_port_range: vec!["2:3".into()],
        port: vec![443],
        port_range: vec!["80:81".into()],
        process_name: vec!["curl".into()],
        process_path: vec!["/bin/curl".into()],
        process_path_regex: vec!["curl$".into()],
        package_name: vec!["pkg".into()],
        network_type: vec!["wifi".into()],
        network_is_expensive: Some(true),
        network_is_constrained: Some(false),
        wifi_ssid: vec!["ssid".into()],
        wifi_bssid: vec!["bssid".into()],
        default_interface_address: vec!["192.0.2.1".into()],
        invert: true,
        mode: "and".into(),
        rules: vec![],
    };
    let strategy = NetworkStrategy {
        kind: vec!["tcp".into()],
        fallback_type: vec!["udp".into()],
        fallback_delay: "250ms".into(),
    };
    let resolver = DomainResolveOptions {
        server: "dns".into(),
        strategy: "ipv4_only".into(),
        disable_cache: true,
        rewrite_ttl: Some(60),
        client_subnet: "192.0.2.0/24".into(),
    };
    let dialer = DialerOptions {
        detour: "direct".into(),
        bind_interface: "eth0".into(),
        inet4_bind_address: "192.0.2.1".into(),
        inet6_bind_address: "2001:db8::1".into(),
        routing_mark: 9,
        reuse_addr: true,
        connect_timeout: "5s".into(),
        tcp_fast_open: true,
        tcp_multi_path: true,
        udp_fragment: true,
        udp_timeout: "10s".into(),
        domain_strategy: "prefer_ipv4".into(),
        bind_address_no_port: true,
        protect_path: "/protect".into(),
        netns: "ns".into(),
        disable_tcp_keep_alive: true,
        tcp_keep_alive: "30s".into(),
        tcp_keep_alive_interval: "10s".into(),
        domain_resolver: Some(resolver.clone()),
        network_strategy: Some(strategy.clone()),
        network_type: vec!["wifi".into()],
        fallback_network_type: vec!["cellular".into()],
        fallback_delay: "300ms".into(),
    };
    let rule = RouteRule {
        kind: "default".into(),
        inbound: vec!["edge".into()],
        network: vec!["tcp".into()],
        ip_version: 4,
        domain: vec!["example.com".into()],
        domain_suffix: vec!["example.net".into()],
        domain_keyword: vec!["key".into()],
        domain_regex: vec!["^x".into()],
        source_ip_cidr: vec!["10.0.0.0/8".into()],
        ip_cidr: vec!["192.0.2.0/24".into()],
        source_ip_is_private: Some(true),
        ip_is_private: Some(false),
        port: vec![443],
        port_range: vec!["80:90".into()],
        source_port: vec![1000],
        source_port_range: vec!["1000:2000".into()],
        protocol: vec!["tls".into()],
        rule_set: vec!["remote".into()],
        invert: true,
        action: "route".into(),
        outbound: "direct".into(),
        method: "default".into(),
        no_drop: true,
        mode: "and".into(),
        rules: vec![RouteRule::default()],
        auth_user: vec!["alice".into()],
        client: vec!["client".into()],
        geosite: vec!["cn".into()],
        source_geoip: vec!["us".into()],
        geoip: vec!["cn".into()],
        process_name: vec!["curl".into()],
        process_path: vec!["/bin/curl".into()],
        process_path_regex: vec!["curl$".into()],
        package_name: vec!["pkg".into()],
        user: vec!["user".into()],
        user_id: vec![1000],
        clash_mode: "global".into(),
        network_type: vec!["wifi".into()],
        network_is_expensive: Some(true),
        network_is_constrained: Some(false),
        wifi_ssid: vec!["ssid".into()],
        wifi_bssid: vec!["bssid".into()],
        default_interface_address: vec!["192.0.2.1".into()],
        preferred_by: vec!["eth0".into()],
        rule_set_ip_cidr_match_source: true,
        route_options: Some(RouteActionOptions {
            override_address: "example.org".into(),
            override_port: 8443,
            network_strategy: Some(strategy.clone()),
            fallback_delay: 42,
            udp_disable_domain_unmapping: true,
            udp_connect: true,
            udp_timeout: "5s".into(),
            tls_fragment: true,
            tls_fragment_fallback_delay: "10ms".into(),
            tls_record_fragment: true,
        }),
        direct_options: Some(dialer),
        sniff_options: Some(SniffActionOptions {
            sniffer: vec!["tls".into()],
            timeout: "300ms".into(),
        }),
        resolve_options: Some(ResolveActionOptions {
            server: "dns".into(),
            strategy: "ipv6_only".into(),
            disable_cache: true,
            rewrite_ttl: Some(30),
            client_subnet: "2001:db8::/64".into(),
        }),
    };
    let original = MachineTopology {
        machine_id: "machine".into(),
        revision: 9,
        nodes: vec![node(
            "node",
            VLESS_REALITY_VISION_ID,
            vless_config("edge", 1443),
            vec![active_user("alice", UUID)],
        )],
        outbounds: vec![Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: RawJson::new(br#"{"bind_interface":"eth0"}"#.to_vec()),
        }],
        route: Some(Route {
            rules: vec![rule],
            rule_sets: vec![RouteRuleSet {
                kind: "inline".into(),
                tag: "remote".into(),
                format: "source".into(),
                path: "/rules".into(),
                url: "https://example/rules".into(),
                download_detour: "direct".into(),
                update_interval: "1d".into(),
                rules: vec![nested],
            }],
            final_: "direct".into(),
            auto_detect_interface: true,
            default_interface: "eth0".into(),
            default_mark: 7,
            find_process: true,
            geoip: Some(GeoIpOptions {
                path: "/geoip".into(),
                download_url: "https://example/geoip".into(),
                download_detour: "direct".into(),
            }),
            geosite: Some(GeositeOptions {
                path: "/geosite".into(),
                download_url: "https://example/geosite".into(),
                download_detour: "direct".into(),
            }),
            override_android_vpn: true,
            default_domain_resolver: Some(resolver),
            default_network_strategy: Some(strategy),
            default_network_type: vec!["wifi".into()],
            default_fallback_network_type: vec!["cellular".into()],
            default_fallback_delay: "500ms".into(),
        }),
        dns: Some(Dns {
            rules: vec![DnsRule {
                inbound: vec!["edge".into()],
                domain: vec!["example.com".into()],
                domain_suffix: vec!["example.net".into()],
                domain_keyword: vec!["key".into()],
                domain_regex: vec!["^x".into()],
                rule_set: vec!["remote".into()],
                action: "route".into(),
                rcode: "NOERROR".into(),
                server: "dns".into(),
                method: "default".into(),
                no_drop: true,
                answer: vec!["1.1.1.1".into()],
                ns: vec!["ns.example".into()],
                extra: vec!["extra".into()],
                disable_cache: true,
                rewrite_ttl: "60".into(),
                timeout: "5s".into(),
                client_subnet: "192.0.2.0/24".into(),
            }],
            servers: vec![DnsServer {
                kind: "https".into(),
                tag: "dns".into(),
                server: "1.1.1.1".into(),
                detour: "direct".into(),
            }],
            final_: "dns".into(),
        }),
        snapshot: None,
    };

    let snapshot = to_snapshot(&original);
    let decoded = from_snapshot("fallback", Some(&snapshot));
    assert_eq!(decoded.machine_id, original.machine_id);
    assert_eq!(decoded.revision, original.revision);
    assert_eq!(decoded.nodes, original.nodes);
    assert_eq!(decoded.outbounds, original.outbounds);
    assert_eq!(decoded.route, original.route);
    assert_eq!(decoded.dns, original.dns);
    assert_eq!(to_snapshot(&decoded), snapshot);

    let json = serde_json::to_value(&decoded).expect("serialize topology");
    assert_eq!(json["route"]["final"], "direct");
    assert!(json["route"].get("final_").is_none());
}

#[test]
fn serde_missing_fields_follow_go_zero_value_semantics() {
    let topology: MachineTopology =
        serde_json::from_value(json!({"machine_id": "machine"})).unwrap();
    assert_eq!(topology.revision, 0);
    assert!(topology.nodes.is_empty());

    let provider: VlessRealityVisionConfig = serde_json::from_value(json!({})).unwrap();
    assert_eq!(provider.listen_port, 0);
    assert!(!provider.tls.enabled);
}

#[test]
fn snapshot_mutations_match_go_semantics() {
    let mut top = topology(vec![node(
        "node-a",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1443),
        vec![active_user("alice", UUID)],
    )]);
    top.snapshot = Some(to_snapshot(&top));

    apply_user_mutation_to_snapshot(
        &mut top,
        &UserMutation {
            operation: MutationOperation::Disable as i32,
            node_id: "node-a".into(),
            user: Some(acp_proto::UserCredential {
                user_id: "alice".into(),
                status: UserStatus::Active as i32,
                ..acp_proto::UserCredential::default()
            }),
            ..UserMutation::default()
        },
    );
    assert!(top.snapshot.as_ref().unwrap().nodes[0].users.is_empty());

    apply_node_mutation_to_snapshot(
        &mut top,
        &NodeMutation {
            operation: MutationOperation::Upsert as i32,
            node_id: "node-b".into(),
            node: Some(NodeTopology::default()),
        },
    );
    assert_eq!(top.snapshot.as_ref().unwrap().nodes[1].node_id, "node-b");

    apply_route_patch_to_snapshot(
        &mut top,
        &TopologyRoutePatch {
            machine_id: "patched".into(),
            revision: 22,
            outbounds: vec![],
            route: Some(acp_proto::RouteConfig {
                r#final: "direct".into(),
                ..acp_proto::RouteConfig::default()
            }),
            dns: None,
        },
    );
    let snapshot = top.snapshot.unwrap();
    assert_eq!(snapshot.machine_id, "patched");
    assert_eq!(snapshot.revision, 22);
    assert_eq!(snapshot.route.unwrap().r#final, "direct");
}

#[test]
fn machine_config_fallback_id_does_not_change_snapshot_digest_input() {
    let config = acp_proto::MachineConfig {
        machine_id: String::new(),
        revision: 3,
        nodes: vec![acp_proto::NodeConfig {
            node_id: "node".into(),
            provider_id: VLESS_REALITY_VISION_ID.into(),
            provider_config_version: 1,
            provider_config_json: br#"{}"#.to_vec(),
        }],
        ..acp_proto::MachineConfig::default()
    };
    let topology = from_machine_config("fallback", Some(&config));
    assert_eq!(topology.machine_id, "fallback");
    assert_eq!(topology.snapshot.as_ref().unwrap().machine_id, "");
    assert!(
        topology.snapshot.as_ref().unwrap().nodes[0]
            .users
            .is_empty()
    );

    let panel_snapshot = acp_proto::TopologySnapshot {
        machine_id: String::new(),
        revision: 3,
        nodes: vec![NodeTopology {
            node_id: "node".into(),
            provider_id: VLESS_REALITY_VISION_ID.into(),
            provider_config_version: 1,
            provider_config_json: br#"{}"#.to_vec(),
            users: vec![],
        }],
        ..acp_proto::TopologySnapshot::default()
    };
    assert_eq!(
        acp_proto::digest::sum(topology.snapshot.as_ref()),
        acp_proto::digest::sum(Some(&panel_snapshot))
    );
    assert_eq!(
        digest(&topology),
        Some(acp_proto::digest::sum(Some(&panel_snapshot)))
    );
}

#[tokio::test]
async fn both_protocols_compile_to_engine_accepted_native_shoes_json() {
    let mut disabled = active_user("disabled", "");
    disabled.status = "disabled".into();
    let mut limited = active_user("alice", UUID);
    limited.upload_speed_limit_bps = 1_000_000;
    limited.download_speed_limit_bps = 2_000_000;
    let top = topology(vec![
        node(
            "vless-node",
            VLESS_REALITY_VISION_ID,
            vless_config("vless-edge", 14430),
            vec![limited, disabled.clone()],
        ),
        node(
            "hy2-node",
            HYSTERIA2_SALAMANDER_ID,
            hysteria_config("hy2-edge", 14431),
            vec![active_user("bob", "hy2-password"), disabled],
        ),
    ]);
    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("both native configs pass engine preflight");
    assert_eq!(output.runtime.inbounds.len(), 2);
    for inbound in &output.runtime.inbounds {
        assert_eq!(inbound.spec.users.as_ref().unwrap().len(), 1);
        assert!(
            inbound
                .spec
                .users
                .as_ref()
                .unwrap()
                .iter()
                .all(|user| user.resolved_id() != Some("disabled"))
        );
    }
    let vless = output
        .runtime
        .inbounds
        .iter()
        .find(|inbound| inbound.protocol == "vless")
        .unwrap();
    assert_eq!(
        vless.spec.config["protocol"]["reality_targets"]["example.com"]["vision"],
        true
    );
    assert_eq!(vless.spec.config["sniff"], false);
    let hysteria2 = output
        .runtime
        .inbounds
        .iter()
        .find(|inbound| inbound.protocol == "hysteria2")
        .unwrap();
    assert!(
        hysteria2.spec.config.get("sniff").is_none(),
        "Hysteria2 has no provider sniff switch and must retain Shoes auto mode"
    );
    let user = &vless.spec.users.as_ref().unwrap()[0];
    assert_eq!(user.upload_limit_bps, Some(1_000_000));
    assert_eq!(user.download_limit_bps, Some(2_000_000));
}

#[tokio::test]
async fn local_srs_drives_route_and_dns_policy_through_engine_preflight() {
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source
        .write_all(br#"{"version":4,"rules":[{"domain_suffix":["ads.example"]}]}"#)
        .unwrap();
    source.flush().unwrap();

    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14433),
        vec![active_user("alice", UUID)],
    )]);
    let rule_set = RouteRuleSet {
        kind: "local".into(),
        tag: "ads".into(),
        format: "source".into(),
        path: source.path().to_string_lossy().into_owned(),
        ..RouteRuleSet::default()
    };
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain: vec!["direct.example".into()],
            rule_set: vec!["ads".into()],
            action: "reject".into(),
            ..RouteRule::default()
        }],
        rule_sets: vec![rule_set],
        final_: "direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        rules: vec![DnsRule {
            domain: vec!["direct.example".into()],
            rule_set: vec!["ads".into()],
            action: "predefined".into(),
            rcode: "NOERROR".into(),
            ..DnsRule::default()
        }],
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("local SRS route and DNS policy pass engine preflight");
    let config = &output.runtime.inbounds[0].spec.config;
    assert_eq!(config["rules"][0]["action"], "block");
    assert_eq!(
        config["rules"][0]["match"]["rule_set"][0]["format"],
        "source"
    );
    assert_eq!(
        config["rules"][0]["match"]["domain"],
        json!(["direct.example"])
    );
    assert_eq!(config["dns"]["rules"][0]["action"], "predefined");
    assert_eq!(
        config["dns"]["rules"][0]["rule_set"][0]["path"],
        source.path().to_string_lossy().as_ref()
    );
    assert_eq!(
        config["dns"]["rules"][0]["domain"],
        json!(["direct.example"])
    );
    assert_eq!(config["dns"]["rules"][0]["answer"], json!([]));
}

#[tokio::test]
async fn inline_rule_sets_support_mixed_route_and_dns_without_widening() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14435),
        vec![],
    )]);
    let inline = |tag: &str, suffix: &str| RouteRuleSet {
        kind: "inline".into(),
        tag: tag.into(),
        rules: vec![HeadlessRule {
            domain_suffix: vec![suffix.into()],
            ..HeadlessRule::default()
        }],
        ..RouteRuleSet::default()
    };
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain: vec!["direct.example".into()],
            rule_set: vec!["ads".into(), "telemetry".into()],
            invert: true,
            action: "reject".into(),
            ..RouteRule::default()
        }],
        rule_sets: vec![
            inline("ads", "ads.example"),
            inline("telemetry", "telemetry.example"),
        ],
        final_: "direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        rules: vec![DnsRule {
            domain: vec!["direct.example".into()],
            rule_set: vec!["ads".into(), "telemetry".into()],
            action: "predefined".into(),
            rcode: "NOERROR".into(),
            ..DnsRule::default()
        }],
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("inline domain rule-sets pass route and DNS preflight");
    assert_eq!(output.runtime.rule_sets.len(), 2);
    let config = &output.runtime.inbounds[0].spec.config;
    assert_eq!(config["rules"][0]["match"]["invert"], true);
    assert_eq!(
        config["rules"][0]["match"]["rule_set"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        config["dns"]["rules"][0]["rule_set"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // DNS Lookup has no destination port metadata. Keeping that field in an
    // inline set must reject the candidate rather than broaden it to domains.
    top.route.as_mut().unwrap().rule_sets[0].rules[0].port = vec![53];
    let error = compile_and_preflight(&top, &engine).await.unwrap_err();
    assert!(
        error.to_string().contains("cannot evaluate port"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn dns_rcodes_reject_methods_and_full_rr_sections_pass_engine_preflight() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14434),
        vec![],
    )]);
    let mut rules = ["NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL"]
        .into_iter()
        .map(|rcode| DnsRule {
            domain: vec![format!("{}.example", rcode.to_ascii_lowercase())],
            action: "predefined".into(),
            rcode: rcode.into(),
            ..DnsRule::default()
        })
        .collect::<Vec<_>>();
    rules[0].answer = vec![
        "noerror.example. 60 IN A 192.0.2.7".into(),
        "noerror.example. 60 IN TXT \"validated but not projected\"".into(),
        "uri.noerror.example. 60 IN URI 10 20 \"https://example.test/a b\"".into(),
        "loc.noerror.example. 60 IN LOC 37 47 0.0 N 122 23 0.0 W 10m".into(),
        "apl.noerror.example. 60 IN APL 1:192.0.2.0/24 !2:2001:db8::/32".into(),
        "hip.noerror.example. 60 IN HIP 2 200100107B1A74DF365639CC39F1D578 AQID rvs.example.test."
            .into(),
        r"unknown.noerror.example. 60 IN TYPE65400 \# 4 DEADBEEF".into(),
        // RFC 3597 presentation of A must still be decoded and projected.
        r"generic-a.noerror.example. 60 IN TYPE1 \# 4 C0000209".into(),
        // A zero-RDLENGTH known type is a Go-compatible update record and
        // must never become a lookup address.
        r"empty-a.noerror.example. 60 IN TYPE1 \# 0".into(),
        format!(
            "uri-limit.noerror.example. 60 IN URI 1 1 \"{}\"",
            "x".repeat(255)
        ),
        // Standalone wire-format A RR for example.test. => 192.0.2.8.
        "B2V4YW1wbGUEdGVzdAAAAQABAAAAPAAEwAACCA==".into(),
        // Go StdEncoding ignores CR/LF and sing-box ignores bytes after the
        // first successfully unpacked RR.
        "B2V4YW1wbGUEdGVzdAAA\r\nAQABAAAAPAAEwAACCN6tvg==".into(),
    ];
    rules[0].ns = vec!["noerror.example. 60 IN NS ns.noerror.example.".into()];
    rules[0].extra = vec!["ns.noerror.example. 60 IN A 192.0.2.53".into()];
    rules.extend([
        DnsRule {
            domain: vec!["reject.example".into()],
            action: "reject".into(),
            method: "default".into(),
            ..DnsRule::default()
        },
        DnsRule {
            domain: vec!["drop.example".into()],
            action: "reject".into(),
            method: "drop".into(),
            ..DnsRule::default()
        },
    ]);
    top.dns = Some(Dns {
        rules,
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("panel DNS terminal actions and resource records pass preflight");
    let compiled = output.runtime.inbounds[0].spec.config["dns"]["rules"]
        .as_array()
        .unwrap();
    for (index, rcode) in ["NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(compiled[index]["rcode"], rcode);
    }
    assert_eq!(
        compiled[0]["answer"],
        json!(top.dns.as_ref().unwrap().rules[0].answer)
    );
    assert_eq!(
        compiled[0]["ns"],
        json!(top.dns.as_ref().unwrap().rules[0].ns)
    );
    assert_eq!(
        compiled[0]["extra"],
        json!(top.dns.as_ref().unwrap().rules[0].extra)
    );
    assert_eq!(compiled[4]["method"], "default");
    assert_eq!(compiled[5]["method"], "drop");
}

#[test]
fn dns_predefined_rcode_names_match_miekg_strictly() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14436),
        vec![],
    )]);

    for rcode in ["FORMERR", "BADCOOKIE", "NOTIMPL"] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                domain: vec!["rcode.example".into()],
                action: "predefined".into(),
                rcode: rcode.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let output = compile_with_warnings(&top).unwrap_or_else(|error| panic!("{rcode}: {error}"));
        assert_eq!(
            output.runtime.inbounds[0].spec.config["dns"]["rules"][0]["rcode"], rcode,
            "the NOTIMPL compatibility alias must remain unmodified"
        );
    }

    for rcode in ["SUCCESS", "noerror", " NOERROR", "NOERROR "] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                domain: vec!["rcode.example".into()],
                action: "predefined".into(),
                rcode: rcode.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&top).unwrap_err();
        assert!(
            error.to_string().contains("exact miekg/dns"),
            "{rcode:?}: {error}"
        );
    }
}

#[test]
fn dns_predefined_rr_validation_is_bounded_and_fails_during_compile() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14435),
        vec![],
    )]);
    for (answer, expected) in [
        (vec!["not a resource record".to_string()], "resource record"),
        (
            vec![r"bounded.example. 0 IN TYPE65400 \# 5 DEADBEEF".to_string()],
            "RFC3597 RDLENGTH",
        ),
        (
            vec![r"bounded.example. 0 IN TYPE29 \# 5 0000000000".to_string()],
            "TYPE29",
        ),
        (
            vec![format!(
                "bounded.example. 0 IN URI 1 1 \"{}\"",
                "x".repeat(256)
            )],
            "limit is 255",
        ),
        (
            vec!["bounded.example. 0 IN TXT \"x\"".to_string(); 257],
            "limit is 256",
        ),
    ] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "predefined".into(),
                rcode: "NOERROR".into(),
                answer,
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&top).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn hysteria_bandwidth_directions_are_independent() {
    for (up, down) in [(0, 0), (100, 0), (0, 200), (100, 200)] {
        let mut config = hysteria_config("hy2", 14432);
        config.up_mbps = up;
        config.down_mbps = down;
        let output = compile_with_warnings(&topology(vec![node(
            "node",
            HYSTERIA2_SALAMANDER_ID,
            config,
            vec![active_user("alice", "password")],
        )]))
        .expect("bandwidth combination");
        let protocol = &output.runtime.inbounds[0].spec.config["protocol"];
        assert_eq!(protocol["up_mbps"], up);
        assert_eq!(protocol["down_mbps"], down);
    }
}

#[tokio::test]
async fn hysteria_proxy_and_fixed_masquerades_map_to_shoes() {
    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    for (index, masquerade) in [
        Hysteria2MasqueradeConfig {
            kind: "proxy".into(),
            url: "https://www.example.com/landing".into(),
            rewrite_host: true,
            ..Hysteria2MasqueradeConfig::default()
        },
        Hysteria2MasqueradeConfig {
            kind: "string".into(),
            content: "<h1>Welcome</h1>".into(),
            ..Hysteria2MasqueradeConfig::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut config = hysteria_config("hy2", 14500 + index as u16);
        config.obfs = Hysteria2ObfsConfig::default();
        config.masquerade = Some(masquerade.clone());
        let output = compile_and_preflight(
            &topology(vec![node(
                "node",
                HYSTERIA2_SALAMANDER_ID,
                config,
                vec![active_user("alice", "password")],
            )]),
            &engine,
        )
        .await
        .expect("masquerade passes engine preflight");
        let protocol = &output.runtime.inbounds[0].spec.config["protocol"];
        assert!(protocol.get("obfs").is_none());
        assert_eq!(protocol["masquerade"]["type"], masquerade.kind);
        if masquerade.kind == "proxy" {
            assert_eq!(protocol["masquerade"]["use_native_roots"], true);
        }
        if masquerade.kind == "string" {
            assert_eq!(
                protocol["masquerade"]["content_type"],
                "text/html; charset=utf-8"
            );
        }
    }
}

#[test]
fn provider_registry_rejects_go_validation_failures() {
    let mut cases: Vec<(NodeInstance, &str)> = Vec::new();
    let mut no_tls = vless_config("edge", 1443);
    no_tls.tls.enabled = false;
    cases.push((
        node("vless", VLESS_REALITY_VISION_ID, no_tls, vec![]),
        "tls.enabled",
    ));
    let mut no_handshake = vless_config("edge", 1443);
    no_handshake.tls.reality.handshake.server.clear();
    cases.push((
        node("vless", VLESS_REALITY_VISION_ID, no_handshake, vec![]),
        "handshake server",
    ));
    let mut negative = hysteria_config("hy2", 1444);
    negative.up_mbps = -1;
    cases.push((
        node("hy2", HYSTERIA2_SALAMANDER_ID, negative, vec![]),
        "must not be negative",
    ));
    let mut conflict = hysteria_config("hy2", 1444);
    conflict.masquerade = Some(Hysteria2MasqueradeConfig {
        kind: "string".into(),
        content: "cover".into(),
        ..Hysteria2MasqueradeConfig::default()
    });
    cases.push((
        node("hy2", HYSTERIA2_SALAMANDER_ID, conflict, vec![]),
        "requires obfs to be disabled",
    ));
    for (node, expected) in cases {
        let error = compile_with_warnings(&topology(vec![node])).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn unimplemented_inbound_and_route_controls_are_rejected_before_apply() {
    let mut tfo = vless_config("edge", 1443);
    tfo.tcp_fast_open = true;
    let error = compile_with_warnings(&topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        tfo,
        vec![],
    )]))
    .unwrap_err()
    .to_string();
    assert!(error.contains("tcp_fast_open"), "{error}");

    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1444),
        vec![],
    )]);
    top.route = Some(Route {
        auto_detect_interface: true,
        default_interface: "eth0".into(),
        default_mark: 7,
        find_process: true,
        geoip: Some(GeoIpOptions::default()),
        geosite: Some(GeositeOptions::default()),
        override_android_vpn: true,
        default_network_strategy: Some(NetworkStrategy::default()),
        default_network_type: vec!["wifi".into()],
        default_fallback_network_type: vec!["cellular".into()],
        default_fallback_delay: "500ms".into(),
        ..Route::default()
    });
    let error = compile_with_warnings(&top).unwrap_err().to_string();
    for field in [
        "auto_detect_interface",
        "default_interface",
        "default_mark",
        "find_process",
        "geoip",
        "geosite",
        "override_android_vpn",
        "default_network_strategy",
        "default_network_type",
        "default_fallback_network_type",
        "default_fallback_delay",
    ] {
        assert!(error.contains(field), "missing {field}: {error}");
    }
}

#[test]
fn provider_id_version_node_and_tag_uniqueness_are_enforced() {
    let unknown = node("node", "unknown@1", json!({}), vec![]);
    assert!(
        compile_with_warnings(&topology(vec![unknown]))
            .unwrap_err()
            .to_string()
            .contains("unsupported provider")
    );

    let mut bad_version = node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1443),
        vec![],
    );
    bad_version.provider_config_version = 2;
    assert!(
        compile_with_warnings(&topology(vec![bad_version]))
            .unwrap_err()
            .to_string()
            .contains("version 2")
    );

    let duplicate_node = topology(vec![
        node(
            "same",
            VLESS_REALITY_VISION_ID,
            vless_config("a", 1443),
            vec![],
        ),
        node(
            "same",
            VLESS_REALITY_VISION_ID,
            vless_config("b", 1444),
            vec![],
        ),
    ]);
    assert!(
        compile_with_warnings(&duplicate_node)
            .unwrap_err()
            .to_string()
            .contains("duplicate node_id")
    );

    let duplicate_tag = topology(vec![
        node(
            "a",
            VLESS_REALITY_VISION_ID,
            vless_config("same", 1443),
            vec![],
        ),
        node(
            "b",
            VLESS_REALITY_VISION_ID,
            vless_config("same", 1444),
            vec![],
        ),
    ]);
    assert!(
        compile_with_warnings(&duplicate_tag)
            .unwrap_err()
            .to_string()
            .contains("duplicate inbound tag")
    );
}

#[test]
fn outbound_validation_matches_core_go_vectors() {
    let base = node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1443),
        vec![],
    );
    for (outbound, expected) in [
        (
            Outbound {
                kind: "unknown".into(),
                tag: "test".into(),
                options: raw(json!({})),
            },
            "unknown outbound type",
        ),
        (
            Outbound {
                kind: "direct".into(),
                tag: "test".into(),
                options: raw(json!({"unknown": true})),
            },
            "unknown field",
        ),
        (
            Outbound {
                kind: "direct".into(),
                tag: "test".into(),
                options: raw(json!({"Tag": "other"})),
            },
            "managed field",
        ),
        (
            Outbound {
                kind: "direct".into(),
                tag: "test".into(),
                options: raw(json!([])),
            },
            "JSON object",
        ),
    ] {
        let mut top = topology(vec![base.clone()]);
        top.outbounds = vec![outbound];
        let error = compile_with_warnings(&top).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn unused_proxy_outbound_is_fully_validated_before_apply() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14590),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "trojan".into(),
            tag: "unused-trojan".into(),
            options: raw(json!({
                "server": "192.0.2.10",
                "server_port": 443,
                "password": "secret",
                "bogus": true
            })),
        },
    ];

    let error = compile_with_warnings(&top).expect_err("unused outbound must be validated");
    assert!(
        error
            .to_string()
            .contains("outbound \"unused-trojan\" trojan field \"bogus\""),
        "{error}"
    );
}

#[test]
fn unused_unsupported_outbound_combination_is_rejected_before_apply() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14592),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "shadowsocks".into(),
            tag: "unused-shadowsocks".into(),
            options: raw(json!({
                "server": "192.0.2.12",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
                "detour": "direct"
            })),
        },
    ];

    let error = compile_with_warnings(&top).expect_err("unused capability gap must be rejected");
    assert!(
        error.to_string().contains("native UDP with detour"),
        "{error}"
    );
}

#[test]
fn selector_validates_non_default_members_before_apply() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14591),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "selector".into(),
            tag: "selected".into(),
            options: raw(json!({
                "outbounds": ["direct", "unused-trojan"],
                "default": "direct"
            })),
        },
        Outbound {
            kind: "trojan".into(),
            tag: "unused-trojan".into(),
            options: raw(json!({
                "server": "192.0.2.11",
                "server_port": 443,
                "password": "secret",
                "bogus": true
            })),
        },
    ];

    let error = compile_with_warnings(&top).expect_err("inactive selector member must be checked");
    assert!(
        error.to_string().contains(
            "compile outbound \"unused-trojan\": outbound \"unused-trojan\" trojan field \"bogus\""
        ),
        "{error}"
    );
}

#[test]
fn selector_ignores_an_inactive_urltest_and_url_syntax_is_runtime_deferred() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14640),
        vec![],
    )]);
    top.outbounds = vec![
        outbound("direct", "direct", json!({})),
        outbound("urltest", "automatic", json!({"outbounds": ["direct"]})),
        outbound(
            "selector",
            "manual",
            json!({
                "outbounds": ["direct", "automatic"],
                "default": "direct",
            }),
        ),
    ];
    top.route = Some(Route {
        final_: "manual".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top).expect("inactive URLTest is not compiled by selector");
    let final_rule = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(final_rule["client_chains"].as_array().unwrap().len(), 1);
    assert_eq!(
        final_rule["client_chains"][0]["chain"][0]["protocol"]["type"],
        "direct"
    );
    assert!(final_rule.get("client_chain_selection").is_none());

    top.outbounds[1].options = raw(json!({
        "outbounds": ["direct"],
        "url": "relative-probe",
    }));
    compile_with_warnings(&top).expect("Go defers URL syntax errors to the async probe");

    top.route.as_mut().unwrap().final_ = "automatic".into();
    let output =
        compile_with_warnings(&top).expect("relative URL is preserved for runtime failure");
    let final_rule = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(
        final_rule["client_chain_selection"]["url"],
        "relative-probe"
    );
}

#[test]
fn selector_promotes_a_selected_urltest_action() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14641),
        vec![],
    )]);
    top.outbounds = vec![
        outbound("direct", "direct", json!({})),
        outbound(
            "vless",
            "proxy",
            json!({
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": UUID,
                "network": "tcp",
            }),
        ),
        outbound(
            "urltest",
            "automatic",
            json!({
                "outbounds": ["direct", "proxy"],
                "url": "https://example.com/generate_204",
            }),
        ),
        outbound(
            "selector",
            "manual",
            json!({"outbounds": ["direct", "automatic"], "default": "automatic"}),
        ),
    ];
    top.route = Some(Route {
        final_: "manual".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "proxied-dns".into(),
            server: "1.1.1.1".into(),
            detour: "manual".into(),
        }],
        final_: "proxied-dns".into(),
        ..Dns::default()
    });

    let output = compile_with_warnings(&top).expect("selected URLTest action is promoted");
    let config = &output.runtime.inbounds[0].spec.config;
    let final_rule = config["rules"].as_array().unwrap().last().unwrap();
    assert_eq!(final_rule["client_chains"].as_array().unwrap().len(), 2);
    assert_eq!(final_rule["client_chain_selection"]["type"], "urltest");
    assert_eq!(
        final_rule["client_chain_selection"]["url"],
        "https://example.com/generate_204"
    );
    assert_eq!(
        final_rule["client_chain_selection"]["history_keys"],
        json!(["direct", "proxy"])
    );
    assert_eq!(
        final_rule["client_chain_selection"]["failure_history_keys"],
        json!(["direct", "proxy"])
    );
    let shared_id = final_rule["client_chain_selection"]["shared_id"]
        .as_str()
        .expect("compiled URLTest action has a runtime identity");
    assert!(shared_id.starts_with("node-agent-urltest-v1:"));
    assert_eq!(shared_id.len(), "node-agent-urltest-v1:".len() + 64);
    let dns = &config["dns"]["servers"][0];
    assert_eq!(dns["client_chain"].as_array().unwrap().len(), 2);
    assert_eq!(
        dns["client_chain_selection"],
        final_rule["client_chain_selection"]
    );
}

#[test]
fn urltest_optional_scalar_nulls_follow_go_zero_value_decoding() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14648),
        vec![],
    )]);
    top.outbounds = vec![
        outbound("direct", "direct", json!({})),
        outbound(
            "urltest",
            "automatic",
            json!({
                "outbounds": ["direct"],
                "url": null,
                "tolerance": null,
                "interrupt_exist_connections": null,
            }),
        ),
    ];
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top).expect("Go ignores null primitive URLTest fields");
    let selection = &output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chain_selection"];
    assert_eq!(selection["url"], "");
    assert_eq!(selection["tolerance_millis"], 50);
    assert_eq!(selection["reselect_on_connection_failure"], false);

    top.outbounds[1].options = raw(json!({
        "outbounds": ["direct"],
        "url": "https://user%3Aname:p%40ss@example.com/health",
    }));
    let authenticated =
        compile_with_warnings(&top).expect("Go URLTest supports URL Basic authentication");
    let selection = &authenticated.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chain_selection"];
    assert_eq!(
        selection["url"],
        "https://user%3Aname:p%40ss@example.com/health"
    );

    top.outbounds[1].options = raw(json!({
        "outbounds": ["direct"],
        "interval": null,
    }));
    let error = compile_with_warnings(&top)
        .expect_err("Go duration wrappers still reject an explicit null");
    assert!(error.to_string().contains("Go duration string"), "{error}");
}

#[test]
fn selector_accepts_duplicate_members_and_lazy_interrupt_flag() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14642),
        vec![],
    )]);
    top.outbounds = vec![
        outbound("direct", "direct", json!({})),
        outbound(
            "selector",
            "manual",
            json!({
                "outbounds": ["direct", "direct"],
                "default": "direct",
                "interrupt_exist_connections": true,
            }),
        ),
    ];
    top.route = Some(Route {
        final_: "manual".into(),
        ..Route::default()
    });
    compile_with_warnings(&top)
        .expect("Go permits duplicate selector members and a boolean interrupt flag");

    top.outbounds[1].options = raw(json!({
        "outbounds": ["direct"],
        "interrupt_exist_connections": "true",
    }));
    let error = compile_with_warnings(&top).expect_err("the lazy field remains type-strict");
    assert!(error.to_string().contains("must be a boolean"), "{error}");
}

#[test]
fn outbound_reference_identity_preserves_nonempty_tag_whitespace() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14648),
        vec![],
    )]);
    top.outbounds = vec![
        outbound("direct", " direct ", json!({})),
        outbound(
            "selector",
            "direct",
            json!({"outbounds": [" direct "], "default": " direct "}),
        ),
    ];
    top.route = Some(Route {
        final_: "direct".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top)
        .expect("graph and adapter must use the same exact outbound tag identity");
    let final_rule = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(
        final_rule["client_chains"][0]["chain"][0]["protocol"]["type"],
        "direct"
    );
}

#[test]
fn catalog_rejects_inactive_selector_cycles() {
    let mut top = topology(vec![]);
    top.outbounds = vec![
        outbound("direct", "direct", json!({})),
        outbound(
            "selector",
            "a",
            json!({"outbounds": ["direct", "b"], "default": "direct"}),
        ),
        outbound(
            "selector",
            "b",
            json!({"outbounds": ["direct", "a"], "default": "direct"}),
        ),
    ];

    let error = compile_with_warnings(&top).expect_err("inactive graph edges still form a cycle");
    assert!(error.to_string().contains("a -> b -> a"), "{error}");
}

#[test]
fn layered_selector_diamond_validation_is_memoized() {
    // A depth-30 expansion used to make more than eight billion recursive
    // adapter calls even though the catalog contains only 62 outbounds.
    let mut top = topology(vec![]);
    top.outbounds = layered_selector_diamond(30);
    compile_with_warnings(&top).expect("shared selector subgraphs validate once per node");
}

#[test]
fn outbound_reference_depth_limit_has_an_exact_boundary() {
    let mut at_limit = topology(vec![]);
    at_limit.outbounds = selector_reference_chain(MAX_OUTBOUND_REFERENCE_DEPTH);
    compile_with_warnings(&at_limit).expect("the documented maximum depth is accepted");

    let mut above_limit = topology(vec![]);
    above_limit.outbounds = selector_reference_chain(MAX_OUTBOUND_REFERENCE_DEPTH + 1);
    let error = compile_with_warnings(&above_limit).expect_err("depth above the limit is rejected");
    assert!(
        error
            .to_string()
            .contains(&format!("maximum {MAX_OUTBOUND_REFERENCE_DEPTH}")),
        "{error}"
    );
}

#[test]
fn urltest_deduplicates_selected_real_tags_in_first_occurrence_order() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14643),
        vec![],
    )]);
    top.outbounds = vec![
        outbound(
            "shadowsocks",
            "first",
            json!({
                "server": "192.0.2.1",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
                "network": "tcp",
            }),
        ),
        outbound(
            "shadowsocks",
            "second",
            json!({
                "server": "192.0.2.2",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
                "network": "tcp",
            }),
        ),
        outbound(
            "urltest",
            "automatic",
            json!({
                "outbounds": ["first-choice", "first-choice", "first-alias", "second"]
            }),
        ),
        outbound(
            "selector",
            "first-choice",
            json!({"outbounds": ["first"], "default": "first"}),
        ),
        outbound(
            "selector",
            "first-alias",
            json!({"outbounds": ["first"], "default": "first"}),
        ),
    ];
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top)
        .expect("duplicate URLTest RealTags share one Go-equivalent probe candidate");
    let final_rule = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(
        final_rule["client_chain_selection"]["history_keys"],
        json!(["first", "second"])
    );
    assert_eq!(
        final_rule["client_chain_selection"]["failure_history_keys"],
        json!(["first-choice", "second"])
    );
    let chains = final_rule["client_chains"].as_array().unwrap();
    let addresses: Vec<&str> = chains
        .iter()
        .map(|chain| chain["chain"][0]["address"].as_str().unwrap())
        .collect();
    assert_eq!(addresses, ["192.0.2.1:8388", "192.0.2.2:8388"]);
}

#[test]
fn urltest_real_tag_folds_only_one_selector_layer() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14646),
        vec![],
    )]);
    top.outbounds = vec![
        outbound(
            "shadowsocks",
            "terminal",
            json!({
                "server": "192.0.2.3",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret",
                "network": "tcp",
            }),
        ),
        outbound(
            "selector",
            "inner",
            json!({"outbounds": ["terminal"], "default": "terminal"}),
        ),
        outbound(
            "selector",
            "outer",
            json!({"outbounds": ["inner"], "default": "inner"}),
        ),
        outbound(
            "urltest",
            "automatic",
            json!({"outbounds": ["outer", "inner"]}),
        ),
    ];
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top)
        .expect("one-level Go RealTags inner and terminal remain separate candidates");
    let final_rule = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(
        final_rule["client_chain_selection"]["history_keys"],
        json!(["inner", "terminal"])
    );
    assert_eq!(
        final_rule["client_chain_selection"]["failure_history_keys"],
        json!(["outer", "inner"])
    );
    let chains = final_rule["client_chains"].as_array().unwrap();
    let addresses: Vec<&str> = chains
        .iter()
        .map(|chain| chain["chain"][0]["address"].as_str().unwrap())
        .collect();
    assert_eq!(addresses, ["192.0.2.3:8388", "192.0.2.3:8388"]);
}

#[test]
fn urltest_distinct_real_tags_share_a_wide_terminal_projection() {
    const MEMBER_COUNT: usize = 4_096;
    const CANDIDATE_COUNT: usize = 256;

    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14647),
        vec![],
    )]);
    top.outbounds.push(outbound(
        "shadowsocks",
        "terminal",
        json!({
            "server": "192.0.2.4",
            "server_port": 8388,
            "method": "aes-128-gcm",
            "password": "secret",
            "network": "tcp",
        }),
    ));
    top.outbounds.push(outbound(
        "selector",
        "shared",
        json!({
            "outbounds": vec!["terminal"; MEMBER_COUNT],
            "default": "terminal",
        }),
    ));

    let mut candidates = Vec::with_capacity(CANDIDATE_COUNT);
    for index in 0..CANDIDATE_COUNT {
        let inner = format!("inner-{index:03}");
        let outer = format!("outer-{index:03}");
        top.outbounds.push(outbound(
            "selector",
            &inner,
            json!({"outbounds": ["shared"], "default": "shared"}),
        ));
        top.outbounds.push(outbound(
            "selector",
            &outer,
            json!({"outbounds": [&inner], "default": inner}),
        ));
        candidates.push(outer);
    }
    top.outbounds.push(outbound(
        "urltest",
        "automatic",
        json!({"outbounds": candidates}),
    ));
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let output = compile_with_warnings(&top)
        .expect("distinct one-level RealTags retain candidates while sharing terminal work");
    let chains = output.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chains"]
        .as_array()
        .unwrap();
    assert_eq!(chains.len(), CANDIDATE_COUNT);
    assert!(
        chains
            .iter()
            .all(|chain| chain["chain"][0]["address"] == "192.0.2.4:8388")
    );
}

#[test]
fn urltest_rejects_shared_chain_expansion_at_the_hop_budget() {
    let shared_hops = MAX_OUTBOUND_REFERENCE_DEPTH - 2;
    let projected_hops_per_member = shared_hops + 1;
    let member_count = MAX_PROJECTED_CLIENT_CHAIN_HOPS / projected_hops_per_member + 1;
    let shared_tag = format!("hop-{:03}", shared_hops - 1);
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14644),
        vec![],
    )]);
    top.outbounds = proxy_detour_chain(shared_hops);
    let members = append_shared_detour_candidates(&mut top.outbounds, member_count, &shared_tag);
    top.outbounds.push(outbound(
        "urltest",
        "automatic",
        json!({"outbounds": members}),
    ));
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let error = compile_with_warnings(&top)
        .expect_err("the repeated N by D expansion must fail before cloning all chains");
    assert!(
        error.to_string().contains("projection budget exceeded"),
        "{error}"
    );
    assert!(
        error.to_string().contains(&format!(
            "maximums are {MAX_PROJECTED_CLIENT_CHAIN_HOPS} hops"
        )),
        "{error}"
    );
}

#[test]
fn distinct_active_urltests_fail_loudly_at_the_group_budget() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14649),
        vec![],
    )]);
    top.outbounds.push(outbound("direct", "direct", json!({})));
    let mut rules = Vec::new();
    for index in 0..=MAX_PROJECTED_URLTEST_GROUPS {
        let tag = format!("automatic-{index:03}");
        top.outbounds
            .push(outbound("urltest", &tag, json!({"outbounds": ["direct"]})));
        rules.push(RouteRule {
            domain: vec![format!("probe-{index:03}.example")],
            action: "route".into(),
            outbound: tag,
            ..RouteRule::default()
        });
    }
    top.route = Some(Route {
        rules,
        final_: "direct".into(),
        ..Route::default()
    });

    let error = compile_with_warnings(&top)
        .expect_err("each distinct URLTest owns one worker and must be bounded");
    assert!(
        error
            .to_string()
            .contains(&format!("maximum is {MAX_PROJECTED_URLTEST_GROUPS}")),
        "{error}"
    );
}

#[test]
fn urltest_rejects_large_shared_members_at_the_byte_budget() {
    let password = "x".repeat(128 * 1024);
    let member_count = 520;
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14645),
        vec![],
    )]);
    top.outbounds = vec![outbound(
        "trojan",
        "wide",
        json!({
            "server": "192.0.2.1",
            "server_port": 443,
            "password": password,
            "network": "tcp",
        }),
    )];
    let members = append_shared_detour_candidates(&mut top.outbounds, member_count, "wide");
    top.outbounds.push(outbound(
        "urltest",
        "automatic",
        json!({"outbounds": members}),
    ));
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let error = compile_with_warnings(&top)
        .expect_err("the serialized shared-chain projection must fail before final assembly");
    assert!(
        error.to_string().contains("projection budget exceeded"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains(&format!("{MAX_PROJECTED_CLIENT_CHAIN_BYTES} bytes")),
        "{error}"
    );
}

#[test]
fn projection_budget_accumulates_across_runtime_inbounds() {
    let shared_hops = MAX_OUTBOUND_REFERENCE_DEPTH - 2;
    let projected_hops_per_member = shared_hops + 1;
    let members_per_inbound = MAX_PROJECTED_CLIENT_CHAIN_HOPS / 2 / projected_hops_per_member + 1;
    let shared_tag = format!("hop-{:03}", shared_hops - 1);
    let mut top = topology(vec![
        node(
            "first-node",
            VLESS_REALITY_VISION_ID,
            vless_config("first-edge", 14646),
            vec![],
        ),
        node(
            "second-node",
            VLESS_REALITY_VISION_ID,
            vless_config("second-edge", 14647),
            vec![],
        ),
    ]);
    top.outbounds = proxy_detour_chain(shared_hops);
    let members =
        append_shared_detour_candidates(&mut top.outbounds, members_per_inbound, &shared_tag);
    top.outbounds.push(outbound(
        "urltest",
        "automatic",
        json!({"outbounds": members}),
    ));
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });

    let error = compile_with_warnings(&top)
        .expect_err("two individually valid projections must share one RuntimeConfig budget");
    assert!(
        error.to_string().contains("projection budget exceeded"),
        "{error}"
    );
    assert!(
        error.to_string().contains(&format!(
            "maximums are {MAX_PROJECTED_CLIENT_CHAIN_HOPS} hops"
        )),
        "{error}"
    );
}

#[test]
fn projection_budget_counts_dns_rule_profile_variant_chain_copies() {
    let shared_hops = MAX_OUTBOUND_REFERENCE_DEPTH - 2;
    let projected_hops_per_member = shared_hops + 1;
    let member_count = MAX_PROJECTED_CLIENT_CHAIN_HOPS / 2 / projected_hops_per_member + 1;
    let shared_tag = format!("hop-{:03}", shared_hops - 1);
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14649),
        vec![],
    )]);
    top.outbounds = proxy_detour_chain(shared_hops);
    top.outbounds
        .push(outbound("direct", "route-direct", json!({})));
    let members = append_shared_detour_candidates(&mut top.outbounds, member_count, &shared_tag);
    top.outbounds.push(outbound(
        "urltest",
        "automatic",
        json!({"outbounds": members}),
    ));
    top.route = Some(Route {
        final_: "route-direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "proxied-dns".into(),
            server: "1.1.1.1".into(),
            detour: "automatic".into(),
        }],
        rules: vec![DnsRule {
            domain: vec!["example.com".into()],
            action: "route".into(),
            server: "proxied-dns".into(),
            rewrite_ttl: "60".into(),
            ..DnsRule::default()
        }],
        final_: "proxied-dns".into(),
    });

    let error = compile_with_warnings(&top)
        .expect_err("a private DNS profile must reserve its copied client chains before cloning");
    assert!(
        error
            .to_string()
            .contains("dns.rules[0] private DNS profile variant"),
        "{error}"
    );
    assert!(
        error.to_string().contains("projection budget exceeded"),
        "{error}"
    );
}

#[test]
fn nested_active_urltests_and_urltest_detours_are_rejected() {
    let base = vec![
        outbound("direct", "direct", json!({})),
        outbound("urltest", "inner", json!({"outbounds": ["direct"]})),
        outbound(
            "selector",
            "selected-inner",
            json!({"outbounds": ["direct", "inner"], "default": "inner"}),
        ),
    ];

    let mut nested = topology(vec![]);
    nested.outbounds = base.clone();
    nested.outbounds.push(outbound(
        "urltest",
        "outer",
        json!({"outbounds": ["selected-inner"]}),
    ));
    let error = compile_with_warnings(&nested).expect_err("active nested URLTest is unsupported");
    assert!(
        error.to_string().contains("nested active urltest"),
        "{error}"
    );

    let mut detoured = topology(vec![]);
    detoured.outbounds = base;
    detoured.outbounds.push(outbound(
        "vless",
        "proxy",
        json!({
            "server": "127.0.0.1",
            "server_port": 443,
            "uuid": UUID,
            "network": "tcp",
            "detour": "selected-inner",
        }),
    ));
    let error = compile_with_warnings(&detoured).expect_err("URLTest cannot be a protocol detour");
    assert!(
        error
            .to_string()
            .contains("cannot embed active client-chain selection"),
        "{error}"
    );
}

#[test]
fn all_go_registered_outbound_types_validate_and_raw_options_are_audited() {
    let cases = [
        ("direct", json!({"inet4_bind_address": "127.0.0.1"})),
        (
            "selector",
            json!({"outbounds": ["direct"], "default": "direct"}),
        ),
        (
            "urltest",
            json!({
                "outbounds": ["direct"],
                "url": "https://example.com/generate_204",
                "interval": "5m"
            }),
        ),
        (
            "shadowsocks",
            json!({
                "server": "127.0.0.1",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "secret"
            }),
        ),
        (
            "trojan",
            json!({"server": "127.0.0.1", "server_port": 443, "password": "secret"}),
        ),
        (
            "vless",
            json!({"server": "127.0.0.1", "server_port": 443, "uuid": UUID}),
        ),
        (
            "hysteria2",
            json!({
                "server": "127.0.0.1",
                "server_port": 443,
                "password": "secret",
                "tls": {"enabled": true, "server_name": "example.com", "insecure": true}
            }),
        ),
    ];
    for (index, (kind, options)) in cases.into_iter().enumerate() {
        let mut top = topology(vec![node(
            "node",
            VLESS_REALITY_VISION_ID,
            vless_config("edge", 14600 + index as u16),
            vec![],
        )]);
        let candidate = Outbound {
            kind: kind.into(),
            tag: if kind == "direct" {
                "direct".into()
            } else {
                format!("test-{kind}")
            },
            options: raw(options),
        };
        top.outbounds = if kind == "direct" {
            vec![candidate]
        } else {
            vec![
                Outbound {
                    kind: "direct".into(),
                    tag: "direct".into(),
                    options: raw(json!({})),
                },
                candidate,
            ]
        };
        compile_with_warnings(&top).expect("registered Go outbound type validates");
    }

    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14620),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "direct".into(),
            tag: "bound-direct".into(),
            options: raw(json!({
                "inet4_bind_address": "203.0.113.10",
                "domain_resolver": {"server": "bound-dns", "strategy": "ipv4_only"}
            })),
        },
    ];
    top.route = Some(Route {
        final_: "bound-direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "bound-dns".into(),
            server: "1.1.1.1".into(),
            ..DnsServer::default()
        }],
        final_: "bound-dns".into(),
        ..Dns::default()
    });
    let output = compile_with_warnings(&top).expect("per-outbound resolver is native");
    let config = &output.runtime.inbounds[0].spec.config;
    let final_chain = config["rules"].as_array().unwrap().last().unwrap();
    let resolver_tag = final_chain["client_chains"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    assert!(resolver_tag.starts_with("__acp_dns_profile_"));
    let variant = config["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|server| server["tag"] == resolver_tag)
        .unwrap();
    assert_eq!(variant["ip_strategy"], "ipv4_only");
    assert_eq!(variant["url"], "https://1.1.1.1/dns-query");
}

#[test]
fn direct_outbound_empty_semantics_match_go_vectors() {
    for (options, expected) in [
        (json!({}), true),
        (json!({"bind_interface": ""}), true),
        (json!({"inet4_bind_address": "192.0.2.10"}), false),
        (json!({"domain_resolver": {"server": "default-dns"}}), false),
        (json!({"udp_fragment": false}), false),
    ] {
        assert_eq!(direct_outbound_is_empty(&raw(options)).unwrap(), expected);
    }
    assert!(direct_outbound_is_empty(&raw(json!({"unknown": true}))).is_err());
}

#[tokio::test]
async fn route_and_doq_detours_compile_through_the_decoupled_outbound_adapter() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14630),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "vless".into(),
            tag: "proxy".into(),
            options: raw(json!({
                "server": "proxy.example.com",
                "server_port": 443,
                "uuid": UUID,
                "network": ["tcp", "udp"],
                "tls": {"enabled": true, "server_name": "proxy.example.com"}
            })),
        },
        Outbound {
            kind: "selector".into(),
            tag: "selected".into(),
            options: raw(json!({
                "outbounds": ["direct", "proxy"],
                "default": "proxy"
            })),
        },
    ];
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain_suffix: vec!["example.com".into()],
            action: "route".into(),
            outbound: "selected".into(),
            ..RouteRule::default()
        }],
        final_: "direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![
            DnsServer {
                kind: "quic".into(),
                tag: "proxied-dns".into(),
                server: "1.1.1.1".into(),
                detour: "selected".into(),
            },
            DnsServer {
                kind: "h3".into(),
                tag: "proxied-h3".into(),
                server: "1.0.0.1".into(),
                detour: "selected".into(),
            },
        ],
        final_: "proxied-dns".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("route and DNS detours must pass shoes preflight");
    let config = &output.runtime.inbounds[0].spec.config;
    assert_eq!(
        config["rules"][0]["client_chains"][0]["chain"][0]["address"],
        "proxy.example.com:443"
    );
    assert!(
        config["rules"][0]["client_chains"][0]["chain"][0]
            .get("pool")
            .is_none(),
        "selector must remain its static default, not become round-robin"
    );
    assert_eq!(
        config["rules"][1]["client_chains"][0]["chain"][0]["protocol"]["type"],
        "direct"
    );
    assert_eq!(
        config["dns"]["servers"][0]["client_chain"][0]["chain"][0]["address"],
        "proxy.example.com:443"
    );
    assert_eq!(
        config["dns"]["servers"][0]["client_chain"][0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
        true
    );
    assert_eq!(config["dns"]["servers"][0]["url"], "quic://1.1.1.1");
    assert_eq!(
        config["dns"]["servers"][1]["client_chain"][0]["chain"][0]["address"],
        "proxy.example.com:443"
    );
    assert_eq!(config["dns"]["servers"][1]["url"], "h3://1.0.0.1/dns-query");
}

#[tokio::test]
async fn hysteria2_outbound_routes_and_dns_detours_pass_shoes_preflight() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14633),
        vec![],
    )]);
    top.outbounds = vec![Outbound {
        kind: "hysteria2".into(),
        tag: "hy2-proxy".into(),
        options: raw(json!({
            "server": "hy2.example.com",
            "server_port": 443,
            "password": "proxy-secret",
            "up_mbps": 100,
            "down_mbps": 200,
            "obfs": { "type": "salamander", "password": "obfs-secret" },
            "tls": {
                "enabled": true,
                "server_name": "hy2.example.com",
                "insecure": true
            }
        })),
    }];
    top.route = Some(Route {
        final_: "hy2-proxy".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "proxied-dns".into(),
            server: "1.1.1.1".into(),
            detour: "hy2-proxy".into(),
        }],
        final_: "proxied-dns".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("Hysteria2 route and DNS detour must pass shoes preflight");
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);

    let config = &output.runtime.inbounds[0].spec.config;
    let route_hop =
        &config["rules"].as_array().unwrap().last().unwrap()["client_chains"][0]["chain"][0];
    assert_eq!(route_hop["address"], "hy2.example.com:443");
    assert_eq!(route_hop["transport"], "quic");
    assert_eq!(route_hop["protocol"]["type"], "hysteria2");
    assert_eq!(route_hop["protocol"]["udp_enabled"], true);
    assert_eq!(route_hop["protocol"]["up_mbps"], 100);
    assert_eq!(route_hop["protocol"]["down_mbps"], 200);

    let dns_hop = &config["dns"]["servers"][0]["client_chain"][0]["chain"][0];
    assert_eq!(dns_hop, route_hop);
}

#[tokio::test]
async fn urltest_selects_complete_route_and_dns_detour_chains() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14634),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "vless".into(),
            tag: "proxy".into(),
            options: raw(json!({
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": UUID,
                "network": ["tcp", "udp"]
            })),
        },
        Outbound {
            kind: "urltest".into(),
            tag: "automatic".into(),
            options: raw(json!({
                "outbounds": ["direct", "proxy"],
                "url": "https://example.com/generate_204",
                "interval": "5m",
                "idle_timeout": "10m",
                "tolerance": 75
            })),
        },
    ];
    top.route = Some(Route {
        final_: "automatic".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "proxied-dns".into(),
            server: "1.1.1.1".into(),
            detour: "automatic".into(),
        }],
        final_: "proxied-dns".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("URLTest route and DNS detour must pass shoes preflight");
    let config = &output.runtime.inbounds[0].spec.config;
    let final_rule = config["rules"].as_array().unwrap().last().unwrap();
    assert_eq!(final_rule["client_chains"].as_array().unwrap().len(), 2);
    assert_eq!(final_rule["client_chain_selection"]["type"], "urltest");
    assert_eq!(
        final_rule["client_chain_selection"]["use_native_roots"],
        true
    );
    assert_eq!(
        final_rule["client_chain_selection"]["reselect_on_connection_failure"],
        false
    );
    assert_eq!(
        final_rule["client_chain_selection"]["url"],
        "https://example.com/generate_204"
    );
    assert_eq!(
        final_rule["client_chain_selection"]["interval_millis"],
        300_000
    );
    assert_eq!(
        final_rule["client_chain_selection"]["idle_timeout_millis"],
        600_000
    );
    assert_eq!(final_rule["client_chain_selection"]["tolerance_millis"], 75);

    let dns = &config["dns"]["servers"][0];
    assert_eq!(dns["use_native_roots"], true);
    assert_eq!(dns["client_chain"].as_array().unwrap().len(), 2);
    assert!(dns.get("client_chains").is_none());
    assert_eq!(
        dns["client_chain_selection"],
        final_rule["client_chain_selection"]
    );
}

#[test]
fn urltest_rejects_semantics_that_cannot_be_preserved() {
    for (options, expected) in [
        (
            json!({
                "outbounds": ["direct"],
                "interval": "1500us"
            }),
            "sub-millisecond precision",
        ),
        (
            json!({
                "outbounds": ["direct"],
                "interval": "2m",
                "idle_timeout": "1m"
            }),
            "interval must be less than or equal",
        ),
        (
            json!({
                "outbounds": ["direct"],
                "interrupt_exist_connections": true
            }),
            "cannot revoke already-established connections",
        ),
    ] {
        let mut top = topology(vec![node(
            "node",
            VLESS_REALITY_VISION_ID,
            vless_config("edge", 14636),
            vec![],
        )]);
        top.outbounds = vec![
            Outbound {
                kind: "direct".into(),
                tag: "direct".into(),
                options: raw(json!({})),
            },
            Outbound {
                kind: "urltest".into(),
                tag: "automatic".into(),
                options: raw(options),
            },
        ];
        top.route = Some(Route {
            final_: "automatic".into(),
            ..Route::default()
        });
        let error = compile_with_warnings(&top).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[tokio::test]
async fn proxy_domain_resolver_selects_a_private_named_upstream_variant() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14635),
        vec![],
    )]);
    let proxy_options = json!({
        "server": "proxy.example.com",
        "server_port": 443,
        "uuid": UUID,
        "network": "tcp",
        "domain_resolver": {
            "server": "proxy-dns",
            "strategy": "prefer_ipv6",
            "disable_cache": true,
            "rewrite_ttl": 0,
            "client_subnet": "192.0.2.129/24"
        }
    });
    top.outbounds = vec![
        Outbound {
            kind: "vless".into(),
            tag: "proxy".into(),
            options: raw(proxy_options.clone()),
        },
        Outbound {
            kind: "vless".into(),
            tag: "proxy-copy".into(),
            options: raw(proxy_options),
        },
    ];
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain: vec!["copy.example".into()],
            action: "route".into(),
            outbound: "proxy-copy".into(),
            ..RouteRule::default()
        }],
        final_: "proxy".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "proxy-dns".into(),
            server: "1.1.1.1".into(),
            ..DnsServer::default()
        }],
        final_: "proxy-dns".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("a proxy-specific resolver must pass shoes preflight");
    let config = &output.runtime.inbounds[0].spec.config;
    let hop = &config["rules"].as_array().unwrap().last().unwrap()["client_chains"][0]["chain"][0];
    let resolver_tag = hop["dns_resolver"].as_str().unwrap();
    assert!(resolver_tag.starts_with("__acp_dns_profile_"));
    assert_eq!(
        config["rules"][0]["client_chains"][0]["chain"][0]["dns_resolver"], resolver_tag,
        "identical outbound profiles must reuse one private resolver"
    );

    let servers = config["dns"]["servers"].as_array().unwrap();
    let base = servers
        .iter()
        .find(|server| server["tag"] == "proxy-dns")
        .unwrap();
    assert_eq!(base["ip_strategy"], "ipv4_and_ipv6");
    let variant = servers
        .iter()
        .find(|server| server["tag"] == resolver_tag)
        .unwrap();
    assert_eq!(variant["ip_strategy"], "ipv6_and_ipv4");
    assert_eq!(variant["url"], base["url"]);
    assert_eq!(variant["disable_cache"], true);
    assert_eq!(variant["rewrite_ttl"], 0);
    assert_eq!(variant["client_subnet"], "192.0.2.0/24");
    assert_eq!(servers.len(), 2, "base plus one deduplicated profile");
}

#[test]
fn outbound_domain_resolver_accepts_sing_box_string_and_null_forms() {
    for (value, expected) in [
        (json!("explicit-dns"), "explicit-dns"),
        (
            json!({
                "server": "explicit-dns",
                "strategy": "as_is",
                "disable_cache": null,
                "rewrite_ttl": null,
                "client_subnet": null
            }),
            "explicit-dns",
        ),
        (Value::Null, "default-dns"),
        (json!(""), "default-dns"),
    ] {
        let mut top = topology(vec![node(
            "node",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-in", 14635),
            vec![],
        )]);
        top.outbounds = vec![Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({"domain_resolver": value.clone()})),
        }];
        top.route = Some(Route {
            final_: "direct".into(),
            default_domain_resolver: Some(DomainResolveOptions {
                server: "default-dns".into(),
                strategy: "as_is".into(),
                ..DomainResolveOptions::default()
            }),
            ..Route::default()
        });
        top.dns = Some(Dns {
            servers: vec![
                DnsServer {
                    kind: "https".into(),
                    tag: "explicit-dns".into(),
                    server: "1.1.1.1".into(),
                    ..DnsServer::default()
                },
                DnsServer {
                    kind: "https".into(),
                    tag: "default-dns".into(),
                    server: "8.8.8.8".into(),
                    ..DnsServer::default()
                },
            ],
            final_: "default-dns".into(),
            ..Dns::default()
        });

        let output = compile_with_warnings(&top).unwrap();
        let rules = output.runtime.inbounds[0].spec.config["rules"]
            .as_array()
            .unwrap();
        assert_eq!(
            rules.last().unwrap()["client_chains"][0]["chain"][0]["dns_resolver"],
            expected,
            "domain_resolver form {value:?}"
        );
    }
}

#[test]
fn outbound_domain_resolver_rejects_invalid_advanced_query_controls() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14636),
        vec![],
    )]);
    for (field, value) in [
        ("disable_cache", json!("true")),
        ("rewrite_ttl", json!(-1)),
        ("rewrite_ttl", json!(1.5)),
        ("rewrite_ttl", json!(4_294_967_296_u64)),
        ("client_subnet", json!(" 192.0.2.1/24 ")),
        ("client_subnet", json!("192.0.2.1/024")),
        ("client_subnet", json!(24)),
    ] {
        let mut top = base.clone();
        let mut resolver = json!({"server": "default-dns"});
        resolver
            .as_object_mut()
            .unwrap()
            .insert(field.into(), value);
        top.outbounds = vec![Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({"domain_resolver": resolver})),
        }];
        top.route = Some(Route {
            final_: "direct".into(),
            ..Route::default()
        });
        let error = compile_with_warnings(&top).unwrap_err().to_string();
        assert!(
            error.contains(field),
            "expected {field:?} for invalid resolver option: {error}"
        );
    }
}

#[tokio::test]
async fn panel_same_egress_direct_resolver_is_consumed_without_global_widening() {
    const ORIGINAL: &str = "bound-direct";
    const RUNTIME: &str = "__acp_direct_2_dns_1_same_egress";
    const SYNTHETIC_DNS: &str = "__acp_dns_1_via_2";

    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14631),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "direct".into(),
            tag: ORIGINAL.into(),
            options: raw(json!({
                "inet4_bind_address": "127.0.0.1",
                "domain_resolver": {
                    "server": "default-dns",
                    "strategy": "ipv4_only"
                }
            })),
        },
        Outbound {
            kind: "direct".into(),
            tag: RUNTIME.into(),
            options: raw(json!({
                "inet4_bind_address": "127.0.0.1",
                "domain_resolver": {
                    "server": SYNTHETIC_DNS,
                    "strategy": "ipv4_only"
                }
            })),
        },
    ];
    top.route = Some(Route {
        rules: vec![
            RouteRule {
                network: vec!["tcp".into(), "udp".into()],
                ip_version: 6,
                action: "reject".into(),
                ..RouteRule::default()
            },
            RouteRule {
                network: vec!["tcp".into(), "udp".into()],
                action: "route".into(),
                outbound: RUNTIME.into(),
                ..RouteRule::default()
            },
        ],
        final_: "direct".into(),
        default_domain_resolver: Some(DomainResolveOptions {
            server: "default-dns".into(),
            ..DomainResolveOptions::default()
        }),
        ..Route::default()
    });
    top.dns = Some(Dns {
        rules: vec![DnsRule {
            action: "route".into(),
            server: SYNTHETIC_DNS.into(),
            ..DnsRule::default()
        }],
        servers: vec![
            DnsServer {
                kind: "https".into(),
                tag: "default-dns".into(),
                server: "1.1.1.1".into(),
                ..DnsServer::default()
            },
            DnsServer {
                kind: "https".into(),
                tag: SYNTHETIC_DNS.into(),
                server: "1.1.1.1".into(),
                detour: ORIGINAL.into(),
            },
        ],
        final_: "default-dns".into(),
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("panel same-egress topology must pass shoes preflight");
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| !warning.contains("default_domain_resolver"))
    );
    let config = &output.runtime.inbounds[0].spec.config;
    assert_eq!(
        config["rules"][1]["client_chains"][0]["chain"][0]["inet4_bind_address"],
        "127.0.0.1"
    );
    assert_eq!(
        config["rules"][1]["client_chains"][0]["chain"][0]["dns_resolver"],
        SYNTHETIC_DNS
    );
    assert!(
        config["rules"][1]["client_chains"][0]["chain"][0]
            .get("domain_resolver")
            .is_none()
    );
    let servers = config["dns"]["servers"].as_array().unwrap();
    let default = servers
        .iter()
        .find(|server| server["tag"] == "default-dns")
        .unwrap();
    assert_eq!(default["ip_strategy"], "ipv4_and_ipv6");
    let synthetic = servers
        .iter()
        .find(|server| server["tag"] == SYNTHETIC_DNS)
        .unwrap();
    assert_eq!(synthetic["ip_strategy"], "ipv4_only");
    assert_eq!(
        synthetic["client_chain"][0]["chain"][0]["inet4_bind_address"],
        "127.0.0.1"
    );
    let original_resolver = synthetic["client_chain"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    let original_variant = servers
        .iter()
        .find(|server| server["tag"] == original_resolver)
        .unwrap();
    assert_eq!(original_variant["ip_strategy"], "ipv4_only");
    let diagnostic = String::from_utf8(output.runtime.diagnostic_yaml).unwrap();
    assert!(diagnostic.contains("domain_resolver"));
    assert!(diagnostic.contains(SYNTHETIC_DNS));
}

#[tokio::test]
async fn default_domain_resolver_can_differ_from_final_and_carry_a_private_profile() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14632),
        vec![],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "direct".into(),
            tag: "explicit".into(),
            options: raw(json!({
                "domain_resolver": {
                    "server": "doq"
                }
            })),
        },
    ];
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain: vec!["explicit.example".into()],
            action: "route".into(),
            outbound: "explicit".into(),
            ..RouteRule::default()
        }],
        final_: "direct".into(),
        default_domain_resolver: Some(DomainResolveOptions {
            server: "system-dns".into(),
            strategy: "prefer_ipv6".into(),
            disable_cache: true,
            rewrite_ttl: Some(u32::MAX),
            client_subnet: "2001:db8::ffff/64".into(),
        }),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![
            DnsServer {
                kind: "quic".into(),
                tag: "doq".into(),
                server: "1.1.1.1".into(),
                ..DnsServer::default()
            },
            DnsServer {
                kind: "system".into(),
                tag: "system-dns".into(),
                server: "system".into(),
                ..DnsServer::default()
            },
        ],
        final_: "doq".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("a default resolver independent from dns.final must compile");
    let config = &output.runtime.inbounds[0].spec.config;
    let rules = config["rules"].as_array().unwrap();
    assert_eq!(
        rules[0]["client_chains"][0]["chain"][0]["dns_resolver"], "doq",
        "an explicit outbound resolver must override the route default"
    );
    let default_variant_tag = rules.last().unwrap()["client_chains"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    assert!(default_variant_tag.starts_with("__acp_dns_profile_"));
    let dns = &config["dns"];
    assert_eq!(dns["final"], "doq");
    let servers = dns["servers"].as_array().unwrap();
    let doq = servers
        .iter()
        .find(|server| server["tag"] == "doq")
        .unwrap();
    assert_eq!(doq["url"], "quic://1.1.1.1");
    let default_variant = servers
        .iter()
        .find(|server| server["tag"] == default_variant_tag)
        .unwrap();
    assert_eq!(default_variant["url"], "system");
    assert_eq!(default_variant["ip_strategy"], "ipv6_and_ipv4");
    assert_eq!(default_variant["disable_cache"], true);
    assert_eq!(default_variant["rewrite_ttl"], u32::MAX);
    assert_eq!(default_variant["client_subnet"], "2001:db8::/64");

    let resolver = top
        .route
        .as_mut()
        .unwrap()
        .default_domain_resolver
        .as_mut()
        .unwrap();
    resolver.client_subnet = "192.0.2.1/024".into();
    let error = compile_with_warnings(&top).unwrap_err().to_string();
    assert!(error.contains("client_subnet"), "{error}");

    let resolver = top
        .route
        .as_mut()
        .unwrap()
        .default_domain_resolver
        .as_mut()
        .unwrap();
    resolver.client_subnet = "2001:db8::ffff/64".into();
    resolver.server = "other".into();
    let error = compile_with_warnings(&top).unwrap_err().to_string();
    assert!(error.contains("unknown DNS server"), "{error}");
}

#[test]
fn default_domain_resolver_follows_go_detour_dialer_lifecycle() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14638),
        vec![],
    )]);
    let entry_options = json!({
        "server": "entry.example.com",
        "server_port": 443,
        "uuid": UUID,
        "network": "tcp"
    });
    let exit_options = json!({
        "server": "exit.example.com",
        "server_port": 443,
        "uuid": UUID,
        "network": "tcp",
        "detour": "entry"
    });
    top.outbounds = vec![
        Outbound {
            kind: "vless".into(),
            tag: "entry".into(),
            options: raw(entry_options),
        },
        Outbound {
            kind: "vless".into(),
            tag: "exit".into(),
            options: raw(exit_options.clone()),
        },
    ];
    top.route = Some(Route {
        final_: "exit".into(),
        default_domain_resolver: Some(DomainResolveOptions {
            server: "default-dns".into(),
            disable_cache: true,
            ..DomainResolveOptions::default()
        }),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![
            DnsServer {
                kind: "https".into(),
                tag: "default-dns".into(),
                server: "1.1.1.1".into(),
                ..DnsServer::default()
            },
            DnsServer {
                kind: "https".into(),
                tag: "explicit-dns".into(),
                server: "1.0.0.1".into(),
                ..DnsServer::default()
            },
        ],
        final_: "default-dns".into(),
        ..Dns::default()
    });

    let default_only = compile_with_warnings(&top).expect("detour with route default compiles");
    let chain = default_only.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chains"][0]["chain"]
        .as_array()
        .unwrap();
    let inherited_tag = chain[0]["dns_resolver"].as_str().unwrap();
    assert!(inherited_tag.starts_with("__acp_dns_profile_"));
    assert!(
        chain[1].get("dns_resolver").is_none(),
        "Go bypasses the current outbound's default dialer resolver when detour is set"
    );

    let mut explicit_exit = exit_options.clone();
    explicit_exit["domain_resolver"] = json!({"server": "explicit-dns"});
    top.outbounds[1].options = raw(explicit_exit);
    let explicit = compile_with_warnings(&top).expect("explicit resolver on detour compiles");
    let chain = explicit.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chains"][0]["chain"]
        .as_array()
        .unwrap();
    assert_eq!(chain[0]["dns_resolver"], inherited_tag);
    assert_eq!(
        chain[1]["dns_resolver"], "explicit-dns",
        "an explicit resolver remains attached to the current hop"
    );

    let mut no_detour = exit_options;
    no_detour.as_object_mut().unwrap().remove("detour");
    top.outbounds[1].options = raw(no_detour);
    let inherited = compile_with_warnings(&top).expect("plain outbound inherits route default");
    let chain = inherited.runtime.inbounds[0].spec.config["rules"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["client_chains"][0]["chain"]
        .as_array()
        .unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0]["dns_resolver"], inherited_tag);
}

#[tokio::test]
async fn doq_and_doh3_detours_require_an_udp_capable_proxy_chain() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge-in", 14633),
        vec![],
    )]);
    top.outbounds = vec![Outbound {
        kind: "vless".into(),
        tag: "udp-proxy".into(),
        options: raw(json!({
            "server": "127.0.0.1",
            "server_port": 443,
            "uuid": UUID,
            "network": ["tcp", "udp"]
        })),
    }];
    top.route = Some(Route {
        final_: "udp-proxy".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "quic".into(),
            tag: "encrypted-dns".into(),
            server: "1.1.1.1".into(),
            detour: "udp-proxy".into(),
        }],
        final_: "encrypted-dns".into(),
        ..Dns::default()
    });

    let engine = Engine::bootstrap().await.unwrap();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("DoQ must accept a VLESS UDP proxy chain");
    let server = &output.runtime.inbounds[0].spec.config["dns"]["servers"][0];
    assert_eq!(server["url"], "quic://1.1.1.1");
    assert_eq!(
        server["client_chain"][0]["chain"][0]["protocol"]["udp_enabled"],
        true
    );

    top.dns.as_mut().unwrap().servers[0].kind = "h3".into();
    let output = compile_and_preflight(&top, &engine)
        .await
        .expect("DoH3 must use the same UDP-capable proxy adapter");
    assert_eq!(
        output.runtime.inbounds[0].spec.config["dns"]["servers"][0]["url"],
        "h3://1.1.1.1/dns-query"
    );

    top.outbounds[0].options = raw(json!({
        "server": "127.0.0.1",
        "server_port": 443,
        "uuid": UUID,
        "network": "tcp"
    }));
    let error = compile_and_preflight(&top, &engine).await.unwrap_err();
    assert!(
        error.to_string().contains("no UDP-capable chain"),
        "{error}"
    );
}

#[test]
fn route_dns_and_supported_query_controls_compile_without_weakening_validation() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1443),
        vec![active_user("alice", UUID)],
    )]);
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "direct".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "trojan".into(),
            tag: "remote".into(),
            options: raw(json!({
                "server": "192.0.2.1",
                "server_port": 443,
                "password": "outbound-secret"
            })),
        },
    ];
    top.route = Some(Route {
        rules: vec![
            RouteRule {
                domain_suffix: vec!["example.com".into()],
                port: vec![443],
                outbound: "direct".into(),
                ..RouteRule::default()
            },
            RouteRule {
                process_name: vec!["curl".into()],
                outbound: "remote".into(),
                ..RouteRule::default()
            },
        ],
        final_: "remote".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "cloudflare".into(),
            server: "1.1.1.1".into(),
            ..DnsServer::default()
        }],
        final_: "cloudflare".into(),
        rules: vec![DnsRule {
            action: "route".into(),
            server: "cloudflare".into(),
            rewrite_ttl: "60".into(),
            ..DnsRule::default()
        }],
    });

    let first_error = compile_with_warnings(&top).unwrap_err().to_string();
    let second_error = compile_with_warnings(&top).unwrap_err().to_string();
    assert_eq!(first_error, second_error);
    assert!(first_error.contains("process_name"), "{first_error}");

    top.route.as_mut().unwrap().rules.pop();
    let dns_rule = &mut top.dns.as_mut().unwrap().rules[0];
    dns_rule.rewrite_ttl.clear();
    dns_rule.server = "cloudflare".into();
    compile_with_warnings(&top).expect("Trojan native UDP is supported");

    top.route.as_mut().unwrap().final_ = "direct".into();
    top.dns.as_mut().unwrap().rules[0].rewrite_ttl = "60".into();
    let with_ttl = compile_with_warnings(&top).expect("DNS TTL control is supported");
    let dns = &with_ttl.runtime.inbounds[0].spec.config["dns"];
    let variant_tag = dns["rules"][0]["server"].as_str().unwrap();
    assert!(variant_tag.starts_with("__acp_dns_profile_"));
    let variant = dns["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|server| server["tag"] == variant_tag)
        .unwrap();
    assert_eq!(variant["rewrite_ttl"], 60);
    assert!(dns["rules"][0].get("rewrite_ttl").is_none());

    top.dns.as_mut().unwrap().rules[0].rewrite_ttl.clear();
    top.dns.as_mut().unwrap().rules[0].domain_suffix = vec!["dns.example".into()];
    top.dns.as_mut().unwrap().rules[0].server = "cloudflare".into();
    let first = compile_with_warnings(&top).expect("supported policy compiles");
    let second = compile_with_warnings(&top).expect("compile is stable");
    assert_eq!(first.warnings, second.warnings);
    assert_eq!(
        first.runtime.diagnostic_yaml,
        second.runtime.diagnostic_yaml
    );
    let config = &first.runtime.inbounds[0].spec.config;
    assert_eq!(config["rules"][0]["masks"], "0.0.0.0/0");
    assert_eq!(
        config["rules"][0]["match"]["domain_suffix"],
        json!(["example.com"])
    );
    assert_eq!(config["rules"][0]["match"]["port"], json!([443]));
    assert_eq!(config["rules"][0]["action"], "allow");
    assert_eq!(config["dns"]["final"], "cloudflare");
    assert_eq!(
        config["dns"]["servers"][0]["url"],
        "https://1.1.1.1/dns-query"
    );
    assert_eq!(config["dns"]["rules"][0]["action"], "route");
    let yaml = String::from_utf8(first.runtime.diagnostic_yaml).unwrap();
    assert!(yaml.contains("<redacted>"));
    assert!(!yaml.contains("outbound-secret"));
    assert!(!yaml.contains(REALITY_KEY));
}

#[test]
fn route_inbound_scope_ip_cidr_port_range_and_reject_are_mapped_exactly() {
    let mut top = topology(vec![
        node(
            "a",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-a", 14700),
            vec![],
        ),
        node(
            "b",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-b", 14701),
            vec![],
        ),
    ]);
    top.route = Some(Route {
        rules: vec![RouteRule {
            inbound: vec!["edge-a".into()],
            ip_version: 4,
            ip_cidr: vec!["192.0.2.0/24".into()],
            port_range: vec!["80:82".into()],
            action: "reject".into(),
            ..RouteRule::default()
        }],
        ..Route::default()
    });
    let output = compile_with_warnings(&top).unwrap();
    let a = output
        .runtime
        .inbounds
        .iter()
        .find(|inbound| inbound.spec.tag == "edge-a")
        .unwrap();
    let b = output
        .runtime
        .inbounds
        .iter()
        .find(|inbound| inbound.spec.tag == "edge-b")
        .unwrap();
    assert_eq!(a.spec.config["rules"][0]["action"], "block");
    assert_eq!(a.spec.config["rules"][0]["masks"], "0.0.0.0/0");
    assert_eq!(
        a.spec.config["rules"][0]["match"]["ip_cidr"],
        json!(["192.0.2.0/24"])
    );
    assert_eq!(a.spec.config["rules"][0]["match"]["ip_version"], json!([4]));
    assert_eq!(
        a.spec.config["rules"][0]["match"]["port_range"],
        json!(["80:82"])
    );
    assert_eq!(b.spec.config["rules"].as_array().unwrap().len(), 1);
    assert_eq!(b.spec.config["rules"][0]["action"], "allow");
}

#[test]
fn protocol_route_rules_require_provider_sniff_and_compile_http_tls_only() {
    let mut config = vless_config("edge", 14710);
    config.sniff = true;
    let mut top = topology(vec![node("node", VLESS_REALITY_VISION_ID, config, vec![])]);
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain_suffix: vec!["example.com".into()],
            protocol: vec!["tls".into(), "http".into()],
            action: "reject".into(),
            ..RouteRule::default()
        }],
        ..Route::default()
    });

    let compiled = compile_with_warnings(&top).expect("sniff-enabled VLESS supports protocol");
    assert_eq!(compiled.runtime.inbounds[0].spec.config["sniff"], true);
    assert_eq!(
        compiled.runtime.inbounds[0].spec.config["rules"][0]["match"]["protocol"],
        json!(["tls", "http"])
    );

    let mut disabled = vless_config("edge", 14711);
    disabled.sniff = false;
    top.nodes[0].provider_config = raw(disabled);
    let error = compile_with_warnings(&top).unwrap_err().to_string();
    assert!(error.contains("does not enable sniff"), "{error}");

    let mut enabled = vless_config("edge", 14712);
    enabled.sniff = true;
    top.nodes[0].provider_config = raw(enabled);
    top.route.as_mut().unwrap().rules[0].protocol = vec!["quic".into()];
    let error = compile_with_warnings(&top).unwrap_err().to_string();
    assert!(error.contains("supports http and tls"), "{error}");

    top.nodes = vec![node(
        "hy2",
        HYSTERIA2_SALAMANDER_ID,
        hysteria_config("hy2-edge", 14713),
        vec![],
    )];
    top.route.as_mut().unwrap().rules[0].protocol = vec!["tls".into()];
    let compiled = compile_with_warnings(&top)
        .expect("Hysteria2 uses engine-level demand-driven protocol sniffing");
    assert_eq!(
        compiled.runtime.inbounds[0].spec.config["rules"][0]["match"]["protocol"],
        json!(["tls"])
    );
}

#[test]
fn dns_route_query_controls_use_normalized_deduplicated_server_variants() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14720),
        vec![],
    )]);
    top.dns = Some(Dns {
        rules: vec![
            DnsRule {
                domain: vec!["first.example".into()],
                action: "route".into(),
                server: "default-dns".into(),
                disable_cache: true,
                rewrite_ttl: " 3600 ".into(),
                client_subnet: "192.0.2.7".into(),
                ..DnsRule::default()
            },
            DnsRule {
                domain: vec!["second.example".into()],
                action: "route".into(),
                server: "default-dns".into(),
                disable_cache: true,
                rewrite_ttl: "3600".into(),
                client_subnet: "192.0.2.7/32".into(),
                ..DnsRule::default()
            },
            DnsRule {
                domain: vec!["ipv6.example".into()],
                action: "route".into(),
                server: "default-dns".into(),
                client_subnet: "2001:0db8:0:0::1/64".into(),
                ..DnsRule::default()
            },
            DnsRule {
                domain: vec!["masked.example".into()],
                action: "route".into(),
                server: "default-dns".into(),
                client_subnet: "2001:db8:0:0:ffff::1/65".into(),
                ..DnsRule::default()
            },
            DnsRule {
                domain: vec!["plain.example".into()],
                action: "route".into(),
                server: "default-dns".into(),
                ..DnsRule::default()
            },
        ],
        ..Dns::default()
    });

    let output = compile_with_warnings(&top).expect("DNS query controls compile");
    let dns = &output.runtime.inbounds[0].spec.config["dns"];
    let rules = dns["rules"].as_array().unwrap();
    let first_variant_tag = rules[0]["server"].as_str().unwrap();
    assert!(first_variant_tag.starts_with("__acp_dns_profile_"));
    assert_eq!(rules[1]["server"], first_variant_tag);
    assert_ne!(rules[2]["server"], first_variant_tag);
    assert_eq!(rules[4]["server"], "default-dns");
    for rule in rules {
        assert!(rule.get("disable_cache").is_none());
        assert!(rule.get("rewrite_ttl").is_none());
        assert!(rule.get("client_subnet").is_none());
    }

    let servers = dns["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 4, "base plus three distinct profiles");
    let first_variant = servers
        .iter()
        .find(|server| server["tag"] == first_variant_tag)
        .unwrap();
    assert_eq!(first_variant["url"], "https://1.1.1.1/dns-query");
    assert_eq!(first_variant["disable_cache"], true);
    assert_eq!(first_variant["rewrite_ttl"], 3600);
    assert_eq!(first_variant["client_subnet"], "192.0.2.7/32");

    let ipv6_variant_tag = rules[2]["server"].as_str().unwrap();
    let ipv6_variant = servers
        .iter()
        .find(|server| server["tag"] == ipv6_variant_tag)
        .unwrap();
    assert_eq!(ipv6_variant["client_subnet"], "2001:db8::/64");
    assert!(ipv6_variant.get("disable_cache").is_none());
    assert!(ipv6_variant.get("rewrite_ttl").is_none());

    let masked_variant_tag = rules[3]["server"].as_str().unwrap();
    let masked_variant = servers
        .iter()
        .find(|server| server["tag"] == masked_variant_tag)
        .unwrap();
    assert_eq!(masked_variant["client_subnet"], "2001:db8:0:0:8000::/65");
}

#[test]
fn identical_dns_profiles_share_one_variant_across_rule_default_and_outbound_paths() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14726),
        vec![],
    )]);
    let query = json!({
        "server": "shared-dns",
        "disable_cache": true,
        "rewrite_ttl": 60,
        "client_subnet": "192.0.2.129/24"
    });
    top.outbounds = vec![
        Outbound {
            kind: "direct".into(),
            tag: "defaulted".into(),
            options: raw(json!({})),
        },
        Outbound {
            kind: "direct".into(),
            tag: "explicit".into(),
            options: raw(json!({"domain_resolver": query})),
        },
    ];
    top.route = Some(Route {
        rules: vec![RouteRule {
            domain: vec!["explicit.example".into()],
            action: "route".into(),
            outbound: "explicit".into(),
            ..RouteRule::default()
        }],
        final_: "defaulted".into(),
        default_domain_resolver: Some(DomainResolveOptions {
            server: "shared-dns".into(),
            disable_cache: true,
            rewrite_ttl: Some(60),
            client_subnet: "192.0.2.0/24".into(),
            ..DomainResolveOptions::default()
        }),
        ..Route::default()
    });
    top.dns = Some(Dns {
        rules: vec![DnsRule {
            domain: vec!["dns.example".into()],
            action: "route".into(),
            server: "shared-dns".into(),
            disable_cache: true,
            rewrite_ttl: "60".into(),
            client_subnet: "192.0.2.200/24".into(),
            ..DnsRule::default()
        }],
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "shared-dns".into(),
            server: "1.1.1.1".into(),
            ..DnsServer::default()
        }],
        final_: "shared-dns".into(),
    });

    let output = compile_with_warnings(&top).expect("identical profiles compile");
    let config = &output.runtime.inbounds[0].spec.config;
    let route_rules = config["rules"].as_array().unwrap();
    let explicit_tag = route_rules[0]["client_chains"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    let default_tag = route_rules.last().unwrap()["client_chains"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    let rule_tag = config["dns"]["rules"][0]["server"].as_str().unwrap();
    assert!(explicit_tag.starts_with("__acp_dns_profile_"));
    assert_eq!(default_tag, explicit_tag);
    assert_eq!(rule_tag, explicit_tag);

    let servers = config["dns"]["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2, "base plus one shared profile variant");
    let variant = servers
        .iter()
        .find(|server| server["tag"] == explicit_tag)
        .unwrap();
    assert_eq!(variant["ip_strategy"], "ipv4_and_ipv6");
    assert_eq!(variant["disable_cache"], true);
    assert_eq!(variant["rewrite_ttl"], 60);
    assert_eq!(variant["client_subnet"], "192.0.2.0/24");
    assert_eq!(variant["__acp_source_tag"], "shared-dns");
    assert!(
        servers
            .iter()
            .find(|server| server["tag"] == "shared-dns")
            .unwrap()
            .get("__acp_source_tag")
            .is_none()
    );

    let repeated = compile_with_warnings(&top).expect("profile catalog output is stable");
    assert_eq!(
        repeated.runtime.inbounds[0].spec.config["dns"],
        config["dns"]
    );
}

#[test]
fn distinct_dns_profiles_remain_isolated_across_rule_and_outbound_paths() {
    let mut top = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14727),
        vec![],
    )]);
    top.outbounds = vec![Outbound {
        kind: "direct".into(),
        tag: "direct".into(),
        options: raw(json!({
            "domain_resolver": {
                "server": "shared-dns",
                "disable_cache": true,
                "rewrite_ttl": 61,
                "client_subnet": "192.0.2.0/24"
            }
        })),
    }];
    top.route = Some(Route {
        final_: "direct".into(),
        ..Route::default()
    });
    top.dns = Some(Dns {
        rules: vec![DnsRule {
            action: "route".into(),
            server: "shared-dns".into(),
            disable_cache: true,
            rewrite_ttl: "60".into(),
            client_subnet: "192.0.2.0/24".into(),
            ..DnsRule::default()
        }],
        servers: vec![DnsServer {
            kind: "https".into(),
            tag: "shared-dns".into(),
            server: "1.1.1.1".into(),
            ..DnsServer::default()
        }],
        final_: "shared-dns".into(),
    });

    let output = compile_with_warnings(&top).expect("distinct profiles compile");
    let config = &output.runtime.inbounds[0].spec.config;
    let outbound_tag = config["rules"].as_array().unwrap().last().unwrap()
        ["client_chains"][0]["chain"][0]["dns_resolver"]
        .as_str()
        .unwrap();
    let rule_tag = config["dns"]["rules"][0]["server"].as_str().unwrap();
    assert_ne!(outbound_tag, rule_tag);

    let servers = config["dns"]["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 3, "base plus two isolated profiles");
    assert_eq!(
        servers
            .iter()
            .find(|server| server["tag"] == outbound_tag)
            .unwrap()["rewrite_ttl"],
        61
    );
    assert_eq!(
        servers
            .iter()
            .find(|server| server["tag"] == rule_tag)
            .unwrap()["rewrite_ttl"],
        60
    );
}

#[test]
fn dns_rewrite_ttl_accepts_trimmed_uint32_boundaries() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14722),
        vec![],
    )]);
    for (value, expected) in [
        ("0", 0_u64),
        ("+60", 60),
        ("0001", 1),
        (" 3600 ", 3600),
        (" 4294967295 ", u32::MAX as u64),
    ] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                rewrite_ttl: value.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let output = compile_with_warnings(&top).expect("valid uint32 TTL compiles");
        let dns = &output.runtime.inbounds[0].spec.config["dns"];
        let variant_tag = dns["rules"][0]["server"].as_str().unwrap();
        let variant = dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|server| server["tag"] == variant_tag)
            .unwrap();
        assert_eq!(variant["rewrite_ttl"], expected, "TTL {value:?}");
    }
}

#[test]
fn dns_no_drop_and_query_controls_obey_action_constraints() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14721),
        vec![],
    )]);

    for method in ["", "default", " DEFAULT "] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "reject".into(),
                method: method.into(),
                no_drop: true,
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let output = compile_with_warnings(&top).expect("default rejection permits no_drop");
        let rule = &output.runtime.inbounds[0].spec.config["dns"]["rules"][0];
        assert_eq!(rule["no_drop"], true);
        assert!(rule.get("__acp_reject_flood_key").is_none());
        if method.is_empty() {
            assert!(rule.get("method").is_none());
        } else {
            assert_eq!(rule["method"], "default");
        }
    }

    let invalid_rules = [
        (
            DnsRule {
                action: "reject".into(),
                method: "drop".into(),
                no_drop: true,
                ..DnsRule::default()
            },
            "no_drop",
        ),
        (
            DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                no_drop: true,
                ..DnsRule::default()
            },
            "no_drop",
        ),
        (
            DnsRule {
                action: "reject".into(),
                disable_cache: true,
                ..DnsRule::default()
            },
            "disable_cache",
        ),
        (
            DnsRule {
                action: "predefined".into(),
                rcode: "NOERROR".into(),
                rewrite_ttl: "60".into(),
                ..DnsRule::default()
            },
            "rewrite_ttl",
        ),
        (
            DnsRule {
                action: "predefined".into(),
                rcode: "NOERROR".into(),
                client_subnet: "192.0.2.0/24".into(),
                ..DnsRule::default()
            },
            "client_subnet",
        ),
    ];
    for (rule, field) in invalid_rules {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![rule],
            ..Dns::default()
        });
        let error = compile_with_warnings(&top).unwrap_err().to_string();
        assert!(error.contains(field), "expected {field:?} in {error}");
    }
}

#[test]
fn dns_reject_flood_state_key_is_stable_across_per_inbound_projections() {
    let mut top = topology(vec![
        node(
            "node-a",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-a", 14731),
            vec![],
        ),
        node(
            "node-b",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-b", 14732),
            vec![],
        ),
    ]);
    top.dns = Some(Dns {
        rules: vec![
            DnsRule {
                inbound: vec!["edge-a".into()],
                domain: vec!["only-a.example".into()],
                action: "predefined".into(),
                answer: vec!["192.0.2.7".into()],
                ..DnsRule::default()
            },
            DnsRule {
                action: "reject".into(),
                ..DnsRule::default()
            },
        ],
        ..Dns::default()
    });

    let output = compile_with_warnings(&top).unwrap();
    let first_rules = output.runtime.inbounds[0].spec.config["dns"]["rules"]
        .as_array()
        .unwrap();
    let second_rules = output.runtime.inbounds[1].spec.config["dns"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(first_rules.len(), 2);
    assert_eq!(second_rules.len(), 1);
    let first_key = first_rules[1]["__acp_reject_flood_key"].as_str().unwrap();
    let second_key = second_rules[0]["__acp_reject_flood_key"].as_str().unwrap();
    assert_eq!(first_key, second_key);
    let digest = first_key
        .strip_prefix("__acp_dns_reject_v1_")
        .expect("reserved internal prefix");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let repeated = compile_with_warnings(&top).unwrap();
    assert_eq!(
        repeated.runtime.inbounds[1].spec.config["dns"]["rules"][0]["__acp_reject_flood_key"],
        second_key
    );
}

#[test]
fn urltest_probe_dns_has_no_inbound_context_and_is_order_independent() {
    let mut top = topology(vec![
        node(
            "node-a",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-a", 14733),
            vec![],
        ),
        node(
            "node-b",
            VLESS_REALITY_VISION_ID,
            vless_config("edge-b", 14734),
            vec![],
        ),
    ]);
    top.dns = Some(Dns {
        rules: vec![
            DnsRule {
                inbound: vec!["edge-a".into()],
                domain_suffix: vec!["probe.example".into()],
                action: "predefined".into(),
                answer: vec!["192.0.2.8".into()],
                ..DnsRule::default()
            },
            DnsRule {
                action: "reject".into(),
                ..DnsRule::default()
            },
        ],
        ..Dns::default()
    });

    let output = compile_with_warnings(&top).unwrap();
    let edge_a = &output.runtime.inbounds[0].spec.config;
    let edge_b = &output.runtime.inbounds[1].spec.config;
    assert_eq!(edge_a["dns"]["rules"].as_array().unwrap().len(), 2);
    assert_eq!(edge_b["dns"]["rules"].as_array().unwrap().len(), 1);
    let probe_dns = output
        .runtime
        .urltest_probe_dns
        .as_ref()
        .expect("compiler emits one generation-global probe DNS graph");
    let probe_rules = probe_dns["rules"].as_array().unwrap();
    assert_eq!(probe_rules.len(), 1);
    assert!(probe_rules[0].get("domain_suffix").is_none());

    top.nodes.reverse();
    let reversed = compile_with_warnings(&top).unwrap();
    assert_eq!(reversed.runtime.urltest_probe_dns.as_ref(), Some(probe_dns));
}

#[test]
fn dns_invalid_query_controls_and_unknown_references_fail_loudly() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 1443),
        vec![],
    )]);
    for value in ["-1", "+", "1.5", "4294967296", "+4294967296", "invalid"] {
        let mut invalid_ttl = base.clone();
        invalid_ttl.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                rewrite_ttl: value.into(),
                timeout: "5s".into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&invalid_ttl).unwrap_err().to_string();
        assert!(error.contains("rewrite_ttl"), "{error}");
    }

    for value in [
        "not-an-ip",
        "192.0.2.1/33",
        "2001:db8::1/129",
        "192.0.2.1/",
        "/24",
        "192.0.2.1/24/1",
        "192.0.2.1 /24",
        "192.0.2.1/+24",
        "192.0.2.1/-1",
        " 192.0.2.1/24 ",
        "192.0.2.1/024",
    ] {
        let mut invalid_subnet = base.clone();
        invalid_subnet.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                client_subnet: value.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&invalid_subnet)
            .unwrap_err()
            .to_string();
        assert!(error.contains("client_subnet"), "value {value:?}: {error}");
    }

    for dns in [None, Some(Dns::default())] {
        let mut default_dns = base.clone();
        default_dns.dns = dns;
        let output = compile_with_warnings(&default_dns).unwrap();
        let dns = &output.runtime.inbounds[0].spec.config["dns"];
        assert_eq!(dns["final"], "default-dns");
        assert_eq!(dns["servers"][0]["url"], "https://1.1.1.1/dns-query");
        assert_eq!(dns["servers"][0]["use_native_roots"], true);
    }

    for (kind, server, expected) in [
        ("local", "system", false),
        ("udp", "1.1.1.1", false),
        ("tcp", "1.1.1.1", false),
        ("tls", "1.1.1.1", true),
        ("quic", "1.1.1.1", true),
        ("https", "1.1.1.1", true),
        ("h3", "1.1.1.1", true),
    ] {
        let mut topology = base.clone();
        topology.dns = Some(Dns {
            servers: vec![DnsServer {
                kind: kind.into(),
                tag: "default-dns".into(),
                server: server.into(),
                ..DnsServer::default()
            }],
            final_: "default-dns".into(),
            ..Dns::default()
        });
        let output = compile_with_warnings(&topology).unwrap();
        let compiled = &output.runtime.inbounds[0].spec.config["dns"]["servers"][0];
        assert_eq!(
            compiled["use_native_roots"], expected,
            "unexpected native-root policy for {kind}"
        );
    }

    let mut unknown_final = base;
    unknown_final.outbounds = vec![Outbound {
        kind: "direct".into(),
        tag: "direct".into(),
        options: raw(json!({})),
    }];
    unknown_final.route = Some(Route {
        final_: "missing".into(),
        ..Route::default()
    });
    assert!(
        compile_with_warnings(&unknown_final)
            .unwrap_err()
            .to_string()
            .contains("unknown outbound")
    );

    let mut no_nodes = topology(vec![]);
    no_nodes.outbounds = vec![Outbound {
        kind: "direct".into(),
        tag: "direct".into(),
        options: raw(json!({})),
    }];
    no_nodes.route = Some(Route {
        rules: vec![RouteRule {
            process_name: vec!["curl".into()],
            outbound: "missing".into(),
            ..RouteRule::default()
        }],
        ..Route::default()
    });
    assert!(
        compile_with_warnings(&no_nodes)
            .unwrap_err()
            .to_string()
            .contains("unknown outbound")
    );

    no_nodes.route = Some(Route {
        rule_sets: vec![RouteRuleSet {
            kind: "remote".into(),
            tag: String::new(),
            ..RouteRuleSet::default()
        }],
        ..Route::default()
    });
    assert!(
        compile_with_warnings(&no_nodes)
            .unwrap_err()
            .to_string()
            .contains("rule_set tag is required")
    );
}

#[tokio::test]
async fn dns_route_timeout_uses_exact_positive_go_duration_milliseconds() {
    let base = topology(vec![node(
        "node",
        VLESS_REALITY_VISION_ID,
        vless_config("edge", 14930),
        vec![],
    )]);

    for (duration, expected_millis) in [
        ("500ms", 500_u64),
        ("1.5s", 1_500),
        ("1m2.5s", 62_500),
        (".5s", 500),
    ] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                timeout: duration.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let output = compile_with_warnings(&top).expect("valid route timeout");
        assert_eq!(
            output.runtime.inbounds[0].spec.config["dns"]["rules"][0]["timeout_millis"],
            expected_millis,
            "duration {duration:?}"
        );
    }

    for duration in [
        "0",
        "0s",
        "1us",
        "1.5ms",
        "5",
        "-1s",
        "1s trailing",
        "2562047h47m16.854775808s",
    ] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: "route".into(),
                server: "default-dns".into(),
                timeout: duration.into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&top).unwrap_err().to_string();
        assert!(error.contains("timeout"), "duration {duration:?}: {error}");
    }

    for action in ["reject", "predefined"] {
        let mut top = base.clone();
        top.dns = Some(Dns {
            rules: vec![DnsRule {
                action: action.into(),
                rcode: if action == "predefined" {
                    "NOERROR".into()
                } else {
                    String::new()
                },
                timeout: "1s".into(),
                ..DnsRule::default()
            }],
            ..Dns::default()
        });
        let error = compile_with_warnings(&top).unwrap_err().to_string();
        assert!(error.contains("timeout"), "action {action:?}: {error}");
    }

    let mut preflight = base;
    preflight.dns = Some(Dns {
        rules: vec![DnsRule {
            action: "route".into(),
            server: "default-dns".into(),
            timeout: "1.5s".into(),
            ..DnsRule::default()
        }],
        ..Dns::default()
    });
    let engine = Engine::bootstrap().await.expect("bootstrap engine");
    compile_and_preflight(&preflight, &engine)
        .await
        .expect("timeout_millis passes shoes preflight");
}
