//! Pure topology-to-forwarding plan compiler.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::port_ranges::{PortRange, parse_port_ranges};
use crate::topology::MachineTopology;
use crate::topology::provider::{HYSTERIA2_SALAMANDER_ID, Hysteria2SalamanderConfig};

/// The configured UDP destination ports redirected to one Hysteria2 listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub node_id: String,
    pub listen_port: u16,
    pub ports: Vec<PortRange>,
}

/// Complete machine-wide forwarding state owned by one node-agent process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub redirects: Vec<Redirect>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.redirects.is_empty()
    }

    /// Stable SHA-256 identity, byte-for-byte compatible with Go `Plan.Digest`.
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        for redirect in &self.redirects {
            hash.update(redirect.node_id.as_bytes());
            hash.update([0]);
            hash.update(redirect.listen_port.to_string().as_bytes());
            hash.update([0]);
            for port_range in &redirect.ports {
                hash.update(port_range.start.to_string().as_bytes());
                hash.update(b"-");
                hash.update(port_range.end.to_string().as_bytes());
                hash.update(b",");
            }
            hash.update([0]);
        }
        lower_hex(&hash.finalize())
    }

    pub fn rule_count(&self) -> usize {
        self.redirects
            .iter()
            .map(|redirect| redirect.ports.len())
            .sum()
    }
}

/// Build and validate the port-hopping plan from the full candidate topology.
pub fn build_plan(topology: &MachineTopology) -> Result<Plan, PlanError> {
    let mut redirects = Vec::new();
    let mut listen_ports = BTreeMap::<String, u16>::new();
    let mut original_hopping = BTreeMap::<String, Vec<PortRange>>::new();
    let mut seen_node_ids = HashSet::with_capacity(topology.nodes.len());

    for node in &topology.nodes {
        if !seen_node_ids.insert(node.node_id.as_str()) {
            return Err(PlanError::new(format!(
                "topology contains duplicate node_id {:?}",
                node.node_id
            )));
        }
        if node.provider_id != HYSTERIA2_SALAMANDER_ID {
            continue;
        }
        let config = decode_hysteria_config(node.provider_config.as_bytes()).map_err(|error| {
            PlanError::new(format!(
                "node {} decode hysteria2 port hopping config: {error}",
                node.node_id
            ))
        })?;
        if config.listen_port != 0 {
            listen_ports.insert(node.node_id.clone(), config.listen_port);
        }
        let original = parse_port_ranges(&config.port_hopping).map_err(|error| {
            PlanError::new(format!(
                "node {} invalid hysteria2 port_hopping: {error}",
                node.node_id
            ))
        })?;
        original_hopping.insert(node.node_id.clone(), original.clone());
        let ports = remove_self_redirects(&original, config.listen_port);
        if ports.is_empty() {
            continue;
        }
        if config.listen_port == 0 {
            return Err(PlanError::new(format!(
                "node {} hysteria2 listen_port is required for port hopping",
                node.node_id
            )));
        }
        redirects.push(Redirect {
            node_id: node.node_id.clone(),
            listen_port: config.listen_port,
            ports,
        });
    }

    redirects.sort_by(|left, right| left.node_id.cmp(&right.node_id));

    // This deliberately uses the original ranges. A node hopping onto another
    // node's equal listen port remains a conflict even though its own equal
    // listen port would later be removed from the redirect ranges.
    for (node_id, ranges) in &original_hopping {
        for port_range in ranges {
            for (other_node_id, listen_port) in &listen_ports {
                if node_id != other_node_id && port_range.contains(*listen_port) {
                    return Err(PlanError::new(format!(
                        "node {node_id} port_hopping {port_range} conflicts with node {other_node_id} hysteria2 listen_port {listen_port}"
                    )));
                }
            }
        }
    }

    for (index, right) in redirects.iter().enumerate() {
        for left in &redirects[..index] {
            if let Some(overlap) = first_overlap(&left.ports, &right.ports) {
                return Err(PlanError::new(format!(
                    "hysteria2 port_hopping conflict between nodes {} and {} at {overlap}",
                    left.node_id, right.node_id
                )));
            }
        }
    }
    Ok(Plan { redirects })
}

fn decode_hysteria_config(bytes: &[u8]) -> serde_json::Result<Hysteria2SalamanderConfig> {
    // Go's json.Unmarshal("null", &struct) succeeds and leaves the zero value.
    if bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .eq(b"null".iter().copied())
    {
        Ok(Hysteria2SalamanderConfig::default())
    } else {
        serde_json::from_slice(bytes)
    }
}

fn remove_self_redirects(ranges: &[PortRange], listen_port: u16) -> Vec<PortRange> {
    let mut result = Vec::with_capacity(ranges.len() + 1);
    for port_range in ranges {
        if !port_range.contains(listen_port) {
            result.push(*port_range);
            continue;
        }
        if port_range.start < listen_port {
            result.push(PortRange::new(port_range.start, listen_port - 1));
        }
        if listen_port < port_range.end {
            result.push(PortRange::new(listen_port + 1, port_range.end));
        }
    }
    result
}

pub(crate) fn first_overlap(left: &[PortRange], right: &[PortRange]) -> Option<PortRange> {
    for first in left {
        for second in right {
            let start = first.start.max(second.start);
            let end = first.end.min(second.end);
            if start <= end {
                return Some(PortRange::new(start, end));
            }
        }
    }
    None
}

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(String);

impl PlanError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PlanError {}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::{Plan, Redirect, build_plan};
    use crate::porthopping::PortRange;
    use crate::topology::provider::{HYSTERIA2_SALAMANDER_ID, Hysteria2SalamanderConfig};
    use crate::topology::{MachineTopology, NodeInstance, RawJson};

    fn hysteria_node(node_id: &str, listen_port: u16, port_hopping: &str) -> NodeInstance {
        NodeInstance {
            node_id: node_id.into(),
            provider_id: HYSTERIA2_SALAMANDER_ID.into(),
            provider_config_version: 1,
            provider_config: RawJson::from(
                serde_json::to_value(Hysteria2SalamanderConfig {
                    kind: "hysteria2".into(),
                    listen_port,
                    port_hopping: port_hopping.into(),
                    ..Hysteria2SalamanderConfig::default()
                })
                .unwrap(),
            ),
            users: Vec::new(),
        }
    }

    #[test]
    fn builds_sorted_plan_removes_self_and_matches_go_digest() {
        let topology = MachineTopology {
            nodes: vec![
                hysteria_node("node-b", 8443, "30000,20000-20010"),
                hysteria_node("node-a", 443, "10000-10010,443"),
                NodeInstance {
                    node_id: "node-vless".into(),
                    provider_id: "vless-reality-vision@1".into(),
                    ..NodeInstance::default()
                },
            ],
            ..MachineTopology::default()
        };
        let plan = build_plan(&topology).unwrap();
        assert_eq!(
            plan,
            Plan {
                redirects: vec![
                    Redirect {
                        node_id: "node-a".into(),
                        listen_port: 443,
                        ports: vec![PortRange::new(10000, 10010)],
                    },
                    Redirect {
                        node_id: "node-b".into(),
                        listen_port: 8443,
                        ports: vec![PortRange::new(20000, 20010), PortRange::new(30000, 30000),],
                    },
                ],
            }
        );
        assert_eq!(plan.rule_count(), 3);
        assert_eq!(
            plan.digest(),
            "ad8ee5018fc120b4a0d53eec4e01fcbfb84f91272d8f7be36e9245522e280908"
        );
        assert_eq!(
            Plan::default().digest(),
            super::lower_hex(&sha2::Sha256::digest([]))
        );
    }

    #[test]
    fn splits_self_redirect_at_every_boundary() {
        for (listen_port, expression, expected) in [
            (
                25000,
                "20000-30000",
                vec![PortRange::new(20000, 24999), PortRange::new(25001, 30000)],
            ),
            (20000, "20000-30000", vec![PortRange::new(20001, 30000)]),
            (30000, "20000-30000", vec![PortRange::new(20000, 29999)]),
            (25000, "25000", Vec::new()),
        ] {
            let plan = build_plan(&MachineTopology {
                nodes: vec![hysteria_node("node-a", listen_port, expression)],
                ..MachineTopology::default()
            })
            .unwrap();
            assert_eq!(
                plan.redirects
                    .first()
                    .map(|redirect| redirect.ports.clone())
                    .unwrap_or_default(),
                expected
            );
        }
    }

    #[test]
    fn rejects_every_go_conflict_case() {
        let cases = [
            (
                vec![
                    hysteria_node("node-a", 443, "10000-20000"),
                    hysteria_node("node-b", 8443, "15000-25000"),
                ],
                "port_hopping conflict",
            ),
            (
                vec![
                    hysteria_node("node-a", 443, "8000-9000"),
                    hysteria_node("node-b", 8443, ""),
                ],
                "listen_port 8443",
            ),
            (
                vec![
                    hysteria_node("node-a", 8443, "8000-9000"),
                    hysteria_node("node-b", 8443, ""),
                ],
                "node-b hysteria2 listen_port 8443",
            ),
            (
                vec![hysteria_node("node-a", 443, "200-100")],
                "invalid hysteria2 port_hopping",
            ),
            (
                vec![
                    hysteria_node("node-a", 443, "10000"),
                    hysteria_node("node-a", 8443, "20000"),
                ],
                "duplicate node_id",
            ),
        ];
        for (nodes, expected) in cases {
            let error = build_plan(&MachineTopology {
                nodes,
                ..MachineTopology::default()
            })
            .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn listener_conflict_message_is_deterministic() {
        let topology = MachineTopology {
            nodes: vec![
                hysteria_node("node-z", 443, "8000-9000"),
                hysteria_node("node-b", 8555, ""),
                hysteria_node("node-a", 8443, ""),
            ],
            ..MachineTopology::default()
        };
        let expected = "node node-z port_hopping 8000-9000 conflicts with node node-a hysteria2 listen_port 8443";
        for _ in 0..20 {
            assert_eq!(build_plan(&topology).unwrap_err().to_string(), expected);
        }
    }
}
