//! The topology convergence digest.
//!
//! When the control stream opens, the panel sends its own digest of the
//! machine's topology in the `x-acp-topology-digest` header. The agent compares
//! it against a digest of what it already has loaded: equal means "you are
//! already converged, keep running", different means "re-pull everything".
//!
//! So this function must agree with the panel's, byte for byte. It is a direct
//! port of `src/api/topologydigest/digest.go`:
//!
//! ```text
//! clone -> revision = 0 -> stable-sort nodes by node_id
//!       -> stable-sort each node's users by user_id
//!       -> deterministic proto marshal -> SHA-256 -> lowercase hex
//! ```
//!
//! Revision is zeroed because it is delivery-order metadata, not configuration:
//! two topologies that differ only in revision produce the same runtime. Node
//! and user order is normalized for the same reason.

use prost::Message;
use sha2::{Digest as _, Sha256};

use crate::hex;
use crate::v1::TopologySnapshot;

/// Returns the lowercase-hex SHA-256 digest of a topology snapshot's *effective*
/// content.
///
/// # Encoding agreement with Go
///
/// Go uses `proto.MarshalOptions{Deterministic: true}`. Determinism there only
/// governs map iteration order, and `TopologySnapshot` transitively contains no
/// map fields, so the flag is a no-op for this message. What remains -- fields
/// in ascending tag order, proto3 implicit-presence defaults omitted, repeated
/// fields in slice order -- is exactly what prost emits.
///
/// One known asymmetry: Go's `proto.Clone` carries unknown fields through into
/// the marshalled bytes, while prost drops them. If the panel ever sends a field
/// this build's `acp.proto` does not define, the two digests diverge and every
/// reconnect re-pulls the topology. That is a performance regression, not a
/// correctness one, and keeping `proto/acp.proto` in sync prevents it.
pub fn sum(snapshot: Option<&TopologySnapshot>) -> String {
    let mut normalized = snapshot.cloned().unwrap_or_default();

    normalized.revision = 0;
    normalized
        .nodes
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    for node in &mut normalized.nodes {
        node.users
            .sort_by(|left, right| left.user_id.cmp(&right.user_id));
    }

    hex::encode(&Sha256::digest(normalized.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::sum;
    use crate::v1::{NodeTopology, TopologySnapshot, UserCredential, UserStatus};

    fn user(id: &str, credential: &str) -> UserCredential {
        UserCredential {
            user_id: id.to_string(),
            name: format!("name-{id}"),
            credential: credential.to_string(),
            status: UserStatus::Active as i32,
            upload_speed_limit_bps: 0,
            download_speed_limit_bps: 0,
        }
    }

    fn node(id: &str, users: Vec<UserCredential>) -> NodeTopology {
        NodeTopology {
            node_id: id.to_string(),
            provider_id: "vless-reality-vision@1".to_string(),
            provider_config_version: 1,
            provider_config_json: br#"{"listen_port":443}"#.to_vec(),
            users,
        }
    }

    /// Digests produced by the real Go `topologydigest.Sum` over the exact
    /// fixtures built below. Cross-language vectors are the whole point: a
    /// self-consistent Rust digest that disagrees with the panel would look
    /// perfectly healthy in this test suite while re-pulling the topology on
    /// every single reconnect in production.
    const GO_DIGEST_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const GO_DIGEST_POPULATED: &str =
        "176f1959740e50eb1af3337071dd782d8c87949eb0d6f27c377b1fa6818293ac";

    fn populated() -> TopologySnapshot {
        TopologySnapshot {
            machine_id: "m1".to_string(),
            revision: 7,
            nodes: vec![
                node("b", vec![user("u2", "c2"), user("u1", "c1")]),
                node("a", vec![user("u3", "c3")]),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn digests_match_the_go_implementation() {
        assert_eq!(sum(Some(&TopologySnapshot::default())), GO_DIGEST_EMPTY);
        assert_eq!(sum(Some(&populated())), GO_DIGEST_POPULATED);
    }

    #[test]
    fn prost_and_go_agree_that_an_empty_snapshot_encodes_to_no_bytes() {
        // Every field of an empty snapshot is a proto3 implicit-presence
        // default, so a conforming encoder emits nothing at all. This pins the
        // one property most likely to differ between the two encoders.
        use prost::Message as _;
        assert!(TopologySnapshot::default().encode_to_vec().is_empty());
    }

    #[test]
    fn revision_is_excluded_because_it_is_delivery_metadata() {
        let at_seven = TopologySnapshot {
            machine_id: "m1".to_string(),
            revision: 7,
            nodes: vec![node("n1", vec![user("u1", "cred")])],
            ..Default::default()
        };
        let at_nine = TopologySnapshot {
            revision: 9,
            ..at_seven.clone()
        };

        assert_eq!(sum(Some(&at_seven)), sum(Some(&at_nine)));
    }

    #[test]
    fn node_and_user_order_are_normalized() {
        let one_order = TopologySnapshot {
            machine_id: "m1".to_string(),
            revision: 3,
            nodes: vec![
                node("b", vec![user("u2", "c2"), user("u1", "c1")]),
                node("a", vec![user("u3", "c3")]),
            ],
            ..Default::default()
        };
        let other_order = TopologySnapshot {
            machine_id: "m1".to_string(),
            revision: 3,
            nodes: vec![
                node("a", vec![user("u3", "c3")]),
                node("b", vec![user("u1", "c1"), user("u2", "c2")]),
            ],
            ..Default::default()
        };

        assert_eq!(sum(Some(&one_order)), sum(Some(&other_order)));
    }

    #[test]
    fn content_changes_do_move_the_digest() {
        let before = TopologySnapshot {
            machine_id: "m1".to_string(),
            nodes: vec![node("n1", vec![user("u1", "cred-old")])],
            ..Default::default()
        };
        let after = TopologySnapshot {
            machine_id: "m1".to_string(),
            nodes: vec![node("n1", vec![user("u1", "cred-new")])],
            ..Default::default()
        };

        assert_ne!(
            sum(Some(&before)),
            sum(Some(&after)),
            "a rotated credential must be visible to the convergence check"
        );
    }

    #[test]
    fn an_absent_snapshot_digests_as_the_empty_one() {
        assert_eq!(sum(None), sum(Some(&TopologySnapshot::default())));
    }

    #[test]
    fn the_digest_is_thirty_two_bytes_of_lowercase_hex() {
        let digest = sum(Some(&TopologySnapshot::default()));
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }
}
