//! The ACP wire contract: protobuf types, gRPC clients, and the two derivations
//! the panel verifies byte for byte.
//!
//! # What "compatible" means here
//!
//! A Rust agent and the Go agent it replaces are interchangeable only if four
//! things match exactly. Three of them live in this crate:
//!
//! 1. **The protobuf encoding** -- guaranteed by compiling the same `.proto`.
//! 2. **The HMAC canonical strings** ([`auth`]) -- one wrong byte is an
//!    `Unauthenticated` status and the session never opens.
//! 3. **The topology digest** ([`digest`]) -- a mismatch is not fatal, but it
//!    makes every reconnect re-pull the whole topology, forever.
//!
//! The fourth, the control-stream handshake sequence, is session behaviour and
//! lives in the agent crate.

pub mod analysis;
pub mod auth;
pub mod digest;
/// Lowercase hex, shared with the agent crate: it decodes the panel's
/// `x-acp-topology-digest` header before comparing it.
pub mod hex;

/// SHA-256 of the LF-normalized `proto/acp.proto`, as a guard against silent
/// divergence.
///
/// `acp.proto` is shared with `panel-api-server`; this crate holds a *copy*, not
/// a fork. If the upstream contract changes, this constant must be updated in
/// the same commit that re-copies the file -- that is the point. The test below
/// fails loudly rather than letting the two drift into a wire incompatibility
/// that only shows up against a live panel.
pub const PROTO_SHA256: &str = "59bc1ea85b0c28a9e13131ea97637e1d65b86709b1925e29c5fc454bdd1a7c1a";

/// Marks the one-time telemetry clock handshake; individual samples have no ACK.
pub const TELEMETRY_READY_METADATA_KEY: &str = "x-acp-telemetry-ready";

/// Generated protobuf messages and gRPC clients for `package acp.v1`.
// Prost and Tonic own this expansion. Lint the hand-written boundary around it,
// but do not turn generator implementation details into warnings for this crate.
#[allow(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod v1 {
    tonic::include_proto!("acp.v1");
}

pub use analysis::{
    default_config as default_traffic_analysis_config,
    normalize_config as normalize_traffic_analysis_config,
};
pub use v1::*;

#[cfg(test)]
mod tests {
    use prost::Message;
    use sha2::{Digest, Sha256};

    #[test]
    fn route_contract_decodes_string_strategies_and_explicit_false_fragmentation() {
        // ACP's current contract uses scalar strings here, not nested messages.
        let route_wire = b"\x62\x08fallback";
        let route = crate::RouteConfig::decode(route_wire.as_slice()).unwrap();
        assert_eq!(route.default_network_strategy, "fallback");
        assert_eq!(route.encode_to_vec(), route_wire);

        let action_wire = b"\x1a\x06hybrid";
        let action = crate::RouteActionOptions::decode(action_wire.as_slice()).unwrap();
        assert_eq!(action.network_strategy, "hybrid");
        assert_eq!(action.encode_to_vec(), action_wire);

        let direct_wire = b"\x50\x00\xa2\x01\x07default";
        let direct = crate::DirectActionOptions::decode(direct_wire.as_slice()).unwrap();
        assert_eq!(direct.network_strategy, "default");
        assert_eq!(direct.udp_fragment, Some(false));
        assert_eq!(direct.encode_to_vec(), direct_wire);
        assert_eq!(crate::DirectActionOptions::default().udp_fragment, None);
    }

    #[test]
    fn the_vendored_proto_matches_its_recorded_checksum() {
        // Git may materialize text files with CRLF on Windows even though the
        // canonical panel copy uses LF. Line endings do not change the protobuf
        // contract, so hash the one canonical representation on every platform.
        let source = include_str!("../proto/acp.proto").replace("\r\n", "\n");
        let actual = crate::hex::encode(&Sha256::digest(source.as_bytes()));
        assert_eq!(
            actual,
            super::PROTO_SHA256,
            "proto/acp.proto changed without updating PROTO_SHA256; if this was \
             a deliberate re-copy from panel-api-server, update the constant"
        );
    }

    #[test]
    fn generated_surface_keeps_all_eight_clients_and_server_traits() {
        use crate::v1::*;

        // Mentioning every server trait makes this fail at compile time if the
        // test-only mock surface is accidentally disabled again.
        #[allow(dead_code)]
        fn server_traits_exist<A, C, T, M, L, R, G, N>()
        where
            A: auth_service_server::AuthService,
            C: control_service_server::ControlService,
            T: traffic_service_server::TrafficService,
            M: telemetry_service_server::TelemetryService,
            L: log_service_server::LogService,
            R: remote_control_service_server::RemoteControlService,
            G: config_service_server::ConfigService,
            N: traffic_analysis_service_server::TrafficAnalysisService,
        {
        }

        let clients = [
            std::any::type_name::<auth_service_client::AuthServiceClient<tonic::transport::Channel>>(
            ),
            std::any::type_name::<
                control_service_client::ControlServiceClient<tonic::transport::Channel>,
            >(),
            std::any::type_name::<
                traffic_service_client::TrafficServiceClient<tonic::transport::Channel>,
            >(),
            std::any::type_name::<
                traffic_analysis_service_client::TrafficAnalysisServiceClient<
                    tonic::transport::Channel,
                >,
            >(),
            std::any::type_name::<
                telemetry_service_client::TelemetryServiceClient<tonic::transport::Channel>,
            >(),
            std::any::type_name::<log_service_client::LogServiceClient<tonic::transport::Channel>>(
            ),
            std::any::type_name::<
                remote_control_service_client::RemoteControlServiceClient<
                    tonic::transport::Channel,
                >,
            >(),
            std::any::type_name::<
                config_service_client::ConfigServiceClient<tonic::transport::Channel>,
            >(),
        ];
        assert_eq!(clients.len(), 8);

        let proto = include_str!("../proto/acp.proto");
        assert_eq!(
            proto
                .lines()
                .filter(|line| line.trim_start().starts_with("service "))
                .count(),
            8
        );
        assert_eq!(
            proto
                .lines()
                .filter(|line| line.trim_start().starts_with("rpc "))
                .count(),
            9,
            "ConfigService is the one service with two methods"
        );
    }
}
