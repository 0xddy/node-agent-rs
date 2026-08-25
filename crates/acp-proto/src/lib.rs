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

pub mod auth;
pub mod digest;
/// Lowercase hex, shared with the agent crate: it decodes the panel's
/// `x-acp-topology-digest` header before comparing it.
pub mod hex;

/// SHA-256 of `proto/acp.proto`, as a guard against silent divergence.
///
/// `acp.proto` is shared with `panel-api-server`; this crate holds a *copy*, not
/// a fork. If the upstream contract changes, this constant must be updated in
/// the same commit that re-copies the file -- that is the point. The test below
/// fails loudly rather than letting the two drift into a wire incompatibility
/// that only shows up against a live panel.
pub const PROTO_SHA256: &str = "631d4ccf9a5a475d6d73c6ee483680a472f75b83a7c405acd2c22191d8d35ac3";

/// Generated protobuf messages and gRPC clients for `package acp.v1`.
pub mod v1 {
    tonic::include_proto!("acp.v1");
}

pub use v1::*;

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    #[test]
    fn the_vendored_proto_matches_its_recorded_checksum() {
        let source = include_bytes!("../proto/acp.proto");
        let actual = crate::hex::encode(&Sha256::digest(source));
        assert_eq!(
            actual,
            super::PROTO_SHA256,
            "proto/acp.proto changed without updating PROTO_SHA256; if this was \
             a deliberate re-copy from panel-api-server, update the constant"
        );
    }

    #[test]
    fn generated_surface_keeps_all_seven_clients_and_server_traits() {
        use crate::v1::*;

        // Mentioning every server trait makes this fail at compile time if the
        // test-only mock surface is accidentally disabled again.
        #[allow(dead_code)]
        fn server_traits_exist<A, C, T, M, L, R, G>()
        where
            A: auth_service_server::AuthService,
            C: control_service_server::ControlService,
            T: traffic_service_server::TrafficService,
            M: telemetry_service_server::TelemetryService,
            L: log_service_server::LogService,
            R: remote_control_service_server::RemoteControlService,
            G: config_service_server::ConfigService,
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
        assert_eq!(clients.len(), 7);

        let proto = include_str!("../proto/acp.proto");
        assert_eq!(
            proto
                .lines()
                .filter(|line| line.trim_start().starts_with("service "))
                .count(),
            7
        );
        assert_eq!(
            proto
                .lines()
                .filter(|line| line.trim_start().starts_with("rpc "))
                .count(),
            8,
            "ConfigService is the one service with two methods"
        );
    }
}
