use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        /// Response normally written after the remote connection succeeds. A caller
        /// that needs application-protocol sniffing must send and flush it first,
        /// because response-gated clients cannot provide sniffable bytes otherwise.
        connection_success_response: Option<Box<[u8]>>,
        /// Initial data to send to the remote location
        initial_remote_data: Option<Box<[u8]>>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
    },
    /// Connection has been fully handled (e.g., spawned as a background task).
    /// No further processing needed by the caller.
    AlreadyHandled,
    /// The stream was handed to a probing-resistance or camouflage fallback after
    /// proxy authentication failed (or before deferred authentication completed).
    ///
    /// Transport callers must stop processing this stream, but must not count it as
    /// a successful proxy handshake for a multiplexed connection-wide auth gate.
    UnauthenticatedFallbackHandled,
}

impl TcpServerSetupResult {
    pub(crate) fn is_already_handled(&self) -> bool {
        matches!(
            self,
            Self::AlreadyHandled | Self::UnauthenticatedFallbackHandled
        )
    }

    pub(crate) fn completes_protocol_handshake(&self) -> bool {
        !matches!(self, Self::UnauthenticatedFallbackHandled)
    }

    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
            TcpServerSetupResult::AlreadyHandled
            | TcpServerSetupResult::UnauthenticatedFallbackHandled => {}
        }
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
    /// Early application data that was buffered during protocol handshake.
    /// Only expected from the final destination - intermediate hops should not
    /// return early data (all proxy protocols are client-initiated).
    pub early_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    /// Setup a client connection through this proxy.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `remote_location` - The destination to connect to through the proxy.
    ///                       May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// * `client_stream` - The wrapped stream ready for application data
    /// * `early_data` - Any application data received during handshake (from final destination)
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Whether this handler returns a connection whose protocol request is
    /// conceptually performed by the first application write in sing-box.
    ///
    /// Shoes performs these handshakes eagerly.  The marker lets URLTest place
    /// its latency boundary at the equivalent point without delaying ordinary
    /// connection setup.
    fn needs_handshake_for_write(&self) -> bool {
        false
    }

    /// Returns true if this handler supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    /// Returns true when this protocol carries UDP as native datagrams to the
    /// proxy server instead of tunnelling messages over a byte stream.
    fn supports_native_udp(&self) -> bool {
        false
    }

    /// Setup a bidirectional UDP message stream over a TCP connection.
    /// Only called if `supports_udp_over_tcp()` returns true.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `target` - The destination for UDP packets.
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// A message stream for sending/receiving UDP packets to the target.
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }

    /// Wrap a native UDP socket connected to the proxy server.
    ///
    /// Protocols such as Shadowsocks SIP003 encrypt each datagram independently,
    /// so forcing them through `setup_client_udp_bidirectional` would incorrectly
    /// turn native UDP into UDP-over-TCP.
    async fn setup_client_native_udp(
        &self,
        _client_stream: Box<dyn AsyncMessageStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native UDP not supported by this protocol",
        ))
    }
}
