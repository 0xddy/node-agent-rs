use lru::LruCache;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

/// Maximum number of fragmented packets to track per session.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of concurrent UDP sessions one connection may hold open.
///
/// A session is not free: it owns a client-side UDP socket, a spawned task, and
/// that task's 64 KiB receive buffer. The session id is a client-chosen `u32`, so
/// without a ceiling here an authenticated client can name four billion of them and
/// the only thing bounding the cost is how fast it can send datagrams. That is a
/// file-descriptor exhaustion long before it is a memory one, and on a shared
/// inbound it takes every other user's connections down with it.
///
/// 512 leaves the ceiling well above what a real client reaches -- each session is
/// one destination flow, and even a busy peer-to-peer workload sits far below it --
/// while capping one connection at roughly 32 MiB and 512 descriptors.
const MAX_UDP_SESSIONS: usize = 512;

/// HTTP/3 error code for normal closure.
/// Per official hysteria reference: https://github.com/apernet/hysteria/blob/master/core/server/server.go#L20
const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::dynamic::{ConnContext, SelectorSlot, TrafficMeterStream, UserContext, UserRegistry};
use crate::quic_server::{
    QUIC_PRE_AUTH_TIMEOUT, QUIC_TRANSPORT_HANDSHAKE_TIMEOUT, require_validated_quic_address,
};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, ResolverCache};
use crate::routing::protocol::sniff_tcp;
use crate::stream_reader::StreamReader;
use crate::tcp::handshake_gate::{
    HandshakeGate, HandshakePermit, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use crate::tcp::tcp_server::setup_client_tcp_stream_with_metadata;
use crate::util::allocate_vec;

/// The accounting record for one authenticated QUIC connection, or `None` when the
/// inbound is not metered.
///
/// Hysteria2 multiplexes every proxied stream and datagram over a single QUIC
/// connection, and it authenticates once, up front, before any of them exist. So
/// unlike the TCP path there is no anonymous phase to hand over: one context is
/// bound to its user immediately and then shared by every loop below.
///
/// It travels as an explicit parameter rather than through
/// [`scope_connection`](crate::dynamic::scope_connection), because each of those
/// loops runs in a task of its own and a task local would not survive the spawn.
type Meter = Option<Arc<ConnContext>>;

/// Decode the QUIC-varint address length at byte 8 of a Hysteria UDP datagram.
///
/// The first nine bytes are fixed-width through the first varint byte. Returning
/// `None` for a truncated multi-byte varint lets the datagram loop discard hostile
/// input without ever constructing an out-of-bounds slice.
fn decode_udp_address_length(data: &[u8]) -> Option<(usize, usize)> {
    let first_byte = *data.get(8)?;
    let num_bytes = 1usize << (first_byte >> 6);
    let mut value = u64::from(first_byte & 0b0011_1111);
    let next_index = 8usize.checked_add(num_bytes)?;

    for byte in data.get(9..next_index)? {
        value = (value << 8) | u64::from(*byte);
    }

    Some((usize::try_from(value).ok()?, next_index))
}

#[inline]
fn valid_udp_fragment(fragment_id: u8, fragment_count: u8) -> bool {
    fragment_count != 0 && fragment_id < fragment_count
}

#[derive(Clone)]
struct Hysteria2ConnectionSettings {
    users: Arc<dyn UserRegistry>,
    metered: bool,
    udp_enabled: bool,
    up_mbps: u64,
    down_mbps: u64,
    masquerade: Arc<crate::hysteria2_masquerade::Hysteria2Masquerade>,
}

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    conn: quinn::Incoming,
    settings: Hysteria2ConnectionSettings,
    handshake_permit: HandshakePermit,
    pre_auth_deadline: Instant,
) -> std::io::Result<()> {
    let transport_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let connection = match timeout_at(transport_deadline, conn).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Hysteria2 QUIC handshake exceeded the pre-auth deadline",
            ));
        }
    };

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = CancellationToken::new();
    // `process_connection` has several early returns and drives attacker-controlled
    // parsers. Keep cleanup exception-safe: unwinding or dropping this future must
    // cancel every child token even when control never reaches the normal epilogue.
    let _cancel_guard = cancel_token.clone().drop_guard();

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    //
    // we keep this function waiting for the tcp and udp tasks both to finish before dropping,
    // instead of passing the connection to one of the two loops, incase one finishes first.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

    let h3_setup_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> = match timeout_at(
        h3_setup_deadline,
        h3::server::Connection::new(h3_quinn_connection),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(e)) => {
            return Err(std::io::Error::other(format!(
                "H3 connection setup failed: {e}"
            )));
        }
        Err(_elapsed) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"pre-auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Hysteria2 H3 setup exceeded the pre-auth deadline",
            ));
        }
    };

    // Preserve the sing-box-compatible three-second application-authentication
    // window after H3 setup, but never let it outlive the 60-second absolute outer
    // deadline that began at gate admission.
    let auth_deadline = std::cmp::min(pre_auth_deadline, Instant::now() + AUTH_TIMEOUT);
    let meter = match timeout_at(
        auth_deadline,
        auth_connection(&mut h3_conn, &connection, &settings),
    )
    .await
    {
        Ok(Ok(user)) => user,
        Ok(Err(e)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    };

    // Hysteria2 authenticates once for the whole QUIC connection. From this point
    // on the connection is charged to its user (when metering is enabled), so it no
    // longer belongs in the anonymous-handshake budget. Every error above releases
    // the permit through normal drop as well.
    drop(handshake_permit);

    // The auth exchange itself goes uncounted: it rides h3's own streams, whose
    // framing and QPACK encoding quinn and h3 own between them. It is a few hundred
    // bytes once per connection, and the same argument already applies to the QUIC
    // handshake that carried it.
    let removal_meter = meter.clone();

    let udp_connection = connection.clone();
    let udp_client_proxy_selector = client_proxy_selector.clone();
    let udp_resolver = resolver.clone();
    let udp_cancel_token = cancel_token.clone();
    let udp_meter = meter.clone();

    let uni_connection = connection.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let udp_loop = async {
        if settings.udp_enabled {
            run_udp_local_to_remote_loop(
                udp_connection,
                udp_client_proxy_selector,
                udp_resolver,
                udp_meter,
                udp_cancel_token,
            )
            .await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        // Depending on the client, unidirectional streams could still be sent, accept and drop.
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(tcp_connection, client_proxy_selector, resolver, meter);

    let user_removed = async move {
        match removal_meter {
            Some(context) => context.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };

    let result = tokio::select! {
        biased;
        () = user_removed => {
            cancel_token.cancel();
            connection.close(CLOSE_ERR_CODE_OK.into(), b"user removed");
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "connection closed because its user was removed",
            ))
        }
        result = async { tokio::try_join!(udp_loop, uni_loop, tcp_loop) } => result,
    };

    cancel_token.cancel();

    // Per sing-box reference (service.go:277-293), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check that this really is a hysteria2 auth request, and hand back whose it is.
///
/// The password arrives in cleartext in a header, so a registry lookup is the whole
/// of authentication here -- there is nothing derived and nothing to recompute. That
/// is also why the rejection message no longer echoes the value: with more than one
/// user it is somebody's live credential, or a guess at one, and neither belongs in
/// a log line.
fn validate_auth_request<T>(
    req: &http::Request<T>,
    users: &dyn UserRegistry,
) -> std::io::Result<Arc<UserContext>> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;

    users
        .find_password(auth_str)
        .ok_or_else(|| std::io::Error::other("unrecognized auth password"))
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    connection: &quinn::Connection,
    settings: &Hysteria2ConnectionSettings,
) -> std::io::Result<Meter> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(&req, settings.users.as_ref()) {
                    Ok(user) => {
                        // Admission and connection registration are one lifecycle
                        // operation. Do it before sending success, so remove_user
                        // cannot return while this peer is being told it authenticated.
                        let meter = if settings.metered {
                            let context = ConnContext::new();
                            if !context.bind_authenticated(user) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "user could not be admitted: removed, suspended, or at their connection limit",
                                ));
                            }
                            Some(context)
                        } else {
                            if !user.admit_unmetered() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "user could not be admitted: removed, suspended, or at their connection limit",
                                ));
                            }
                            None
                        };

                        // Hysteria2's header is bytes per second despite the
                        // configuration being expressed in Mbps. Missing and
                        // malformed values are zero in sing-quic and select BBR.
                        let client_receive_bps = req
                            .headers()
                            .get("Hysteria-CC-RX")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(0);
                        let bandwidth = crate::hysteria2::brutal::negotiate_server(
                            client_receive_bps,
                            settings.up_mbps,
                            settings.down_mbps,
                        );
                        if let Some(send_bps) = bandwidth.send_bps {
                            crate::hysteria2::brutal::activate(connection, send_bps)?;
                        }
                        let advertised_receive = bandwidth.advertised_receive.header_value();

                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header(
                                "Hysteria-UDP",
                                if settings.udp_enabled {
                                    "true"
                                } else {
                                    "false"
                                },
                            )
                            .header("Hysteria-CC-RX", advertised_receive)
                            .header("Hysteria-Padding", generate_ascii_string())
                            .body(())
                            .unwrap();

                        let respond = async {
                            stream.send_response(resp).await.map_err(|e| {
                                std::io::Error::other(format!("failed to send auth response: {e}"))
                            })?;
                            stream.finish().await.map_err(|e| {
                                std::io::Error::other(format!("failed to finish auth stream: {e}"))
                            })
                        };

                        if let Some(context) = &meter {
                            tokio::select! {
                                biased;
                                () = context.cancelled() => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::ConnectionAborted,
                                        "user removed",
                                    ));
                                }
                                result = respond => result?,
                            }
                        } else {
                            respond.await?;
                        }

                        return Ok(meter);
                    }
                    Err(e) => {
                        debug!("Serving Hysteria2 masquerade response: {e}");
                        settings.masquerade.respond(req, stream).await?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

struct UdpSession {
    fragments: LruCache<u16, FragmentedPacket>,
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
}

impl Drop for UdpSession {
    /// Stop the remote-to-local task this session started.
    ///
    /// A `CancellationToken` does not fire when its last handle is dropped -- only
    /// an explicit `cancel` or a `DropGuard` does that -- and the spawned loop holds
    /// its own clone of this one along with the client socket and a 64 KiB receive
    /// buffer. So every path that discards a session without going through the
    /// reaper would otherwise strand that task, its fd and its buffer until the
    /// whole QUIC connection ends: the send-failure `remove` below is one such path,
    /// and it is the one an unreachable destination reaches on the first packet.
    ///
    /// Cancelling here rather than at each call site makes the release a property of
    /// the session's lifetime, so a future path that drops one is covered too. The
    /// reaper's explicit `cancel` is left in place and is simply idempotent.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: NetLocation,
}

impl UdpSession {
    // TODO: remove this function completely and inline?
    #[allow(clippy::too_many_arguments)]
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        meter: Meter,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        let removal_meter = meter.clone();
        tokio::spawn(async move {
            let work = run_udp_remote_to_local_loop(
                session_id,
                connection,
                client_socket,
                override_local_write_location,
                meter,
                session_cancel_token,
            );
            let result = if let Some(context) = removal_meter {
                tokio::select! {
                    biased;
                    () = context.cancelled() => Ok(()),
                    result = work => result,
                }
            } else {
                work.await
            };

            if let Err(e) = result {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<(Bytes, Bytes)> = match override_local_write_address {
        Some(a) => {
            let address_bytes: Bytes = a.to_string().into_bytes().into();
            let address_len = address_bytes.len();
            let address_len_bytes = encode_varint(address_len as u64)?;
            Some((address_bytes, address_len_bytes.into()))
        }
        None => None,
    };

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535);
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        // This prevents starvation during heavy UDP traffic.
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let (address_bytes, address_len_bytes) = match original_address_bytes {
            Some((ref a, ref b)) => (a.clone(), b.clone()),
            None => {
                let address_bytes: Bytes = src_addr.to_string().into_bytes().into();
                // no need to do a length check since this is a socket address and an IP.
                let address_len = address_bytes.len();
                let address_len_bytes = encode_varint(address_len as u64)?.into();
                (address_bytes, address_len_bytes)
            }
        };

        // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length varint + address bytes
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();

        // Not an assertion, because `header_overhead` is not a fact about this
        // program: the address in it is the location the *client* asked for, echoed
        // back so it recognises the reply, and this inbound accepts one of up to 2048
        // bytes while a QUIC datagram holds barely more than an MTU. A client that
        // names a destination longer than the datagram it must be announced in makes
        // this arithmetic underflow one line below, and a panic there would be a
        // remote client deciding when a task on this server dies.
        //
        // The address is fixed for the session's lifetime, so this cannot come right
        // on a later packet: end the loop and let the reaper collect the session.
        if max_datagram_size <= header_overhead {
            return Err(std::io::Error::other(format!(
                "the requested destination needs {header_overhead} header bytes, which does not \
                 fit a {max_datagram_size} byte datagram"
            )));
        }

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            // fragment id = 0, fragment count = 0
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            // Counted after the send, and by datagram length rather than payload
            // length, so the session and address headers the client is charged for
            // receiving are the ones actually put on the wire.
            let datagram = datagram.freeze();
            let datagram_len = datagram.len();
            connection
                .send_datagram(datagram)
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
            if let Some(meter) = &meter {
                meter.count_datagram_tx(datagram_len).await;
            }
        } else {
            let available_payload = max_datagram_size - header_overhead;
            let fragment_count = payload_len.div_ceil(available_payload) as u8;
            for fragment_id in 0..fragment_count {
                let start = (fragment_id as usize) * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);
                let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_id, fragment_count]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                let datagram = datagram.freeze();
                let datagram_len = datagram.len();
                connection.send_datagram(datagram).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
                if let Some(meter) = &meter {
                    meter.count_datagram_tx(datagram_len).await;
                }
            }
        }
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    meter: Meter,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let mut last_cleanup = std::time::Instant::now();

    // Match reference implementation defaults for UDP session management
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            sessions.retain(|session_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    // Cancel the session's background task before removing
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {session_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // Counted before any of the validation below, because every one of those
        // `continue`s discards a datagram the client has already sent and this proxy
        // has already received. Billing only the well-formed ones would let a client
        // move bytes for free by malforming them.
        if let Some(meter) = &meter {
            meter.count_datagram_rx(data.len()).await;
        }

        // Per official hysteria reference (server.go:332-353), parse errors are ignored
        // and we continue waiting for the next message. Only connection errors are fatal.
        if data.len() < 9 {
            debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        if !valid_udp_fragment(fragment_id, fragment_count) {
            debug!("Ignoring datagram with invalid fragment {fragment_id}/{fragment_count}");
            continue;
        }

        let Some((address_len, next_index)) = decode_udp_address_length(&data) else {
            debug!("Ignoring datagram with truncated address length");
            continue;
        };

        if address_len == 0 {
            debug!("Ignoring packet with empty address");
            continue;
        }

        if address_len > 2048 {
            debug!("Ignoring packet with address length {address_len}");
            continue;
        }

        if data.len() < next_index + address_len {
            debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        // Read before taking the entry, which borrows the map for the rest of the
        // match. Nothing mutates in between, so this is the exact live count.
        let session_count = sessions.len();

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                if session_count >= MAX_UDP_SESSIONS {
                    // Refusing the packet rather than evicting somebody: an eviction
                    // policy would let a client at the ceiling knock out its own
                    // established flows by naming new ids, and would hand an attacker
                    // a way to churn sockets indefinitely at a fixed occupancy.
                    debug!(
                        "Refusing new UDP session {session_id}: at the {MAX_UDP_SESSIONS} session limit"
                    );
                    continue;
                }

                let action = client_proxy_selector
                    .judge_udp(remote_location.clone().into(), &resolver)
                    .await;

                let (_chain_group, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    }) => (chain_group, remote_location),
                    Ok(ConnectDecision::Block) => {
                        warn!("Blocked UDP forward to {remote_location}");
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to judge UDP forward to {remote_location}: {e}");
                        continue;
                    }
                };

                // the remote location specified at the beginning of a session is assumed
                // to be the remote location for the entire session iif it does not match
                // the resolved address, as per the official client - which is only if
                // it's a hostname. in our case, we also have to handle when the remote
                // location is replaced by a different location in the rules.
                //
                // it's possible that when we receive packets on the client socket,
                // it could be the resolved hostname versus what was initially provided,
                // and we need to write datagrams back to the user using their provided
                // address so that they know where it's from.
                //
                // it would be much simpler to always replace, or never, but we stick to
                // the official client behavior for now.
                //
                // ref: https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/udp.go#L137

                let resolved_address = match resolver_cache
                    .resolve_location(updated_location.location())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to resolve initial remote location {remote_location}: {e}");
                        continue;
                    }
                };

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        (None, None)
                    };

                // TODO: the configured client socket is for the current remote_location, but
                // the remote_location could be changed later on with a different client_socket
                // configuration.
                //
                // The family follows the first destination, as `SocketConnector` does
                // for every other protocol (`tcp/socket_connector_impl.rs:328`). An
                // AF_INET6 socket is not a dual-stack shortcut here: sending to a plain
                // `SocketAddr::V4` from one is a WSAEFAULT/EINVAL, and reaching an IPv4
                // peer through its `::ffff:` form would put a mapped address in the
                // source field this loop writes back to the client.
                let client_socket =
                    crate::socket_util::new_udp_socket(resolved_address.is_ipv6(), None)?;

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    remote_location.clone(),
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                    meter.clone(),
                    &cancel_token,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        // The client just sent something for this session, so it is not idle. Without
        // this the field only ever held its creation time and the reaper below tore
        // every session down 60 seconds in, however busy it was -- a plain bug, and
        // the reason the idle limit did not bound the map either.
        //
        // Refreshed here, on arrival, rather than after a successful forward: a
        // session receiving the fragments of one large packet is active even before
        // any of them can be reassembled and sent, and being reaped mid-reassembly
        // would discard the fragments already held.
        session.last_activity = std::time::Instant::now();

        let (complete_payload, remote_location) = if fragment_count == 1 {
            (payload_fragment, remote_location)
        } else {
            let is_new = !session.fragments.contains(&packet_id);

            if is_new {
                session.fragments.put(
                    packet_id,
                    FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }

            let entry = match session.fragments.get_mut(&packet_id) {
                Some(e) => e,
                None => {
                    // This shouldn't happen since we just inserted it
                    error!("Fragment cache error for session {session_id}");
                    continue;
                }
            };

            if entry.fragment_count != fragment_count {
                session.fragments.pop(&packet_id);
                error!("Mismatched fragment count for session {session_id} packet {packet_id}");
                continue;
            }
            if entry.received[fragment_id as usize].is_some() {
                session.fragments.pop(&packet_id);
                error!("Duplicate fragment for session {session_id} packet {packet_id}");
                continue;
            }
            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            // All fragments received - remove from cache and process
            let FragmentedPacket {
                remote_location: initial_location,
                received,
                packet_len,
                ..
            } = session.fragments.pop(&packet_id).unwrap();
            let mut complete_payload = BytesMut::with_capacity(packet_len);
            for frag in received.iter() {
                complete_payload.extend_from_slice(frag.as_ref().unwrap());
            }
            (complete_payload.freeze(), initial_location)
        };

        let socket_addr = match session.override_remote_write_address {
            Some(addr) => addr,
            None => {
                if remote_location == session.last_location {
                    session.last_socket_addr
                } else {
                    warn!(
                        "Location changed during ongoing UDP session: {}",
                        remote_location.clone()
                    );
                    let action = client_proxy_selector
                        .judge_udp(remote_location.clone().into(), &resolver)
                        .await;
                    let updated_location = match action {
                        Ok(ConnectDecision::Allow {
                            chain_group: _,
                            remote_location,
                        }) => remote_location,
                        Ok(ConnectDecision::Block) => {
                            warn!("Blocked UDP forward to {remote_location}");
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to judge UDP forward to {remote_location}: {e}");
                            continue;
                        }
                    };
                    let updated_socket_addr = match resolver_cache
                        .resolve_location(updated_location.location())
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve updated remote location {}: {e}",
                                updated_location.location()
                            );
                            continue;
                        }
                    };
                    session.last_location = updated_location.into_location();
                    session.last_socket_addr = updated_socket_addr;
                    updated_socket_addr
                }
            }
        };

        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {session_id}: {e}");
            sessions.remove(&session_id);
        }
    }
}

async fn run_tcp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    meter: Meter,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        // Every stream on this connection shares the one context, so a user's
        // counters cover all of them at once and the live-connection count follows
        // the QUIC connection rather than the streams multiplexed over it.
        let meter = meter.clone();
        let removal_meter = meter.clone();
        tokio::spawn(async move {
            let work = process_tcp_stream(
                client_proxy_selector,
                resolver,
                meter,
                send_stream,
                recv_stream,
            );
            let result = if let Some(meter) = removal_meter {
                tokio::select! {
                    biased;
                    () = meter.cancelled() => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "user removed",
                    )),
                    result = work => result,
                }
            } else {
                work.await
            };
            if let Err(e) = result {
                error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

/// TCP request frame type constant from Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

async fn handle_tcp_header(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    // Read the TCP request frame type as a QUIC varint per protocol spec.
    // The value 0x401 can be encoded in multiple valid ways (e.g., [0x44, 0x01] as 2-byte form).
    let tcp_request_id = read_varint(stream, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_len = read_varint(stream, &mut stream_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader
        .read_slice(stream, address_len as usize)
        .await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(stream, &mut stream_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader
        .read_slice(stream, padding_len as usize)
        .await?;

    let response_bytes = {
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut rng = rand::rng();

        // only use the lower 6 bits so that the varint always fits in a single u8
        let padding_len = rng.random_range(0..=63);

        // first 3 bytes of status = 0x0, message length = 0, padding length
        let mut response_bytes = allocate_vec(3 + (padding_len as usize));
        response_bytes[0] = 0;
        response_bytes[1] = 0;
        response_bytes[2] = padding_len;
        rng.fill_bytes(&mut response_bytes[3..]);

        response_bytes
    };

    let len = response_bytes.len();
    let mut i = 0;
    while i < len {
        let count = stream
            .write(&response_bytes[i..len])
            .await
            .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
        i += count;
    }

    Ok((remote_location, stream_reader))
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    meter: Meter,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) -> std::io::Result<()> {
    // Metered before the request header is read, rather than after, so the address,
    // the padding, and the status response this proxy writes back are all billed --
    // they are bytes the client put on the wire and had put back to it. Reading the
    // header through the wrapper is also what makes `handle_tcp_header` take one
    // stream instead of quinn's send and recv halves.
    let mut server_stream: Box<dyn AsyncStream> = match meter {
        Some(meter) => Box::new(TrafficMeterStream::new(QuicStream::from(send, recv), meter)),
        None => Box::new(QuicStream::from(send, recv)),
    };

    let (remote_location, stream_reader) = match handle_tcp_header(&mut server_stream).await {
        Ok(res) => res,
        Err(e) => {
            let _ = server_stream.shutdown().await;
            return Err(e);
        }
    };

    let mut replay = stream_reader
        .unparsed_data_owned()
        .map(Vec::from)
        .unwrap_or_default();
    drop(stream_reader);
    let sniffed = if client_proxy_selector.needs_tcp_sniff() {
        sniff_tcp(&mut server_stream, &mut replay).await?
    } else {
        None
    };

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream_with_metadata(
            &mut server_stream,
            client_proxy_selector,
            resolver,
            remote_location.clone(),
            sniffed,
        ),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    let client_requires_flush = if replay.is_empty() {
        false
    } else {
        let len = replay.len();
        let mut i = 0;
        while i < len {
            let count = client_stream
                .write(&replay[i..len])
                .await
                .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
            i += count;
        }
        true
    };

    // Use 32KB buffers to match hysteria2/sing-box reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

async fn read_varint(
    stream: &mut Box<dyn AsyncStream>,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(stream).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            // impossible since we only have 2 bits
            panic!("invalid num bytes value");
        }
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(stream, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub async fn start_hysteria2_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    users: Arc<dyn UserRegistry>,
    metered: bool,
    // Read once per accepted connection, so a rules reload reaches the next
    // connection and never one already running. See `SelectorSlot`.
    // The resolver travels inside the slot, alongside the rules it was built with,
    // so this loop takes no copy of its own.
    selector: Arc<SelectorSlot>,
    num_endpoints: usize,
    udp_enabled: bool,
    up_mbps: u64,
    down_mbps: u64,
    // Salamander obfuscation, or `None` for plain QUIC.
    obfs: Option<crate::hysteria2_obfs::Salamander>,
    masquerade: Arc<crate::hysteria2_masquerade::Hysteria2Masquerade>,
    shutdown: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    // `num_endpoints` is an SO_REUSEPORT fan-out for one logical listener, not a
    // multiplier for its unauthenticated-connection budget.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    for _ in 0..num_endpoints {
        let quic_server_config = quic_server_config.clone();
        let obfs = obfs.clone();
        let connection_settings = Hysteria2ConnectionSettings {
            users: users.clone(),
            metered,
            udp_enabled,
            up_mbps,
            down_mbps,
            masquerade: masquerade.clone(),
        };
        // No resolver clone: the accept loop takes it from the selector slot, so the
        // rules and the DNS a connection routes by are always one generation.
        let selector = selector.clone();
        let handshake_gate = handshake_gate.clone();
        let shutdown = shutdown.clone();

        let join_handle = tokio::spawn(async move {
            let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config);

            // values estimated from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/config.go#L16
            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                .max_concurrent_bidi_streams(4096_u32.into())
                // required for HTTP/3 QPACK updates
                .max_concurrent_uni_streams(1024_u32.into())
                .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .send_window(16 * 1024 * 1024)
                .receive_window((20u32 * 1024 * 1024).into())
                .stream_receive_window((8u32 * 1024 * 1024).into())
                // MTU settings per official TUIC reference
                .initial_mtu(1200)
                .min_mtu(1200)
                // Enable MTU discovery for larger packets on capable networks
                .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
                // QUIC exists before the HTTP/3 auth request carrying
                // Hysteria-CC-RX. This factory starts each connection on BBR and
                // exposes a connection-local switch that auth flips to Brutal.
                .congestion_controller_factory(Arc::new(crate::hysteria2::brutal::BrutalConfig))
                // Enable GSO (Generic Segmentation Offload) for better throughput.
                // Salamander gives every datagram its own salt, so a coalesced
                // batch cannot be obfuscated as one buffer -- the offload has to
                // go when obfuscation is on.
                .enable_segmentation_offload(obfs.is_none())
                // Lower initial RTT estimate for faster initial window growth
                .initial_rtt(Duration::from_millis(100));

            // Use 7.5MB socket buffers for high-throughput QUIC (8.625MB on BSD for 15% kernel overhead)
            // https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes
            //
            // SO_REUSEPORT only when there is a second endpoint to share the port with:
            // platforms without it panic rather than fail.
            let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                bind_address.is_ipv6(),
                None,
                Some(bind_address),
                num_endpoints > 1,
                Some(8_625_000),
            )
            .unwrap();

            // `wrap_udp_socket` lives on the Runtime trait.
            use quinn::Runtime as _;
            let runtime = Arc::new(quinn::TokioRuntime);
            let endpoint = match obfs {
                // Obfuscation is a transformation of the bytes leaving and
                // entering the socket, so it wraps quinn's own socket rather
                // than replacing it: everything platform-specific about the UDP
                // path stays where quinn maintains it.
                Some(salamander) => {
                    let inner = runtime
                        .wrap_udp_socket(socket2_socket.into())
                        .expect("wrap the hysteria2 udp socket");
                    quinn::Endpoint::new_with_abstract_socket(
                        quinn::EndpointConfig::default(),
                        Some(server_config),
                        Arc::new(crate::hysteria2_obfs::ObfuscatedUdpSocket::new(
                            inner, salamander,
                        )),
                        runtime,
                    )
                }
                None => quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    socket2_socket.into(),
                    runtime,
                ),
            }
            .unwrap();

            loop {
                let conn = tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    incoming = endpoint.accept() => match incoming {
                        Some(conn) => conn,
                        None => break,
                    },
                };
                let Some(conn) = require_validated_quic_address(conn, "Hysteria2") else {
                    continue;
                };
                let remote_ip = conn.remote_address().ip();
                let Some(handshake_permit) = handshake_gate.enter(Some(remote_ip)) else {
                    debug!(
                        "refusing Hysteria2 peer {remote_ip}: the listener is at its pending-handshake limit"
                    );
                    conn.refuse();
                    continue;
                };
                let pre_auth_deadline = Instant::now() + QUIC_PRE_AUTH_TIMEOUT;
                // Loaded here rather than inside the spawned task: a connection
                // must be pinned to the rules it was *accepted* under, not to
                // whichever generation happened to be current when its task ran.
                // The resolver travels with the rules, so a connection cannot be
                // accepted under one generation and route by another's DNS.
                let (cloned_selector, cloned_resolver) = selector.load();
                let connection_settings = connection_settings.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        cloned_selector,
                        cloned_resolver,
                        conn,
                        connection_settings,
                        handshake_permit,
                        pre_auth_deadline,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }

            // The connections are multiplexed over this endpoint's socket, so
            // letting them finish and giving the port back are the same act.
            crate::quic_server::drain_endpoint(endpoint, bind_address).await;
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_FRAGMENT_CACHE_SIZE, UdpSession, decode_udp_address_length, valid_udp_fragment,
    };
    use crate::address::{Address, NetLocation};
    use lru::LruCache;
    use std::net::Ipv4Addr;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    /// Dropping a session must stop the task it started.
    ///
    /// The reaper cancels explicitly, but it is not the only way a session leaves
    /// the map: a failed forward removes one too, and that is the path an
    /// unreachable destination takes on its very first packet. Constructed by hand
    /// rather than through `start`, because the point is the struct's own lifetime.
    #[tokio::test]
    async fn dropping_a_session_cancels_its_background_task() {
        let parent = CancellationToken::new();
        let token = parent.child_token();

        let session = UdpSession {
            fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
            send_socket: Arc::new(
                tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("bind a loopback socket"),
            ),
            last_location: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 1),
            last_socket_addr: "127.0.0.1:1".parse().unwrap(),
            override_remote_write_address: None,
            last_activity: std::time::Instant::now(),
            cancel_token: token.clone(),
        };

        assert!(!token.is_cancelled(), "a live session is not cancelled");
        drop(session);
        assert!(
            token.is_cancelled(),
            "the spawned loop holds its own clone of this token and would otherwise              keep its socket and 64 KiB buffer alive until the connection ended"
        );
        assert!(
            !parent.is_cancelled(),
            "one session ending must not take the whole connection with it"
        );
    }

    #[test]
    fn udp_address_length_rejects_truncated_multibyte_varints() {
        for first_byte in [0x40, 0x80, 0xc0] {
            let mut datagram = [0u8; 9];
            datagram[8] = first_byte;
            assert_eq!(decode_udp_address_length(&datagram), None);
        }
    }

    #[test]
    fn udp_address_length_accepts_complete_varints() {
        let mut one_byte = [0u8; 9];
        one_byte[8] = 7;
        assert_eq!(decode_udp_address_length(&one_byte), Some((7, 9)));

        let mut eight_byte = [0u8; 16];
        eight_byte[8] = 0xc0;
        eight_byte[15] = 1;
        assert_eq!(decode_udp_address_length(&eight_byte), Some((1, 16)));
    }

    #[test]
    fn udp_fragment_indices_must_be_within_the_declared_count() {
        assert!(!valid_udp_fragment(0, 0));
        assert!(!valid_udp_fragment(1, 1));
        assert!(!valid_udp_fragment(2, 2));
        assert!(valid_udp_fragment(0, 1));
        assert!(valid_udp_fragment(1, 2));
    }
}
