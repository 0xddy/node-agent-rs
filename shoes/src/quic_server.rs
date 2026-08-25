use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{debug, error};
use quinn::EndpointConfig;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ConnectDecision;
use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ServerQuicConfig,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::dynamic::{
    ConnContext, HandlerSlot, ServerHandle, StaticUserRegistry, TrafficMeterStream, UserRegistry,
    scope_connection_until_cancelled,
};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::rustls_config_util::create_server_config;
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp::handshake_gate::{
    HandshakeGate, HandshakePermit, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::{
    run_udp_copy, setup_client_tcp_stream_with_metadata, sniff_tcp_after_success_response,
};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler_with_replay_state;

/// How long a cancelled QUIC endpoint waits for its live connections before it
/// drops the socket.
///
/// A QUIC connection is multiplexed over the endpoint's UDP socket, so unlike TCP
/// the port cannot be released while connections are still using it -- letting them
/// finish and freeing the port are the same act. The wait has to be bounded anyway:
/// a client holding a connection open must not be able to keep the port claimed
/// indefinitely and block whatever wants to listen there next.
pub(crate) const QUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// The absolute lifetime of an application-layer-unauthenticated QUIC peer.
///
/// This outer deadline starts when a Retry-validated Incoming is charged to a gate
/// and covers the transport handshake plus H3/application setup. Native protocols
/// retain their shorter application-authentication timer inside this ceiling. QUIC
/// activity, including PING frames, cannot reset either deadline.
pub(crate) const QUIC_PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time spent on the QUIC transport handshake after Retry has validated
/// the peer's address.
///
/// Application protocols keep their own authentication window inside the outer
/// pre-auth deadline. A shorter transport-only window prevents a real but silent
/// peer from holding one listener admission for the transport's 30-60 second idle
/// timeout without ever reaching application authentication.
pub(crate) const QUIC_TRANSPORT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Live generic-QUIC transports admitted by one listener.
///
/// Unlike the stream gate, this is deliberately an active-connection quota rather
/// than a pending-handshake quota. Generic QUIC has no connection-level identity:
/// every bidi stream can authenticate independently (or use an unauthenticated
/// protocol), so releasing this quota after one cheap stream would allow unlimited
/// empty transports kept alive with QUIC PING frames. These names stay separate from
/// the handshake constants so their different lifetime and sizing are explicit.
const MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS: usize = 1024;
const MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS_PER_SOURCE: usize = 64;

/// Error codes used only by the generic QUIC transport.
///
/// Zero means success/application shutdown in a number of protocols. Refusing work
/// because a resource or authentication deadline was exceeded must be observable as
/// an error by the peer rather than looking like a clean end of stream.
const QUIC_ERR_PRE_AUTH_TIMEOUT: u32 = 1;
const QUIC_ERR_HANDSHAKE_LIMIT: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IncomingAddressAction {
    Accept,
    Retry,
    Refuse,
}

fn incoming_address_action(validated: bool, may_retry: bool) -> IncomingAddressAction {
    if validated {
        IncomingAddressAction::Accept
    } else if may_retry {
        IncomingAddressAction::Retry
    } else {
        // Quinn currently guarantees that an unvalidated Incoming may be retried.
        // Keep this branch defensive: accepting here after an API/implementation
        // change would charge a spoofable source address to the listener gate.
        IncomingAddressAction::Refuse
    }
}

/// Require QUIC address validation before allocating a connection or gate permit.
///
/// A successful Retry consumes `incoming`; the client's token-bearing Initial will
/// arrive through `Endpoint::accept` as a new, validated Incoming. A theoretically
/// impossible Retry failure returns the original Incoming, which is explicitly
/// refused rather than accidentally accepted without validation.
pub(crate) fn require_validated_quic_address(
    incoming: quinn::Incoming,
    protocol: &str,
) -> Option<quinn::Incoming> {
    let remote = incoming.remote_address();
    match incoming_address_action(incoming.remote_address_validated(), incoming.may_retry()) {
        IncomingAddressAction::Accept => Some(incoming),
        IncomingAddressAction::Retry => {
            debug!("requiring QUIC address validation from {remote} before {protocol} admission");
            if let Err(error) = incoming.retry() {
                debug!(
                    "QUIC Retry unexpectedly unavailable for {remote}; refusing {protocol} peer"
                );
                error.into_incoming().refuse();
            }
            None
        }
        IncomingAddressAction::Refuse => {
            debug!("refusing unvalidated {protocol} peer {remote}: QUIC Retry is unavailable");
            incoming.refuse();
            None
        }
    }
}

/// Pending protocol handshakes carried by one generic QUIC connection.
///
/// Generic QUIC differs from Hysteria2 and TUIC: the QUIC connection itself has no
/// application authentication, and every bidi stream performs an independent
/// configured-protocol handshake. Its connection-lifetime permit is therefore kept
/// separately by `process_connection`, while every pending stream takes a permit
/// from this state. Keeping the two gates separate matters: a source legitimately at
/// its connection ceiling must still be able to authenticate a stream on those
/// connections rather than deadlocking against its own connection permits.
struct QuicHandshakeState {
    stream_gate: Arc<HandshakeGate>,
    source: IpAddr,
    first_handshake_completed: AtomicBool,
    first_handshake_notify: Notify,
}

impl QuicHandshakeState {
    fn new(stream_gate: Arc<HandshakeGate>, source: IpAddr) -> Arc<Self> {
        Arc::new(Self {
            stream_gate,
            source,
            first_handshake_completed: AtomicBool::new(false),
            first_handshake_notify: Notify::new(),
        })
    }

    fn enter_stream(self: &Arc<Self>) -> Option<QuicStreamHandshakePermit> {
        self.stream_gate
            .enter(Some(self.source))
            .map(|permit| QuicStreamHandshakePermit {
                state: self.clone(),
                _permit: permit,
            })
    }

    fn first_handshake_completed(&self) -> bool {
        self.first_handshake_completed.load(Ordering::Acquire)
    }
}

async fn first_handshake_completed_before_deadline(
    state: Arc<QuicHandshakeState>,
    deadline: Instant,
) -> bool {
    loop {
        // `notify_one` stores a permit when it races this future before polling, so
        // constructing the waiter before the acquire-load cannot lose completion.
        let completed = state.first_handshake_notify.notified();
        if state.first_handshake_completed() {
            return true;
        }
        tokio::select! {
            () = completed => {}
            () = sleep_until(deadline) => return state.first_handshake_completed(),
        }
    }
}

/// One generic QUIC stream's place in the pending-handshake budget.
///
/// `complete` is deliberately explicit. Dropping before it means the configured
/// protocol handshake failed or was cancelled, so only a real successful setup can
/// disarm the connection's absolute pre-auth deadline.
struct QuicStreamHandshakePermit {
    state: Arc<QuicHandshakeState>,
    _permit: HandshakePermit,
}

impl QuicStreamHandshakePermit {
    fn complete(self) {
        let was_complete = self
            .state
            .first_handshake_completed
            .swap(true, Ordering::AcqRel);
        if !was_complete {
            self.state.first_handshake_notify.notify_one();
        }
        // `self` then drops the independent stream permit. The connection permit is
        // owned by `process_connection`, whose completion waiter releases it.
    }
}

async fn start_quic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    // No resolver: this loop takes it from the slot, with the handler, so a
    // connection cannot mix one generation's rules with another's DNS.
    handler_slot: Arc<HandlerSlot>,
    num_endpoints: usize,
    metered: bool,
    cancel: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = vec![];
    // Connections and stream handshakes are different resources and need independent
    // shares. Sharing each gate across the endpoint fan-out prevents `num_endpoints`
    // from multiplying either ceiling.
    let connection_gate = HandshakeGate::new(
        MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS,
        MAX_ACTIVE_GENERIC_QUIC_CONNECTIONS_PER_SOURCE,
    );
    let stream_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);
    for _ in 0..num_endpoints {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());
        // A peer cannot create more simultaneous bidi streams on one connection than
        // one source is allowed to hold in the listener-wide stream-handshake gate.
        // Generic QUIC has no use for peer-opened unidirectional streams.
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_bidi_streams((MAX_PENDING_PER_SOURCE as u32).into())
            .max_concurrent_uni_streams(0_u8.into());

        // Only ask for SO_REUSEPORT when there is actually a second endpoint to share
        // the port with; a single endpoint does not need it, and platforms that lack
        // it panic rather than fail.
        let socket2_socket = new_socket2_udp_socket(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            num_endpoints > 1,
        )
        .unwrap();

        let endpoint = quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;

        let handler_slot = handler_slot.clone();
        let connection_gate = connection_gate.clone();
        let stream_gate = stream_gate.clone();
        let cancel = cancel.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                let conn = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    incoming = endpoint.accept() => match incoming {
                        Some(conn) => conn,
                        // The endpoint closed on its own.
                        None => break,
                    },
                };
                let Some(conn) = require_validated_quic_address(conn, "generic QUIC") else {
                    continue;
                };
                let remote_ip = conn.remote_address().ip();
                let Some(connection_permit) = connection_gate.enter(Some(remote_ip)) else {
                    debug!(
                        "refusing QUIC peer {remote_ip}: the listener is at its connection limit"
                    );
                    conn.refuse();
                    continue;
                };
                let pre_auth_deadline = Instant::now() + QUIC_PRE_AUTH_TIMEOUT;
                let handshake_state = QuicHandshakeState::new(stream_gate.clone(), remote_ip);
                // Read once per QUIC connection: every stream it goes on to open
                // is served by the generation that was current when the connection
                // was accepted -- the resolver included, so its rules and its DNS
                // are always from the same reload.
                let (server_handler, resolver) = handler_slot.load();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        resolver,
                        server_handler,
                        conn,
                        metered,
                        handshake_state,
                        connection_permit,
                        pre_auth_deadline,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }

            drain_endpoint(endpoint, bind_address).await;
        });

        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

/// Stop taking new QUIC connections on `endpoint` and let the live ones finish.
///
/// Bounded by [`QUIC_DRAIN_TIMEOUT`]; see its documentation for why the port cannot
/// simply be released the way a TCP listener's is.
pub(crate) async fn drain_endpoint(endpoint: quinn::Endpoint, bind_address: SocketAddr) {
    // quinn refuses an incoming handshake when the endpoint has no server config,
    // which is how it spells "stop accepting" -- it is documented to affect new
    // connections only, so the live ones are untouched.
    endpoint.set_server_config(None);
    if tokio::time::timeout(QUIC_DRAIN_TIMEOUT, endpoint.wait_idle())
        .await
        .is_err()
    {
        debug!(
            "quic endpoint on {bind_address} still had {} live connection(s) after \
             {QUIC_DRAIN_TIMEOUT:?}; closing anyway",
            endpoint.open_connections()
        );
    }
}

async fn process_connection(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    conn: quinn::Incoming,
    metered: bool,
    handshake_state: Arc<QuicHandshakeState>,
    connection_permit: HandshakePermit,
    pre_auth_deadline: Instant,
) -> std::io::Result<()> {
    // Generic QUIC has no connection-level user identity: every stream performs an
    // independent configured-protocol handshake. Keep the separate active-transport
    // quota until the connection ends so one cheap successful stream cannot leave an
    // unlimited pool of empty, PING-kept-alive transports.
    let _connection_permit = connection_permit;
    let transport_deadline = std::cmp::min(
        pre_auth_deadline,
        Instant::now() + QUIC_TRANSPORT_HANDSHAKE_TIMEOUT,
    );
    let connection = match timeout_at(transport_deadline, conn).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "generic QUIC transport handshake exceeded the pre-auth deadline",
            ));
        }
    };

    let mut pre_auth_completion = Box::pin(first_handshake_completed_before_deadline(
        handshake_state.clone(),
        pre_auth_deadline,
    ));
    let mut pre_auth_pending = true;

    loop {
        if pre_auth_pending && handshake_state.first_handshake_completed() {
            pre_auth_pending = false;
        }

        let accepted = tokio::select! {
            completed = &mut pre_auth_completion, if pre_auth_pending => {
                // A stream can complete without opening another stream to wake
                // `accept_bi`; Notify releases the admission immediately rather
                // than retaining it until the absolute deadline.
                if completed {
                    pre_auth_pending = false;
                    continue;
                }
                connection.close(QUIC_ERR_PRE_AUTH_TIMEOUT.into(), b"pre-auth timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "generic QUIC first protocol handshake exceeded the pre-auth deadline",
                ));
            }
            accepted = connection.accept_bi() => accepted,
        };

        let (mut send, mut recv) = match accepted {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("quic connection error: {e}")));
            }
            Ok(s) => s,
        };
        let Some(handshake_permit) = handshake_state.enter_stream() else {
            debug!(
                "refusing a stream from {}: the listener is at its pending-handshake limit",
                connection.remote_address().ip()
            );
            let _ = send.reset(QUIC_ERR_HANDSHAKE_LIMIT.into());
            let _ = recv.stop(QUIC_ERR_HANDSHAKE_LIMIT.into());
            continue;
        };
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) = process_streams(
                cloned_resolver,
                cloned_handler,
                (send, recv),
                metered,
                handshake_permit,
            )
            .await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }

    Ok(())
}

/// Handle one QUIC bidirectional stream, counting its traffic if the inbound is
/// metered.
///
/// Each bidi stream carries its own protocol handshake, so each one authenticates
/// separately and is counted as its own connection even when several share a QUIC
/// connection.
///
/// What gets counted here is stream bytes, not datagram bytes: quinn owns the
/// framing, the packet encryption and the UDP socket, and a datagram on that socket
/// can carry frames belonging to several streams or to no stream at all. So a QUIC
/// inbound's figures exclude QUIC's own per-packet overhead, where a TCP inbound's
/// include TLS's.
async fn process_streams(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    (send, recv): (quinn::SendStream, quinn::RecvStream),
    metered: bool,
    handshake_permit: QuicStreamHandshakePermit,
) -> std::io::Result<()> {
    let quic_stream = QuicStream::from(send, recv);

    if !metered {
        return serve_stream(
            resolver,
            server_handler,
            Box::new(quic_stream),
            handshake_permit,
        )
        .await;
    }

    let conn = ConnContext::new();
    let quic_stream = TrafficMeterStream::new(quic_stream, Arc::clone(&conn));
    scope_connection_until_cancelled(
        conn,
        serve_stream(
            resolver,
            server_handler,
            Box::new(quic_stream),
            handshake_permit,
        ),
    )
    .await
}

async fn serve_stream(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    quic_stream: Box<dyn AsyncStream>,
    handshake_permit: QuicStreamHandshakePermit,
) -> std::io::Result<()> {
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        server_handler.setup_server_stream(quic_stream),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            ));
        }
    };

    finish_stream_handshake(&setup_result, handshake_permit);

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            mut connection_success_response,
            initial_remote_data,
        } => {
            let mut replay = initial_remote_data.map(Vec::from).unwrap_or_default();
            let sniffed = sniff_tcp_after_success_response(
                &mut server_stream,
                proxy_selector.needs_tcp_sniff(),
                &mut connection_success_response,
                &mut replay,
            )
            .await?;
            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_tcp_stream_with_metadata(
                    &mut server_stream,
                    proxy_selector,
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

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = if replay.is_empty() {
                false
            } else {
                client_stream.write_all(&replay).await?;
                true
            };

            let copy_result = copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
                server_need_initial_flush,
                client_need_initial_flush,
            )
            .await;

            let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } => {
            let action = proxy_selector
                .judge_udp(remote_location.into(), &resolver)
                .await?;
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    run_udp_copy(
                        server_stream,
                        client_stream,
                        server_need_initial_flush,
                        false,
                    )
                    .await
                }
                ConnectDecision::Block => Ok(()),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Routes each packet based on its destination
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Routes each session based on its destination
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::AlreadyHandled
        | TcpServerSetupResult::UnauthenticatedFallbackHandled => {
            // Connection already handled by a spawned task (e.g., Reality fallback)
            Ok(())
        }
    }
}

fn finish_stream_handshake(
    setup_result: &TcpServerSetupResult,
    handshake_permit: QuicStreamHandshakePermit,
) {
    if setup_result.completes_protocol_handshake() {
        // This stream completed its configured protocol handshake. Release the
        // stream permit and notify the connection admission waiter immediately.
        handshake_permit.complete();
    } else {
        // A camouflage/fallback task owns the stream after failed or deferred proxy
        // authentication. It no longer consumes a stream-handshake slot, but it
        // must not authenticate the whole multiplexed QUIC connection.
        drop(handshake_permit);
    }
}

pub async fn start_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    // One token for the whole inbound: every accept loop started below selects on
    // it, so the embedder stops all of them together.
    let cancel = CancellationToken::new();

    // Created here, before the config is taken apart, so it can record what the
    // endpoint below is about to bake in -- the certificate and the ALPN list, which
    // a reload cannot rebuild. `check_reload` compares against these.
    let mut handle = ServerHandle::new(config.transport.clone(), cancel.clone());
    handle.record_listener_settings(&config);
    let replay_state = handle.replay_state();

    let ServerConfig {
        bind_location,
        quic_settings,
        protocol,
        sniff,
        rules,
        ..
    } = config;

    println!("Starting {} QUIC server at {}", &protocol, &bind_location);

    // See `start_tcp_servers`: only an inbound whose users the caller manages has
    // counters anyone can read.
    let metered = users.is_some();

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // A direct entry must always exist
    assert!(!rules.is_empty());

    let bind_addresses = match bind_location {
        // TODO: switch to non-blocking resolve?
        BindLocation::Address(addresses) => {
            let mut bind_addresses = Vec::new();
            for address in addresses.into_vec() {
                bind_addresses.extend(address.to_socket_addrs()?);
            }
            bind_addresses
        }
        BindLocation::Path(_) => {
            return Err(std::io::Error::other(
                "Cannot listen on path, QUIC does not have unix domain socket support",
            ));
        }
    };

    let ServerQuicConfig {
        cert,
        key,
        client_ca_certs,
        alpn_protocols,
        client_fingerprints,
        num_endpoints,
    } = quic_settings.unwrap();

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let mut processed_ca_certs = Vec::with_capacity(client_ca_certs.len());
    for cert in client_ca_certs.into_iter() {
        processed_ca_certs.push(cert.as_bytes().to_vec());
    }

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        processed_ca_certs,
        &alpn_protocols.into_vec(),
        &client_fingerprints.into_vec(),
    ));

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|e| std::io::Error::other(format!("invalid QUIC server config: {e}")))?;

    let quic_server_config = Arc::new(quic_server_config);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
        rules.clone(),
        resolver.clone(),
        sniff,
    ));

    // Kept for the two arms below, which record what their accept loops bake in so
    // that a later reload can refuse to change it. The `match` consumes `protocol`.
    let started_protocol = protocol.clone();

    match protocol {
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
            up_mbps,
            down_mbps,
            obfs,
            masquerade,
        } => {
            let obfs = obfs.map(|obfs| match obfs {
                crate::config::Hysteria2ObfsConfig::Salamander { password } => {
                    crate::hysteria2_obfs::Salamander::new(&password)
                }
            });
            // Hysteria2 sends its password in cleartext in a header, so the whole of
            // authentication is one registry lookup. An injected registry takes it
            // over; without one, the config's own password becomes a one-user
            // registry, which is the same comparison this used to do inline.
            let hysteria2_users = match users.as_ref() {
                Some(users) => users.clone(),
                None => StaticUserRegistry::single_password(&password),
            };
            let masquerade = Arc::new(crate::hysteria2_masquerade::Hysteria2Masquerade::new(
                masquerade.as_ref(),
            )?);

            for bind_address in bind_addresses.into_iter() {
                // A rule slot rather than a handler slot: hysteria2 authenticates in
                // its own accept loop rather than through a `TcpServerHandler`, so
                // the rules are the only thing above the socket a reload can reach.
                let selector_slot = handle.push_selector(
                    client_proxy_selector.clone(),
                    &resolver,
                    &started_protocol,
                    users.is_some(),
                );
                let hysteria2_handles = crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config.clone(),
                    hysteria2_users.clone(),
                    metered,
                    selector_slot,
                    num_endpoints,
                    udp_enabled,
                    up_mbps,
                    down_mbps,
                    obfs.clone(),
                    masquerade.clone(),
                    cancel.clone(),
                )
                .await?;
                for listener in hysteria2_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
        ServerProxyConfig::TuicV5 {
            uuid,
            password,
            zero_rtt_handshake,
        } => {
            // TUIC's credential is two values at once: the uuid names the user in
            // cleartext and the password keys the token beside it. An injected registry
            // answers for both; without one, the config's own pair becomes a one-user
            // registry, which is the same comparison this used to do inline.
            let tuic_users = match users.as_ref() {
                Some(users) => users.clone(),
                None => StaticUserRegistry::single_tuic(&uuid, &password)?,
            };

            for bind_address in bind_addresses.into_iter() {
                // As above: rules only.
                let selector_slot = handle.push_selector(
                    client_proxy_selector.clone(),
                    &resolver,
                    &started_protocol,
                    users.is_some(),
                );
                let tuic_handles = crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config.clone(),
                    tuic_users.clone(),
                    metered,
                    selector_slot,
                    num_endpoints,
                    zero_rtt_handshake,
                    cancel.clone(),
                )
                .await?;
                for listener in tuic_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
        tcp_protocol => {
            for bind_address in bind_addresses.into_iter() {
                // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
                let handler_slot = handle.slot_for_ip(bind_address.ip(), &resolver, || {
                    create_tcp_server_handler_with_replay_state(
                        tcp_protocol.clone(),
                        &client_proxy_selector,
                        &resolver,
                        Some(bind_address.ip()),
                        users.as_ref(),
                        &replay_state,
                    )
                    .into()
                });
                let quic_handles = start_quic_server(
                    bind_address,
                    quic_server_config.clone(),
                    handler_slot,
                    num_endpoints,
                    metered,
                    cancel.clone(),
                )
                .await?;

                for listener in quic_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::{
        IncomingAddressAction, QUIC_ERR_HANDSHAKE_LIMIT, QUIC_ERR_PRE_AUTH_TIMEOUT,
        QUIC_PRE_AUTH_TIMEOUT, QUIC_TRANSPORT_HANDSHAKE_TIMEOUT, QuicHandshakeState,
        finish_stream_handshake, first_handshake_completed_before_deadline,
        incoming_address_action,
    };
    use crate::tcp::handshake_gate::{HandshakeGate, MAX_PENDING_PER_SOURCE};
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::time::{Instant, advance};

    fn source(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn unvalidated_incoming_is_retried_before_admission() {
        assert_eq!(
            incoming_address_action(false, true),
            IncomingAddressAction::Retry
        );
        assert_eq!(
            incoming_address_action(false, false),
            IncomingAddressAction::Refuse,
            "an API change that makes Retry unavailable must fail closed"
        );
        assert_eq!(
            incoming_address_action(true, false),
            IncomingAddressAction::Accept
        );
        assert_eq!(
            incoming_address_action(true, true),
            IncomingAddressAction::Accept,
            "a token already validated the address even when another Retry is legal"
        );
    }

    #[tokio::test]
    async fn stream_success_disarms_deadline_but_keeps_active_connection_quota() {
        let connection_gate = HandshakeGate::new(1, 1);
        let stream_gate = HandshakeGate::new(1, 1);
        let ip = source(1);
        let connection_permit = connection_gate
            .enter(Some(ip))
            .expect("admit the QUIC connection");
        let state = QuicHandshakeState::new(stream_gate.clone(), ip);
        let completion_state = state.clone();
        let completion = tokio::spawn(first_handshake_completed_before_deadline(
            completion_state,
            Instant::now() + Duration::from_secs(60),
        ));

        state
            .enter_stream()
            .expect("the independent stream gate is available")
            .complete();
        assert!(
            state.first_handshake_completed(),
            "success disarms only the absolute pre-auth deadline"
        );
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "completing a stream returns its stream-handshake permit"
        );
        assert!(completion.await.unwrap());
        assert!(
            connection_gate.enter(Some(source(2))).is_none(),
            "a stream cannot release the independent active-transport quota"
        );

        drop(connection_permit);
        assert!(connection_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn a_failed_stream_releases_only_its_stream_permit() {
        let stream_gate = HandshakeGate::new(1, 1);
        let ip = source(1);
        let state = QuicHandshakeState::new(stream_gate.clone(), ip);

        let failed = state.enter_stream().expect("first stream");
        assert!(stream_gate.enter(Some(source(2))).is_none());
        drop(failed);
        assert!(
            !state.first_handshake_completed(),
            "failure must not disarm the connection deadline"
        );
        assert!(stream_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn every_concurrent_stream_has_a_per_source_handshake_charge() {
        let stream_gate = HandshakeGate::new(8, 2);
        let ip = source(1);
        let state = QuicHandshakeState::new(stream_gate.clone(), ip);

        let first = state.enter_stream().expect("first stream");
        let second = state.enter_stream().expect("second stream");
        assert!(
            state.enter_stream().is_none(),
            "multiplexing cannot exceed the source's handshake share"
        );
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "one noisy QUIC peer does not consume another source's share"
        );

        second.complete();
        assert!(state.enter_stream().is_some());
        drop(first);
    }

    #[tokio::test(start_paused = true)]
    async fn absolute_deadline_fires_without_a_successful_stream() {
        let state = QuicHandshakeState::new(HandshakeGate::new(1, 1), source(1));
        let deadline = Instant::now() + Duration::from_secs(60);
        let waiter = tokio::spawn(first_handshake_completed_before_deadline(state, deadline));
        tokio::task::yield_now().await;

        advance(Duration::from_secs(60)).await;
        assert!(!waiter.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn first_success_disarms_the_absolute_deadline() {
        let state = QuicHandshakeState::new(HandshakeGate::new(1, 1), source(1));
        let deadline = Instant::now() + Duration::from_secs(60);
        let waiter = tokio::spawn(first_handshake_completed_before_deadline(
            state.clone(),
            deadline,
        ));
        tokio::task::yield_now().await;

        state.enter_stream().expect("stream permit").complete();
        tokio::task::yield_now().await;
        assert!(
            waiter.is_finished(),
            "completion must wake admission immediately rather than at the deadline"
        );
        assert!(waiter.await.unwrap());
    }

    #[test]
    fn unauthenticated_fallback_does_not_complete_the_connection_handshake() {
        let stream_gate = HandshakeGate::new(1, 1);
        let state = QuicHandshakeState::new(stream_gate.clone(), source(1));
        let permit = state.enter_stream().expect("fallback stream permit");

        finish_stream_handshake(
            &TcpServerSetupResult::UnauthenticatedFallbackHandled,
            permit,
        );

        assert!(!state.first_handshake_completed());
        assert!(
            stream_gate.enter(Some(source(2))).is_some(),
            "the handed-off stream no longer consumes a pending stream slot"
        );
    }

    #[test]
    fn authenticated_background_handoff_completes_the_connection_handshake() {
        let stream_gate = HandshakeGate::new(1, 1);
        let state = QuicHandshakeState::new(stream_gate.clone(), source(1));
        let permit = state.enter_stream().expect("authenticated stream permit");

        finish_stream_handshake(&TcpServerSetupResult::AlreadyHandled, permit);

        assert!(state.first_handshake_completed());
        assert!(stream_gate.enter(Some(source(2))).is_some());
    }

    #[test]
    fn generic_transport_limits_use_error_codes_and_match_the_stream_share() {
        assert_ne!(QUIC_ERR_PRE_AUTH_TIMEOUT, 0);
        assert_ne!(QUIC_ERR_HANDSHAKE_LIMIT, 0);
        assert_eq!(MAX_PENDING_PER_SOURCE as u32, 64);
        assert!(QUIC_TRANSPORT_HANDSHAKE_TIMEOUT < QUIC_PRE_AUTH_TIMEOUT);
    }
}
