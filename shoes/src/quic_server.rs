use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use quinn::EndpointConfig;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ConnectDecision;
use crate::config::{
    BindLocation, ConfigSelection, ServerConfig, ServerProxyConfig, ServerQuicConfig,
};
use crate::copy_bidirectional::copy_bidirectional;
use crate::dynamic::{
    ConnContext, HandlerSlot, ServerHandle, TrafficMeterStream, UserRegistry, scope_connection,
};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::rustls_config_util::create_server_config;
use crate::socket_util::new_socket2_udp_socket;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::{run_udp_copy, setup_client_tcp_stream};
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
use crate::uuid_util::parse_uuid;

/// How long a cancelled QUIC endpoint waits for its live connections before it
/// drops the socket.
///
/// A QUIC connection is multiplexed over the endpoint's UDP socket, so unlike TCP
/// the port cannot be released while connections are still using it -- letting them
/// finish and freeing the port are the same act. The wait has to be bounded anyway:
/// a client holding a connection open must not be able to keep the port claimed
/// indefinitely and block whatever wants to listen there next.
pub(crate) const QUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

async fn start_quic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    resolver: Arc<dyn Resolver>,
    handler_slot: Arc<HandlerSlot>,
    num_endpoints: usize,
    metered: bool,
    cancel: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    // TODO: consider setting transport config
    //   Arc::get_mut(&mut server_config.transport)
    //     .unwrap()
    //     .max_concurrent_bidi_streams(1024_u32.into())
    //     .max_concurrent_uni_streams(0_u8.into())
    //     .keep_alive_interval(Some(Duration::from_secs(15)))
    //     .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

    let mut join_handles = vec![];
    for _ in 0..num_endpoints {
        let server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());

        let socket2_socket =
            new_socket2_udp_socket(bind_address.is_ipv6(), None, Some(bind_address), true).unwrap();

        let endpoint = quinn::Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;

        let resolver = resolver.clone();
        let handler_slot = handler_slot.clone();
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
                let resolver = resolver.clone();
                // Read once per QUIC connection: every stream it goes on to open
                // is served by the generation that was current when the connection
                // was accepted.
                let server_handler = handler_slot.load();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(resolver, server_handler, conn, metered).await
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
) -> std::io::Result<()> {
    let connection = conn.await?;

    loop {
        let stream = match connection.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("quic connection error: {e}")));
            }
            Ok(s) => s,
        };
        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_streams(cloned_resolver, cloned_handler, stream, metered).await
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
) -> std::io::Result<()> {
    let quic_stream = QuicStream::from(send, recv);

    if !metered {
        return serve_stream(resolver, server_handler, Box::new(quic_stream)).await;
    }

    let conn = ConnContext::new();
    let quic_stream = TrafficMeterStream::new(quic_stream, Arc::clone(&conn));
    scope_connection(
        conn,
        serve_stream(resolver, server_handler, Box::new(quic_stream)),
    )
    .await
}

async fn serve_stream(
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
    quic_stream: Box<dyn AsyncStream>,
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

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            connection_success_response,
            initial_remote_data,
        } => {
            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_tcp_stream(
                    &mut server_stream,
                    proxy_selector,
                    resolver,
                    remote_location.clone(),
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

            let client_need_initial_flush = match initial_remote_data {
                Some(data) => {
                    client_stream.write_all(&data).await?;
                    true
                }
                None => false,
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
                .judge(remote_location.into(), &resolver)
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
        TcpServerSetupResult::AlreadyHandled => {
            // Connection already handled by a spawned task (e.g., Reality fallback)
            Ok(())
        }
    }
}

pub async fn start_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    let ServerConfig {
        bind_location,
        transport,
        quic_settings,
        protocol,
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

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

    // One token for the whole inbound: every accept loop started below selects on
    // it, so the embedder stops all of them together.
    let cancel = CancellationToken::new();
    let mut handle = ServerHandle::new(transport, cancel.clone());

    match protocol {
        ServerProxyConfig::Hysteria2 {
            password,
            udp_enabled,
        } => {
            // TODO: hash password instead of passing directly
            let hysteria2_password: Arc<str> = password.into();

            for bind_address in bind_addresses.into_iter() {
                let hysteria2_handles = crate::hysteria2_server::start_hysteria2_server(
                    bind_address,
                    quic_server_config.clone(),
                    hysteria2_password.clone(),
                    client_proxy_selector.clone(),
                    resolver.clone(),
                    num_endpoints,
                    udp_enabled,
                    cancel.clone(),
                )
                .await?;
                // No handler slot is recorded: hysteria2 authenticates inside its
                // own accept loop rather than through a `TcpServerHandler`, so
                // there is nothing here for a reload to swap.
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
            let uuid: Arc<[u8]> = parse_uuid(&uuid)?.into();
            let password: Arc<str> = password.into();
            for bind_address in bind_addresses.into_iter() {
                let tuic_handles = crate::tuic_server::start_tuic_server(
                    bind_address,
                    quic_server_config.clone(),
                    uuid.clone(),
                    password.clone(),
                    client_proxy_selector.clone(),
                    resolver.clone(),
                    num_endpoints,
                    zero_rtt_handshake,
                    cancel.clone(),
                )
                .await?;
                // As above: nothing to swap.
                for listener in tuic_handles {
                    handle.push_listener(listener);
                }
                handle.push_address(bind_address);
            }
        }
        tcp_protocol => {
            for bind_address in bind_addresses.into_iter() {
                // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
                let handler_slot = handle.slot_for_ip(bind_address.ip(), || {
                    create_tcp_server_handler(
                        tcp_protocol.clone(),
                        &client_proxy_selector,
                        &resolver,
                        Some(bind_address.ip()),
                        users.as_ref(),
                    )
                    .into()
                });
                let quic_handles = start_quic_server(
                    bind_address,
                    quic_server_config.clone(),
                    resolver.clone(),
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
