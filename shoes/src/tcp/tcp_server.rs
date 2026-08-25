use std::net::SocketAddr;
// NOTE(shoes-engine): only `run_unix_server` names this type, and that is
// unix-only, so an unconditional import is unused everywhere else.
#[cfg(target_family = "unix")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::handshake_gate::{
    HandshakeGate, HandshakePermit, MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE,
};
use super::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;
use super::tcp_server_handler_factory::create_tcp_server_handler_with_replay_state;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::{AsyncShutdownMessageExt, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::dynamic::{
    ConnContext, HandlerSlot, ServerHandle, TrafficMeterStream, UserRegistry,
    scope_connection_until_cancelled,
};
use crate::quic_server::start_quic_servers;
use crate::resolver::Resolver;
use crate::routing::protocol::{
    SniffedTcpMetadata, TcpPrefixClassification, classify_tcp_prefix, sniff_tcp,
};
use crate::routing::{ServerStream, run_udp_routing};
use crate::socket_util::{new_tcp_listener, set_tcp_keepalive};
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};
#[cfg(unix)]
use crate::tun::start_tun_server;
use crate::util::write_all;

async fn run_tcp_server(
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    handler_slot: Arc<HandlerSlot>,
    metered: bool,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    let listener = new_tcp_listener(bind_address, 4096, None)?;
    // One budget per listener, so a flood against this bind cannot starve another.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);

    loop {
        // Returning here drops the listener, which is what frees the port. The
        // connections accepted so far were spawned off this loop and keep running:
        // they hold their own handler, so they finish under the rules they started
        // with. That is the smooth handover.
        let (stream, addr) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("no longer accepting on {bind_address}");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept failed: {e}");
                    continue;
                }
            },
        };

        // Taken before anything is spent on this connection, and released again the
        // moment its handshake resolves. Dropping `stream` here is the refusal: the
        // peer sees a closed connection and this listener spends nothing further on
        // an address that is already holding as much of the budget as it may.
        let Some(permit) = handshake_gate.enter(Some(addr.ip())) else {
            debug!(
                "refusing {}: the listener is at its pending-handshake limit",
                addr.ip()
            );
            continue;
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        // Read once, here: this connection is pinned to the generation of rules,
        // protocol settings *and DNS* that were current when it was accepted. The
        // resolver comes out of the slot rather than from this loop's own capture,
        // because a reload can hand the rebuilt handler a different one.
        let (cloned_handler, cloned_resolver) = handler_slot.load();
        tokio::spawn(async move {
            if let Err(e) =
                process_metered_stream(stream, metered, cloned_handler, cloned_resolver, permit)
                    .await
            {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

#[cfg(target_family = "unix")]
async fn run_unix_server(
    path_buf: PathBuf,
    handler_slot: Arc<HandlerSlot>,
    metered: bool,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(&path_buf).await;
    }

    let listener = crate::socket_util::new_unix_listener(path_buf, 4096)?;
    // See `run_tcp_server`. A unix peer has no address to hold a share of, so only
    // the total applies here.
    let handshake_gate = HandshakeGate::new(MAX_PENDING_HANDSHAKES, MAX_PENDING_PER_SOURCE);

    loop {
        // See `run_tcp_server`.
        let (stream, addr) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!("no longer accepting on the unix socket");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    error!("Accept failed: {e:?}");
                    continue;
                }
            },
        };

        // See `run_tcp_server`.
        let Some(permit) = handshake_gate.enter(None) else {
            debug!("refusing a unix peer: at the pending-handshake limit");
            continue;
        };

        // See `run_tcp_server`.
        let (cloned_handler, cloned_resolver) = handler_slot.load();
        tokio::spawn(async move {
            if let Err(e) =
                process_metered_stream(stream, metered, cloned_handler, cloned_resolver, permit)
                    .await
            {
                error!("{addr:?} finished with error: {e:?}");
            } else {
                debug!("{addr:?} finished successfully");
            }
        });
    }
}

/// Handle one accepted connection, counting its traffic if the inbound is metered.
///
/// The meter goes on before any protocol touches the stream, so it sees the bytes
/// as they are on the wire. It cannot know whose they are yet -- the credential is
/// still several reads away -- so the connection stays anonymous until a handler
/// calls `bind_connection_user`, which finds this connection through the task local
/// scope installed here.
async fn process_metered_stream<AS>(
    stream: AS,
    metered: bool,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    permit: HandshakePermit,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    if !metered {
        return process_stream(stream, server_handler, resolver, permit).await;
    }

    let conn = ConnContext::new();
    let stream = TrafficMeterStream::new(stream, Arc::clone(&conn));
    scope_connection_until_cancelled(
        conn,
        process_stream(stream, server_handler, resolver, permit),
    )
    .await
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

/// Run one accepted connection to completion.
///
/// `permit` is this connection's place in the listener's pending-handshake budget.
/// It is taken as a value rather than borrowed because the point is to release it
/// early: it is dropped as soon as the handshake below resolves, not when the
/// connection ends. See [`handshake_gate`](super::handshake_gate).
pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    permit: HandshakePermit,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
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

    // The handshake is over, so the budget it was charged against is no longer the
    // right one to hold: everything past this point is either an authenticated
    // connection, bounded by its own user's ceiling, or a protocol that does not
    // authenticate at all. Holding on would turn a bound on handshakes into a bound
    // on connections, which is exactly the shape this gate exists to avoid. The
    // early returns above release it too, by dropping it on the way out.
    drop(permit);

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
                write_all(&mut server_stream, &data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = if replay.is_empty() {
                false
            } else {
                write_all(&mut client_stream, &replay).await?;
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
                ConnectDecision::Block => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Blocked bidirectional udp forward",
                )),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each packet is routed based on its destination
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
            // Per-destination routing: each session is routed based on its destination
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
            // Connection is being handled by a spawned task (e.g., Reality fallback).
            // Nothing more to do here.
            Ok(())
        }
    }
}

/// Sniff application bytes without deadlocking response-gated inbound protocols.
///
/// SOCKS5, HTTP CONNECT and Snell clients do not send application data until the
/// inbound acknowledges their tunnel request. When a protocol rule needs sniffed
/// metadata, that acknowledgement therefore has to be written *and flushed* before
/// [`sniff_tcp`] is allowed to read. Taking the response here also prevents the
/// normal post-connect path from sending it twice. Protocols without a response and
/// handshakes which already supplied early data retain the same replay-safe sniffer.
pub(crate) async fn sniff_tcp_after_success_response(
    server_stream: &mut Box<dyn AsyncStream>,
    should_sniff: bool,
    connection_success_response: &mut Option<Box<[u8]>>,
    replay: &mut Vec<u8>,
) -> std::io::Result<Option<SniffedTcpMetadata>> {
    if !should_sniff {
        return Ok(None);
    }

    // A complete handshake-carried payload can be classified without client I/O,
    // so preserve the usual "success after outbound connect" timing in that case.
    // Only the NeedMore branch can block on a response-gated client.
    match classify_tcp_prefix(replay) {
        TcpPrefixClassification::Matched(metadata) => return Ok(Some(metadata)),
        TcpPrefixClassification::NoMatch => return Ok(None),
        TcpPrefixClassification::NeedMore => {}
    }

    if let Some(response) = connection_success_response.take() {
        write_all(server_stream, &response).await?;
        // This flush cannot be deferred to copy_bidirectional: the client may be
        // waiting for these bytes before it produces anything for the sniffer.
        server_stream.flush().await?;
    }

    sniff_tcp(server_stream, replay).await
}

pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    setup_client_tcp_stream_with_metadata(
        server_stream,
        client_proxy_selector,
        resolver,
        remote_location,
        None,
    )
    .await
}

pub(crate) async fn setup_client_tcp_stream_with_metadata(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    metadata: Option<SniffedTcpMetadata>,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = match metadata {
        Some(metadata) => {
            client_proxy_selector
                .judge_sniffed_tcp(
                    remote_location.into(),
                    &resolver,
                    metadata.protocol,
                    metadata.domain,
                )
                .await?
        }
        None => {
            client_proxy_selector
                .judge_tcp(remote_location.into(), &resolver)
                .await?
        }
    };

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                server_stream.write_all(&data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(
        server_stream.shutdown_message(),
        client_stream.shutdown_message()
    );

    copy_result
}

pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    start_servers_with_users(config, resolver, None)
        .await
        .map(ServerHandle::into_listeners)
}

/// Start one inbound, authenticating against a caller-supplied user registry.
///
/// This is the entry point for an embedder that manages users itself. When `users`
/// is `Some`, it is the sole authority for this inbound and the credentials in the
/// protocol config are not consulted, so an inbound whose registry is empty rejects
/// every client until users are added to it. When `users` is `None` each protocol
/// handler builds a `StaticUserRegistry` from its own config section instead, which
/// is what [`start_servers`] does and what a config file expects.
///
/// The returned [`ServerHandle`] is what makes the inbound manageable afterwards:
/// `reload` swaps its rules and protocol settings without rebinding, `shutdown`
/// stops accepting while established connections finish. Dropping it stops
/// nothing.
///
/// Hysteria2 and TUIC are not covered by the registry yet: both authenticate
/// inside `quic_server.rs` rather than through a `TcpServerHandler`, so they keep
/// using their config credential even when a registry is supplied, and their
/// handle has nothing to reload.
pub async fn start_servers_with_users(
    config: Config,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    match config {
        #[cfg(unix)]
        Config::TunServer(tun_config) => {
            let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
            handle.push_listener(start_tun_server(tun_config, resolver).await?);
            Ok(handle)
        }
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(server_config, resolver, users).await
        }
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    let handle = match config.transport {
        Transport::Tcp => start_tcp_servers(config.clone(), resolver, users).await?,
        Transport::Quic => start_quic_servers(config.clone(), resolver, users).await?,
        Transport::Udp => todo!(),
    };

    if handle.listener_count() == 0 {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            &config.bind_location
        )));
    }

    Ok(handle)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    users: Option<Arc<dyn UserRegistry>>,
) -> std::io::Result<ServerHandle> {
    // Recorded before the config is taken apart. These are the settings the accept
    // loop is about to bake in, and `check_reload` compares against them so that a
    // later update changing one is refused rather than silently ignored.
    let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
    handle.record_listener_settings(&config);
    let replay_state = handle.replay_state();

    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        sniff,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", &protocol, &bind_location);

    // Traffic is only counted for an inbound whose users the caller manages: those
    // are the only `UserContext`s anyone can read the counters off. A config-file
    // inbound gets the stream unwrapped, exactly as before.
    let metered = users.is_some();

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
        rules.clone(),
        resolver.clone(),
        sniff,
    ));

    match bind_location {
        BindLocation::Address(addresses) => {
            for address in addresses.into_vec() {
                for socket_addr in address.to_socket_addrs()? {
                    // Shares protocol state across ports without reusing an
                    // interface-specific UDP bind IP.
                    let handler_slot = handle.slot_for_ip(socket_addr.ip(), &resolver, || {
                        create_tcp_server_handler_with_replay_state(
                            protocol.clone(),
                            &client_proxy_selector,
                            &resolver,
                            Some(socket_addr.ip()),
                            users.as_ref(),
                            &replay_state,
                        )
                        .into()
                    });
                    debug!("TCP handler for {}: {handler_slot:?}", socket_addr.ip());

                    let tcp_config = tcp_config.clone();
                    let cancel = handle.cancel_token();
                    let listener = tokio::spawn(async move {
                        // No resolver here: the loop takes it from the slot, with the
                        // handler, so both come from one generation.
                        run_tcp_server(socket_addr, tcp_config, handler_slot, metered, cancel)
                            .await
                            .unwrap();
                    });
                    handle.push_listener(listener);
                    handle.push_address(socket_addr);
                }
            }
        }
        BindLocation::Path(_path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let handler_slot = handle.slot_for_path(
                    create_tcp_server_handler_with_replay_state(
                        protocol,
                        &client_proxy_selector,
                        &resolver,
                        None,
                        users.as_ref(),
                        &replay_state,
                    )
                    .into(),
                    &resolver,
                );
                debug!("TCP handler: {handler_slot:?}");
                let cancel = handle.cancel_token();
                let listener = tokio::spawn(async move {
                    run_unix_server(_path_buf, handler_slot, metered, cancel)
                        .await
                        .unwrap();
                });
                handle.push_listener(listener);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::other(
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::sniff_tcp_after_success_response;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::routing::predicate::RouteProtocol;

    struct TestDuplexStream(tokio::io::DuplexStream);

    impl AsyncRead for TestDuplexStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestDuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            unreachable!("test stream does not support ping")
        }
    }

    impl AsyncStream for TestDuplexStream {}

    #[tokio::test]
    async fn tunnel_success_response_is_flushed_before_sniff_reads_payload() {
        const RESPONSE: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n";

        let (server, mut client) = tokio::io::duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut response = vec![0; RESPONSE.len()];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, RESPONSE);
            client.write_all(REQUEST).await.unwrap();
        });

        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(RESPONSE.to_vec().into_boxed_slice());
        let mut replay = Vec::new();
        let metadata = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sniff_tcp_after_success_response(&mut stream, true, &mut response, &mut replay),
        )
        .await
        .expect("the response-gated client must not wait for the 300 ms sniff timeout")
        .unwrap()
        .expect("HTTP request should be classified");

        client_task.await.unwrap();
        assert!(response.is_none(), "the normal path must not send it twice");
        assert_eq!(replay, REQUEST);
        assert_eq!(metadata.protocol, RouteProtocol::Http);
        assert_eq!(metadata.domain.as_deref(), Some("sniff.example"));
    }

    #[tokio::test]
    async fn existing_early_data_is_classified_without_touching_the_stream() {
        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: early.example\r\n\r\n";
        let (server, _client) = tokio::io::duplex(64);
        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(Box::from(&b"ok"[..]));
        let mut replay = REQUEST.to_vec();

        let metadata = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sniff_tcp_after_success_response(&mut stream, true, &mut response, &mut replay),
        )
        .await
        .expect("complete early data must not wait for a read")
        .unwrap()
        .unwrap();

        assert_eq!(metadata.domain.as_deref(), Some("early.example"));
        assert_eq!(replay, REQUEST);
        assert_eq!(
            response.as_deref(),
            Some(&b"ok"[..]),
            "classification without a read keeps the normal post-connect response timing"
        );
    }

    #[tokio::test]
    async fn selector_without_protocol_rules_leaves_deferred_response_untouched() {
        let (server, _client) = tokio::io::duplex(64);
        let mut stream: Box<dyn AsyncStream> = Box::new(TestDuplexStream(server));
        let mut response = Some(Box::from(&b"ok"[..]));
        let mut replay = b"early".to_vec();

        let metadata =
            sniff_tcp_after_success_response(&mut stream, false, &mut response, &mut replay)
                .await
                .unwrap();

        assert!(metadata.is_none());
        assert_eq!(response.as_deref(), Some(&b"ok"[..]));
        assert_eq!(replay, b"early");
    }
}
