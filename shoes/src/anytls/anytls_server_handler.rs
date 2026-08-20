//! AnyTLS Server Handler
//!
//! Implements TcpServerHandler for AnyTLS protocol.
//! This handler:
//! 1. Authenticates clients via SHA256(password)
//! 2. Creates an AnyTlsSession with all routing dependencies
//! 3. Runs the session which handles streams internally

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_server_session::AnyTlsSession;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional;
use crate::dynamic::{UserRegistry, bind_connection_user};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;

/// AnyTLS server handler implementing TcpServerHandler
///
/// This handler receives a post-TLS stream and handles AnyTLS protocol.
/// It authenticates the client, creates a session with routing dependencies,
/// and runs the session which handles all streams internally.
#[derive(Debug)]
pub struct AnyTlsServerHandler {
    /// Who a password hash belongs to, and the 8-byte-prefix probe that decides
    /// whether to keep reading one. Both questions go to the same registry: an
    /// injected one for a multi-user inbound, or a one-user registry built from this
    /// inbound's own config credential.
    users: Arc<dyn UserRegistry>,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// Resolver for destination addresses
    resolver: Arc<dyn Resolver>,
    /// Proxy provider for routing decisions
    proxy_provider: Arc<ClientProxySelector>,
    /// UDP enabled for UoT support
    udp_enabled: bool,
    /// Fallback destination for failed authentication
    fallback: Option<NetLocation>,
}

impl AnyTlsServerHandler {
    /// Create a new AnyTLS server handler.
    ///
    /// # Arguments
    /// * `users` - The registry this inbound authenticates against
    /// * `padding` - Padding factory for traffic obfuscation
    /// * `resolver` - DNS resolver for destination addresses
    /// * `proxy_provider` - Proxy selector for routing decisions
    /// * `udp_enabled` - Whether UDP-over-TCP is enabled
    /// * `fallback` - Optional fallback destination for failed auth
    pub fn new(
        users: Arc<dyn UserRegistry>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        Self {
            users,
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
        }
    }
}

#[async_trait]
impl TcpServerHandler for AnyTlsServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // Use StreamReader to peek at auth header without consuming
        let mut reader = StreamReader::new();

        // First, peek at the 8-byte prefix for quick fallback.
        // This allows us to reject non-AnyTLS traffic (e.g., small HTTP requests)
        // without hanging waiting for the full 32-byte hash.
        //
        // Timing side-channel note: This creates a timing difference between prefix
        // match and mismatch, but is not exploitable since enumerating 2^64 prefixes
        // is infeasible, and discovering a valid prefix doesn't help recover the
        // password or the remaining 24 bytes of the SHA256 hash.
        let prefix_data = reader.peek_slice(&mut server_stream, 8).await?;
        let prefix: [u8; 8] = prefix_data.try_into().expect("peek_slice returned 8 bytes");

        if !self.users.has_password_sha256_prefix(&prefix) {
            log::debug!("AnyTLS quick fallback: 8-byte prefix doesn't match any user");
            if let Some(ref fallback) = self.fallback {
                return self.fallback_to_dest(server_stream, reader, fallback).await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication failed (prefix mismatch)",
            ));
        }

        // Prefix matches - now read the full 32-byte hash
        let auth_data = reader.peek_slice(&mut server_stream, 32).await?;
        let hash: [u8; 32] = auth_data.try_into().expect("peek_slice returned 32 bytes");

        let user_name = match self.users.find_password_sha256(&hash) {
            Some(user) => {
                log::debug!("AnyTLS user authenticated: {}", user.id());
                // Auth succeeded - consume the header bytes
                reader.consume(32);
                // The stream is metered from the moment it was accepted, so this hands
                // the TLS handshake already counted against nobody over to whoever
                // just proved they own it. Inline on the accepting task, before the
                // session is spawned, which is what lets the task local reach it.
                bind_connection_user(&user);
                user.id().to_string()
            }
            None => {
                log::debug!("AnyTLS authentication failed: unknown password");
                // If fallback is configured, forward the connection there. A disabled
                // user lands here too, deliberately: the registry reports them absent
                // so that a suspension is not observable from outside.
                if let Some(ref fallback) = self.fallback {
                    return self.fallback_to_dest(server_stream, reader, fallback).await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication failed",
                ));
            }
        };

        let padding_len = reader.read_u16_be(&mut server_stream).await?;

        // Skip padding bytes (consume them from the reader)
        if padding_len > 0 {
            let _ = reader
                .read_slice(&mut *server_stream, padding_len as usize)
                .await?;
        }

        // Get any remaining unparsed data that may have been buffered
        let initial_data = reader.unparsed_data_owned();

        // Create session with all dependencies for internal stream handling
        let session = AnyTlsSession::new_server_with_initial_data(
            server_stream,
            Arc::clone(&self.padding),
            Arc::clone(&self.resolver),
            Arc::clone(&self.proxy_provider),
            self.udp_enabled,
            user_name,
            initial_data,
        );

        // Run the session in a background task
        tokio::spawn(async move {
            if let Err(e) = session.run().await {
                log::debug!("AnyTLS session ended: {}", e);
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

impl AnyTlsServerHandler {
    /// Forward the connection to a fallback destination when authentication fails.
    ///
    /// This makes the server indistinguishable from a legitimate server by transparently
    /// proxying failed auth attempts to the configured fallback destination.
    async fn fallback_to_dest(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        reader: StreamReader,
        fallback: &NetLocation,
    ) -> std::io::Result<TcpServerSetupResult> {
        log::debug!("AnyTLS FALLBACK: Connecting to fallback: {}", fallback);

        // Get the unconsumed data from the reader (includes auth header)
        let unconsumed_data = reader.unparsed_data();

        // Resolve and connect to the fallback destination
        let dest_addr = crate::resolver::resolve_single_address(&self.resolver, fallback).await?;

        log::debug!("AnyTLS FALLBACK: Resolved {} to {}", fallback, dest_addr);

        let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

        log::debug!(
            "AnyTLS FALLBACK: Connected to fallback, forwarding {} bytes",
            unconsumed_data.len()
        );

        // Forward the unconsumed data (auth header that the client sent)
        if !unconsumed_data.is_empty() {
            write_all(&mut dest_stream, unconsumed_data).await?;
            dest_stream.flush().await?;
        }

        log::debug!("AnyTLS FALLBACK: Spawning bidirectional copy");

        // Spawn the long-running bidirectional copy as a background task.
        // This allows the setup to complete within the timeout while the actual
        // data transfer runs indefinitely.
        tokio::spawn(async move {
            let result = copy_bidirectional(
                &mut *client_stream,
                &mut *dest_stream,
                false, // client doesn't need initial flush
                false, // dest doesn't need initial flush
            )
            .await;

            let _ = client_stream.shutdown().await;
            let _ = dest_stream.shutdown().await;

            if let Err(e) = result {
                log::debug!("AnyTLS FALLBACK: Connection ended: {}", e);
            } else {
                log::debug!("AnyTLS FALLBACK: Connection completed");
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dynamic::StaticUserRegistry;
    use crate::dynamic::credential::{password_sha256, password_sha256_prefix};

    #[test]
    fn the_wire_credential_is_the_raw_sha256_of_the_password() {
        // The handler compares what the client sends against this derivation, so if
        // it ever drifted every AnyTLS client in the world would stop connecting.
        let hash = password_sha256("secret123");
        let expected = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"secret123");
        assert_eq!(&hash[..], expected.as_ref());
        assert_ne!(password_sha256("pass1"), password_sha256("pass2"));
    }

    #[test]
    fn a_config_built_registry_answers_both_questions_the_handler_asks() {
        // The handler asks twice: an 8-byte prefix probe before it has read the whole
        // credential, then the full 32 bytes. Both go to the registry.
        let registry = StaticUserRegistry::single_anytls_password("alice", "password1");
        let hash = password_sha256("password1");

        assert!(registry.has_password_sha256_prefix(&password_sha256_prefix(&hash)));
        assert_eq!(
            registry
                .find_password_sha256(&hash)
                .map(|user| user.id().to_string()),
            Some("alice".to_string())
        );
    }

    #[test]
    fn a_probe_that_is_not_a_credential_is_turned_away_at_the_prefix() {
        // What actually shows up on a public port: an HTTP request. It must be sent
        // to the fallback after 8 bytes rather than hang the handler waiting for 32.
        let registry = StaticUserRegistry::single_anytls_password("alice", "password1");
        let http: [u8; 8] = *b"GET / HT";
        assert!(!registry.has_password_sha256_prefix(&http));
    }

    #[test]
    fn two_users_are_told_apart_by_the_full_hash() {
        let mut registry = StaticUserRegistry::new();
        registry.add_anytls_password("alice", "password1");
        registry.add_anytls_password("bob", "password2");
        let registry: Arc<dyn UserRegistry> = Arc::new(registry);

        assert_eq!(
            registry
                .find_password_sha256(&password_sha256("password1"))
                .map(|u| u.id().to_string()),
            Some("alice".to_string())
        );
        assert_eq!(
            registry
                .find_password_sha256(&password_sha256("password2"))
                .map(|u| u.id().to_string()),
            Some("bob".to_string())
        );
        assert_eq!(registry.user_count(), 2);
    }
}
