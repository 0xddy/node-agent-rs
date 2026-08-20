use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use log::debug;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
use crate::dynamic::UserRegistry;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{CMD_CONNECT, CMD_UDP_ASSOCIATE, read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    /// Authenticates incoming connections. `Some` exactly when this handler was built
    /// for server use; the client direction has nobody to authenticate.
    users: Option<Arc<dyn UserRegistry>>,
    /// The digest this handler presents when it is the client. `Some` exactly when this
    /// handler was built for client use, since a server never sends a credential.
    password_hash: Option<Box<[u8]>>,
    shadowsocks_data: Option<ShadowsocksData>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        users: Arc<dyn UserRegistry>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_inner(
            Some(users),
            None,
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
        )
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_inner(
            None,
            Some(create_password_hash(password)),
            shadowsocks_config,
            None,
            None,
        )
    }

    fn new_inner(
        users: Option<Arc<dyn UserRegistry>>,
        password_hash: Option<Box<[u8]>>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
        resolver: Option<Arc<dyn Resolver>>,
    ) -> Self {
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| match config {
            ShadowsocksConfig::Legacy {
                cipher,
                password: shadowsocks_password,
            } => {
                let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                    shadowsocks_password,
                    cipher.algorithm().key_len(),
                )));
                ShadowsocksData {
                    cipher: *cipher,
                    key,
                }
            }
            ShadowsocksConfig::Aead2022 { .. } => {
                panic!("Trojan does not support shadowsocks 2022 ciphers (checked during config validation)")
            }
        });

        Self {
            users,
            password_hash,
            shadowsocks_data,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            server_stream = Box::new(ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        let users = self
            .users
            .as_ref()
            .expect("user registry required for server handler");

        // read the entire line rather than exactly 56 bytes, so that we can masquerade as an HTTP server
        // and handle the request as if it were a HTTP request.
        // TODO: implement http response
        let received_hash = stream_reader.read_line_bytes(&mut server_stream).await?;
        if received_hash.len() != PASSWORD_HASH_LEN {
            return Err(std::io::Error::other(format!(
                "Invalid password hash length, expected {}, got {}",
                PASSWORD_HASH_LEN,
                received_hash.len()
            )));
        }

        // NOTE(shoes-engine): the registry hashes to a bucket and finishes with a
        // constant-time comparison, so this is still not a timing oracle. Phase 3 hands
        // the returned context to the traffic meter.
        let _user = match users.find_trojan_hash(received_hash) {
            Some(user) => user,
            None => return Err(std::io::Error::other("Invalid password hash")),
        };

        let command_type = stream_reader.read_u8(&mut server_stream).await?;

        if command_type == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
        }

        if command_type != CMD_CONNECT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {command_type}"),
            ));
        }

        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        let request_suffix = stream_reader.read_u16_be(&mut server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {request_suffix}"
            )));
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");

            let initial_data = stream_reader.unparsed_data_owned();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session(
                    server_stream,
                    initial_data,
                    false,
                    proxy_selector,
                    resolver,
                )
                .await
                {
                    debug!("Trojan h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let password_hash = self
            .password_hash
            .as_ref()
            .expect("password hash required for client handler");
        write_all(&mut client_stream, password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_CONNECT]).await?;
        let location_bytes = write_location_to_vec(remote_location.location());
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        // TODO: Return true once setup_client_udp_bidirectional is implemented
        false
    }

    // TODO: Implement Trojan UDP-over-TCP
    // Trojan UDP uses a message-framed protocol where each packet has:
    // ATYPE + Address + Port + Length(2 bytes) + CRLF + Payload
    // async fn setup_client_udp_bidirectional(...)
}

/// Length of a Trojan credential on the wire: SHA-224 rendered as lowercase hex.
pub(crate) const PASSWORD_HASH_LEN: usize = 56;

pub(crate) fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{b:02x}"));
    }
    let hex_bytes = hex_str.into_bytes().into_boxed_slice();
    if hex_bytes.len() != PASSWORD_HASH_LEN {
        panic!(
            "Invalid password hash length, expected {}, got {}",
            PASSWORD_HASH_LEN,
            hex_bytes.len()
        );
    }
    hex_bytes
}
