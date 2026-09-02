//! A minimal Hysteria2 client, written because shoes does not have one.
//!
//! Every other protocol suite here builds its client half out of shoes itself: a
//! plain socks5 inbound whose rule carries a `client_chain` speaking the protocol
//! under test (see [`start_leg`](super::start_leg)). Hysteria2 has no client side in
//! this crate to borrow, so the alternative to the ~250 lines below is a suite that
//! never authenticates anybody -- which would leave the one thing worth proving,
//! that authentication now goes through the registry, untested.
//!
//! What it implements is only what the tests need:
//!
//! * the HTTP/3 auth exchange (`POST https://hysteria/auth`, `hysteria-auth: <pw>`,
//!   success being the protocol's non-standard status **233**),
//! * the TCP request frame (`0x401`, address, padding) and its status reply,
//! * unfragmented UDP over QUIC datagrams,
//! * the negotiated client-side Brutal controller used by sustained-upload tests.
//!
//! Fragmentation and port hopping are left out. The small HTTP probe helper at the
//! bottom does exercise the masquerade site. The wire formats are those in
//! `../shoes-plus/src/hysteria2_server.rs`.

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};

use super::IO_TIMEOUT;

/// The status Hysteria2 uses for "authenticated". Not an HTTP status at all, which is
/// the point: it makes the server invisible to anything that is not a Hysteria2
/// client.
const AUTH_OK: u16 = 233;

/// TCP request frame type, mirroring `FRAME_TYPE_TCP_REQUEST`.
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

// ------------------------------------------------------------------------ tls setup

/// The same certificate verifier shoes installs for a `verify: false` outbound.
///
/// Reimplemented rather than reused because `shoes::rustls_config_util` is private,
/// and making it public would be a change to upstream source for a test's benefit.
/// The bundled fixture is a self-signed `CN=e2e.test` with no subject alt name, so
/// no amount of root-store configuration would let webpki accept it.
#[derive(Debug)]
struct NoVerification {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Built once: a `ClientConfig` carries a whole crypto provider, and rebuilding one
/// per connection is slow enough to show up in a suite that opens dozens.
fn client_config(brutal_capable: bool) -> quinn::ClientConfig {
    static DEFAULT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    static BRUTAL_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    let slot = if brutal_capable {
        &BRUTAL_CONFIG
    } else {
        &DEFAULT_CONFIG
    };
    slot.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let algorithms = provider.signature_verification_algorithms;

        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            // QUIC is TLS 1.3 only, and naming that here is what lets
            // `QuicClientConfig::try_from` accept the config.
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3 should be available")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification { algorithms }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .expect("the tls config should be usable for quic");
        let mut config = quinn::ClientConfig::new(Arc::new(quic));
        if brutal_capable {
            // A real Hysteria2 client has to install the switchable controller
            // before the QUIC handshake, then activates it only after auth has
            // returned the server's receive ceiling.  Most tests do not need
            // that machinery; upload-pressure tests do, otherwise they exercise
            // Quinn's default controller rather than the Hysteria2 upload path.
            let mut transport = quinn::TransportConfig::default();
            transport
                .send_window(16 * 1024 * 1024)
                .receive_window((20_u32 * 1024 * 1024).into())
                .stream_receive_window((8_u32 * 1024 * 1024).into())
                .congestion_controller_factory(Arc::new(shoes::hysteria2::brutal::BrutalConfig))
                .initial_rtt(Duration::from_millis(100));
            config.transport_config(Arc::new(transport));
        }
        config
    })
    .clone()
}

// --------------------------------------------------------------------------- client

/// One authenticated Hysteria2 connection.
///
/// Everything the client does afterwards is multiplexed over it, which is exactly why
/// the server binds one accounting context per connection rather than per stream.
pub struct Hysteria2Client {
    connection: quinn::Connection,
    /// Whether the server said it would carry UDP, from `Hysteria-UDP`.
    pub udp_enabled: bool,
    /// Server receive rate from `Hysteria-CC-RX`, in bytes per second.
    pub advertised_receive_bps: u64,
    /// Whether the response asked the client to keep bandwidth detection (BBR).
    pub advertised_receive_auto: bool,
    /// Client-to-server rate selected after applying both peers' ceilings.
    ///
    /// Zero means the test client retained its default congestion controller.
    pub negotiated_send_bps: u64,
    /// The HTTP/3 driver. Held for the client's whole life on purpose: h3 closes the
    /// QUIC connection underneath it when the driver is dropped, which would take the
    /// proxied streams with it. The server keeps its own half alive for the same
    /// reason -- see the comment at `../shoes-plus/src/hysteria2_server.rs:70`.
    driver: tokio::task::JoinHandle<()>,
    /// Also held rather than dropped: the endpoint owns the client's UDP socket.
    endpoint: quinn::Endpoint,
    /// And the request half, for the same reason as `driver`: h3 shuts the connection
    /// down once the last `SendRequest` is gone, and the auth request is the only one
    /// this client ever makes.
    requests: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

impl Hysteria2Client {
    /// Snapshot the underlying QUIC path for throughput/liveness diagnostics.
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }

    /// Connects and authenticates, or fails.
    ///
    /// A wrong password is *not* an error from the QUIC handshake: the server answers
    /// 404 and waits for another request until its 3-second auth timeout expires. So a
    /// rejection arrives here as a status that is not 233, promptly, which is what
    /// makes [`denied`] fast.
    pub async fn connect(server: SocketAddr, password: &str) -> io::Result<Self> {
        Self::connect_with_receive_bps(server, password, 0).await
    }

    /// Connects while declaring the fixed rate this client can receive.
    ///
    /// Hysteria2 expresses this header in bytes per second, not Mbps. A zero value
    /// asks the server to retain its fallback congestion controller.
    pub async fn connect_with_receive_bps(
        server: SocketAddr,
        password: &str,
        receive_bps: u64,
    ) -> io::Result<Self> {
        Self::connect_over(
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?,
            server,
            password,
            receive_bps,
            0,
            false,
        )
        .await
    }

    /// Connects while declaring fixed receive and send rates in bytes per second.
    ///
    /// The send half mirrors a production Hysteria2 client: its switchable Brutal
    /// controller is installed before QUIC starts and activated after authentication,
    /// capped by the server's `Hysteria-CC-RX` response.  This matters for sustained
    /// uploads; merely putting the header on the wire only tests the server's download
    /// direction.
    pub async fn connect_with_rates_bps(
        server: SocketAddr,
        password: &str,
        receive_bps: u64,
        send_bps: u64,
    ) -> io::Result<Self> {
        Self::connect_over(
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?,
            server,
            password,
            receive_bps,
            send_bps,
            true,
        )
        .await
    }

    /// Connects through a Salamander-obfuscated socket.
    ///
    /// Built the same way the server builds its own -- quinn's socket wrapped in
    /// `ObfuscatedUdpSocket` -- so a test that passes here is evidence the two
    /// sides agree on the wire format, not evidence that one implementation is
    /// self-consistent.
    pub async fn connect_obfuscated(
        server: SocketAddr,
        password: &str,
        obfs_password: &str,
    ) -> io::Result<Self> {
        use quinn::Runtime as _;

        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let inner = runtime.wrap_udp_socket(socket)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(shoes::hysteria2_obfs::ObfuscatedUdpSocket::new(
                inner,
                shoes::hysteria2_obfs::Salamander::new(obfs_password),
            )),
            runtime,
        )?;
        Self::connect_over(endpoint, server, password, 0, 0, false).await
    }

    async fn connect_over(
        endpoint: quinn::Endpoint,
        server: SocketAddr,
        password: &str,
        receive_bps: u64,
        send_bps: u64,
        brutal_capable: bool,
    ) -> io::Result<Self> {
        let connecting = endpoint
            .connect_with(client_config(brutal_capable), server, "e2e.test")
            .map_err(|e| io::Error::other(format!("quic connect rejected: {e}")))?;
        let connection = deadline(connecting)
            .await?
            .map_err(|e| io::Error::other(format!("quic handshake failed: {e}")))?;

        let (mut driver, mut requests) = deadline(h3::client::new(h3_quinn::Connection::new(
            connection.clone(),
        )))
        .await?
        .map_err(|e| io::Error::other(format!("h3 setup failed: {e}")))?;
        // `wait_idle` is what drives the connection; nothing else polls it. It returns
        // as soon as the auth request finishes, and *dropping* the h3 connection closes
        // the QUIC connection underneath -- the trap the server documents at
        // `../shoes-plus/src/hysteria2_server.rs:70`. So the task parks instead of ending,
        // holding the h3 half alive until `Drop` aborts it.
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
            std::future::pending::<()>().await;
        });

        let request = http::Request::post("https://hysteria/auth")
            .header("hysteria-auth", password)
            .header("Hysteria-CC-RX", receive_bps)
            .body(())
            .expect("the auth request should be well formed");

        let response =
            async {
                let mut stream = requests.send_request(request).await.map_err(|e| {
                    io::Error::other(format!("could not send the auth request: {e}"))
                })?;
                // No body, and the server will not answer until the request is complete.
                stream.finish().await.map_err(|e| {
                    io::Error::other(format!("could not finish the auth request: {e}"))
                })?;
                stream
                    .recv_response()
                    .await
                    .map_err(|e| io::Error::other(format!("no auth response: {e}")))
            };
        let response = deadline(response).await??;

        let status = response.status().as_u16();
        if status != AUTH_OK {
            connection.close(0x100u32.into(), b"auth rejected");
            return Err(io::Error::other(format!(
                "hysteria2 auth refused with status {status}"
            )));
        }

        let udp_enabled = response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|value| value.to_str().ok())
            == Some("true");
        let advertised_receive_header = response
            .headers()
            .get("Hysteria-CC-RX")
            .and_then(|value| value.to_str().ok());
        let advertised_receive_auto = advertised_receive_header == Some("auto");
        let advertised_receive_bps = advertised_receive_header
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let negotiated_send_bps = if advertised_receive_auto || send_bps == 0 {
            0
        } else if advertised_receive_bps == 0 {
            send_bps
        } else {
            send_bps.min(advertised_receive_bps)
        };
        if negotiated_send_bps != 0 {
            shoes::hysteria2::brutal::activate(&connection, negotiated_send_bps).map_err(
                |error| io::Error::other(format!("could not activate client Brutal: {error}")),
            )?;
        }

        Ok(Self {
            connection,
            udp_enabled,
            advertised_receive_bps,
            advertised_receive_auto,
            negotiated_send_bps,
            driver,
            endpoint,
            requests,
        })
    }

    /// Opens a proxied TCP stream to `dest` and completes the request exchange.
    ///
    /// Note this goes straight to `quinn::Connection::open_bi` rather than through h3:
    /// after auth, Hysteria2 stops speaking HTTP/3 and uses raw QUIC streams.
    pub async fn open_tcp(&self, dest: SocketAddr) -> io::Result<Hysteria2Stream> {
        let (mut send, mut recv) = deadline(self.connection.open_bi())
            .await?
            .map_err(|e| io::Error::other(format!("could not open a stream: {e}")))?;

        let address = dest.to_string();
        let mut request = varint(FRAME_TYPE_TCP_REQUEST);
        request.extend_from_slice(&varint(address.len() as u64));
        request.extend_from_slice(address.as_bytes());
        // No padding. Real clients send some to blur the request length; a test that
        // checks byte counts would rather the length were predictable.
        request.extend_from_slice(&varint(0));
        deadline(send.write_all(&request))
            .await?
            .map_err(stream_err)?;

        // [status] [varint message length] [message] [varint padding length] [padding]
        let mut status = [0u8; 1];
        deadline(recv.read_exact(&mut status))
            .await?
            .map_err(stream_err)?;
        if status[0] != 0 {
            return Err(io::Error::other(format!(
                "the proxy refused the connection to {dest}: status {}",
                status[0]
            )));
        }
        for _ in 0..2 {
            let length = read_varint(&mut recv).await?;
            let mut discard = vec![0u8; length as usize];
            deadline(recv.read_exact(&mut discard))
                .await?
                .map_err(stream_err)?;
        }

        Ok(Hysteria2Stream { send, recv })
    }

    /// Sends one unfragmented datagram to `dest` within `session`.
    pub async fn send_udp(
        &self,
        session: u32,
        packet: u16,
        dest: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let address = dest.to_string();
        let mut datagram = Vec::with_capacity(8 + address.len() + payload.len() + 2);
        datagram.extend_from_slice(&session.to_be_bytes());
        datagram.extend_from_slice(&packet.to_be_bytes());
        // Fragment 0 of 1.
        datagram.extend_from_slice(&[0, 1]);
        datagram.extend_from_slice(&varint(address.len() as u64));
        datagram.extend_from_slice(address.as_bytes());
        datagram.extend_from_slice(payload);

        self.connection
            .send_datagram(datagram.into())
            .map_err(|e| io::Error::other(format!("could not send a datagram: {e}")))
    }

    /// Reads one datagram and returns its session id and payload.
    ///
    /// The address the server prefixes is the *source* of the reply, which for these
    /// tests is always the echo peer, so it is parsed only far enough to be skipped.
    pub async fn recv_udp(&self, wait: Duration) -> io::Result<(u32, Vec<u8>)> {
        let datagram = tokio::time::timeout(wait, self.connection.read_datagram())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no datagram came back"))?
            .map_err(|e| io::Error::other(format!("could not read a datagram: {e}")))?;

        if datagram.len() < 9 {
            return Err(io::Error::other(format!(
                "a {}-byte datagram is too short to be a udp packet",
                datagram.len()
            )));
        }
        let session = u32::from_be_bytes(datagram[0..4].try_into().unwrap());
        let (address_len, header) = parse_varint(&datagram[8..])
            .ok_or_else(|| io::Error::other("truncated address length"))?;
        let start = 8 + header + address_len as usize;
        if start > datagram.len() {
            return Err(io::Error::other("the address runs past the datagram"));
        }
        Ok((session, datagram[start..].to_vec()))
    }
}

impl Drop for Hysteria2Client {
    fn drop(&mut self) {
        // Closing explicitly rather than letting the endpoint fall out of scope: the
        // server's accounting context lives as long as the connection, and the tests
        // read counters as soon as a client goes away.
        self.connection.close(0x100u32.into(), b"");
        self.driver.abort();
        self.endpoint.close(0x100u32.into(), b"");
    }
}

/// A proxied stream, past the request exchange, carrying nothing but payload.
pub struct Hysteria2Stream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl Hysteria2Stream {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        deadline(self.send.write_all(data))
            .await?
            .map_err(stream_err)
    }

    /// Reads up to the next `\n`, trimmed, mirroring [`super::read_line`].
    pub async fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        deadline(async {
            loop {
                match self.recv.read(&mut byte).await.map_err(stream_err)? {
                    None | Some(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("the stream closed after {} byte(s)", line.len()),
                        ));
                    }
                    Some(_) if byte[0] == b'\n' => return Ok(()),
                    Some(_) => line.push(byte[0]),
                }
            }
        })
        .await??;
        Ok(String::from_utf8_lossy(&line).trim().to_string())
    }
}

// -------------------------------------------------------------------------- varints

/// QUIC's variable-length integer encoding, as `encode_varint` in the server.
fn varint(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b0100_0000;
        bytes.to_vec()
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b1000_0000;
        bytes.to_vec()
    } else {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b1100_0000;
        bytes.to_vec()
    }
}

/// Decodes a varint from the front of `bytes`, returning it and how much it took.
fn parse_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    if bytes.len() < width {
        return None;
    }
    let mut value = (first & 0b0011_1111) as u64;
    for byte in &bytes[1..width] {
        value = (value << 8) | *byte as u64;
    }
    Some((value, width))
}

async fn read_varint(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut buffer = [0u8; 8];
    deadline(recv.read_exact(&mut buffer[..1]))
        .await?
        .map_err(stream_err)?;
    let width = 1usize << (buffer[0] >> 6);
    if width > 1 {
        deadline(recv.read_exact(&mut buffer[1..width]))
            .await?
            .map_err(stream_err)?;
    }
    parse_varint(&buffer[..width])
        .map(|(value, _)| value)
        .ok_or_else(|| io::Error::other("malformed varint"))
}

async fn deadline<T>(future: impl std::future::Future<Output = T>) -> io::Result<T> {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hysteria2 did not answer in time"))
}

/// quinn's stream errors are its own types rather than `io::Error`, and the harness
/// only ever reports them.
fn stream_err(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("quic stream error: {error}"))
}

// --------------------------------------------------------------------------- probes

/// Sends one ordinary HTTP/3 request without authenticating.
///
/// A camouflage site is only visible during the three-second authentication
/// window, so this owns a fresh QUIC connection and drives the complete request
/// before returning the response body.
pub async fn request(
    server: SocketAddr,
    request: http::Request<Bytes>,
) -> io::Result<http::Response<Bytes>> {
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    let connection = deadline(
        endpoint
            .connect_with(client_config(false), server, "e2e.test")
            .map_err(|e| io::Error::other(format!("quic connect rejected: {e}")))?,
    )
    .await?
    .map_err(|e| io::Error::other(format!("quic handshake failed: {e}")))?;
    let (mut driver, mut requests) = deadline(h3::client::new(h3_quinn::Connection::new(
        connection.clone(),
    )))
    .await?
    .map_err(|e| io::Error::other(format!("h3 setup failed: {e}")))?;
    let driver = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
        std::future::pending::<()>().await;
    });

    let (parts, body) = request.into_parts();
    let mut stream = deadline(requests.send_request(http::Request::from_parts(parts, ())))
        .await?
        .map_err(|e| io::Error::other(format!("could not send probe request: {e}")))?;
    if !body.is_empty() {
        deadline(stream.send_data(body))
            .await?
            .map_err(|e| io::Error::other(format!("could not send probe body: {e}")))?;
    }
    deadline(stream.finish())
        .await?
        .map_err(|e| io::Error::other(format!("could not finish probe request: {e}")))?;

    let response = deadline(stream.recv_response())
        .await?
        .map_err(|e| io::Error::other(format!("no probe response: {e}")))?;
    let (parts, ()) = response.into_parts();
    let mut body = BytesMut::new();
    while let Some(mut data) = deadline(stream.recv_data())
        .await?
        .map_err(|e| io::Error::other(format!("could not read probe response: {e}")))?
    {
        let remaining = data.remaining();
        body.extend_from_slice(&data.copy_to_bytes(remaining));
    }

    connection.close(0x100u32.into(), b"probe complete");
    driver.abort();
    drop(requests);
    drop(endpoint);
    Ok(http::Response::from_parts(parts, body.freeze()))
}

/// Asks `dest` who it is through a fresh Hysteria2 connection.
pub async fn reach(server: SocketAddr, password: &str, dest: SocketAddr) -> io::Result<String> {
    let client = Hysteria2Client::connect(server, password).await?;
    let mut stream = client.open_tcp(dest).await?;
    stream.write_all(b"who\n").await?;
    stream.read_line().await
}

/// True if the inbound will not carry traffic for this password.
///
/// Unlike the TCP protocols, a Hysteria2 rejection is visible before any payload
/// moves: the auth response is a complete answer in itself. The short deadline is
/// there to keep the 3-second server-side auth timeout from being mistaken for a hang.
pub async fn denied(server: SocketAddr, password: &str, dest: SocketAddr) -> bool {
    match tokio::time::timeout(Duration::from_secs(6), reach(server, password, dest)).await {
        Ok(Ok(name)) => {
            println!("      reached {name} when the password should have been refused");
            false
        }
        Ok(Err(_)) => true,
        Err(_) => {
            println!("      the inbound neither answered nor refused -- treating as refused");
            true
        }
    }
}

/// Moves `upload` bytes up and `download` bytes down, returning how much came back.
pub async fn transfer(
    server: SocketAddr,
    password: &str,
    dest: SocketAddr,
    upload: usize,
    download: usize,
) -> io::Result<usize> {
    let client = Hysteria2Client::connect(server, password).await?;
    let mut stream = client.open_tcp(dest).await?;
    stream
        .write_all(format!("{upload} {download}\n").as_bytes())
        .await?;
    stream.write_all(&vec![b'x'; upload]).await?;

    let mut received = 0usize;
    let mut scratch = vec![0u8; 65536];
    while received < download {
        match deadline(stream.recv.read(&mut scratch))
            .await?
            .map_err(stream_err)?
        {
            None | Some(0) => break,
            Some(n) => received += n,
        }
    }
    Ok(received)
}

/// True if a datagram makes it through the inbound and back.
pub async fn udp_roundtrip(
    server: SocketAddr,
    password: &str,
    dest: SocketAddr,
    wait: Duration,
) -> bool {
    let Ok(client) = Hysteria2Client::connect(server, password).await else {
        return false;
    };
    if client.send_udp(1, 0, dest, b"ping").await.is_err() {
        return false;
    }
    match client.recv_udp(wait).await {
        Ok((_, payload)) => payload == b"ping",
        Err(e) => {
            println!("      {e}");
            false
        }
    }
}

/// Sends `count` datagrams of `size` bytes, returning how many came back.
///
/// One in flight at a time, for the reason [`super::udp_burst`] gives: a test that
/// cannot tell a lost datagram from a late one cannot put an upper bound on bytes.
pub async fn udp_burst(
    server: SocketAddr,
    password: &str,
    dest: SocketAddr,
    size: usize,
    count: usize,
) -> io::Result<usize> {
    let client = Hysteria2Client::connect(server, password).await?;
    let payload = vec![b'u'; size];

    let mut echoed = 0usize;
    for packet in 0..count {
        client.send_udp(1, packet as u16, dest, &payload).await?;
        match client.recv_udp(Duration::from_secs(3)).await {
            Ok((_, back)) if back == payload => echoed += 1,
            Ok((_, back)) => println!("      unexpected {}-byte reply", back.len()),
            Err(e) => println!("      {e}"),
        }
    }
    Ok(echoed)
}
