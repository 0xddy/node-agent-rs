//! A minimal TUIC v5 client, written because shoes does not have one.
//!
//! Same reason as [`super::hysteria2`]: every other protocol suite here builds its
//! client half out of shoes itself, by pointing a plain socks5 inbound's
//! `client_chain` at the protocol under test. TUIC has no client side in this crate
//! to borrow, so the alternative to the code below is a suite that never
//! authenticates anybody -- leaving the one thing worth proving, that authentication
//! now goes through the registry, untested.
//!
//! Unlike the Hysteria2 client this one needs no HTTP/3: TUIC speaks its own commands
//! straight over QUIC streams and datagrams. What it implements is only what the
//! tests need:
//!
//! * `AUTHENTICATE` on a uni stream -- the uuid in cleartext beside a 32 byte token
//!   derived from the password *and* the connection's exported keying material,
//! * `CONNECT` on a bidirectional stream, which has no reply at all: the server
//!   starts proxying the moment it has read the address,
//! * `PACKET` over datagrams (TUIC's `native` UDP relay mode) and over uni streams
//!   (its `quic` mode), unfragmented.
//!
//! Fragmentation, `DISSOCIATE`, heartbeats and 0-RTT are left out; none of them
//! affect who a connection is billed to. The wire formats are those in
//! `shoes/src/tuic_server.rs`: the command constants at the top, `read_address` and
//! `serialize_address` for the address encoding, and the datagram header built in
//! `run_udp_remote_to_local_datagram_loop`.
//!
//! # The token is why this cannot be a table of fixtures
//!
//! `AUTHENTICATE` carries `export_keying_material(uuid, password)` over the live TLS
//! session, so the 32 bytes differ on every connection even for the same user. A
//! recorded handshake would never replay, and a client that derives the token wrongly
//! is indistinguishable from a server that looked up the wrong password -- which is
//! precisely the confusion these tests exist to rule out.

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::IO_TIMEOUT;

const TUIC_VERSION: u8 = 5;
const COMMAND_AUTHENTICATE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_PACKET: u8 = 0x02;

// ------------------------------------------------------------------------ tls setup

/// The same certificate verifier shoes installs for a `verify: false` outbound.
///
/// Duplicated from [`super::hysteria2`] rather than shared: the two clients are
/// deliberately independent, so a change made for one protocol's sake cannot quietly
/// alter what the other proves.
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
fn client_config() -> quinn::ClientConfig {
    static CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let algorithms = provider.signature_verification_algorithms;

            let mut tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("tls 1.3 should be available")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerification { algorithms }))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];

            let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .expect("the tls config should be usable for quic");
            let mut config = quinn::ClientConfig::new(Arc::new(quic));

            // Generous, because a suite that opens dozens of connections should fail
            // by assertion rather than by a client-side idle timeout.
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
            config.transport_config(Arc::new(transport));
            config
        })
        .clone()
}

// --------------------------------------------------------------------------- client

/// One authenticated TUIC connection.
///
/// Everything afterwards is multiplexed over it, which is exactly why the server
/// binds one accounting context per connection rather than per stream.
pub struct TuicClient {
    connection: quinn::Connection,
    /// Held rather than dropped: the endpoint owns the client's UDP socket.
    endpoint: quinn::Endpoint,
}

impl TuicClient {
    /// Connects and authenticates, or fails.
    ///
    /// A rejected credential is *not* visible here. TUIC's `AUTHENTICATE` has no
    /// reply: the server either carries on or closes the connection, and closing is
    /// asynchronous, so this returns `Ok` for a wrong password and the failure only
    /// shows up when a stream is opened. That is why [`denied`] probes by trying to
    /// reach a destination rather than by connecting.
    pub async fn connect(server: SocketAddr, uuid: &str, password: &str) -> io::Result<Self> {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;

        let connecting = endpoint
            .connect_with(client_config(), server, "e2e.test")
            .map_err(|e| io::Error::other(format!("quic connect rejected: {e}")))?;
        let connection = deadline(connecting)
            .await?
            .map_err(|e| io::Error::other(format!("quic handshake failed: {e}")))?;

        let uuid_bytes = parse_uuid(uuid)?;

        // The token is bound to this TLS session, so it cannot be precomputed and it
        // cannot be replayed onto another connection.
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &uuid_bytes, password.as_bytes())
            .map_err(|e| io::Error::other(format!("could not export keying material: {e:?}")))?;

        let mut send = deadline(connection.open_uni())
            .await?
            .map_err(|e| io::Error::other(format!("could not open the auth stream: {e}")))?;

        let mut command = Vec::with_capacity(2 + 16 + 32);
        command.extend_from_slice(&[TUIC_VERSION, COMMAND_AUTHENTICATE]);
        command.extend_from_slice(&uuid_bytes);
        command.extend_from_slice(&token);
        deadline(send.write_all(&command))
            .await?
            .map_err(stream_err)?;
        // Finished, not left open: one uni stream carries exactly one command.
        send.finish().map_err(stream_err)?;

        Ok(Self {
            connection,
            endpoint,
        })
    }

    /// Opens a proxied TCP stream to `dest`.
    ///
    /// There is no response to read. `CONNECT` is address-only and the server begins
    /// relaying immediately, so a refused user is discovered by the stream closing
    /// under the first read rather than by a status byte.
    pub async fn open_tcp(&self, dest: SocketAddr) -> io::Result<TuicStream> {
        let (mut send, recv) = deadline(self.connection.open_bi())
            .await?
            .map_err(|e| io::Error::other(format!("could not open a stream: {e}")))?;

        let mut request = vec![TUIC_VERSION, COMMAND_CONNECT];
        request.extend_from_slice(&serialize_address(dest));
        deadline(send.write_all(&request))
            .await?
            .map_err(stream_err)?;

        Ok(TuicStream { send, recv })
    }

    /// Sends one unfragmented `PACKET` to `dest` as a QUIC datagram -- `native` mode.
    pub async fn send_udp_datagram(
        &self,
        assoc_id: u16,
        packet_id: u16,
        dest: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut datagram = vec![TUIC_VERSION, COMMAND_PACKET];
        datagram.extend_from_slice(&packet_header(assoc_id, packet_id, dest, payload.len()));
        datagram.extend_from_slice(payload);

        self.connection
            .send_datagram(datagram.into())
            .map_err(|e| io::Error::other(format!("could not send a datagram: {e}")))
    }

    /// Sends one unfragmented `PACKET` on its own uni stream -- `quic` mode.
    pub async fn send_udp_stream(
        &self,
        assoc_id: u16,
        packet_id: u16,
        dest: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut send = deadline(self.connection.open_uni())
            .await?
            .map_err(|e| io::Error::other(format!("could not open a packet stream: {e}")))?;

        let mut command = vec![TUIC_VERSION, COMMAND_PACKET];
        command.extend_from_slice(&packet_header(assoc_id, packet_id, dest, payload.len()));
        command.extend_from_slice(payload);
        deadline(send.write_all(&command))
            .await?
            .map_err(stream_err)?;
        send.finish().map_err(stream_err)
    }

    /// Reads one datagram and returns its assoc id and payload.
    ///
    /// Heartbeats are skipped rather than reported: the server sends one every ten
    /// seconds and a test waiting on an echo should not see one as a failure.
    pub async fn recv_udp_datagram(&self, wait: Duration) -> io::Result<(u16, Vec<u8>)> {
        let deadline_at = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline_at.saturating_duration_since(tokio::time::Instant::now());
            let datagram = tokio::time::timeout(remaining, self.connection.read_datagram())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no datagram came back"))?
                .map_err(|e| io::Error::other(format!("could not read a datagram: {e}")))?;

            if datagram.len() >= 2 && datagram[1] != COMMAND_PACKET {
                continue;
            }
            return parse_packet(&datagram);
        }
    }

    /// Accepts the uni stream the server opens for a `quic`-mode reply and reads one
    /// packet off it.
    ///
    /// Read field by field rather than to end: the server keeps this stream open for
    /// the life of the UDP session, so `read_to_end` would block until it times out.
    pub async fn recv_udp_stream(&self, wait: Duration) -> io::Result<(u16, Vec<u8>)> {
        let mut recv = tokio::time::timeout(wait, self.connection.accept_uni())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no packet stream was opened"))?
            .map_err(|e| io::Error::other(format!("could not accept a packet stream: {e}")))?;

        // version, command, assoc id, packet id, fragment total, fragment id, size.
        let mut packet = vec![0u8; 10];
        deadline(recv.read_exact(&mut packet))
            .await?
            .map_err(stream_err)?;

        // One more byte says which address form follows, and so how much of it there is.
        let mut kind = [0u8; 1];
        deadline(recv.read_exact(&mut kind))
            .await?
            .map_err(stream_err)?;
        packet.push(kind[0]);
        let address_len = match kind[0] {
            0xff => 0,
            0x00 => {
                let mut len = [0u8; 1];
                deadline(recv.read_exact(&mut len))
                    .await?
                    .map_err(stream_err)?;
                packet.push(len[0]);
                len[0] as usize + 2
            }
            0x01 => 4 + 2,
            0x02 => 16 + 2,
            other => return Err(io::Error::other(format!("bad address type {other}"))),
        };

        let payload_len = u16::from_be_bytes([packet[8], packet[9]]) as usize;
        let mut rest = vec![0u8; address_len + payload_len];
        deadline(recv.read_exact(&mut rest))
            .await?
            .map_err(stream_err)?;
        packet.extend_from_slice(&rest);

        parse_packet(&packet)
    }
}

impl Drop for TuicClient {
    fn drop(&mut self) {
        // Closed explicitly rather than left to fall out of scope: the server's
        // accounting context lives as long as the connection, and the tests read
        // counters as soon as a client goes away.
        self.connection.close(0u32.into(), b"");
        self.endpoint.close(0u32.into(), b"");
    }
}

/// A proxied stream, past the `CONNECT` header, carrying nothing but payload.
pub struct TuicStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl TuicStream {
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

// --------------------------------------------------------------------- wire helpers

/// The address form `read_address` expects: a type byte, the address, then the port.
fn serialize_address(address: SocketAddr) -> Vec<u8> {
    let mut bytes = match address {
        SocketAddr::V4(v4) => {
            let mut out = vec![0x01];
            out.extend_from_slice(&v4.ip().octets());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = vec![0x02];
            out.extend_from_slice(&v6.ip().octets());
            out
        }
    };
    bytes.extend_from_slice(&address.port().to_be_bytes());
    bytes
}

/// Everything in a `PACKET` between the command byte and the payload.
fn packet_header(assoc_id: u16, packet_id: u16, dest: SocketAddr, payload_len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(8 + 7);
    header.extend_from_slice(&assoc_id.to_be_bytes());
    header.extend_from_slice(&packet_id.to_be_bytes());
    // Fragment 0 of 1.
    header.extend_from_slice(&[1, 0]);
    header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    header.extend_from_slice(&serialize_address(dest));
    header
}

/// Splits a whole `PACKET` command into its assoc id and payload.
///
/// The address the server prefixes is the *source* of the reply, which for these
/// tests is always the echo peer, so it is parsed only far enough to be skipped.
fn parse_packet(packet: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    if packet.len() < 11 {
        return Err(io::Error::other(format!(
            "a {}-byte packet is too short",
            packet.len()
        )));
    }
    if packet[0] != TUIC_VERSION {
        return Err(io::Error::other(format!(
            "the server sent version {} rather than {TUIC_VERSION}",
            packet[0]
        )));
    }
    if packet[1] != COMMAND_PACKET {
        return Err(io::Error::other(format!(
            "the server sent command {} rather than a packet",
            packet[1]
        )));
    }

    let assoc_id = u16::from_be_bytes([packet[2], packet[3]]);
    let payload_len = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let start = match packet[10] {
        0xff => 11,
        0x00 => 11 + 1 + packet[11] as usize + 2,
        0x01 => 11 + 4 + 2,
        0x02 => 11 + 16 + 2,
        other => return Err(io::Error::other(format!("bad address type {other}"))),
    };
    if start + payload_len > packet.len() {
        return Err(io::Error::other("the payload runs past the packet"));
    }
    Ok((assoc_id, packet[start..start + payload_len].to_vec()))
}

/// Both spellings, since the wire carries raw bytes and a config may use either.
fn parse_uuid(uuid: &str) -> io::Result<[u8; 16]> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(io::Error::other(format!("{uuid:?} is not a uuid")));
    }
    let mut bytes = [0u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|e| io::Error::other(format!("{uuid:?} is not a uuid: {e}")))?;
    }
    Ok(bytes)
}

async fn deadline<T>(future: impl std::future::Future<Output = T>) -> io::Result<T> {
    tokio::time::timeout(IO_TIMEOUT, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tuic did not answer in time"))
}

/// quinn's stream errors are its own types rather than `io::Error`, and the harness
/// only ever reports them.
fn stream_err(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("quic stream error: {error}"))
}

// --------------------------------------------------------------------------- probes

/// Asks `dest` who it is through a fresh TUIC connection.
pub async fn reach(
    server: SocketAddr,
    uuid: &str,
    password: &str,
    dest: SocketAddr,
) -> io::Result<String> {
    let client = TuicClient::connect(server, uuid, password).await?;
    let mut stream = client.open_tcp(dest).await?;
    stream.write_all(b"who\n").await?;
    stream.read_line().await
}

/// True if the inbound will not carry traffic for this credential.
///
/// A TUIC rejection has no message. The server closes the connection after
/// `AUTHENTICATE`, so what a client sees is a stream that dies without answering --
/// and if it is quick enough off the mark, a `CONNECT` that appears to be written and
/// then goes quiet. Either way no line comes back, which is what this checks.
pub async fn denied(server: SocketAddr, uuid: &str, password: &str, dest: SocketAddr) -> bool {
    match tokio::time::timeout(Duration::from_secs(8), reach(server, uuid, password, dest)).await {
        Ok(Ok(name)) => {
            println!("      reached {name} when the credential should have been refused");
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
    uuid: &str,
    password: &str,
    dest: SocketAddr,
    upload: usize,
    download: usize,
) -> io::Result<usize> {
    let client = TuicClient::connect(server, uuid, password).await?;
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

/// True if a datagram makes it through the inbound and back -- `native` mode.
pub async fn udp_roundtrip(
    server: SocketAddr,
    uuid: &str,
    password: &str,
    dest: SocketAddr,
    wait: Duration,
) -> bool {
    let Ok(client) = TuicClient::connect(server, uuid, password).await else {
        return false;
    };
    if client.send_udp_datagram(1, 0, dest, b"ping").await.is_err() {
        return false;
    }
    match client.recv_udp_datagram(wait).await {
        Ok((_, payload)) => payload == b"ping",
        Err(e) => {
            println!("      {e}");
            false
        }
    }
}

/// True if a packet makes it through over uni streams and back -- `quic` mode.
///
/// The reply arrives on a stream the *server* opens, which is the half that used to
/// go out without its `[version, command]` header.
pub async fn udp_stream_roundtrip(
    server: SocketAddr,
    uuid: &str,
    password: &str,
    dest: SocketAddr,
    wait: Duration,
) -> bool {
    let Ok(client) = TuicClient::connect(server, uuid, password).await else {
        return false;
    };
    if client.send_udp_stream(2, 0, dest, b"ping").await.is_err() {
        return false;
    }
    match client.recv_udp_stream(wait).await {
        Ok((assoc_id, payload)) => assoc_id == 2 && payload == b"ping",
        Err(e) => {
            println!("      {e}");
            false
        }
    }
}

/// Sends `count` datagrams of `size` bytes, returning how many came back.
///
/// One in flight at a time: a test that cannot tell a lost datagram from a late one
/// cannot put an upper bound on bytes.
pub async fn udp_burst(
    server: SocketAddr,
    uuid: &str,
    password: &str,
    dest: SocketAddr,
    size: usize,
    count: usize,
) -> io::Result<usize> {
    let client = TuicClient::connect(server, uuid, password).await?;
    let payload = vec![b'u'; size];

    let mut echoed = 0usize;
    for packet in 0..count {
        client
            .send_udp_datagram(1, packet as u16, dest, &payload)
            .await?;
        match client.recv_udp_datagram(Duration::from_secs(3)).await {
            Ok((_, back)) if back == payload => echoed += 1,
            Ok((_, back)) => println!("      unexpected {}-byte reply", back.len()),
            Err(e) => println!("      {e}"),
        }
    }
    Ok(echoed)
}
