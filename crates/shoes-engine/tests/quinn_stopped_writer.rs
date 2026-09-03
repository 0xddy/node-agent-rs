//! Exercise the patched transport through public Quinn APIs and real loopback UDP.
//!
//! A zero initial receive window keeps connection credit exhausted after STOP:
//! there is no received payload whose discard could automatically grant MAX_DATA
//! and accidentally hide the terminal-error ordering bug. This isolates the
//! transport contract; it does not claim to reproduce a browser's cancellation.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

const DEADLINE: Duration = Duration::from_secs(5);

// The shared fixture certificate is a CA certificate without SANs. Pin its exact
// bytes while still verifying TLS signatures; no other certificate is accepted.
#[derive(Debug)]
struct PinnedTestCertificate {
    certificate: CertificateDer<'static>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinnedTestCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if certificate != &self.certificate {
            return Err(rustls::Error::General("unexpected test certificate".into()));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    let certificate = CertificateDer::from_pem_slice(include_bytes!("fixtures/test.crt")).unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/test.key")).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

    let verifier = PinnedTestCertificate {
        certificate,
        algorithms: provider.signature_verification_algorithms,
    };
    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .receive_window(0u32.into())
        .stream_receive_window(4096u32.into());
    client_config.transport_config(Arc::new(transport));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    (server, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_stop_unblocks_a_writer_without_connection_credit() {
    tokio::time::timeout(Duration::from_secs(20), exercise_stopped_writer())
        .await
        .expect("the complete stop/reopen scenario must remain bounded");
}

async fn exercise_stopped_writer() {
    let (server_endpoint, client_endpoint) = endpoints();
    let handshake = async {
        let client_connecting = client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "e2e.test")
            .unwrap();
        let server_connecting = async { server_endpoint.accept().await.unwrap().await.unwrap() };
        let (server, client) = tokio::join!(server_connecting, client_connecting);
        (server, client.unwrap())
    };
    let (server, client) = tokio::time::timeout(DEADLINE, handshake).await.unwrap();

    // A bidirectional stream becomes visible to the server after the client's
    // request. Receiving request bytes uses the opposite flow-control direction.
    let (mut request, mut response) = client.open_bi().await.unwrap();
    request.write_all(b"download").await.unwrap();
    request.finish().unwrap();
    let (mut writer, mut reader) = tokio::time::timeout(DEADLINE, server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reader.read_to_end(64).await.unwrap(), b"download");

    let mut write = Box::pin(writer.write(b"payload"));
    poll_fn(|cx| {
        assert!(
            write.as_mut().poll(cx).is_pending(),
            "write must await MAX_DATA"
        );
        Poll::Ready(())
    })
    .await;
    let reason = 42u32.into();
    response.stop(reason).unwrap();
    let stopped = tokio::time::timeout(DEADLINE, write.as_mut()).await;
    assert!(
        matches!(stopped, Ok(Err(quinn::WriteError::Stopped(code))) if code == reason),
        "STOP must terminate the existing blocked writer without requiring extra credit: {stopped:?}"
    );
    drop(write);
    // This is the same public Drop path reached when HY2's relay task returns.
    drop(writer);
    drop(reader);
    drop(request);
    drop(response);

    // A reset does not invent peer-owned credit. Explicitly grant a new receive
    // window, then prove a fresh request succeeds on the original connection.
    client.set_receive_window(4096u32.into());
    let next_request = async {
        let (mut request, mut response) = client.open_bi().await.unwrap();
        request.write_all(b"probe").await.unwrap();
        request.finish().unwrap();
        let (mut writer, mut reader) = server.accept_bi().await.unwrap();
        assert_eq!(reader.read_to_end(64).await.unwrap(), b"probe");
        writer.write_all(b"ok").await.unwrap();
        writer.finish().unwrap();
        assert_eq!(response.read_to_end(64).await.unwrap(), b"ok");
    };
    tokio::time::timeout(DEADLINE, next_request).await.unwrap();
    assert!(server.close_reason().is_none());
    assert!(client.close_reason().is_none());
    client.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
}
