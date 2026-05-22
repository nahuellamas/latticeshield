//! QUIC listener — accepts quinn connections and relays each bidi stream
//! to the backend over an independent TCP connection.
//! No HTTP/3 framing. Raw stream relay.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpStream;
use tracing::warn;

use crate::tls;

/// Relays each QUIC bidi stream to a fresh backend TCP connection.
/// Must derive Clone so it can be moved into per-connection and per-stream spawned tasks.
#[derive(Clone)]
pub struct QuicRelay {
    pub backend_addr: SocketAddr,
}

/// Build a quinn Endpoint bound to `listen_addr` using the cert+key at the given paths.
pub fn build_endpoint(
    cert_path: &Path,
    key_path: &Path,
    listen_addr: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    let rustls_config = tls::build_server_config(cert_path, key_path)?;
    let quinn_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .context("failed to build quinn crypto config from rustls ServerConfig")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto));
    let endpoint = quinn::Endpoint::server(server_config, listen_addr)
        .with_context(|| format!("failed to bind QUIC endpoint on {listen_addr}"))?;
    Ok(endpoint)
}

impl QuicRelay {
    pub fn new(backend_addr: SocketAddr) -> Self {
        Self { backend_addr }
    }

    /// Accept bidi streams from a QUIC connection and spawn a relay task per stream.
    /// Returns Ok on normal connection close (ApplicationClosed, LocallyClosed).
    /// Returns Err on unexpected connection errors.
    pub async fn relay_connection(&self, connection: quinn::Connection) -> anyhow::Result<()> {
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let relay = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = relay.relay_stream(send, recv).await {
                            warn!("QUIC stream relay error: {e:#}");
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::LocallyClosed) => {
                    break; // normal client-initiated close
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("QUIC connection error: {e}"));
                }
            }
        }
        Ok(())
    }

    /// Relay a single QUIC bidi stream to a fresh backend TCP connection.
    ///
    /// Uses `tokio::try_join!` (NOT `tokio::select!`) so BOTH copy directions run to
    /// completion. `select!` would race and cancel the losing direction, dropping pending
    /// bytes — wrong for QUIC where half-close semantics matter.
    ///
    /// IMPORTANT: `send.finish()` MUST be called explicitly after try_join! completes.
    /// In quinn 0.11, finish() is NOT called on SendStream::drop(). Omitting this
    /// causes the QUIC peer to hang forever waiting for EOF.
    pub async fn relay_stream(
        &self,
        mut send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> anyhow::Result<()> {
        let backend = TcpStream::connect(self.backend_addr)
            .await
            .with_context(|| {
                format!("QUIC relay: backend connect failed: {}", self.backend_addr)
            })?;

        let (mut backend_r, mut backend_w) = tokio::io::split(backend);
        let mut recv = recv; // quinn RecvStream implements AsyncRead directly in quinn 0.11

        // Run both copy directions concurrently. try_join! waits for BOTH to finish.
        // When QUIC client closes its send side, recv returns Ok(0) via AsyncRead → copy A done.
        // When backend closes connection, backend_r returns Ok(0) → copy B done.
        let _ = tokio::try_join!(
            tokio::io::copy(&mut recv, &mut backend_w),
            tokio::io::copy(&mut backend_r, &mut send)
        );

        // MANDATORY: signal EOF to the QUIC peer. NOT called on Drop in quinn 0.11.
        if let Err(e) = send.finish() {
            warn!("QUIC SendStream::finish() error: {e}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;

    fn make_self_signed_files() -> (NamedTempFile, NamedTempFile) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen failed");
        let mut cert_f = NamedTempFile::new().unwrap();
        let mut key_f = NamedTempFile::new().unwrap();
        cert_f.write_all(certified.cert.pem().as_bytes()).unwrap();
        key_f
            .write_all(certified.key_pair.serialize_pem().as_bytes())
            .unwrap();
        (cert_f, key_f)
    }

    #[tokio::test]
    async fn build_endpoint_valid_cert_ok() {
        let (cert_f, key_f) = make_self_signed_files();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = build_endpoint(cert_f.path(), key_f.path(), addr);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    #[test]
    fn build_endpoint_missing_cert_err() {
        let key_f = NamedTempFile::new().unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let err = build_endpoint(Path::new("/nonexistent/tls.crt"), key_f.path(), addr)
            .expect_err("should be Err")
            .to_string();
        assert!(!err.is_empty(), "expected non-empty error");
    }

    #[test]
    fn build_endpoint_missing_key_err() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut cert_f = NamedTempFile::new().unwrap();
        cert_f.write_all(certified.cert.pem().as_bytes()).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let err = build_endpoint(cert_f.path(), Path::new("/nonexistent/tls.key"), addr)
            .expect_err("should be Err")
            .to_string();
        assert!(!err.is_empty(), "expected non-empty error");
    }

    #[tokio::test]
    async fn backend_down_stream_returns_err_no_panic() {
        // Find a port that immediately refuses connections (bind then drop listener)
        let temp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = temp_listener.local_addr().unwrap();
        drop(temp_listener); // port is now closed — connect will get ECONNREFUSED immediately

        let relay = QuicRelay::new(backend_addr);

        // We need real quinn streams. Build a minimal loopback using make_quic_pair.
        let (client_endpoint, server_endpoint) = make_quic_pair().await;

        // Connect client to server
        let server_addr = server_endpoint.local_addr().unwrap();
        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

        let accept_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            incoming.await.unwrap()
        });

        let client_conn = connecting.await.unwrap();
        let server_conn = accept_task.await.unwrap();

        // Run client and server concurrently:
        // In quinn 0.11, open_bi() does NOT send a STREAM frame until data is written.
        // server_conn.accept_bi() only returns when it receives that STREAM frame.
        // We must write data from the client side concurrently so accept_bi() unblocks.
        let relay_clone = relay.clone();
        let server_task = tokio::spawn(async move {
            let (server_send, server_recv) = server_conn.accept_bi().await.unwrap();
            relay_clone.relay_stream(server_send, server_recv).await
        });

        // Write a byte to trigger the STREAM frame so server's accept_bi() unblocks
        let (mut client_send, _client_recv) = client_conn.open_bi().await.unwrap();
        client_send.write_all(b"x").await.unwrap();
        client_send.finish().unwrap();

        // relay_stream should error (cannot connect to backend)
        let result = server_task.await.unwrap();
        assert!(result.is_err(), "expected Err when backend is down");
    }

    #[tokio::test]
    async fn relay_stream_forwards_bytes_end_to_end() {
        // Spin up a mock TCP backend
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut conn, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            // echo back
            conn.write_all(&buf[..n]).await.unwrap();
            buf[..n].to_vec()
        });

        let relay = QuicRelay::new(backend_addr);
        let (client_endpoint, server_endpoint) = make_quic_pair().await;

        let server_addr = server_endpoint.local_addr().unwrap();
        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

        let relay_clone = relay.clone();
        // Use a channel to signal when relay_stream completes, while keeping server_conn alive
        let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel::<anyhow::Result<()>>();
        let accept_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let server_conn = incoming.await.unwrap();
            let (server_send, server_recv) = server_conn.accept_bi().await.unwrap();
            let result = relay_clone.relay_stream(server_send, server_recv).await;
            // Signal done but keep server_conn alive until this task is awaited
            let _ = relay_done_tx.send(result);
            // Hold server_conn alive briefly so the stream FIN propagates
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(server_conn);
        });

        let client_conn = connecting.await.unwrap();
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();

        let payload = b"hello from QUIC";
        client_send.write_all(payload).await.unwrap();
        client_send.finish().unwrap();

        // Wait for relay to finish processing (backend echoed, send.finish() called)
        let relay_result = relay_done_rx.await.unwrap();
        assert!(
            relay_result.is_ok(),
            "relay_stream should succeed: {:?}",
            relay_result
        );

        // Read the echo response from backend via relay.
        let mut resp_buf = Vec::new();
        tokio::io::copy(&mut client_recv, &mut resp_buf)
            .await
            .unwrap();

        let _ = accept_task.await;
        let received = backend_task.await.unwrap();

        assert_eq!(&received, payload as &[u8]);
        assert_eq!(&resp_buf, payload as &[u8]);
    }

    #[tokio::test]
    async fn relay_connection_normal_close_returns_ok() {
        // Mock backend
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = backend_listener.accept().await;
        });

        let relay = QuicRelay::new(backend_addr);
        let (client_endpoint, server_endpoint) = make_quic_pair().await;

        let server_addr = server_endpoint.local_addr().unwrap();
        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();

        let relay_clone = relay.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let server_conn = incoming.await.unwrap();
            relay_clone.relay_connection(server_conn).await
        });

        let client_conn = connecting.await.unwrap();
        // Close the connection
        client_conn.close(0u32.into(), b"done");

        let result = server_task.await.unwrap();
        assert!(
            result.is_ok(),
            "expected Ok on normal close, got: {:?}",
            result.err()
        );
    }

    /// Build a (client_endpoint, server_endpoint) pair using rcgen self-signed cert.
    /// Client uses a custom ServerCertVerifier that accepts self-signed certs (test only).
    async fn make_quic_pair() -> (quinn::Endpoint, quinn::Endpoint) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
        use std::sync::Arc;

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der = certified.key_pair.serialize_der();

        // ── Server endpoint ──────────────────────────────────────────────────
        let cert_chain = vec![cert_der.clone()];
        let key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_rustls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let quinn_server_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_rustls_config))
                .unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_server_crypto));
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

        // ── Client endpoint — trust-any verifier (test only) ─────────────────
        #[derive(Debug)]
        struct AcceptAnyCert;

        impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }

        let client_rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();

        let quinn_client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_rustls_config))
                .unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(quinn_client_crypto));

        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        (client_endpoint, server_endpoint)
    }
}
