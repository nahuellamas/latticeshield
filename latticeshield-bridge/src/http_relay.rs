//! HTTP/1.1 dumb relay — parse request head, forward verbatim, stream response back.

use std::net::SocketAddr;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

const HEAD_BUF_MAX: usize = 8 * 1024; // 8 KiB — matches nginx default

/// Returns the byte offset where the HTTP head ends (exclusive).
/// Returns None if Status::Partial (caller should read more).
/// Returns Err on parse error.
fn parse_head(buf: &[u8]) -> anyhow::Result<Option<usize>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf)? {
        httparse::Status::Complete(consumed) => Ok(Some(consumed)),
        httparse::Status::Partial => Ok(None),
    }
}

/// Handles TLS-terminated HTTP/1.1 connections and relays them to a plain TCP backend.
pub struct HttpRelay {
    pub backend_addr: SocketAddr,
}

impl HttpRelay {
    pub fn new(backend_addr: SocketAddr) -> Self {
        Self { backend_addr }
    }

    /// Relay one HTTP/1.1 connection from a TLS stream to the backend.
    pub async fn handle(
        &self,
        stream: TlsStream<TcpStream>,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        let (mut client_r, mut client_w) = tokio::io::split(stream);

        // ── Read HTTP head (up to HEAD_BUF_MAX bytes) ───────────────────────
        let mut buf = Vec::with_capacity(4096);
        loop {
            let mut chunk = [0u8; 4096];
            let n = client_r
                .read(&mut chunk)
                .await
                .context("reading from TLS client")?;
            if n == 0 {
                // Client closed before sending a complete head
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);

            match parse_head(&buf) {
                Ok(Some(_consumed)) => break,
                Ok(None) => {
                    if buf.len() >= HEAD_BUF_MAX {
                        // Head too large — return 400
                        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = client_w.write_all(resp).await;
                        return Ok(());
                    }
                    // Keep reading
                }
                Err(e) => {
                    warn!(%peer, "HTTP parse error: {e}");
                    let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = client_w.write_all(resp).await;
                    return Ok(());
                }
            }
        }

        // Log the first line for debug visibility
        if let Ok(head_str) = std::str::from_utf8(&buf) {
            if let Some(first_line) = head_str.lines().next() {
                debug!(%peer, "HTTP request: {first_line}");
            }
        }

        // ── Connect to backend ───────────────────────────────────────────────
        let backend = match TcpStream::connect(self.backend_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(%peer, "backend connect failed: {e}");
                let resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = client_w.write_all(resp).await;
                return Ok(());
            }
        };

        let (mut backend_r, mut backend_w) = tokio::io::split(backend);

        // ── Forward all buffered bytes (head + any body already read) ────────
        backend_w
            .write_all(&buf)
            .await
            .context("writing head to backend")?;

        // ── Bidirectional relay ──────────────────────────────────────────────
        let client_to_backend = tokio::io::copy(&mut client_r, &mut backend_w);
        let backend_to_client = tokio::io::copy(&mut backend_r, &mut client_w);

        tokio::select! {
            r = client_to_backend => { r.context("client→backend copy")?; }
            r = backend_to_client => { r.context("backend→client copy")?; }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // ── parse_head unit tests (pure, no I/O) ─────────────────────────────────

    #[test]
    fn parse_head_complete_get() {
        let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let consumed = parse_head(req).unwrap().unwrap();
        assert_eq!(consumed, req.len()); // entire input is the head
    }

    #[test]
    fn parse_head_partial_returns_none() {
        let partial = b"GET / HTTP/1.1\r\nHost: local";
        assert!(parse_head(partial).unwrap().is_none());
    }

    #[test]
    fn parse_head_with_body_returns_head_end() {
        let req = b"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
        let consumed = parse_head(req).unwrap().unwrap();
        // consumed should point to end of headers (before "hello")
        assert!(consumed < req.len());
        assert_eq!(&req[consumed..], b"hello");
    }

    // ── handle() integration tests ────────────────────────────────────────────

    /// Spin up a real TLS server+client pair using rcgen self-signed cert.
    async fn make_tls_pair() -> (
        tokio_rustls::client::TlsStream<TcpStream>,
        TlsStream<TcpStream>,
        SocketAddr,
    ) {
        use std::sync::Arc;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::{TlsAcceptor, TlsConnector};
        use tokio_rustls::rustls;

        // Generate self-signed cert
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der = certified.key_pair.serialize_der();

        // Server config
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        // Client config (trusts our self-signed cert)
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(cert_der))
            .unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        // Bind a local listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept in background
        let accept_task = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            (tls, peer)
        });

        // Connect from client side
        let tcp_client = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let client_tls = connector.connect(server_name, tcp_client).await.unwrap();

        let (server_tls, peer) = accept_task.await.unwrap();
        (client_tls, server_tls, peer)
    }

    #[tokio::test]
    async fn relay_get_request_forwarded_to_backend() {
        // Spin up a mock backend TCP server
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            let (mut conn, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            let received = buf[..n].to_vec();
            // Send a minimal HTTP response
            conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            received
        });

        // Build TLS pair
        let (mut client_tls, server_tls, peer) = make_tls_pair().await;

        // Run relay in background
        let relay = HttpRelay::new(backend_addr);
        tokio::spawn(async move {
            relay.handle(server_tls, peer).await.unwrap();
        });

        // Send HTTP GET from client
        let req = b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
        client_tls.write_all(req).await.unwrap();

        // Read response
        let mut resp_buf = vec![0u8; 256];
        let n = client_tls.read(&mut resp_buf).await.unwrap();
        let resp = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp.contains("200"), "expected 200 in response, got: {resp}");

        // Verify backend received the full raw request bytes
        let received = backend_task.await.unwrap();
        assert_eq!(&received, req as &[u8]);
    }

    #[tokio::test]
    async fn relay_backend_down_returns_502() {
        // Use a port that is definitely not listening
        let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let (mut client_tls, server_tls, peer) = make_tls_pair().await;
        let relay = HttpRelay::new(backend_addr);
        tokio::spawn(async move {
            relay.handle(server_tls, peer).await.ok();
        });

        client_tls
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 256];
        let n = client_tls.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.contains("502"), "expected 502, got: {resp}");
    }

    #[tokio::test]
    async fn relay_oversized_head_returns_400() {
        // Send >8KiB of headers without \r\n\r\n — should get 400
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        // Backend task — just accept so the port exists; relay should 400 before connecting
        tokio::spawn(async move { backend_listener.accept().await.ok() });

        let (mut client_tls, server_tls, peer) = make_tls_pair().await;
        let relay = HttpRelay::new(backend_addr);
        tokio::spawn(async move {
            relay.handle(server_tls, peer).await.ok();
        });

        // Send 9 KiB of garbage with no \r\n\r\n
        let oversized = vec![b'X'; 9 * 1024];
        client_tls.write_all(&oversized).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = client_tls.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.contains("400"), "expected 400, got: {resp}");
    }

    #[tokio::test]
    async fn relay_post_with_body_forwarded_to_backend() {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            let (mut conn, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = conn.read(&mut buf).await.unwrap();
            let received = buf[..n].to_vec();
            conn.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            received
        });

        let (mut client_tls, server_tls, peer) = make_tls_pair().await;
        let relay = HttpRelay::new(backend_addr);
        tokio::spawn(async move {
            relay.handle(server_tls, peer).await.ok();
        });

        let body = b"hello=world";
        let req = format!(
            "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        client_tls.write_all(req.as_bytes()).await.unwrap();

        let mut resp_buf = vec![0u8; 256];
        let n = client_tls.read(&mut resp_buf).await.unwrap();
        let resp = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp.contains("201"), "expected 201, got: {resp}");

        let received = backend_task.await.unwrap();
        let received_str = std::str::from_utf8(&received).unwrap();
        assert!(received_str.contains("POST /submit"), "missing request line");
        assert!(received_str.contains("hello=world"), "body not forwarded");
    }
}
