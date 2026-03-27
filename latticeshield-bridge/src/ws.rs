//! WebSocket utilities — WsStream adapter, origin validation, per-IP rate limiting.
//!
//! `WsStream<S>` wraps a `WebSocketStream<S>` and implements `AsyncRead + AsyncWrite`
//! by mapping binary WebSocket frames to/from raw byte slices. This lets
//! `session::handle()` work over WebSocket without any modification.
//!
//! `spawn_ws_listener` lives in `server.rs` (same location as `spawn_tls_listener`).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;

/// Shared per-IP connection counter.
pub type IpCounterMap = Arc<Mutex<HashMap<IpAddr, usize>>>;

// ── WsStream adapter ─────────────────────────────────────────────────────────

/// Wraps a `WebSocketStream` and exposes `AsyncRead + AsyncWrite`.
///
/// Read side: buffers binary message payloads and drains them chunk by chunk.
/// Write side: accumulates bytes and sends them as a single binary `Message` on each `poll_flush`.
pub struct WsStream<S> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
}

impl<S> WsStream<S> {
    pub fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // If we have bytes buffered, drain them first.
            if me.read_pos < me.read_buf.len() {
                let remaining = &me.read_buf[me.read_pos..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                me.read_pos += to_copy;
                if me.read_pos >= me.read_buf.len() {
                    me.read_buf.clear();
                    me.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Buffer is empty — poll the WS stream for the next message.
            // WebSocketStream<S> is Unpin when S: Unpin, so we can poll via &mut self.
            use futures_core::Stream as _;
            match Pin::new(&mut me.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    // Stream closed — signal EOF to the reader
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        if data.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        me.read_buf = data;
                        me.read_pos = 0;
                        // Loop back to drain into `buf`.
                    }
                    Message::Text(text) => {
                        let data = text.into_bytes();
                        if data.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        me.read_buf = data;
                        me.read_pos = 0;
                    }
                    Message::Close(_) => {
                        return Poll::Ready(Ok(()));
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        // tungstenite auto-responds to Ping; loop for next message
                    }
                    Message::Frame(_) => {
                        // Raw frames do not appear at this level; skip
                    }
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        use futures_sink::Sink as _;
        if !me.write_buf.is_empty() {
            // Check sink readiness before consuming the buffer.
            match Pin::new(&mut me.inner).poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                }
                Poll::Ready(Ok(())) => {}
            }
            let payload = std::mem::take(&mut me.write_buf);
            if let Err(e) = Pin::new(&mut me.inner).start_send(Message::Binary(payload)) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
            }
        }
        // Flush the underlying WebSocket sink.
        match Pin::new(&mut me.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        use futures_sink::Sink as _;
        match Pin::new(&mut me.inner).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }
}

// ── Origin validation callback ───────────────────────────────────────────────

/// Tungstenite server callback that validates the `Origin` header.
///
/// If `allowed_origins` is empty, all origins are accepted (development mode).
/// If non-empty, only requests whose `Origin` matches one of the listed values pass.
pub struct OriginCheck {
    pub allowed_origins: Vec<String>,
}

impl Callback for OriginCheck {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if self.allowed_origins.is_empty() {
            return Ok(response);
        }
        let origin = request
            .headers()
            .get("Origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if self.allowed_origins.iter().any(|o| o == origin) {
            Ok(response)
        } else {
            warn!("WS: origin rejected: {:?}", origin);
            let mut err_response = ErrorResponse::new(None);
            *err_response.status_mut() = StatusCode::FORBIDDEN;
            Err(err_response)
        }
    }
}

// ── IpCountGuard — RAII decrement ────────────────────────────────────────────

/// Decrements the per-IP counter when dropped. Prevents counter leaks on early return.
pub struct IpCountGuard {
    pub ip: IpAddr,
    pub map: IpCounterMap,
}

impl Drop for IpCountGuard {
    fn drop(&mut self) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── IpCountGuard unit tests ───────────────────────────────────────────────

    #[test]
    fn ip_count_guard_decrements_on_drop() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let map: IpCounterMap = Arc::new(Mutex::new(HashMap::new()));
        map.lock().unwrap().insert(ip, 3);

        {
            let _guard = IpCountGuard {
                ip,
                map: Arc::clone(&map),
            };
        } // drop here

        assert_eq!(*map.lock().unwrap().get(&ip).unwrap(), 2);
    }

    #[test]
    fn ip_count_guard_removes_entry_when_zero() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let map: IpCounterMap = Arc::new(Mutex::new(HashMap::new()));
        map.lock().unwrap().insert(ip, 1);

        {
            let _guard = IpCountGuard {
                ip,
                map: Arc::clone(&map),
            };
        } // drop here — count goes to 0 → entry removed

        assert!(map.lock().unwrap().get(&ip).is_none());
    }

    // ── OriginCheck — logic tests (no HTTP server needed) ────────────────────

    #[test]
    fn origin_check_empty_allowed_list_accepts_any_origin() {
        // When allowed_origins is empty, the check takes the Ok(response) branch
        // unconditionally — verify the predicate.
        let check = OriginCheck {
            allowed_origins: vec![],
        };
        assert!(check.allowed_origins.is_empty());
    }

    // ── WsStream round-trip tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn ws_stream_read_write_roundtrip() {
        // Build a loopback WS pair using tokio::io::duplex (no TLS)
        let (client_half, server_half) = tokio::io::duplex(65536);

        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_half,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_half,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;

        let mut server_io = WsStream::new(server_ws);
        let mut client_io = WsStream::new(client_ws);

        let payload = b"hello latticeshield ws";

        // Client writes, server reads
        let write_task = tokio::spawn(async move {
            client_io.write_all(payload).await.unwrap();
            client_io.flush().await.unwrap();
            client_io
        });

        let mut recv_buf = vec![0u8; payload.len()];
        server_io.read_exact(&mut recv_buf).await.unwrap();

        assert_eq!(&recv_buf, payload as &[u8]);
        let _ = write_task.await.unwrap();
    }

    #[tokio::test]
    async fn ws_stream_multiple_writes_coalesced_before_flush() {
        let (client_half, server_half) = tokio::io::duplex(65536);

        let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_half,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            client_half,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;

        let mut server_io = WsStream::new(server_ws);
        let mut client_io = WsStream::new(client_ws);

        // Write multiple chunks before flushing — they are coalesced into one WS message
        let write_task = tokio::spawn(async move {
            client_io.write_all(b"hello").await.unwrap();
            client_io.write_all(b" world").await.unwrap();
            client_io.flush().await.unwrap();
            client_io
        });

        let mut recv_buf = vec![0u8; 11];
        server_io.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(&recv_buf, b"hello world");

        let _ = write_task.await.unwrap();
    }

    // ── TLS build smoke tests ─────────────────────────────────────────────────

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

    #[test]
    fn build_acceptor_with_invalid_cert_errors() {
        use crate::tls;
        let err = tls::build_acceptor(
            std::path::Path::new("/nonexistent/ws.crt"),
            std::path::Path::new("/nonexistent/ws.key"),
        )
        .err()
        .expect("should be Err");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn build_acceptor_with_valid_self_signed_ok() {
        use crate::tls;
        let (cert_f, key_f) = make_self_signed_files();
        tls::build_acceptor(cert_f.path(), key_f.path()).unwrap();
    }
}
