//! TCP listener — acepta conexiones y despacha una tarea por sesion.
//! Tambien inicia el servidor HTTP de metricas Prometheus en un puerto dedicado.
//!
//! El endpoint POST /rotate envia una senal de rotacion a todas las sesiones activas
//! via un tokio::sync::watch::Sender<u64>. Cada sesion subscribe al mismo canal.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::header::CONTENT_TYPE,
    response::IntoResponse,
    routing::get,
};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

use crate::{config::ValidConfig, control_plane, control_plane::BridgeCommand, http_relay::HttpRelay, identity::{ClientVerifyingIdentity, ServerIdentity}, metrics, metrics::MetricsState, quic, session, tls, vk_share};

/// Estado compartido del servidor HTTP de metricas.
/// Se pasa a los handlers axum via State extractor.
#[derive(Clone)]
pub(crate) struct MetricsAppState {
    pub prometheus_handle: PrometheusHandle,
}

pub async fn run(config: ValidConfig) -> anyhow::Result<()> {
    let metrics_handle = metrics::init()?;
    let metrics_state = MetricsState::new();

    // ── Canal de rotacion de claves — broadcast a todas las sesiones ─────────
    let (rotate_tx, _rotate_rx_init) = watch::channel(0u64);
    let rotate_tx = Arc::new(rotate_tx);

    // ── Cargar identidad del servidor (falla rapido si no existe o permisos incorrectos)
    let identity = Arc::new(
        ServerIdentity::load(&config.signing_key_path)
            .map_err(|e| anyhow::anyhow!(
                "no se pudo cargar el keypair del servidor: {e}\n\
                 Hint: ejecuta `latticeshield-bridge --keygen ./keys` para generar las claves."
            ))?,
    );
    info!(path = %config.signing_key_path.display(), "identidad del servidor cargada");

    // ── Cargar VK del cliente para autenticacion mutua (opcional) ───────────
    let client_vk: Option<Arc<ClientVerifyingIdentity>> = if config.client_auth_enabled {
        let path = config.client_vk_path.as_ref().expect("client_auth_enabled => client_vk_path is Some");
        let vk = ClientVerifyingIdentity::load(path)
            .map_err(|e| anyhow::anyhow!(
                "no se pudo cargar la VK del cliente desde {}: {e}\n\
                 Hint: distribuye la VK del cliente en la ruta configurada en [auth].client_vk_path.",
                path.display()
            ))?;
        info!(path = %path.display(), "autenticacion mutua habilitada — VK del cliente cargada");
        Some(Arc::new(vk))
    } else {
        None
    };

    // ── VkShareStore — initialised once at startup, shared across handlers ───
    let vk_store = vk_share::new_store();

    // ── Metrics HTTP server (puerto dedicado, plain HTTP) ───────────────────
    let tls_base_url = format!("https://{}", config.tls_listen_addr);
    let app_state = MetricsAppState {
        prometheus_handle: metrics_handle.clone(),
    };
    spawn_metrics_server(config.metrics_addr, app_state);

    // ── QUIC listener (optional — only when quic.enabled = true) ────────────
    if config.quic_enabled {
        spawn_quic_listener(config.clone());
    }

    // ── TLS listener (optional — only when tls.enabled = true) ──────────────
    if config.tls_enabled {
        let acceptor = tls::build_acceptor(&config.tls_cert_path, &config.tls_key_path)
            .map_err(|e| anyhow::anyhow!(
                "TLS setup failed: {e}\n\
                 Hint: use `latticeshield-bridge tls-keygen ./keys` to generate a self-signed cert."
            ))?;
        spawn_tls_listener(config.clone(), Arc::new(acceptor), Arc::clone(&vk_store));
    }

    // ── Admin PQC listener (:8445 — optional) ───────────────────────────────
    if config.admin_enabled {
        let path = config.admin_control_plane_vk_path.as_ref()
            .expect("admin_enabled => admin_control_plane_vk_path is Some — validado en Config::validate()");
        let cp_vk = crate::identity::ControlPlaneVerifyingIdentity::load(path)
            .map_err(|e| anyhow::anyhow!(
                "no se pudo cargar la VK del control plane desde {}: {e}\n\
                 Hint: ejecuta `latticeshield-bridge admin-keygen ./keys` para generar las claves.",
                path.display()
            ))?;
        crate::admin::spawn_admin_listener(
            config.admin_listen_addr,
            Arc::clone(&identity),
            Arc::new(cp_vk),
            Arc::clone(&vk_store),
            Arc::clone(&metrics_state),
            Arc::clone(&rotate_tx),
            metrics_handle.clone(),
            tls_base_url.clone(),
            crate::admin::AdminListenerConfig {
                rate_limit_per_second: config.admin_rate_limit_per_second,
                handshake_timeout_secs: config.admin_handshake_timeout_secs,
            },
        );
        info!(addr = %config.admin_listen_addr, "admin PQC listener iniciado");
    }

    // ── TCP proxy listener ───────────────────────────────────────────────────
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "LatticeShield escuchando");
    info!(backend = %config.backend_addr, "backend configurado");

    // ── Control plane heartbeat task (non-blocking, optional) ────────────────
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<BridgeCommand>(32);
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            tracing::info!(?cmd, "BridgeCommand received (stub handler — Mes 14)");
        }
    });
    if config.control_plane_enabled && !config.control_plane_endpoint.is_empty() {
        let cfg = config.clone();
        let ms = Arc::clone(&metrics_state);
        let id = Arc::clone(&identity);
        tokio::spawn(async move {
            control_plane::start(cfg, ms, id, cmd_tx).await;
        });
    }

    loop {
        let (socket, peer) = listener.accept().await?;
        let identity = Arc::clone(&identity);
        let client_vk = client_vk.clone();
        let ms = Arc::clone(&metrics_state);
        let rtx = Arc::clone(&rotate_tx);
        let cfg = config.clone();

        tokio::spawn(async move {
            if let Err(e) = session::handle(socket, peer, identity, client_vk, ms, rtx, cfg).await {
                error!(%peer, "sesion error: {e:#}");
            }
        });
    }
}

pub(crate) fn metrics_app(state: MetricsAppState) -> axum::Router {
    axum::Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Maximum HTTP head size for the TLS routing pre-read (8 KiB — matches nginx default).
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Result of reading the HTTP head from a TLS stream.
enum HeadResult {
    /// Full head found (ended with `\r\n\r\n`). Contains all bytes read so far.
    Complete(Vec<u8>),
    /// Buffer exceeded 8 KiB without finding end-of-headers — respond 400.
    TooLarge,
    /// Client closed the connection before sending a complete head.
    Eof,
}

/// Read bytes from `stream` into `buf` until `\r\n\r\n` is found.
///
/// Returns:
/// - `HeadResult::Complete(buf)` when the full head is in the buffer.
/// - `HeadResult::TooLarge` when `buf.len() >= MAX_HEAD_BYTES` before `\r\n\r\n`.
/// - `HeadResult::Eof` when the connection closes before the head is complete.
async fn read_http_head_inplace(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    buf: &mut Vec<u8>,
) -> HeadResult {
    loop {
        // Check limit before reading more — prevent unbounded memory growth
        if buf.len() >= MAX_HEAD_BYTES {
            return HeadResult::TooLarge;
        }

        let mut chunk = [0u8; 4096];
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(_) => return HeadResult::Eof,
        };
        if n == 0 {
            return HeadResult::Eof;
        }
        buf.extend_from_slice(&chunk[..n]);

        // Check again after reading (the chunk might have pushed us over the limit)
        if buf.len() >= MAX_HEAD_BYTES {
            // We have enough bytes — check if the head is complete before rejecting
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return HeadResult::Complete(buf.clone());
            }
            return HeadResult::TooLarge;
        }

        // Check if we have the end-of-headers marker
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return HeadResult::Complete(buf.clone());
        }
    }
}

/// Extract the token from a `GET /vk/:token` request line.
///
/// Returns `Some(token)` only when:
/// - The HTTP method is exactly `GET` (any other method returns `None` — passed through to relay)
/// - The request path starts with `/vk/`
///
/// Strict GET-only enforcement is intentional: a `POST /vk/...` that belongs to
/// the backend would otherwise be silently hijacked by the bridge.
fn extract_vk_token(buf: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(buf).ok()?.is_complete() {
        let method = req.method?;
        let path = req.path?;
        if method == "GET" {
            path.strip_prefix("/vk/").map(|t| t.to_string())
        } else {
            None
        }
    } else {
        None
    }
}

fn spawn_tls_listener(
    config: ValidConfig,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
    vk_store: vk_share::VkShareStore,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(config.tls_listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(addr = %config.tls_listen_addr, "TLS listener bind failed: {e}");
                return;
            }
        };
        info!(addr = %config.tls_listen_addr, "TLS (HTTPS) listener active");

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("TLS accept error: {e}");
                    continue;
                }
            };

            let acceptor = Arc::clone(&acceptor);
            let relay = HttpRelay::new(config.backend_addr);
            let vk_store = Arc::clone(&vk_store);

            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(mut tls_stream) => {
                        // ── Phase 5: Read HTTP head for routing ──────────────
                        let mut buf = Vec::with_capacity(4096);
                        match read_http_head_inplace(&mut tls_stream, &mut buf).await {
                            HeadResult::TooLarge => {
                                // Head exceeded 8 KiB — respond 400 and close
                                tracing::warn!(%peer, "TLS: HTTP head exceeded 8 KiB — 400");
                                let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let (_, mut w) = tokio::io::split(tls_stream);
                                let _ = w.write_all(resp).await;
                            }
                            HeadResult::Eof => {
                                // Client closed connection — nothing to do
                                tracing::debug!(%peer, "TLS: client EOF before head complete");
                            }
                            HeadResult::Complete(head_bytes) => {
                                if let Some(token) = extract_vk_token(&head_bytes) {
                                    // ── GET /vk/:token — handle locally ─────
                                    let response = vk_share::vk_response(&token, &vk_store, peer);
                                    let (_, mut w) = tokio::io::split(tls_stream);
                                    let _ = w.write_all(&response).await;
                                } else {
                                    // ── All other paths — relay to backend ──
                                    if let Err(e) = relay.handle_with_preread(tls_stream, peer, head_bytes).await {
                                        tracing::warn!(%peer, "TLS relay error: {e:#}");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%peer, "TLS handshake failed: {e}");
                    }
                }
            });
        }
    });
}

fn spawn_quic_listener(config: ValidConfig) {
    tokio::spawn(async move {
        let endpoint = match quic::build_endpoint(
            &config.quic_cert_path,
            &config.quic_key_path,
            config.quic_listen_addr,
        ) {
            Ok(e) => e,
            Err(e) => {
                error!(addr = %config.quic_listen_addr, "QUIC endpoint build failed: {e}");
                return;
            }
        };
        info!(addr = %config.quic_listen_addr, "QUIC listener active");

        let relay = quic::QuicRelay::new(config.backend_addr);

        loop {
            let connecting = match endpoint.accept().await {
                Some(c) => c,
                None => break, // endpoint closed cleanly
            };
            let relay = relay.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(conn) => {
                        if let Err(e) = relay.relay_connection(conn).await {
                            tracing::warn!("QUIC connection error: {e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("QUIC handshake failed: {e}");
                    }
                }
            });
        }
    });
}

fn spawn_metrics_server(addr: SocketAddr, state: MetricsAppState) {
    tokio::spawn(async move {
        let app = metrics_app(state);

        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "metricas Prometheus disponibles en /metrics");
                if let Err(e) = axum::serve(listener, app).await {
                    error!(%addr, "error en servidor de metricas: {e}");
                }
            }
            Err(e) => {
                error!(%addr, "no se pudo iniciar servidor de metricas: {e}");
            }
        }
    });
}

async fn metrics_handler(State(state): State<MetricsAppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.prometheus_handle.render(),
    )
}


// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::body::Body;
    use tower::ServiceExt;

    fn make_test_state() -> MetricsAppState {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        MetricsAppState { prometheus_handle: recorder.handle() }
    }

    #[tokio::test]
    async fn post_rotate_returns_404_on_metrics_app() {
        let state = make_test_state();
        let app = metrics_app(state);

        let req = Request::builder()
            .method("POST")
            .uri("/rotate")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_vk_token_returns_404_on_metrics_app() {
        let state = make_test_state();
        let app = metrics_app(state);

        let req = Request::builder()
            .method("POST")
            .uri("/vk-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_metrics_still_returns_200() {
        let state = make_test_state();
        let app = metrics_app(state);

        let req = Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── extract_vk_token unit tests (pure, no I/O) ────────────────────────────

    #[test]
    fn extract_vk_token_matches_get_vk_prefix() {
        let req = b"GET /vk/some-uuid-here HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), Some("some-uuid-here".to_string()));
    }

    #[test]
    fn extract_vk_token_does_not_match_post_vk() {
        // POST /vk/:token must NOT be intercepted — pass through to relay
        let req = b"POST /vk/some-uuid-here HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), None);
    }

    #[test]
    fn extract_vk_token_does_not_match_put_vk() {
        let req = b"PUT /vk/some-uuid-here HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), None);
    }

    #[test]
    fn extract_vk_token_does_not_match_non_vk_path() {
        let req = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), None);
    }

    #[test]
    fn extract_vk_token_does_not_match_root_path() {
        let req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), None);
    }

    #[test]
    fn extract_vk_token_does_not_match_partial_vk_prefix() {
        // /vkinfo does NOT start with /vk/ — must not be intercepted
        let req = b"GET /vkinfo HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_vk_token(req), None);
    }

    #[test]
    fn extract_vk_token_extracts_uuid_v4_token() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = format!("GET /vk/{uuid} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(extract_vk_token(req.as_bytes()), Some(uuid.to_string()));
    }

    #[test]
    fn extract_vk_token_partial_head_returns_none() {
        // Incomplete head — no \r\n\r\n terminator
        let partial = b"GET /vk/some-token HTTP/1.1\r\nHost: local";
        assert_eq!(extract_vk_token(partial), None);
    }

    // ── read_http_head_inplace unit tests (async, uses make_tls_pair from http_relay) ──

    #[tokio::test]
    async fn read_http_head_returns_complete_on_valid_request() {
        use tokio::io::AsyncWriteExt as _;
        use crate::http_relay::tests_pub::make_tls_pair;

        let (mut client_tls, mut server_tls, _peer) = make_tls_pair().await;
        let req = b"GET /vk/token123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        client_tls.write_all(req).await.unwrap();
        // Close client write side so server read terminates
        drop(client_tls);

        let mut buf = Vec::new();
        let result = read_http_head_inplace(&mut server_tls, &mut buf).await;
        assert!(
            matches!(result, HeadResult::Complete(_)),
            "expected Complete, got something else"
        );
        assert!(buf.windows(4).any(|w| w == b"\r\n\r\n"), "buf must contain \\r\\n\\r\\n");
    }

    #[tokio::test]
    async fn read_http_head_returns_too_large_on_oversized_head() {
        use tokio::io::AsyncWriteExt as _;
        use crate::http_relay::tests_pub::make_tls_pair;

        let (mut client_tls, mut server_tls, _peer) = make_tls_pair().await;
        // 9 KiB of garbage with no \r\n\r\n
        let oversized = vec![b'X'; 9 * 1024];
        client_tls.write_all(&oversized).await.unwrap();
        drop(client_tls);

        let mut buf = Vec::new();
        let result = read_http_head_inplace(&mut server_tls, &mut buf).await;
        assert!(
            matches!(result, HeadResult::TooLarge),
            "expected TooLarge for oversized head"
        );
    }

    #[tokio::test]
    async fn read_http_head_returns_eof_on_empty_connection() {
        use crate::http_relay::tests_pub::make_tls_pair;

        let (client_tls, mut server_tls, _peer) = make_tls_pair().await;
        // Drop client immediately — server gets EOF
        drop(client_tls);

        let mut buf = Vec::new();
        let result = read_http_head_inplace(&mut server_tls, &mut buf).await;
        assert!(
            matches!(result, HeadResult::Eof),
            "expected Eof when client drops connection"
        );
    }
}
