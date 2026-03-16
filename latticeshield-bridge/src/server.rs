//! TCP listener — acepta conexiones y despacha una tarea por sesion.
//! Tambien inicia el servidor HTTP de metricas Prometheus en un puerto dedicado.
//!
//! El endpoint POST /rotate envia una senal de rotacion a todas las sesiones activas
//! via un tokio::sync::watch::Sender<u64>. Cada sesion subscribe al mismo canal.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::State,
    http::header::CONTENT_TYPE,
    response::IntoResponse,
    routing::{get, post},
    Json,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

use crate::{config::ValidConfig, control_plane, http_relay::HttpRelay, identity::{ClientVerifyingIdentity, ServerIdentity}, metrics, metrics::MetricsState, quic, session, tls};

/// Estado compartido del servidor HTTP de metricas.
/// Se pasa a los handlers axum via State extractor.
#[derive(Clone)]
pub(crate) struct MetricsAppState {
    pub prometheus_handle: PrometheusHandle,
    pub rotate_tx: Arc<watch::Sender<u64>>,
    pub metrics_state: Arc<MetricsState>,
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

    // ── Metrics HTTP server (puerto dedicado, plain HTTP) ───────────────────
    let app_state = MetricsAppState {
        prometheus_handle: metrics_handle,
        rotate_tx: Arc::clone(&rotate_tx),
        metrics_state: Arc::clone(&metrics_state),
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
        spawn_tls_listener(config.clone(), Arc::new(acceptor));
    }

    // ── TCP proxy listener ───────────────────────────────────────────────────
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "LatticeShield escuchando");
    info!(backend = %config.backend_addr, "backend configurado");

    // ── Control plane heartbeat task (non-blocking, optional) ────────────────
    if config.control_plane_enabled && !config.control_plane_endpoint.is_empty() {
        let cfg = config.clone();
        let ms = Arc::clone(&metrics_state);
        tokio::spawn(async move {
            control_plane::start(cfg, ms).await;
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
        .route("/rotate", post(rotate_handler))
        .with_state(state)
}

fn spawn_tls_listener(config: ValidConfig, acceptor: Arc<tokio_rustls::TlsAcceptor>) {
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

            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        if let Err(e) = relay.handle(tls_stream, peer).await {
                            tracing::warn!(%peer, "TLS relay error: {e:#}");
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

/// POST /rotate — envia senal de rotacion a todas las sesiones activas.
///
/// Incrementa el contador del watch channel. Cada sesion que escucha via
/// rotate_rx.changed() detecta el cambio y rota su clave de sesion.
async fn rotate_handler(State(state): State<MetricsAppState>) -> impl IntoResponse {
    let active = state.metrics_state.connections_active.load(Ordering::Relaxed);
    state.rotate_tx.send_modify(|counter| *counter += 1);
    Json(json!({"rotated": active}))
}
