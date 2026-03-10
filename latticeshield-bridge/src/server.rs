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

use crate::{config::ValidConfig, control_plane, identity::ServerIdentity, metrics, metrics::MetricsState, session};

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

    // ── Metrics HTTP server (puerto dedicado, plain HTTP) ───────────────────
    let app_state = MetricsAppState {
        prometheus_handle: metrics_handle,
        rotate_tx: Arc::clone(&rotate_tx),
        metrics_state: Arc::clone(&metrics_state),
    };
    spawn_metrics_server(config.metrics_addr, app_state);

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
        let ms = Arc::clone(&metrics_state);
        let rtx = Arc::clone(&rotate_tx);
        let cfg = config.clone();

        tokio::spawn(async move {
            if let Err(e) = session::handle(socket, peer, identity, ms, rtx, cfg).await {
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
