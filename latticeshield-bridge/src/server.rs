//! TCP listener — acepta conexiones y despacha una tarea por sesion.
//! Tambien inicia el servidor HTTP de metricas Prometheus en un puerto dedicado.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::header::CONTENT_TYPE, response::IntoResponse, routing::get};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{config::ValidConfig, control_plane, identity::ServerIdentity, metrics, metrics::MetricsState, session};

pub async fn run(config: ValidConfig) -> anyhow::Result<()> {
    let metrics_handle = metrics::init()?;
    let metrics_state = MetricsState::new();

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
    spawn_metrics_server(config.metrics_addr, metrics_handle);

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
        let backend_addr: SocketAddr = config.backend_addr;
        let max_frame_size = config.max_frame_size;
        let identity = Arc::clone(&identity);
        let ms = Arc::clone(&metrics_state);

        tokio::spawn(async move {
            if let Err(e) = session::handle(socket, peer, backend_addr, max_frame_size, identity, ms).await {
                error!(%peer, "sesion error: {e:#}");
            }
        });
    }
}

pub(crate) fn metrics_app(handle: PrometheusHandle) -> axum::Router {
    axum::Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(handle)
}

fn spawn_metrics_server(addr: SocketAddr, handle: PrometheusHandle) {
    tokio::spawn(async move {
        let app = metrics_app(handle);

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

async fn metrics_handler(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        handle.render(),
    )
}
