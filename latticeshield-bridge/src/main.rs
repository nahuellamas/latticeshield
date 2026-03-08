//! LatticeShield Bridge — reverse proxy quantum-safe.
//!
//! Mes 2: TCP listener + handshake PQC hibrido + canal AES-256-GCM + relay al backend.
//!
//! Variables de entorno:
//!   LISTEN_ADDR   — donde escucha el proxy (default: 0.0.0.0:8443)
//!   BACKEND_ADDR  — backend de destino  (default: 127.0.0.1:8080)
//!   METRICS_ADDR  — metricas Prometheus  (default: 0.0.0.0:8444)
//!   RUST_LOG      — nivel de log        (default: info)

mod channel;
mod config;
mod metrics;
mod server;
mod session;

#[cfg(test)]
mod tests;

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        crypto = "X25519 + ML-KEM-768 + HKDF-SHA256",
        transport = "AES-256-GCM frames over TCP",
        "LatticeShield Bridge arrancando"
    );

    let config = config::Config::from_env()?;
    server::run(config).await
}
