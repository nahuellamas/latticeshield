//! LatticeShield Bridge — reverse proxy quantum-safe.
//!
//! Variables de entorno:
//!   LISTEN_ADDR        — donde escucha el proxy   (default: 0.0.0.0:8443)
//!   BACKEND_ADDR       — backend de destino        (default: 127.0.0.1:8080)
//!   METRICS_ADDR       — metricas Prometheus       (default: 0.0.0.0:8444)
//!   SIGNING_KEY_PATH   — clave de firma ML-DSA-65  (default: ./keys/server.sk)
//!   RUST_LOG           — nivel de log              (default: info)
//!
//! Subcomandos:
//!   --keygen <dir>   Genera server.sk (0600) y server.vk (0644) en <dir>

mod channel;
mod config;
pub(crate) mod identity;
mod metrics;
mod server;
mod session;

#[cfg(test)]
mod tests;

use std::path::Path;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Subcomando --keygen (no requiere runtime async) ──────────────────────
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--keygen") {
        let dir = args.get(2).map(Path::new).unwrap_or(Path::new("./keys"));
        return identity::ServerIdentity::generate_and_save(dir);
    }

    // ── Arranque normal ──────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        crypto = "X25519 + ML-KEM-768 + ML-DSA-65 + HKDF-SHA256",
        transport = "AES-256-GCM frames over TCP",
        "LatticeShield Bridge arrancando"
    );

    let config = config::Config::from_env()?;
    server::run(config).await
}
