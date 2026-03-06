//! LatticeShield Bridge — punto de entrada del agente.
//!
//! Estado actual: stub de Mes 1.
//! El motor criptografico esta en `latticeshield-crypto`.
//! La integracion con TLS (rustls + quinn) se implementa en Mes 2.

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("LatticeShield Bridge v{}", env!("CARGO_PKG_VERSION"));
    info!("Motor criptografico: X25519 + ML-KEM-768 + HKDF-SHA256");
    info!("Estado: Mes 1 — crypto core activo, proxy TLS pendiente");

    Ok(())
}
