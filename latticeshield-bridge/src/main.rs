//! LatticeShield Bridge — quantum-safe reverse proxy.
//!
//! Usage:
//!   latticeshield-bridge [--config <path>]
//!   latticeshield-bridge --version

use std::path::PathBuf;

use clap::Parser;

mod config;
mod http_relay;
pub(crate) mod identity;
mod metrics;
mod quic;
mod server;
mod session;
mod tls;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(
    name = "latticeshield-bridge",
    version,
    about = "Quantum-safe reverse proxy — X25519 + ML-KEM-768 + ML-DSA-65"
)]
struct Cli {
    /// Path to config.toml (default: ./config.toml)
    #[arg(long, default_value = "./config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config FIRST so log_level is available for tracing init
    let config = config::Config::load(&cli.config)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
        )
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.listen_addr,
        backend = %config.backend_addr,
        metrics = %config.metrics_addr,
        "LatticeShield Bridge starting"
    );

    server::run(config).await
}
