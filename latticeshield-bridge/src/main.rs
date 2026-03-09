//! LatticeShield Bridge — quantum-safe reverse proxy.
//!
//! Usage:
//!   latticeshield-bridge [--config <path>]
//!   latticeshield-bridge keygen <dir>
//!   latticeshield-bridge --version

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod channel;
mod config;
pub(crate) mod identity;
mod metrics;
mod server;
mod session;

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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ML-DSA-65 server keypair (server.sk + server.vk)
    Keygen {
        /// Directory to write server.sk (0600) and server.vk (0644)
        #[arg(default_value = "./keys")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::Keygen { dir }) = cli.command {
        return identity::ServerIdentity::generate_and_save(&dir);
    }

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
