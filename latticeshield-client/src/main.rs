//! LatticeShield Client Proxy — entrypoint.
//!
//! Acepta conexiones TCP locales y las reenvía al bridge PQC
//! usando el handshake híbrido X25519 + ML-KEM-768 + ML-DSA-65.

use latticeshield_client::config;
use latticeshield_client::identity;
use latticeshield_client::server;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "latticeshield-client", version, about = "LatticeShield PQC Client Proxy")]
struct Cli {
    #[arg(long, default_value = "./latticeshield-client.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Muestra información de la VerifyingKey del servidor.
    VkInfo {
        /// Ruta al archivo de la VerifyingKey (.vk)
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::VkInfo { path }) => {
            let vk = identity::load_verifying_key(&path)?;
            let fp = identity::fingerprint(&vk);
            println!("fingerprint: {fp}");
            println!("size: {} bytes", vk.to_bytes().len());
        }
        None => {
            // Cargar configuracion
            let config = config::ClientConfig::load(&cli.config)?;

            // Inicializar tracing
            tracing_subscriber::fmt()
                .with_env_filter(
                    std::env::var("RUST_LOG").unwrap_or_else(|_| config.log_level.clone()),
                )
                .init();

            // Cargar VerifyingKey
            let vk = identity::load_verifying_key(&config.server_vk_path)?;
            let vk = Arc::new(vk);

            // Arrancar servidor
            server::run(config, vk).await?;
        }
    }

    Ok(())
}
