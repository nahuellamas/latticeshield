//! LatticeShield Bridge — quantum-safe reverse proxy.
//!
//! Usage:
//!   latticeshield-bridge run [--config <path>]
//!   latticeshield-bridge keygen <dir>
//!   latticeshield-bridge tls-keygen <dir>
//!   latticeshield-bridge admin-keygen <dir>

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

mod admin;
mod config;
mod control_plane;
mod http_relay;
pub(crate) mod identity;
mod metrics;
mod quic;
mod server;
mod session;
mod tls;
mod vk_share;

#[cfg(test)]
mod tests;

#[derive(Parser)]
#[command(
    name = "latticeshield-bridge",
    version,
    about = "Quantum-safe reverse proxy — X25519 + ML-KEM-768 + ML-DSA-65"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the bridge (default operation)
    Run {
        /// Path to config.toml
        #[arg(long, default_value = "./config.toml")]
        config: PathBuf,
    },
    /// Generate ML-DSA-65 keypair for the bridge server identity
    Keygen {
        /// Directory to write server.sk and server.vk
        dir: PathBuf,
    },
    /// Generate TLS keypair for the TLS listener
    TlsKeygen {
        /// Directory to write tls.crt and tls.key
        dir: PathBuf,
    },
    /// Generate ML-DSA-65 keypair for the admin control plane
    AdminKeygen {
        /// Directory to write admin.sk and admin.vk
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config } => {
            // Load config FIRST so log_level is available for tracing init
            let config = config::Config::load(&config)?;

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
        Commands::Keygen { dir } => {
            identity::ServerIdentity::generate_and_save(&dir)?;
            Ok(())
        }
        Commands::TlsKeygen { dir } => {
            #[cfg(feature = "tls-keygen")]
            {
                tls::generate_self_signed(&dir)?;
            }
            #[cfg(not(feature = "tls-keygen"))]
            {
                let _ = dir;
                eprintln!("tls-keygen feature not enabled — rebuild with --features tls-keygen");
            }
            Ok(())
        }
        Commands::AdminKeygen { dir } => {
            admin_keygen(&dir)?;
            Ok(())
        }
    }
}

fn admin_keygen(dir: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::create_dir_all(dir)
        .with_context(|| format!("creando directorio {}", dir.display()))?;

    let (sk, vk) = latticeshield_crypto::generate_keypair(&mut rand_core::OsRng);
    let sk_path = dir.join("admin.sk");
    let vk_path = dir.join("admin.vk");

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&sk_path)
        .with_context(|| format!("creando {}", sk_path.display()))?
        .write_all(sk.to_bytes())
        .context("escribiendo admin signing key")?;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&vk_path)
        .with_context(|| format!("creando {}", vk_path.display()))?
        .write_all(vk.to_bytes())
        .context("escribiendo admin verifying key")?;

    println!("Admin keypair generado exitosamente:");
    println!(
        "  Signing key:    {} (0600 — para el control plane, mantener SECRETO)",
        sk_path.display()
    );
    println!(
        "  Verifying key:  {} (0644 — copiar al bridge en admin.control_plane_vk_path)",
        vk_path.display()
    );
    Ok(())
}
