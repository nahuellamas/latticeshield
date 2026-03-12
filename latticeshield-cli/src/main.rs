//! LatticeShield unified key management CLI.
//!
//! Usage:
//!   latticeshield                     # Shows welcome banner
//!   latticeshield keygen server <dir> # Generate server.sk + server.vk
//!   latticeshield keygen client <dir> # Generate client.sk + client.vk
//!   latticeshield keygen tls <dir>    # Generate tls.crt + tls.key
//!   latticeshield vk-info <path>      # Show VK fingerprint + size

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "latticeshield",
    version,
    about = "LatticeShield unified key management CLI",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate cryptographic key material
    Keygen {
        #[command(subcommand)]
        target: KeygenTarget,
    },
    /// Show fingerprint and metadata of a verifying key file
    VkInfo {
        /// Path to any .vk file (server.vk or client.vk)
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeygenTarget {
    /// Generate server keypair — server.sk (0600) + server.vk (0644)
    Server {
        /// Directory to write keys into (created if absent)
        #[arg(default_value = "./keys")]
        dir: PathBuf,
    },
    /// Generate client keypair — client.sk (0600) + client.vk (0644)
    Client {
        /// Directory to write keys into (created if absent)
        #[arg(default_value = "./keys")]
        dir: PathBuf,
    },
    /// Generate self-signed TLS certificate — tls.crt (0644) + tls.key (0600)
    Tls {
        /// Directory to write cert+key into (created if absent)
        #[arg(default_value = "./keys")]
        dir: PathBuf,
    },
}

fn print_banner() {
    // Inner width: 58 visible chars between ║ and ║ (total line = 60)
    let top    = "╔══════════════════════════════════════════════════════════╗";
    let bottom = "╚══════════════════════════════════════════════════════════╝";
    let empty  = "║                                                          ║";

    println!("{}", top.cyan());
    println!("{}", empty.cyan());
    println!("{}", "║                        ╔══╦══╦══╗                        ║".cyan());
    println!("{}", "║                        ║  ║██║  ║                        ║".cyan());
    println!("{}", "║                        ╠══╬══╬══╣                        ║".cyan());
    println!("{}", "║                        ║██║  ║██║                        ║".cyan());
    println!("{}", "║                        ╠══╩══╩══╣                        ║".cyan());
    println!("{}", "║                         ╲  LS  ╱                         ║".cyan());
    println!("{}", "║                          ╲    ╱                          ║".cyan());
    println!("{}", "║                           ╲  ╱                           ║".cyan());
    println!("{}", "║                            ╲╱                            ║".cyan());
    println!("{}", empty.cyan());

    // Title — border cyan, text white bold
    let title = "   LatticeShield CLI";
    let title_pad = " ".repeat(58usize.saturating_sub(title.len()));
    print!("{}", "║".cyan());
    print!("{}", title.bold().white());
    println!("{}", format!("{}║", title_pad).cyan());

    // Version
    let version = format!("   v{}", env!("CARGO_PKG_VERSION"));
    let ver_pad = " ".repeat(58usize.saturating_sub(version.len()));
    print!("{}", "║".cyan());
    print!("{}", version.white());
    println!("{}", format!("{}║", ver_pad).cyan());

    // Subtitle
    let subtitle = "   Post-Quantum Security for the Edge";
    let sub_pad = " ".repeat(58usize.saturating_sub(subtitle.len()));
    print!("{}", "║".cyan());
    print!("{}", subtitle.white());
    println!("{}", format!("{}║", sub_pad).cyan());

    println!("{}", empty.cyan());
    println!("{}", bottom.cyan());
    println!();
    println!("COMMANDS:");
    println!("  keygen server <dir>   Generate server keys (ML-DSA-65)");
    println!("  keygen client <dir>   Generate client keys (ML-DSA-65)");
    println!("  keygen tls <dir>      Generate TLS certificate (rcgen)");
    println!("  vk-info <path>        Show verifying key fingerprint");
    println!();
    println!("Run 'latticeshield <command> --help' for more info.");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            print_banner();
            Ok(())
        }
        Some(Commands::Keygen { target }) => match target {
            KeygenTarget::Server { dir } => {
                latticeshield_bridge::identity::ServerIdentity::generate_and_save(&dir)
            }
            KeygenTarget::Client { dir } => {
                latticeshield_client::identity::ClientIdentity::generate_and_save(&dir)
            }
            KeygenTarget::Tls { dir } => {
                latticeshield_bridge::tls::generate_self_signed(&dir)
            }
        },
        Some(Commands::VkInfo { path }) => {
            let vk = latticeshield_client::identity::load_verifying_key(&path)?;
            let fp = latticeshield_client::identity::fingerprint(&vk);
            println!("File:    {}", path.display());
            println!("Size:    {} bytes (ML-DSA-65 VerifyingKey)", vk.to_bytes().len());
            println!("SHA-256: {fp}");
            Ok(())
        }
    }
}
