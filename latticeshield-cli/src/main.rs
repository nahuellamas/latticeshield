//! LatticeShield unified key management CLI.
//!
//! Usage:
//!   latticeshield                     # Shows welcome banner
//!   latticeshield keygen server <dir> # Generate server.sk + server.vk
//!   latticeshield keygen client <dir> # Generate client.sk + client.vk
//!   latticeshield keygen tls <dir>    # Generate tls.crt + tls.key
//!   latticeshield vk-info <path>      # Show VK fingerprint + size
//!   latticeshield vk-share            # Request one-time VK download URL from bridge

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
    /// Fetch and display the bridge's VerifyingKey via the vk-share mechanism
    VkShare {
        /// Bridge admin URL (e.g. http://127.0.0.1:8444)
        #[arg(long, default_value = "http://127.0.0.1:8444")]
        bridge: String,

        /// Admin bearer token (can also be set via LATTICESHIELD_ADMIN_TOKEN env var)
        #[arg(long, env = "LATTICESHIELD_ADMIN_TOKEN")]
        token: String,
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
    println!("  vk-share              Request one-time VK download URL from bridge");
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
        Some(Commands::VkShare { bridge, token }) => {
            let url = format!("{bridge}/vk-token");
            let client = reqwest::blocking::Client::new();
            let resp = client
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .map_err(|e| anyhow::anyhow!("bridge unreachable at {url}: {e}"))?;

            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                anyhow::bail!("authentication failed — check LATTICESHIELD_ADMIN_TOKEN");
            }
            if !resp.status().is_success() {
                let status = resp.status();
                anyhow::bail!("bridge returned error {status}");
            }

            let body: serde_json::Value = resp
                .json()
                .map_err(|e| anyhow::anyhow!("failed to parse response: {e}"))?;

            let vk_url = body["url"].as_str().unwrap_or("(missing)");
            let fp = body["fingerprint"].as_str().unwrap_or("(missing)");
            let expires = body["expires_in_secs"].as_u64().unwrap_or(600);
            let minutes = expires / 60;

            println!("One-time VK download URL:");
            println!("  {vk_url}");
            println!("Fingerprint (SHA-256):");
            println!("  {fp}");
            println!("Expires in: {minutes} minutes ({expires} seconds)");
            Ok(())
        }
    }
}
