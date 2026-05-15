//! LatticeShield unified key management CLI.
//!
//! Usage:
//!   latticeshield                              # Shows welcome banner
//!   latticeshield keygen server <dir>          # Generate server.sk + server.vk
//!   latticeshield keygen client <dir>          # Generate client.sk + client.vk
//!   latticeshield keygen tls <dir>             # Generate tls.crt + tls.key
//!   latticeshield vk-info <path>               # Show VK fingerprint + size
//!   latticeshield vk-share --admin-addr ...    # Request one-time VK download URL via PQC admin channel

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use latticeshield_crypto::{
    client_respond, parse_server_hello_signed, serialize_client_response_signed, EncryptedChannel,
    FrameResult, SERVER_HELLO_LEN, SERVER_HELLO_SIGNED_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Local admin protocol types (mirrors latticeshield-bridge::admin, not re-exported) ──

#[derive(serde::Serialize)]
struct CommandFrame {
    seq: u64,
    cmd: &'static str,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum AdminResponse {
    VkToken { token: String, url: String },
    Error { message: String },
    #[serde(other)]
    Unknown,
}

// ── CLI definition ───────────────────────────────────────────────────────────

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
    /// Request a one-time VK download URL via the PQC admin channel
    VkShare {
        /// TCP address of the bridge admin channel
        #[arg(long, default_value = "127.0.0.1:8445")]
        admin_addr: String,

        /// Path to the bridge's verifying key (server.vk) — used to authenticate the bridge
        #[arg(long)]
        bridge_vk: PathBuf,

        /// Path to the admin signing key (admin.sk) — used for mutual auth with the bridge
        #[arg(long)]
        admin_sk: PathBuf,
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

// ── PQC admin channel client ─────────────────────────────────────────────────

const ADMIN_TIMEOUT_SECS: u64 = 10;

async fn cmd_vk_share(
    admin_addr: &str,
    bridge_vk_path: &PathBuf,
    admin_sk_path: &PathBuf,
) -> anyhow::Result<()> {
    use anyhow::Context;

    // Load keys from disk (no IO timeout needed — local FS)
    let bridge_vk = latticeshield_client::identity::load_verifying_key(bridge_vk_path)
        .with_context(|| format!("loading bridge VK from {}", bridge_vk_path.display()))?;
    let admin_identity = latticeshield_bridge::identity::ServerIdentity::load(admin_sk_path)
        .with_context(|| format!("loading admin SK from {}", admin_sk_path.display()))?;

    // Wrap the entire network operation in a single timeout
    tokio::time::timeout(
        std::time::Duration::from_secs(ADMIN_TIMEOUT_SECS),
        run_admin_command(admin_addr, bridge_vk, admin_identity),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "admin channel timed out after {ADMIN_TIMEOUT_SECS}s — is {admin_addr} reachable?"
        )
    })?
}

async fn run_admin_command(
    admin_addr: &str,
    bridge_vk: latticeshield_crypto::VerifyingKey,
    admin_identity: latticeshield_bridge::identity::ServerIdentity,
) -> anyhow::Result<()> {
    use anyhow::Context;

    // TCP connect — set_nodelay prevents Nagle from batching small handshake writes
    let mut stream = tokio::net::TcpStream::connect(admin_addr)
        .await
        .with_context(|| format!("connecting to admin channel at {admin_addr}"))?;
    stream.set_nodelay(true).context("set_nodelay")?;

    // Read signed server hello
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    stream
        .read_exact(&mut hello_buf)
        .await
        .context("reading server hello")?;

    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);

    // Verify bridge signature — fails if bridge_vk is wrong
    let hello = parse_server_hello_signed(&hello_buf, &bridge_vk)
        .map_err(|_| anyhow::anyhow!("bridge authentication failed — is --bridge-vk correct?"))?;

    // Client respond + derive session key
    let (response, session_key) =
        client_respond(&hello, &mut OsRng).context("client_respond failed")?;

    // Sign client response — admin channel requires mutual ML-DSA-65 auth
    let signed = serialize_client_response_signed(
        &response,
        &admin_identity.signing_key,
        &server_hello_raw,
        &mut OsRng,
    )
    .map_err(|e| anyhow::anyhow!("signing client response: {e:?}"))?;

    stream
        .write_all(&signed)
        .await
        .context("writing client response")?;

    // Encrypted channel
    let mut channel = EncryptedChannel::new(session_key.as_bytes(), 64 * 1024);

    // Microsecond timestamp as seq — monotonically increasing, collision-safe within a session
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let cmd = serde_json::to_vec(&CommandFrame {
        seq,
        cmd: "GetVkToken",
    })?;
    channel
        .write_frame(&mut stream, &cmd)
        .await
        .context("writing command frame")?;

    // Read response
    let resp_bytes = match channel
        .read_frame(&mut stream)
        .await
        .context("reading response frame")?
    {
        FrameResult::Data(b) => b,
        FrameResult::KeyRotate(_) => {
            anyhow::bail!("unexpected KEY_ROTATE frame from admin channel");
        }
    };

    let resp: AdminResponse =
        serde_json::from_slice(&resp_bytes).context("parsing admin response")?;

    match resp {
        AdminResponse::VkToken { token, url } => {
            println!("One-time VK download URL:");
            println!("  {url}");
            println!("Token: {token}");
            println!("Expires in: 10 minutes (600 seconds)");
        }
        AdminResponse::Error { message } => {
            anyhow::bail!("admin error: {message}");
        }
        AdminResponse::Unknown => {
            anyhow::bail!("unexpected response type from bridge");
        }
    }

    Ok(())
}

// ── Banner ───────────────────────────────────────────────────────────────────

fn print_banner() {
    let top = "╔══════════════════════════════════════════════════════════╗";
    let bottom = "╚══════════════════════════════════════════════════════════╝";
    let empty = "║                                                          ║";

    println!("{}", top.cyan());
    println!("{}", empty.cyan());
    println!(
        "{}",
        "║                        ╔══╦══╦══╗                        ║".cyan()
    );
    println!(
        "{}",
        "║                        ║  ║██║  ║                        ║".cyan()
    );
    println!(
        "{}",
        "║                        ╠══╬══╬══╣                        ║".cyan()
    );
    println!(
        "{}",
        "║                        ║██║  ║██║                        ║".cyan()
    );
    println!(
        "{}",
        "║                        ╠══╩══╩══╣                        ║".cyan()
    );
    println!(
        "{}",
        "║                         ╲  LS  ╱                         ║".cyan()
    );
    println!(
        "{}",
        "║                          ╲    ╱                          ║".cyan()
    );
    println!(
        "{}",
        "║                           ╲  ╱                           ║".cyan()
    );
    println!(
        "{}",
        "║                            ╲╱                            ║".cyan()
    );
    println!("{}", empty.cyan());

    let title = "   LatticeShield CLI";
    let title_pad = " ".repeat(58usize.saturating_sub(title.len()));
    print!("{}", "║".cyan());
    print!("{}", title.bold().white());
    println!("{}", format!("{}║", title_pad).cyan());

    let version = format!("   v{}", env!("CARGO_PKG_VERSION"));
    let ver_pad = " ".repeat(58usize.saturating_sub(version.len()));
    print!("{}", "║".cyan());
    print!("{}", version.white());
    println!("{}", format!("{}║", ver_pad).cyan());

    let subtitle = "   Post-Quantum Security for the Edge";
    let sub_pad = " ".repeat(58usize.saturating_sub(subtitle.len()));
    print!("{}", "║".cyan());
    print!("{}", subtitle.white());
    println!("{}", format!("{}║", sub_pad).cyan());

    println!("{}", empty.cyan());
    println!("{}", bottom.cyan());
    println!();
    println!("COMMANDS:");
    println!("  keygen server <dir>    Generate server keys (ML-DSA-65)");
    println!("  keygen client <dir>    Generate client keys (ML-DSA-65)");
    println!("  keygen tls <dir>       Generate TLS certificate (rcgen)");
    println!("  vk-info <path>         Show verifying key fingerprint");
    println!("  vk-share               Request one-time VK URL via PQC admin channel");
    println!();
    println!("Run 'latticeshield <command> --help' for more info.");
}

// ── Entry point ──────────────────────────────────────────────────────────────

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
            KeygenTarget::Tls { dir } => latticeshield_bridge::tls::generate_self_signed(&dir),
        },
        Some(Commands::VkInfo { path }) => {
            let vk = latticeshield_client::identity::load_verifying_key(&path)?;
            let fp = latticeshield_client::identity::fingerprint(&vk);
            println!("File:    {}", path.display());
            println!(
                "Size:    {} bytes (ML-DSA-65 VerifyingKey)",
                vk.to_bytes().len()
            );
            println!("SHA-256: {fp}");
            Ok(())
        }
        Some(Commands::VkShare {
            admin_addr,
            bridge_vk,
            admin_sk,
        }) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(cmd_vk_share(&admin_addr, &bridge_vk, &admin_sk)),
    }
}
