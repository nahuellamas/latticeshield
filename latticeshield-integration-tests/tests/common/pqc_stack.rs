use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use latticeshield_bridge::{
    config::ValidConfig,
    identity::ServerIdentity,
    metrics::MetricsState,
    session::{self, SessionContext},
};
use latticeshield_client::{
    client_session::ReconnectEvent,
    config::{PoolConfig, ReconnectConfig, ValidClientConfig},
    identity::ClientIdentity,
    pool::ConnectionPool,
};
use latticeshield_crypto::{generate_keypair, VerifyingKey, VERIFYING_KEY_LEN};
use rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

// ── BridgeKill ─────────────────────────────────────────────────────────────────

/// Handle that can abort bridge session tasks, simulating a mid-session crash.
#[derive(Clone)]
pub struct BridgeKill {
    session_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl BridgeKill {
    pub fn new() -> Self {
        Self {
            session_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn push(&self, handle: JoinHandle<()>) {
        let mut handles = self
            .session_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        handles.push(handle);
    }

    /// Abort every registered bridge session task. Returns the count of tasks aborted.
    pub fn kill_all(&self) -> usize {
        let mut handles = self
            .session_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let count = handles.len();
        for h in handles.drain(..) {
            h.abort();
        }
        count
    }

    /// Wait until at least one session handle is registered, then abort it.
    /// Times out after 2 seconds.
    #[allow(dead_code)]
    pub async fn kill_next(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            {
                let mut handles = self
                    .session_handles
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !handles.is_empty() {
                    let h = handles.remove(0);
                    h.abort();
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("kill_next: timed out waiting for a session handle");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

// ── StackHandles ───────────────────────────────────────────────────────────────

/// Handles returned by `spawn_stack`.
pub struct StackHandles {
    /// The address on which the client proxy is listening. Tests connect here.
    pub client_addr: SocketAddr,
    /// Kill handle for simulating a bridge crash.
    pub bridge_kill: BridgeKill,
    // Public so tests can explicitly abort listener tasks.
    pub bridge_listener_task: JoinHandle<()>,
    pub client_listener_task: JoinHandle<()>,
}

// ── spawn_stack ────────────────────────────────────────────────────────────────

/// Spawns a full PQC stack in-process:
///
/// ```text
/// test client → [client_listener:0] → PQC → [bridge_listener:0] → [backend_addr]
/// ```
///
/// All listeners bind to `127.0.0.1:0` (OS-assigned ports). No filesystem writes.
/// The returned `StackHandles.client_addr` is where tests should connect.
pub async fn spawn_stack(backend_addr: SocketAddr) -> Result<StackHandles> {
    // ── 1. Ephemeral ML-DSA-65 keypair — no disk write ──────────────────────
    let (signing_key, verifying_key) = generate_keypair(&mut OsRng);
    // VerifyingKey does not impl Clone; reconstruct from raw bytes for the client.
    let vk_bytes: [u8; VERIFYING_KEY_LEN] = *verifying_key.to_bytes();
    let vk_for_client =
        Arc::new(VerifyingKey::from_bytes(&vk_bytes).expect("VK round-trip should succeed"));
    let identity = Arc::new(ServerIdentity {
        signing_key,
        verifying_key,
    });

    // ── 2. Bridge listener (port 0) ──────────────────────────────────────────
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await?;
    let bridge_addr = bridge_listener.local_addr()?;

    let bridge_kill = BridgeKill::new();
    let bridge_kill_clone = bridge_kill.clone();

    let bridge_config = ValidConfig::for_test(backend_addr.port());
    let (_shutdown_tx, shutdown_rx) = watch::channel(());

    let bridge_listener_task = tokio::spawn(async move {
        let (rotate_tx, _rotate_rx) = watch::channel(0u64);
        let rotate_tx = Arc::new(rotate_tx);
        // Keep _shutdown_tx alive for the lifetime of the bridge listener
        let _shutdown_tx = _shutdown_tx;

        loop {
            let Ok((socket, peer)) = bridge_listener.accept().await else {
                break;
            };

            let ctx = SessionContext {
                identity: Arc::clone(&identity),
                client_auth: None,
                metrics_state: MetricsState::new(),
                rotate_tx: Arc::clone(&rotate_tx),
            };
            let cfg = bridge_config.clone();
            let sess_shutdown = shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                let _ = session::handle(socket, peer, ctx, cfg, sess_shutdown).await;
            });

            bridge_kill_clone.push(handle);
        }
    });

    // ── 3. Client listener (port 0) ──────────────────────────────────────────
    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;

    let client_config = make_client_config(bridge_addr, client_addr);
    let pool = Arc::new(ConnectionPool::new(bridge_addr, client_config.pool.clone()));

    let pool_for_warmer = Arc::clone(&pool);
    tokio::spawn(async move { pool_for_warmer.warm_loop().await });

    let client_listener_task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = client_listener.accept().await else {
                break;
            };
            let cfg = client_config.clone();
            let vk = Arc::clone(&vk_for_client);
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                if let Err(e) = latticeshield_client::client_session::handle(
                    stream,
                    peer,
                    cfg,
                    vk,
                    None::<Arc<ClientIdentity>>,
                    pool,
                    None,
                )
                .await
                {
                    tracing::debug!("client session error (expected on kill): {e}");
                }
            });
        }
    });

    // Small delay so both listeners are ready before tests proceed.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    Ok(StackHandles {
        client_addr,
        bridge_kill,
        bridge_listener_task,
        client_listener_task,
    })
}

fn make_client_config(bridge_addr: SocketAddr, listen_addr: SocketAddr) -> ValidClientConfig {
    make_client_config_with_reconnect(bridge_addr, listen_addr, ReconnectConfig::default())
}

fn make_client_config_with_reconnect(
    bridge_addr: SocketAddr,
    listen_addr: SocketAddr,
    reconnect: ReconnectConfig,
) -> ValidClientConfig {
    ValidClientConfig {
        listen_addr,
        bridge_addr,
        server_vk_path: PathBuf::from("/dev/null"), // not used — VK passed directly
        client_sk_path: None,
        max_frame_size: 65536,
        log_level: "error".to_string(),
        pool: PoolConfig {
            max_size: 4,
            idle_timeout_secs: 30,
            warm_size: 0, // no pre-warming in tests
            warm_interval_secs: 5,
        },
        reconnect,
    }
}

/// Spawns a full PQC stack with reconnect support enabled.
///
/// Returns `(StackHandles, Receiver<ReconnectEvent>)`. The receiver emits events
/// whenever the client reconnects to or exhausts the bridge.
pub async fn spawn_stack_with_reconnect(
    backend_addr: SocketAddr,
    reconnect_cfg: ReconnectConfig,
) -> Result<(StackHandles, mpsc::Receiver<ReconnectEvent>)> {
    // ── 1. Ephemeral ML-DSA-65 keypair ──────────────────────────────────────
    let (signing_key, verifying_key) = generate_keypair(&mut OsRng);
    let vk_bytes: [u8; VERIFYING_KEY_LEN] = *verifying_key.to_bytes();
    let vk_for_client =
        Arc::new(VerifyingKey::from_bytes(&vk_bytes).expect("VK round-trip should succeed"));
    let identity = Arc::new(ServerIdentity {
        signing_key,
        verifying_key,
    });

    // ── 2. Bridge listener ───────────────────────────────────────────────────
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await?;
    let bridge_addr = bridge_listener.local_addr()?;

    let bridge_kill = BridgeKill::new();
    let bridge_kill_clone = bridge_kill.clone();

    let bridge_config = ValidConfig::for_test(backend_addr.port());
    let (_shutdown_tx, shutdown_rx) = watch::channel(());

    let bridge_listener_task = tokio::spawn(async move {
        let (rotate_tx, _rotate_rx) = watch::channel(0u64);
        let rotate_tx = Arc::new(rotate_tx);
        let _shutdown_tx = _shutdown_tx;

        loop {
            let Ok((socket, peer)) = bridge_listener.accept().await else {
                break;
            };

            let ctx = SessionContext {
                identity: Arc::clone(&identity),
                client_auth: None,
                metrics_state: MetricsState::new(),
                rotate_tx: Arc::clone(&rotate_tx),
            };
            let cfg = bridge_config.clone();
            let sess_shutdown = shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                let _ = session::handle(socket, peer, ctx, cfg, sess_shutdown).await;
            });

            bridge_kill_clone.push(handle);
        }
    });

    // ── 3. Reconnect event channel ───────────────────────────────────────────
    let (reconnect_tx, reconnect_rx) = mpsc::channel::<ReconnectEvent>(32);
    let reconnect_tx = Arc::new(reconnect_tx);

    // ── 4. Client listener ───────────────────────────────────────────────────
    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;

    let client_config = make_client_config_with_reconnect(bridge_addr, client_addr, reconnect_cfg);
    let pool = Arc::new(ConnectionPool::new(bridge_addr, client_config.pool.clone()));

    let pool_for_warmer = Arc::clone(&pool);
    tokio::spawn(async move { pool_for_warmer.warm_loop().await });

    let client_listener_task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = client_listener.accept().await else {
                break;
            };
            let cfg = client_config.clone();
            let vk = Arc::clone(&vk_for_client);
            let pool = Arc::clone(&pool);
            let tx = Arc::clone(&reconnect_tx);
            tokio::spawn(async move {
                if let Err(e) = latticeshield_client::client_session::handle(
                    stream,
                    peer,
                    cfg,
                    vk,
                    None::<Arc<ClientIdentity>>,
                    pool,
                    Some(tx),
                )
                .await
                {
                    tracing::debug!("client session error (expected on kill): {e}");
                }
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let handles = StackHandles {
        client_addr,
        bridge_kill,
        bridge_listener_task,
        client_listener_task,
    };

    Ok((handles, reconnect_rx))
}
