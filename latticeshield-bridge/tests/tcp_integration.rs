//! TCP per-IP connection cap integration test (W1 — SEC-OBS3-2)
//!
//! Validates that the PQC TCP accept loop enforces `max_connections_per_ip`:
//!
//! 1. Bind a real TcpListener with a cap of 2.
//! 2. Establish 2 full PQC sessions from 127.0.0.1 and keep them alive.
//! 3. Attempt a 3rd connection from the same IP.
//! 4. Assert the 3rd connection receives EOF immediately — bridge dropped it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use latticeshield_bridge::{
    config::ValidConfig,
    identity::ServerIdentity,
    metrics::MetricsState,
    session::{self, SessionContext},
    ws::{IpCountGuard, IpCounterMap},
};
use latticeshield_crypto::{
    client_respond, generate_keypair, parse_server_hello_signed, serialize_client_response,
    CLIENT_RESPONSE_LEN, SERVER_HELLO_SIGNED_LEN,
};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_server_identity_with_vk_bytes() -> (
    Arc<ServerIdentity>,
    [u8; latticeshield_crypto::VERIFYING_KEY_LEN],
) {
    let (signing_key, verifying_key) = generate_keypair(&mut OsRng);
    let vk_bytes = *verifying_key.to_bytes();
    let identity = Arc::new(ServerIdentity {
        signing_key,
        verifying_key,
    });
    (identity, vk_bytes)
}

fn make_config(backend_port: u16) -> ValidConfig {
    let dummy = PathBuf::from("/dev/null");
    ValidConfig {
        listen_addr: "127.0.0.1:8443".parse().unwrap(),
        backend_addr: format!("127.0.0.1:{backend_port}").parse().unwrap(),
        metrics_addr: "127.0.0.1:9000".parse().unwrap(),
        max_frame_size: 65536,
        handshake_timeout_secs: 10,
        max_connections_per_ip: 50,
        signing_key_path: dummy.clone(),
        log_level: "error".to_string(),
        control_plane_enabled: false,
        control_plane_endpoint: String::new(),
        control_plane_agent_name: String::new(),
        heartbeat_interval: Duration::from_secs(60),
        key_rotation_enabled: false,
        max_bytes_per_key: u64::MAX,
        key_rotation_interval: Duration::from_secs(3600),
        tls_enabled: false,
        tls_listen_addr: "127.0.0.1:8440".parse().unwrap(),
        tls_cert_path: dummy.clone(),
        tls_key_path: dummy.clone(),
        quic_enabled: false,
        quic_listen_addr: "127.0.0.1:8441".parse().unwrap(),
        quic_cert_path: dummy.clone(),
        quic_key_path: dummy.clone(),
        client_auth_enabled: false,
        client_vk_path: None,
        admin_enabled: false,
        admin_listen_addr: "127.0.0.1:8445".parse().unwrap(),
        admin_control_plane_vk_path: None,
        admin_rate_limit_per_second: 10,
        admin_handshake_timeout_secs: 5,
        control_plane_install_token: None,
        cloud_vk_path: None,
        shutdown_timeout: Duration::from_secs(5),
        ws_enabled: false,
        ws_listen_addr: "127.0.0.1:8446".parse().unwrap(),
        ws_cert_path: dummy.clone(),
        ws_key_path: dummy.clone(),
        ws_allowed_origins: vec![],
        ws_handshake_timeout_secs: 5,
        ws_max_connections_per_ip: 10,
        vk_share_max_tokens: 1000,
    }
}

/// Backend that accepts connections and holds them open for 30 s.
/// Keeps the bridge relay loop alive so the IP counter stays non-zero.
async fn spawn_persistent_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _stream = stream;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

/// Spawns a TCP accept loop that mirrors the per-IP enforcement in `server.rs`
/// (SEC-OBS3-2). Returns the port the listener is bound to.
async fn spawn_capped_listener(
    identity: Arc<ServerIdentity>,
    config: ValidConfig,
    max_per_ip: usize,
    shutdown_rx: watch::Receiver<()>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ip_counter: IpCounterMap = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        let (rotate_tx, _rotate_rx) = watch::channel(0u64);
        let rotate_tx = Arc::new(rotate_tx);

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };

            let peer_ip = peer.ip();
            {
                let mut map = ip_counter.lock().unwrap_or_else(|e| e.into_inner());
                let count = map.entry(peer_ip).or_insert(0);
                if *count >= max_per_ip {
                    drop(socket);
                    continue;
                }
                *count += 1;
            }

            let ip_counter_for_task = Arc::clone(&ip_counter);
            let ctx = SessionContext {
                identity: Arc::clone(&identity),
                client_auth: None,
                metrics_state: MetricsState::new(),
                rotate_tx: Arc::clone(&rotate_tx),
            };
            let cfg = config.clone();
            let sess_shutdown = shutdown_rx.clone();

            tokio::spawn(async move {
                let _ip_guard = IpCountGuard {
                    ip: peer_ip,
                    map: ip_counter_for_task,
                };
                let _ = session::handle(socket, peer, ctx, cfg, sess_shutdown).await;
            });
        }
    });

    port
}

/// Connects to the bridge and completes the full PQC handshake.
/// Returns the TcpStream held open — dropping it ends the session.
async fn do_pqc_handshake(
    bridge_port: u16,
    vk_bytes: &[u8; latticeshield_crypto::VERIFYING_KEY_LEN],
) -> TcpStream {
    use latticeshield_crypto::VerifyingKey;

    let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], bridge_port)))
        .await
        .expect("TCP connect to bridge should succeed");

    let vk = VerifyingKey::from_bytes(vk_bytes).unwrap();

    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    stream
        .read_exact(&mut hello_buf)
        .await
        .expect("should receive SERVER_HELLO_SIGNED");

    let client_hello =
        parse_server_hello_signed(&hello_buf, &vk).expect("SERVER_HELLO_SIGNED should verify");

    let (response, _key) = client_respond(&client_hello, &mut OsRng).unwrap();
    let mut buf = [0u8; CLIENT_RESPONSE_LEN];
    buf.copy_from_slice(&serialize_client_response(&response));

    stream
        .write_all(&buf)
        .await
        .expect("should send CLIENT_RESPONSE");
    stream.flush().await.expect("flush");

    // Stream is kept alive — session enters relay phase, IP counter stays non-zero.
    stream
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// SEC-OBS3-2 — the PQC accept loop drops connections from an IP that has
/// already reached `max_connections_per_ip`.
///
/// Two full PQC sessions are established and held open so the counter stays at
/// the cap. A third TCP connect must receive EOF — bridge drops the socket
/// before the PQC handshake begins.
#[tokio::test]
async fn tcp_per_ip_cap_rejects_third_connection() {
    const MAX_PER_IP: usize = 2;

    let backend_port = spawn_persistent_backend().await;
    let (identity, vk_bytes) = make_server_identity_with_vk_bytes();
    let config = make_config(backend_port);
    let (_shutdown_tx, shutdown_rx) = watch::channel(());

    let bridge_port =
        spawn_capped_listener(Arc::clone(&identity), config, MAX_PER_IP, shutdown_rx).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    // ── Two sessions, counter at cap ─────────────────────────────────────────
    let _stream1 = do_pqc_handshake(bridge_port, &vk_bytes).await;
    let _stream2 = do_pqc_handshake(bridge_port, &vk_bytes).await;

    // Allow both sessions to enter the relay phase before the next connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Third connection — bridge must drop it immediately ───────────────────
    let mut stream3 = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], bridge_port)))
        .await
        .expect("TCP connect should succeed — bridge drops after accept(), not before");

    let mut buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    let result = tokio::time::timeout(Duration::from_secs(2), stream3.read(&mut buf)).await;

    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {
            // EOF or connection reset — bridge dropped the socket. Expected.
        }
        Ok(Ok(n)) => {
            panic!(
                "over-cap connection received {n} bytes — \
                 bridge did not enforce per-IP cap (max={MAX_PER_IP})"
            );
        }
        Err(_elapsed) => {
            panic!(
                "over-cap connection still open after 2s — \
                 bridge did not enforce per-IP cap (max={MAX_PER_IP})"
            );
        }
    }

    // Dropping _stream1 / _stream2 here decrements the counter via IpCountGuard.
}
