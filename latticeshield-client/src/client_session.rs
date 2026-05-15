//! Maneja una sesion PQC con el bridge: handshake + relay bidireccional cifrado.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use latticeshield_crypto::{
    client_respond, parse_server_hello_signed, serialize_client_response,
    serialize_client_response_signed, EncryptedChannel, FrameResult, VerifyingKey,
    SERVER_HELLO_LEN, SERVER_HELLO_SIGNED_LEN,
};

use crate::config::{ReconnectConfig, ValidClientConfig};
use crate::identity::ClientIdentity;
use crate::pool::ConnectionPool;

// ── Public event type ──────────────────────────────────────────────────────────

/// Events emitted by the reconnect loop. Subscribe via `reconnect_tx`.
#[derive(Debug)]
pub enum ReconnectEvent {
    /// A reconnect attempt succeeded. `attempt` starts at 1 (first retry).
    Reconnected { attempt: u32, peer: SocketAddr },
    /// All retries exhausted or a terminal condition was hit.
    Exhausted { attempts: u32, peer: SocketAddr },
}

// ── Private types ──────────────────────────────────────────────────────────────

/// Typed handshake error. Auth failures NEVER retry (REQ-5 / REQ-4/C).
#[derive(Debug)]
enum HandshakeError {
    Auth(anyhow::Error),
    Transport(anyhow::Error),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::Auth(e) => write!(f, "auth: {e}"),
            HandshakeError::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Outcome of a relay cycle. Drives reconnect vs. exit decision.
enum RelayOutcome {
    /// User app closed its TCP side cleanly.
    UserEof,
    /// User app produced an I/O error (treat as terminal).
    #[allow(dead_code)]
    UserError(anyhow::Error),
    /// Bridge side dropped / errored — eligible for reconnect.
    BridgeError(anyhow::Error),
}

// ── do_handshake — sole EncryptedChannel producer ──────────────────────────────

/// Performs the full PQC handshake with the bridge.
///
/// This is the ONLY function allowed to call `EncryptedChannel::new` or
/// `client_respond`. Every reconnect attempt calls this fresh — guaranteeing
/// new ML-KEM-768 + X25519 ephemerals (REQ-1).
async fn do_handshake(
    bridge: TcpStream,
    vk: &VerifyingKey,
    client_identity: Option<&ClientIdentity>,
    config: &ValidClientConfig,
) -> Result<(EncryptedChannel, ReadHalf<TcpStream>, WriteHalf<TcpStream>), HandshakeError> {
    let (mut bridge_r, mut bridge_w) = tokio::io::split(bridge);

    // ── Read ServerHello (signed) ────────────────────────────────────────────
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    bridge_r
        .read_exact(&mut hello_buf)
        .await
        .map_err(|e| HandshakeError::Transport(anyhow::anyhow!("server hello read: {e}")))?;

    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);

    // ── Verify ML-DSA-65 signature — auth failure never retries ─────────────
    let hello = parse_server_hello_signed(&hello_buf, vk)
        .map_err(|e| HandshakeError::Auth(anyhow::anyhow!("verify: {e:?}")))?;

    // ── ML-KEM-768 + X25519 client response — fresh ephemerals per call ─────
    let (response, session_key) = client_respond(&hello, &mut OsRng)
        .map_err(|e| HandshakeError::Transport(anyhow::anyhow!("client_respond: {e}")))?;

    // ── Send client response (signed if mutual auth enabled) ─────────────────
    match client_identity {
        Some(identity) => {
            let signed = serialize_client_response_signed(
                &response,
                &identity.signing_key,
                &server_hello_raw,
                &mut OsRng,
            )
            .map_err(|e| {
                HandshakeError::Transport(anyhow::anyhow!("client response signing: {e:?}"))
            })?;
            bridge_w
                .write_all(&signed)
                .await
                .map_err(|e| HandshakeError::Transport(e.into()))?;
        }
        None => {
            bridge_w
                .write_all(&serialize_client_response(&response))
                .await
                .map_err(|e| HandshakeError::Transport(e.into()))?;
        }
    }

    // ── Build encrypted channel — only call site ─────────────────────────────
    let channel = EncryptedChannel::new(session_key.as_bytes(), config.max_frame_size);
    Ok((channel, bridge_r, bridge_w))
}

// ── run_relay ──────────────────────────────────────────────────────────────────

/// Bidirectional relay between user and bridge using the established encrypted channel.
///
/// Returns a `RelayOutcome` so the caller can decide whether to reconnect.
#[allow(clippy::too_many_arguments)]
async fn run_relay(
    channel: &mut EncryptedChannel,
    user_r: &mut ReadHalf<TcpStream>,
    user_w: &mut WriteHalf<TcpStream>,
    bridge_r: ReadHalf<TcpStream>,
    bridge_w: WriteHalf<TcpStream>,
    user_eof: &mut bool,
    config: &ValidClientConfig,
    peer: SocketAddr,
) -> RelayOutcome {
    let mut bridge_r = bridge_r;
    let mut bridge_w = bridge_w;
    let mut user_buf = vec![0u8; config.max_frame_size];

    loop {
        tokio::select! {
            // user → bridge
            result = user_r.read(&mut user_buf), if !*user_eof => {
                match result {
                    Ok(0) => {
                        *user_eof = true;
                        let _ = bridge_w.shutdown().await;
                    }
                    Ok(n) => {
                        if let Err(e) = channel.write_frame(&mut bridge_w, &user_buf[..n]).await {
                            warn!(peer = %peer, "write frame to bridge failed: {e}");
                            return RelayOutcome::BridgeError(e.into());
                        }
                    }
                    Err(e) => {
                        warn!(peer = %peer, "read from user failed: {e}");
                        return RelayOutcome::UserError(e.into());
                    }
                }
            }

            // bridge → user
            result = channel.read_frame(&mut bridge_r) => {
                match result {
                    Ok(FrameResult::Data(data)) => {
                        if let Err(e) = user_w.write_all(&data).await {
                            warn!(peer = %peer, "write to user failed: {e}");
                            return RelayOutcome::UserError(e.into());
                        }
                    }
                    Ok(FrameResult::KeyRotate(nonce)) => {
                        channel.rotate_key(&nonce);
                    }
                    Err(e) => {
                        if *user_eof {
                            // Bridge closed after we signaled EOF — clean close.
                            return RelayOutcome::UserEof;
                        }
                        warn!(peer = %peer, "read frame from bridge failed: {e}");
                        return RelayOutcome::BridgeError(anyhow::anyhow!("{e}"));
                    }
                }
            }
        }
    }
}

// ── backoff ────────────────────────────────────────────────────────────────────

fn backoff(attempt: u32, cfg: &ReconnectConfig) -> Duration {
    let raw = cfg.base_delay_ms.saturating_mul(1u64 << attempt.min(20));
    let capped = raw.min(cfg.max_delay_ms);
    let jitter_span = (capped / 5).max(1);
    // ±20% jitter: random in [0, jitter_span*2]
    let jitter = OsRng.next_u32() as u64 % (jitter_span * 2 + 1);
    // capped + jitter - jitter_span can underflow if jitter_span > capped
    let ms = (capped as i64 + jitter as i64 - jitter_span as i64).max(1) as u64;
    Duration::from_millis(ms)
}

// ── handle — public entry point ────────────────────────────────────────────────

/// Maneja una conexion de usuario: realiza el handshake PQC con el bridge
/// y luego relay bidireccional cifrado. Soporta reconexion transparente
/// cuando `config.reconnect.max_retries > 0`.
///
/// - `client_identity`: `Some` habilita autenticacion mutua.
/// - `pool`: pool de conexiones pre-calentadas al bridge.
/// - `reconnect_tx`: canal de eventos de reconexion (opcional).
///
/// INVARIANTE: errores de autenticacion fallan inmediatamente sin reintentos.
pub async fn handle(
    user: TcpStream,
    peer: SocketAddr,
    config: ValidClientConfig,
    vk: Arc<VerifyingKey>,
    client_identity: Option<Arc<ClientIdentity>>,
    pool: Arc<ConnectionPool>,
    reconnect_tx: Option<Arc<mpsc::Sender<ReconnectEvent>>>,
) -> anyhow::Result<()> {
    // User-side stream is split ONCE and preserved across bridge reconnects.
    let (mut user_r, mut user_w) = tokio::io::split(user);
    let mut user_eof = false;
    let mut attempt: u32 = 0;
    let max = config.reconnect.max_retries;

    loop {
        // ── Acquire bridge connection from pool ──────────────────────────────
        let bridge = match pool.acquire().await {
            Ok(s) => s,
            Err(e) => {
                warn!(peer = %peer, bridge = %config.bridge_addr, "pool.acquire failed: {e}");
                if attempt < max {
                    tokio::time::sleep(backoff(attempt, &config.reconnect)).await;
                    attempt += 1;
                    continue;
                }
                if max > 0 {
                    if let Some(tx) = &reconnect_tx {
                        let _ = tx
                            .send(ReconnectEvent::Exhausted {
                                attempts: attempt,
                                peer,
                            })
                            .await;
                    }
                }
                let _ = user_w.shutdown().await;
                return Ok(());
            }
        };

        // ── Full PQC handshake — fresh ephemerals every time ─────────────────
        let (mut channel, bridge_r, bridge_w) =
            match do_handshake(bridge, &vk, client_identity.as_deref(), &config).await {
                Ok(t) => t,
                Err(HandshakeError::Auth(e)) => {
                    // Auth failure: NEVER retry (REQ-5 / REQ-4/C).
                    warn!(peer = %peer, "auth failure — no retry: {e}");
                    let _ = user_w.shutdown().await;
                    return Ok(());
                }
                Err(HandshakeError::Transport(e)) => {
                    warn!(peer = %peer, "handshake transport error: {e}");
                    if attempt < max {
                        tokio::time::sleep(backoff(attempt, &config.reconnect)).await;
                        attempt += 1;
                        continue;
                    }
                    if max > 0 {
                        if let Some(tx) = &reconnect_tx {
                            let _ = tx
                                .send(ReconnectEvent::Exhausted {
                                    attempts: attempt,
                                    peer,
                                })
                                .await;
                        }
                    }
                    let _ = user_w.shutdown().await;
                    return Ok(());
                }
            };

        // ── Emit Reconnected event on any attempt after the first ────────────
        if attempt > 0 {
            if let Some(tx) = &reconnect_tx {
                let _ = tx.send(ReconnectEvent::Reconnected { attempt, peer }).await;
            }
        }

        // ── Bidirectional relay ──────────────────────────────────────────────
        match run_relay(
            &mut channel,
            &mut user_r,
            &mut user_w,
            bridge_r,
            bridge_w,
            &mut user_eof,
            &config,
            peer,
        )
        .await
        {
            RelayOutcome::UserEof | RelayOutcome::UserError(_) => {
                info!(peer = %peer, "session ended for {peer}");
                return Ok(());
            }
            RelayOutcome::BridgeError(e) => {
                if user_eof || attempt >= max {
                    if attempt >= max && max > 0 {
                        if let Some(tx) = &reconnect_tx {
                            let _ = tx
                                .send(ReconnectEvent::Exhausted {
                                    attempts: attempt,
                                    peer,
                                })
                                .await;
                        }
                    }
                    let _ = user_w.shutdown().await;
                    info!(peer = %peer, "session ended for {peer}");
                    return Ok(());
                }
                warn!(
                    peer = %peer,
                    "bridge dropped: {e} — reconnecting (attempt {})",
                    attempt + 1
                );
                tokio::time::sleep(backoff(attempt, &config.reconnect)).await;
                attempt += 1;
                // continue loop → fresh pool.acquire() + do_handshake()
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    use latticeshield_crypto::generate_keypair;
    use rand_core::OsRng;

    use crate::config::{PoolConfig, ReconnectConfig, ValidClientConfig};

    fn make_config(bridge_addr: SocketAddr) -> ValidClientConfig {
        ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            pool: PoolConfig::default(),
            reconnect: ReconnectConfig::default(),
        }
    }

    fn make_pool(bridge_addr: SocketAddr) -> Arc<ConnectionPool> {
        Arc::new(ConnectionPool::new(
            bridge_addr,
            PoolConfig {
                max_size: 1,
                idle_timeout_secs: 30,
                warm_size: 0,
                warm_interval_secs: 5,
            },
        ))
    }

    #[tokio::test]
    async fn bridge_connect_refused_closes_session() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Bind a listener to get a valid addr, then drop it so the port is closed.
        let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();
        drop(bridge_listener);

        // User side: listener + stream to simulate a connected user app.
        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();

        let connect_task =
            tokio::spawn(async move { TcpStream::connect(user_addr).await.unwrap() });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let mut user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let config = make_config(bridge_addr);
        let pool = make_pool(bridge_addr);

        // handle debe retornar Ok(()) — error de sesion, no fatal.
        let result = handle(
            user_server_side,
            peer,
            config,
            Arc::new(vk),
            None,
            pool,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "handle should return Ok(()) on bridge refused, got: {result:?}"
        );

        // El usuario debe recibir EOF (handle hace shutdown del user write side).
        let mut buf = [0u8; 1];
        let n = user_client_side.read(&mut buf).await.unwrap();
        assert_eq!(
            n, 0,
            "user side should receive EOF after bridge connect failure"
        );
    }

    #[tokio::test]
    async fn tampered_signature_closes_session() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Mock bridge: escucha y envia SERVER_HELLO_SIGNED_LEN bytes de ceros (firma invalida)
        let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = bridge_listener.accept().await {
                let zeros = vec![0u8; SERVER_HELLO_SIGNED_LEN];
                let _ = stream.write_all(&zeros).await;
                // dejar que el cliente cierre la conexion
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });

        // Crear el user side: listener + stream para simular usuario conectado
        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();

        let connect_task =
            tokio::spawn(async move { TcpStream::connect(user_addr).await.unwrap() });

        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let config = make_config(bridge_addr);
        let pool = make_pool(bridge_addr);

        // handle debe retornar Ok(()) — error de sesion, no fatal
        let result = handle(
            user_server_side,
            peer,
            config,
            Arc::new(vk),
            None,
            pool,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "handle should return Ok(()) for auth failure, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn handle_retries_on_stale_connection() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // El bridge acepta la conexion y cierra inmediatamente (simula EOF → handled by reconnect loop).
        let real_bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = real_bridge.local_addr().unwrap();

        // El mock bridge acepta la conexion y cierra inmediatamente (simula EOF).
        tokio::spawn(async move {
            if let Ok((stream, _)) = real_bridge.accept().await {
                drop(stream);
            }
        });

        // User side.
        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();
        let connect_task =
            tokio::spawn(async move { TcpStream::connect(user_addr).await.unwrap() });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr: real_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            pool: PoolConfig::default(),
            reconnect: ReconnectConfig::default(),
        };
        let pool = make_pool(real_addr);

        // El bridge cierra sin enviar datos → read_exact del hello falla → handshake transport error → handle Ok(())
        let result = handle(
            user_server_side,
            peer,
            config,
            Arc::new(vk),
            None,
            pool,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "handle should return Ok(()) when bridge closes early, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_reconnect_exhausts_max_retries() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Puerto cerrado — acquire fallara.
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();
        let connect_task =
            tokio::spawn(async move { TcpStream::connect(user_addr).await.unwrap() });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let mut user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:33333".parse().unwrap();
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr: closed_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            pool: PoolConfig::default(),
            reconnect: ReconnectConfig::default(),
        };
        let pool = make_pool(closed_addr);

        // acquire falla → Ok(()) con user recibiendo EOF.
        let result = handle(
            user_server_side,
            peer,
            config,
            Arc::new(vk),
            None,
            pool,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "handle should return Ok(()) after acquire fails, got: {result:?}"
        );

        let mut buf = [0u8; 1];
        let n = user_client_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "user side should receive EOF after acquire failure");
    }

    #[tokio::test]
    async fn test_auth_failure_does_not_retry() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Bridge que acepta y envía un hello con firma inválida (ceros).
        let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();

        let accept_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let accept_count_clone = accept_count.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = bridge_listener.accept().await {
                accept_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let zeros = vec![0u8; SERVER_HELLO_SIGNED_LEN];
                let _ = stream.write_all(&zeros).await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });

        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();
        let connect_task =
            tokio::spawn(async move { TcpStream::connect(user_addr).await.unwrap() });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            pool: PoolConfig::default(),
            reconnect: ReconnectConfig {
                max_retries: 3,
                base_delay_ms: 10,
                max_delay_ms: 50,
            },
        };
        let pool = make_pool(bridge_addr);

        let result = handle(
            user_server_side,
            peer,
            config,
            Arc::new(vk),
            None,
            pool,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "handle should return Ok(()) on auth failure, got: {result:?}"
        );

        // Solo debe haber 1 conexion al bridge — no reintentos por auth failure.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let count = accept_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count, 1,
            "bridge should only be connected once (no retry on auth failure), got: {count}"
        );
    }
}
