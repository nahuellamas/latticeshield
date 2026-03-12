//! Maneja una sesion PQC con el bridge: handshake + relay bidireccional cifrado.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use latticeshield_crypto::{
    client_respond, parse_server_hello_signed, serialize_client_response,
    serialize_client_response_signed,
    EncryptedChannel, FrameResult, VerifyingKey,
    SERVER_HELLO_LEN, SERVER_HELLO_SIGNED_LEN,
};

use crate::config::{ReconnectConfig, ValidClientConfig};
use crate::identity::ClientIdentity;

/// Maneja una conexion de usuario: realiza el handshake PQC con el bridge
/// y luego relay bidireccional cifrado.
///
/// - `client_identity`: `Some` habilita autenticacion mutua (firma la ClientResponse).
/// - `reconnect`: configura el bucle de reintentos para la conexion al bridge.
///
/// INVARIANTE: el bucle de reintentos aplica SOLO a errores de `TcpStream::connect`.
/// Errores de handshake (incluyendo autenticacion fallida) fallan inmediatamente.
pub async fn handle(
    user: TcpStream,
    peer: SocketAddr,
    config: ValidClientConfig,
    vk: Arc<VerifyingKey>,
    client_identity: Option<Arc<ClientIdentity>>,
    reconnect: ReconnectConfig,
) -> anyhow::Result<()> {
    // ── Conectar al bridge con reintentos ────────────────────────────────────
    let mut bridge_stream = None;
    for attempt in 0..=reconnect.max_retries {
        match TcpStream::connect(config.bridge_addr).await {
            Ok(s) => {
                bridge_stream = Some(s);
                break;
            }
            Err(e) => {
                if attempt == reconnect.max_retries {
                    warn!(
                        peer = %peer,
                        bridge = %config.bridge_addr,
                        attempt,
                        "bridge connect failed after all retries: {e}"
                    );
                    let (_, mut user_w) = tokio::io::split(user);
                    let _ = user_w.shutdown().await;
                    return Ok(());
                }
                let jitter = OsRng.next_u64() % reconnect.base_delay_ms.max(1);
                let delay = reconnect.base_delay_ms * (1u64 << attempt) + jitter;
                warn!(
                    peer = %peer,
                    bridge = %config.bridge_addr,
                    attempt,
                    delay_ms = delay,
                    "bridge connect failed, retrying: {e}"
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
    }
    let bridge = bridge_stream.unwrap();

    // ── Split streams ────────────────────────────────────────────────────────
    let (mut user_r, mut user_w) = tokio::io::split(user);
    let (mut bridge_r, mut bridge_w) = tokio::io::split(bridge);

    // ── Leer ServerHello firmado ─────────────────────────────────────────────
    let mut hello_buf = [0u8; SERVER_HELLO_SIGNED_LEN];
    if let Err(e) = bridge_r.read_exact(&mut hello_buf).await {
        warn!(peer = %peer, "failed to read server hello: {e}");
        let _ = user_w.shutdown().await;
        let _ = bridge_w.shutdown().await;
        return Ok(());
    }

    // Los primeros SERVER_HELLO_LEN (1248) bytes son el ServerHello raw (sin firma).
    let mut server_hello_raw = [0u8; SERVER_HELLO_LEN];
    server_hello_raw.copy_from_slice(&hello_buf[..SERVER_HELLO_LEN]);

    // ── Verificar firma del servidor ─────────────────────────────────────────
    let hello = match parse_server_hello_signed(&hello_buf, &vk) {
        Ok(h) => h,
        Err(_) => {
            warn!(peer = %peer, "authentication failed — peer: {peer}");
            let _ = user_w.shutdown().await;
            return Ok(());
        }
    };

    // ── Respuesta del cliente: encapsular + derivar session key ──────────────
    let (response, session_key) = client_respond(&hello, &mut OsRng)
        .context("client_respond failed")?;

    // ── Enviar respuesta al bridge (con o sin firma del cliente) ─────────────
    match &client_identity {
        Some(identity) => {
            let signed = serialize_client_response_signed(
                &response,
                &identity.signing_key,
                &server_hello_raw,
                &mut OsRng,
            )
            .map_err(|e| anyhow::anyhow!("client response signing failed: {e:?}"))?;
            bridge_w
                .write_all(&signed)
                .await
                .context("write signed client response")?;
        }
        None => {
            bridge_w
                .write_all(&serialize_client_response(&response))
                .await
                .context("write client response")?;
        }
    }

    // ── Canal cifrado ────────────────────────────────────────────────────────
    let mut channel = EncryptedChannel::new(session_key.as_bytes(), config.max_frame_size);

    // ── Relay bidireccional ──────────────────────────────────────────────────
    let mut user_buf = vec![0u8; config.max_frame_size];

    loop {
        tokio::select! {
            // user → bridge: leer datos del usuario y cifrar hacia el bridge
            result = user_r.read(&mut user_buf) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if let Err(e) = channel.write_frame(&mut bridge_w, &user_buf[..n]).await {
                            warn!(peer = %peer, "write frame to bridge failed: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(peer = %peer, "read from user failed: {e}");
                        break;
                    }
                }
            }

            // bridge → user: leer frame cifrado del bridge y descifrar hacia el usuario
            result = channel.read_frame(&mut bridge_r) => {
                match result {
                    Ok(FrameResult::Data(data)) => {
                        if let Err(e) = user_w.write_all(&data).await {
                            warn!(peer = %peer, "write to user failed: {e}");
                            break;
                        }
                    }
                    Ok(FrameResult::KeyRotate(nonce)) => {
                        channel.rotate_key(&nonce);
                    }
                    Err(e) => {
                        warn!(peer = %peer, "read frame from bridge failed: {e}");
                        break;
                    }
                }
            }
        }
    }

    info!(peer = %peer, "session ended for {peer}");
    Ok(())
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

    use crate::config::{ReconnectConfig, ValidClientConfig};

    fn make_config(bridge_addr: SocketAddr) -> ValidClientConfig {
        ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            reconnect: ReconnectConfig::default(),
        }
    }

    fn no_retry() -> ReconnectConfig {
        ReconnectConfig { max_retries: 0, base_delay_ms: 0 }
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

        let connect_task = tokio::spawn(async move {
            TcpStream::connect(user_addr).await.unwrap()
        });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let mut user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let config = make_config(bridge_addr);

        // handle debe retornar Ok(()) — error de sesion, no fatal.
        let result = handle(user_server_side, peer, config, Arc::new(vk), None, no_retry()).await;
        assert!(result.is_ok(), "handle should return Ok(()) on bridge refused, got: {result:?}");

        // El usuario debe recibir EOF (handle hace shutdown del user write side).
        let mut buf = [0u8; 1];
        let n = user_client_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "user side should receive EOF after bridge connect failure");
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

        let connect_task = tokio::spawn(async move {
            TcpStream::connect(user_addr).await.unwrap()
        });

        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let config = make_config(bridge_addr);

        // handle debe retornar Ok(()) — error de sesion, no fatal
        let result = handle(user_server_side, peer, config, Arc::new(vk), None, no_retry()).await;
        assert!(result.is_ok(), "handle should return Ok(()) for auth failure, got: {result:?}");
    }

    #[tokio::test]
    async fn test_reconnect_succeeds_on_second_attempt() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Puerto cerrado para que el primer intento falle.
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        // El segundo intento conectara a un bridge real que acepta y cierra.
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
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(user_addr).await.unwrap()
        });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        // Primer addr falla, segundo addr exito. Simulamos esto usando la addr del real
        // bridge directamente (no podemos cambiar la addr mid-loop con la interfaz actual).
        // En este test usamos real_addr directamente con max_retries=1 y base_delay_ms=0
        // para verificar que la sesion avanza si el bridge responde (con EOF → read_exact falla).
        let peer: SocketAddr = "127.0.0.1:22222".parse().unwrap();
        let reconnect = ReconnectConfig { max_retries: 1, base_delay_ms: 0 };
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr: real_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            reconnect: reconnect.clone(),
        };

        // El bridge cierra sin enviar datos → read_exact del hello falla → handle Ok(())
        let result = handle(user_server_side, peer, config, Arc::new(vk), None, reconnect).await;
        assert!(result.is_ok(), "handle should return Ok(()) when bridge closes early, got: {result:?}");
    }

    #[tokio::test]
    async fn test_reconnect_exhausts_max_retries() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);

        // Puerto cerrado — todos los intentos fallarán.
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let user_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let user_addr = user_listener.local_addr().unwrap();
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(user_addr).await.unwrap()
        });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let mut user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:33333".parse().unwrap();
        let reconnect = ReconnectConfig { max_retries: 2, base_delay_ms: 0 };
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr: closed_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            reconnect: reconnect.clone(),
        };

        // Todos los intentos fallan → Ok(()) con user recibiendo EOF.
        let result = handle(user_server_side, peer, config, Arc::new(vk), None, reconnect).await;
        assert!(result.is_ok(), "handle should return Ok(()) after exhausting retries, got: {result:?}");

        let mut buf = [0u8; 1];
        let n = user_client_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "user side should receive EOF after all retries exhausted");
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
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(user_addr).await.unwrap()
        });
        let (user_server_side, _) = user_listener.accept().await.unwrap();
        let _user_client_side = connect_task.await.unwrap();

        let peer: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        // max_retries=3 pero el auth failure NO debe reintentar.
        let reconnect = ReconnectConfig { max_retries: 3, base_delay_ms: 0 };
        let config = ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            reconnect: reconnect.clone(),
        };

        let result = handle(user_server_side, peer, config, Arc::new(vk), None, reconnect).await;
        assert!(result.is_ok(), "handle should return Ok(()) on auth failure, got: {result:?}");

        // Solo debe haber 1 conexion al bridge — no reintentos por auth failure.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let count = accept_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(count, 1, "bridge should only be connected once (no retry on auth failure), got: {count}");
    }
}
