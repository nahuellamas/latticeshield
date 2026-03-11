//! Maneja una sesion PQC con el bridge: handshake + relay bidireccional cifrado.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use latticeshield_crypto::{
    client_respond, parse_server_hello_signed, serialize_client_response,
    EncryptedChannel, FrameResult, VerifyingKey, SERVER_HELLO_SIGNED_LEN,
};

use crate::config::ValidClientConfig;

/// Maneja una conexion de usuario: realiza el handshake PQC con el bridge
/// y luego relay bidireccional cifrado.
pub async fn handle(
    user: TcpStream,
    peer: SocketAddr,
    config: ValidClientConfig,
    vk: Arc<VerifyingKey>,
) -> anyhow::Result<()> {
    // ── Conectar al bridge ───────────────────────────────────────────────────
    let bridge = match TcpStream::connect(config.bridge_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(peer = %peer, bridge = %config.bridge_addr, "failed to connect to bridge: {e}");
            let (_, mut user_w) = tokio::io::split(user);
            let _ = user_w.shutdown().await;
            return Ok(());
        }
    };

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

    // ── Enviar respuesta al bridge ───────────────────────────────────────────
    bridge_w
        .write_all(&serialize_client_response(&response))
        .await
        .context("write client response")?;

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

    use crate::config::ValidClientConfig;

    fn make_config(bridge_addr: SocketAddr) -> ValidClientConfig {
        ValidClientConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bridge_addr,
            server_vk_path: std::path::PathBuf::from("./keys/server.vk"),
            max_frame_size: 65536,
            log_level: "info".to_string(),
        }
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
        let result = handle(user_server_side, peer, config, Arc::new(vk)).await;
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
        let result = handle(user_server_side, peer, config, Arc::new(vk)).await;
        assert!(result.is_ok(), "handle should return Ok(()) for auth failure, got: {result:?}");
    }
}
