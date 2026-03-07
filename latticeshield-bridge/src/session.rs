//! Manejo de una conexion de cliente.
//!
//! Flujo por conexion:
//!   1. Handshake PQC hibrido (X25519 + ML-KEM-768 + HKDF-SHA256).
//!   2. Canal cifrado AES-256-GCM establecido.
//!   3. Relay bidireccional entre cliente (cifrado) y backend (plaintext TCP).

use std::net::SocketAddr;

use anyhow::Context;
use latticeshield_crypto::{ServerHandshake, CLIENT_RESPONSE_LEN};
use rand_core::OsRng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info, warn};

use crate::channel::EncryptedChannel;

pub async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    backend_addr: SocketAddr,
    max_frame_size: usize,
) -> anyhow::Result<()> {
    info!(%peer, "conexion entrante");

    // ── 1. Handshake PQC ────────────────────────────────────────────────────

    let server = ServerHandshake::new(&mut OsRng);
    let hello_bytes = server.server_hello_bytes();

    client
        .write_all(&hello_bytes)
        .await
        .context("envio ServerHello")?;
    debug!(%peer, "ServerHello enviado ({} bytes)", hello_bytes.len());

    let mut response_buf = [0u8; CLIENT_RESPONSE_LEN];
    client
        .read_exact(&mut response_buf)
        .await
        .context("lectura ClientResponse")?;
    debug!(%peer, "ClientResponse recibido ({} bytes)", CLIENT_RESPONSE_LEN);

    let session_key = server
        .complete_from_wire(&response_buf)
        .context("handshake PQC fallido")?;
    info!(%peer, "handshake PQC completado — canal cifrado activo");

    // ── 2. Canal cifrado ─────────────────────────────────────────────────────

    let channel = EncryptedChannel::new(session_key.as_bytes(), max_frame_size);

    // ── 3. Conexion al backend ───────────────────────────────────────────────

    let mut backend = TcpStream::connect(backend_addr)
        .await
        .context(format!("conexion a backend {backend_addr}"))?;
    debug!(%peer, "conectado al backend {backend_addr}");

    // ── 4. Relay bidireccional ───────────────────────────────────────────────

    let (mut client_r, mut client_w) = client.split();
    let (mut backend_r, mut backend_w) = backend.split();

    let mut backend_buf = vec![0u8; max_frame_size];

    loop {
        tokio::select! {
            // Cliente → backend (frame cifrado → plaintext)
            frame_result = channel.read_frame(&mut client_r) => {
                match frame_result {
                    Ok(data) => {
                        if data.is_empty() {
                            debug!(%peer, "frame vacio — cerrando sesion");
                            break;
                        }
                        backend_w.write_all(&data).await.context("write al backend")?;
                    }
                    Err(e) => {
                        warn!(%peer, "error leyendo frame del cliente: {e}");
                        break;
                    }
                }
            }

            // Backend → cliente (plaintext → frame cifrado)
            read_result = backend_r.read(&mut backend_buf) => {
                match read_result {
                    Ok(0) => {
                        debug!(%peer, "backend cerro la conexion");
                        break;
                    }
                    Ok(n) => {
                        channel.write_frame(&mut client_w, &backend_buf[..n])
                            .await
                            .context("write frame al cliente")?;
                    }
                    Err(e) => {
                        warn!(%peer, "error leyendo del backend: {e}");
                        break;
                    }
                }
            }
        }
    }

    info!(%peer, "sesion finalizada");
    Ok(())
}
