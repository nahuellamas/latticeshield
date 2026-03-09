//! Manejo de una conexion de cliente.
//!
//! Flujo por conexion:
//!   1. Handshake PQC autenticado: ServerHello firmado con ML-DSA-65 (pre-shared VK).
//!   2. Canal cifrado AES-256-GCM establecido.
//!   3. Relay bidireccional entre cliente (cifrado) y backend (plaintext TCP).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use latticeshield_crypto::{ServerHandshake, CLIENT_RESPONSE_LEN, SERVER_HELLO_SIGNED_LEN};
use rand_core::OsRng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info, warn};

use crate::channel::EncryptedChannel;
use crate::identity::ServerIdentity;
use crate::metrics::{ActiveGuard, MetricsActiveGuard, MetricsState};

pub async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    backend_addr: SocketAddr,
    max_frame_size: usize,
    identity: Arc<ServerIdentity>,
    metrics_state: Arc<MetricsState>,
) -> anyhow::Result<()> {
    info!(%peer, "conexion entrante");
    metrics::counter!(crate::metrics::CONNECTIONS_TOTAL).increment(1);
    metrics_state.connections_total.fetch_add(1, Ordering::Relaxed);

    // ── 1. Handshake PQC autenticado ────────────────────────────────────────

    let t_handshake = Instant::now();
    let server = ServerHandshake::new(&mut OsRng);

    // Firma el ServerHello con la clave de largo plazo — VK pre-shared en el cliente
    let hello_bytes = server
        .server_hello_signed_bytes(&identity.signing_key, &mut OsRng)
        .context("firma del ServerHello")?;

    client
        .write_all(&hello_bytes)
        .await
        .context("envio ServerHello firmado")?;
    debug!(%peer, "ServerHello firmado enviado ({} bytes)", SERVER_HELLO_SIGNED_LEN);

    let mut response_buf = [0u8; CLIENT_RESPONSE_LEN];
    client
        .read_exact(&mut response_buf)
        .await
        .context("lectura ClientResponse")?;
    debug!(%peer, "ClientResponse recibido ({} bytes)", CLIENT_RESPONSE_LEN);

    let session_key = server
        .complete_from_wire(&response_buf)
        .context("handshake PQC fallido")?;
    metrics::histogram!(crate::metrics::HANDSHAKE_DURATION).record(t_handshake.elapsed().as_secs_f64());
    info!(%peer, "handshake PQC completado — canal cifrado activo");

    // ── 2. Canal cifrado ─────────────────────────────────────────────────────

    let _guard = ActiveGuard::new();
    let _ms_guard = MetricsActiveGuard::new(&metrics_state);
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
                        metrics_state.channel_errors_total.fetch_add(1, Ordering::Relaxed);
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
                        metrics_state.bytes_transmitted_total.fetch_add(n as u64, Ordering::Relaxed);
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
