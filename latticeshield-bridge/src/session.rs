//! Manejo de una conexion de cliente.
//!
//! Flujo por conexion:
//!   1. Handshake PQC autenticado: ServerHello firmado con ML-DSA-65 (pre-shared VK).
//!   2. Canal cifrado AES-256-GCM establecido.
//!   3. Relay bidireccional entre cliente (cifrado) y backend (plaintext TCP).
//!
//! Rotacion de clave de sesion (si key_rotation_enabled):
//!   - Trigger por tiempo: key_rotation_interval
//!   - Trigger por bytes: max_bytes_per_key
//!   - Trigger manual: watch::Receiver de rotate_tx (POST /rotate)
//!
//! En cada rotacion: se genera un nonce aleatorio de 32B, se envia KEY_ROTATE al
//! cliente, y se deriva la nueva clave via HKDF-SHA256(current_key, nonce, info).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use latticeshield_crypto::{ServerHandshake, CLIENT_RESPONSE_LEN, CLIENT_RESPONSE_SIGNED_LEN, SERVER_HELLO_SIGNED_LEN};
use rand_core::{OsRng, RngCore};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::MissedTickBehavior,
};
use tracing::{debug, info, warn};

use latticeshield_crypto::channel::{EncryptedChannel, FrameResult};
use crate::config::ValidConfig;
use crate::identity::{ClientVerifyingIdentity, ServerIdentity};
use crate::metrics::{ActiveGuard, MetricsActiveGuard, MetricsState};

pub async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    identity: Arc<ServerIdentity>,
    client_auth: Option<Arc<ClientVerifyingIdentity>>,
    metrics_state: Arc<MetricsState>,
    rotate_tx: Arc<watch::Sender<u64>>,
    config: ValidConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
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

    let session_key = match &client_auth {
        Some(client_identity) => {
            let mut buf = [0u8; CLIENT_RESPONSE_SIGNED_LEN];
            client
                .read_exact(&mut buf)
                .await
                .context("lectura ClientResponse firmado")?;
            debug!(%peer, "ClientResponse firmado recibido ({} bytes)", CLIENT_RESPONSE_SIGNED_LEN);
            server
                .complete_from_wire_signed(&buf, &client_identity.verifying_key)
                .map_err(|e| {
                    warn!(%peer, "autenticacion del cliente fallida: {e}");
                    anyhow::anyhow!("client authentication failed: {e}")
                })?
        }
        None => {
            let mut buf = [0u8; CLIENT_RESPONSE_LEN];
            client
                .read_exact(&mut buf)
                .await
                .context("lectura ClientResponse")?;
            debug!(%peer, "ClientResponse recibido ({} bytes)", CLIENT_RESPONSE_LEN);
            server
                .complete_from_wire(&buf)
                .context("handshake PQC fallido")?
        }
    };
    metrics::histogram!(crate::metrics::HANDSHAKE_DURATION).record(t_handshake.elapsed().as_secs_f64());
    info!(%peer, "handshake PQC completado — canal cifrado activo");

    // ── 2. Canal cifrado ─────────────────────────────────────────────────────

    let _guard = ActiveGuard::new();
    let _ms_guard = MetricsActiveGuard::new(&metrics_state);
    let mut channel = EncryptedChannel::new(session_key.as_bytes(), config.max_frame_size);

    // ── 3. Conexion al backend ───────────────────────────────────────────────

    let mut backend = TcpStream::connect(config.backend_addr)
        .await
        .context(format!("conexion a backend {}", config.backend_addr))?;
    debug!(%peer, "conectado al backend {}", config.backend_addr);

    // ── 4. Relay bidireccional con rotacion de clave ─────────────────────────

    let (mut client_r, mut client_w) = client.split();
    let (mut backend_r, mut backend_w) = backend.split();

    let mut backend_buf = vec![0u8; config.max_frame_size];
    let mut bytes_this_epoch: u64 = 0;

    // Watch receiver para rotacion manual via POST /rotate
    let mut rotate_rx = rotate_tx.subscribe();

    // Intervalo de tiempo para rotacion periodica.
    // El primer tick dispara inmediatamente — lo consumimos antes del loop.
    let mut key_rotation_timer = tokio::time::interval(config.key_rotation_interval);
    key_rotation_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    key_rotation_timer.tick().await; // consume el tick inicial

    loop {
        // select! retorna bool: true = hay que rotar, false = no.
        // Los tres triggers (bytes/tiempo/POST) ponen true.
        // `break` dentro de un arm es divergente (!), coerciona a bool y sale del loop.
        let should_rotate: bool = tokio::select! {
            // ── Cliente → backend (frame cifrado → plaintext) ──────────────
            frame_result = channel.read_frame(&mut client_r) => {
                match frame_result {
                    Ok(FrameResult::Data(data)) => {
                        if data.is_empty() {
                            debug!(%peer, "frame vacio — cerrando sesion");
                            break;
                        }
                        backend_w.write_all(&data).await.context("write al backend")?;
                        false
                    }
                    Ok(FrameResult::KeyRotate(_)) => {
                        // El servidor es siempre el iniciador de rotacion.
                        // Un KEY_ROTATE del cliente es inesperado — cierra sesion.
                        warn!(%peer, "KEY_ROTATE inesperado del cliente — cerrando sesion");
                        break;
                    }
                    Err(e) => {
                        warn!(%peer, "error leyendo frame del cliente: {e}");
                        metrics_state.channel_errors_total.fetch_add(1, Ordering::Relaxed);
                        metrics::counter!(crate::metrics::CHANNEL_ERRORS).increment(1);
                        break;
                    }
                }
            }

            // ── Backend → cliente (plaintext → frame cifrado) ───────────────
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
                        metrics::counter!(crate::metrics::BYTES_TRANSMITTED).increment(n as u64);
                        bytes_this_epoch += n as u64;
                        // Trigger por umbral de bytes
                        config.key_rotation_enabled && bytes_this_epoch >= config.max_bytes_per_key
                    }
                    Err(e) => {
                        warn!(%peer, "error leyendo del backend: {e}");
                        break;
                    }
                }
            }

            // ── Rotacion periodica por intervalo de tiempo ──────────────────
            _ = key_rotation_timer.tick(), if config.key_rotation_enabled => {
                true
            }

            // ── Rotacion manual via POST /rotate ────────────────────────────
            result = rotate_rx.changed() => {
                // result.is_ok() = sender sigue activo → rotar.
                // result.is_err() = sender caido (shutdown) → no rotar.
                result.is_ok()
            }

            // ── Graceful shutdown signal ─────────────────────────────────────
            _ = shutdown_rx.changed() => {
                info!(%peer, "session: shutdown signal, stopping relay");
                break;
            }
        };

        if should_rotate {
            do_rotate(&mut channel, &mut client_w, &metrics_state, peer).await?;
            bytes_this_epoch = 0;
        }
    }

    info!(%peer, "sesion finalizada");
    Ok(())
}

/// Genera un nonce aleatorio, envia KEY_ROTATE al cliente y rota la clave local.
///
/// Usa HKDF-SHA256(ikm=current_key, salt=nonce, info="latticeshield-v1-key-rotation").
/// La clave anterior es zeroizada automaticamente por Zeroizing<T>.
async fn do_rotate(
    channel: &mut EncryptedChannel,
    writer: &mut (impl AsyncWrite + Unpin),
    metrics_state: &Arc<MetricsState>,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    channel
        .send_key_rotate(writer, &nonce)
        .await
        .context("send KEY_ROTATE frame")?;
    channel.rotate_key(&nonce);
    metrics::counter!(crate::metrics::KEY_ROTATIONS_TOTAL).increment(1);
    metrics_state.key_rotations_total.fetch_add(1, Ordering::Relaxed);
    info!(%peer, "clave de sesion rotada");
    Ok(())
}
