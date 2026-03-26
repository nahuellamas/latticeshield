//! Canal admin PQC en :8445 — autenticacion mutua ML-DSA-65 + AES-256-GCM.
//!
//! Protocolo: una conexion TCP = un handshake PQC = un comando = una respuesta = close.
//! Autenticacion mutua: el bridge firma ServerHello con su ServerIdentity;
//! el control plane firma ClientResponse con su clave admin ML-DSA-65.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use latticeshield_crypto::{
    channel::{EncryptedChannel, FrameResult},
    handshake::{HandshakeError, ServerHandshake, SessionKey, CLIENT_RESPONSE_SIGNED_LEN},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::identity::{ControlPlaneVerifyingIdentity, ServerIdentity};
use crate::metrics::MetricsState;
use crate::vk_share::VkShareStore;

// ── Protocol Types ─────────────────────────────────────────────────────────────

/// Frame de comando: seq + cmd, serializado como JSON dentro del frame AES-256-GCM.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandFrame {
    pub seq: u64,
    #[serde(flatten)]
    pub cmd: AdminCommand,
}

/// Comandos aceptados por el canal admin.
/// Exhaustivo: anadir variante nueva DEBE producir error de compilacion si el match no se actualiza.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum AdminCommand {
    GetMetrics,
    Rotate,
    GetVkToken,
}

/// Respuestas del canal admin.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AdminResponse {
    Metrics { data: String },
    Rotated { count: u64 },
    VkToken { token: String, url: String },
    Error { message: String },
}

/// Servicios compartidos por todas las conexiones del listener admin.
#[derive(Clone)]
pub struct AdminServices {
    pub identity: Arc<ServerIdentity>,
    pub cp_vk: Arc<ControlPlaneVerifyingIdentity>,
    pub vk_store: VkShareStore,
    pub metrics_state: Arc<MetricsState>,
    pub rotate_tx: Arc<watch::Sender<u64>>,
    pub prometheus_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub tls_base_url: String,
}

/// Configuracion de runtime del listener admin.
pub struct AdminListenerConfig {
    pub rate_limit_per_second: u32,
    pub handshake_timeout_secs: u64,
}

// ── Sequence number validation (pure fn — testable without I/O) ──────────────

/// Retorna true si `seq` es estrictamente mayor que `last_seen`.
/// seq=0 siempre rechazado (last_seen inicia en 0, primer seq valido es 1+).
pub fn is_seq_valid(seq: u64, last_seen: u64) -> bool {
    seq > last_seen
}

// ── Handshake ─────────────────────────────────────────────────────────────────

async fn do_handshake(
    stream: &mut TcpStream,
    identity: &ServerIdentity,
    cp_vk: &ControlPlaneVerifyingIdentity,
) -> Result<SessionKey, HandshakeError> {
    let server = ServerHandshake::new(&mut OsRng);

    let hello_bytes = server.server_hello_signed_bytes(&identity.signing_key, &mut OsRng)?;
    stream
        .write_all(&hello_bytes)
        .await
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    let mut buf = [0u8; CLIENT_RESPONSE_SIGNED_LEN];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|_| HandshakeError::AuthenticationFailed)?;

    server.complete_from_wire_signed(&buf, &cp_vk.verifying_key)
}

// ── Connection Handler ────────────────────────────────────────────────────────

async fn handle_admin_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    services: AdminServices,
    handshake_timeout_secs: u64,
) -> anyhow::Result<()> {
    // Handshake con timeout
    let session_key = match tokio::time::timeout(
        Duration::from_secs(handshake_timeout_secs),
        do_handshake(&mut stream, &services.identity, &services.cp_vk),
    )
    .await
    {
        Err(_elapsed) => {
            warn!(%peer, "admin: handshake timeout");
            return Ok(());
        }
        Ok(Err(e)) => {
            warn!(%peer, "admin: handshake failed: {e}");
            return Ok(());
        }
        Ok(Ok(key)) => key,
    };

    let mut channel = EncryptedChannel::new(session_key.as_bytes(), 64 * 1024);

    // Read one command frame
    let frame_bytes = match channel.read_frame(&mut stream).await {
        Ok(FrameResult::Data(b)) => b,
        Ok(FrameResult::KeyRotate(_)) => {
            warn!(%peer, "admin: unexpected KEY_ROTATE frame");
            return Ok(());
        }
        Err(e) => {
            warn!(%peer, "admin: error leyendo frame: {e}");
            return Ok(());
        }
    };

    let cmd_frame: CommandFrame = match serde_json::from_slice(&frame_bytes) {
        Ok(f) => f,
        Err(_) => {
            warn!(%peer, "admin: malformed JSON command");
            return Ok(());
        }
    };

    // Sequence number check (per-connection, starts at 0)
    let last_seen_seq = 0u64;
    if !is_seq_valid(cmd_frame.seq, last_seen_seq) {
        warn!(%peer, seq=%cmd_frame.seq, last_seen=%last_seen_seq, "admin: sequence violation");
        return Ok(());
    }

    // Dispatch command
    let response = match cmd_frame.cmd {
        AdminCommand::GetMetrics => handle_get_metrics(&services.prometheus_handle),
        AdminCommand::Rotate => handle_rotate(&services.rotate_tx, &services.metrics_state),
        AdminCommand::GetVkToken => handle_get_vk_token(
            &services.vk_store,
            &services.identity,
            &services.tls_base_url,
        ),
    };

    let resp_bytes = serde_json::to_vec(&response)?;
    channel.write_frame(&mut stream, &resp_bytes).await?;

    Ok(())
}

// ── Command Handlers ─────────────────────────────────────────────────────────

fn handle_get_metrics(
    prometheus_handle: &metrics_exporter_prometheus::PrometheusHandle,
) -> AdminResponse {
    AdminResponse::Metrics {
        data: prometheus_handle.render(),
    }
}

fn handle_rotate(rotate_tx: &watch::Sender<u64>, metrics_state: &MetricsState) -> AdminResponse {
    rotate_tx.send_modify(|c| *c += 1);
    let count = metrics_state
        .connections_active
        .load(std::sync::atomic::Ordering::Relaxed);
    AdminResponse::Rotated { count }
}

fn handle_get_vk_token(
    vk_store: &VkShareStore,
    identity: &ServerIdentity,
    tls_base_url: &str,
) -> AdminResponse {
    let vk_bytes = identity.verifying_key.to_bytes();
    let ttl = std::time::Duration::from_secs(crate::vk_share::DEFAULT_TOKEN_TTL_SECS);
    let (token, _fingerprint) = crate::vk_share::create_token(vk_store, vk_bytes, ttl);
    let url = format!("{}/vk/{}", tls_base_url, token);
    AdminResponse::VkToken { token, url }
}

// ── Listener ─────────────────────────────────────────────────────────────────

pub fn spawn_admin_listener(
    listen_addr: SocketAddr,
    services: AdminServices,
    config: AdminListenerConfig,
    mut shutdown_rx: watch::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%listen_addr, "admin: no se pudo bindear el listener: {e}");
                return;
            }
        };
        info!(%listen_addr, "admin PQC listener activo — autenticacion mutua ML-DSA-65");

        let mut rate_window_start = Instant::now();
        let mut rate_count: u32 = 0;

        loop {
            let (stream, peer) = tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("admin: accept error: {e}");
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("shutdown: admin listener stopping");
                    break;
                }
            };

            // Rate limiting
            if rate_window_start.elapsed() >= Duration::from_secs(1) {
                rate_window_start = Instant::now();
                rate_count = 0;
            }
            rate_count += 1;
            if rate_count > config.rate_limit_per_second {
                warn!(%peer, "admin: connection dropped — rate limit exceeded");
                drop(stream);
                continue;
            }

            let services = services.clone();
            let timeout_secs = config.handshake_timeout_secs;

            tokio::spawn(async move {
                if let Err(e) = handle_admin_connection(stream, peer, services, timeout_secs).await
                {
                    warn!(%peer, "admin: connection error: {e:#}");
                }
            });
        }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frame_get_metrics_roundtrip() {
        let frame = CommandFrame {
            seq: 1,
            cmd: AdminCommand::GetMetrics,
        };
        let json = serde_json::to_string(&frame).unwrap();
        let decoded: CommandFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 1);
        assert!(matches!(decoded.cmd, AdminCommand::GetMetrics));
    }

    #[test]
    fn command_frame_rotate_roundtrip() {
        let frame = CommandFrame {
            seq: 2,
            cmd: AdminCommand::Rotate,
        };
        let json = serde_json::to_string(&frame).unwrap();
        let decoded: CommandFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 2);
        assert!(matches!(decoded.cmd, AdminCommand::Rotate));
    }

    #[test]
    fn command_frame_get_vk_token_roundtrip() {
        let frame = CommandFrame {
            seq: 3,
            cmd: AdminCommand::GetVkToken,
        };
        let json = serde_json::to_string(&frame).unwrap();
        let decoded: CommandFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 3);
        assert!(matches!(decoded.cmd, AdminCommand::GetVkToken));
    }

    #[test]
    fn command_frame_unknown_cmd_fails() {
        let json = r#"{"seq":1,"cmd":"DeleteAll"}"#;
        let result = serde_json::from_str::<CommandFrame>(json);
        assert!(
            result.is_err(),
            "unknown cmd variant must fail deserialization"
        );
    }

    #[test]
    fn seq_zero_rejected() {
        assert!(!is_seq_valid(0, 0), "seq=0 should always be rejected");
    }

    #[test]
    fn seq_one_accepted_after_zero() {
        assert!(
            is_seq_valid(1, 0),
            "seq=1 should be accepted after last_seen=0"
        );
    }

    #[test]
    fn seq_replay_same_rejected() {
        assert!(
            !is_seq_valid(5, 5),
            "same seq as last_seen should be rejected"
        );
    }

    #[test]
    fn seq_old_rejected() {
        assert!(
            !is_seq_valid(3, 5),
            "seq older than last_seen should be rejected"
        );
    }
}
