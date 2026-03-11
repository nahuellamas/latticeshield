//! TCP listener del cliente proxy: acepta conexiones de aplicaciones locales
//! y las retransmite al bridge PQC.

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use latticeshield_crypto::VerifyingKey;

use crate::client_session;
use crate::config::ValidClientConfig;

/// Arranca el listener TCP y acepta conexiones indefinidamente.
///
/// Cada conexion se maneja en una task tokio separada via `client_session::handle`.
pub async fn run(config: ValidClientConfig, vk: Arc<VerifyingKey>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "LatticeShield Client listening");
    info!(bridge = %config.bridge_addr, "targeting bridge");

    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        let vk = Arc::clone(&vk);
        tokio::spawn(async move {
            if let Err(e) = client_session::handle(stream, peer, config, vk).await {
                tracing::warn!(peer = %peer, "session error: {e}");
            }
        });
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use latticeshield_crypto::generate_keypair;
    use rand_core::OsRng;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn run_binds_and_accepts() {
        let mut rng = OsRng;
        let (_sk, vk) = generate_keypair(&mut rng);
        let vk = Arc::new(vk);

        // Bind a port=0 to get an ephemeral port, then build config with that addr
        let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = temp_listener.local_addr().unwrap();
        drop(temp_listener); // release so server::run can bind it

        let config = ValidClientConfig {
            listen_addr,
            bridge_addr: "127.0.0.1:8443".parse().unwrap(),
            server_vk_path: PathBuf::from("./keys/server.vk"),
            max_frame_size: 65536,
            log_level: "info".to_string(),
        };

        let task = tokio::spawn(run(config, Arc::clone(&vk)));

        // Give server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Connect to the server
        let result = TcpStream::connect(listen_addr).await;
        assert!(result.is_ok(), "should be able to connect to running server");

        task.abort();
    }
}
