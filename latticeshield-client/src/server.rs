//! TCP listener del cliente proxy: acepta conexiones de aplicaciones locales
//! y las retransmite al bridge PQC.

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::info;

use latticeshield_crypto::VerifyingKey;

use crate::client_session;
use crate::config::ValidClientConfig;
use crate::identity::ClientIdentity;
use crate::pool::ConnectionPool;

/// Arranca el listener TCP y acepta conexiones indefinidamente.
///
/// Cada conexion se maneja en una task tokio separada via `client_session::handle`.
pub async fn run(
    config: ValidClientConfig,
    vk: Arc<VerifyingKey>,
    client_identity: Option<Arc<ClientIdentity>>,
) -> anyhow::Result<()> {
    let pool = Arc::new(ConnectionPool::new(config.bridge_addr, config.pool.clone()));

    let pool_for_warmer = Arc::clone(&pool);
    tokio::spawn(async move { pool_for_warmer.warm_loop().await });

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "LatticeShield Client listening");
    info!(bridge = %config.bridge_addr, "targeting bridge");

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        #[cfg(unix)]
        let shutdown_future = async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        };
        #[cfg(not(unix))]
        let shutdown_future = tokio::signal::ctrl_c();

        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                let config = config.clone();
                let vk = Arc::clone(&vk);
                let client_identity = client_identity.clone();
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    if let Err(e) = client_session::handle(stream, peer, config, vk, client_identity, pool).await {
                        tracing::warn!(peer = %peer, "session error: {e}");
                    }
                });
            }
            _ = shutdown_future => {
                info!("shutdown signal received — stopping accept loop");
                pool.shutdown().await;
                return Ok(());
            }
        }
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

    use crate::config::PoolConfig;

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
            client_sk_path: None,
            max_frame_size: 65536,
            log_level: "info".to_string(),
            pool: PoolConfig::default(),
        };

        let task = tokio::spawn(run(config, Arc::clone(&vk), None));

        // Give server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Connect to the server
        let result = TcpStream::connect(listen_addr).await;
        assert!(
            result.is_ok(),
            "should be able to connect to running server"
        );

        task.abort();
    }
}
