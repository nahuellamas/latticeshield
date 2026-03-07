//! TCP listener — acepta conexiones y despacha una tarea por sesion.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{config::Config, session};

pub async fn run(config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "LatticeShield escuchando");
    info!(backend = %config.backend_addr, "backend configurado");

    loop {
        let (socket, peer) = listener.accept().await?;
        let backend_addr: SocketAddr = config.backend_addr;
        let max_frame_size = config.max_frame_size;

        tokio::spawn(async move {
            if let Err(e) = session::handle(socket, peer, backend_addr, max_frame_size).await {
                error!(%peer, "sesion error: {e:#}");
            }
        });
    }
}
