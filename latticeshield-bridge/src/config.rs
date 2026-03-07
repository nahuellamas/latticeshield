//! Configuracion del proxy. Se carga desde variables de entorno.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    /// Direccion donde el proxy escucha conexiones de clientes.
    pub listen_addr: SocketAddr,

    /// Direccion del backend al que el proxy reenvía el trafico.
    pub backend_addr: SocketAddr,

    /// Tamano maximo de un frame de datos (bytes de payload). Default: 64 KiB.
    pub max_frame_size: usize,
}

impl Config {
    /// Carga la configuracion desde variables de entorno.
    ///
    /// Variables:
    ///   LISTEN_ADDR  — default: 0.0.0.0:8443
    ///   BACKEND_ADDR — default: 127.0.0.1:8080
    pub fn from_env() -> anyhow::Result<Self> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
            .parse()?;

        let backend_addr = std::env::var("BACKEND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()?;

        Ok(Self {
            listen_addr,
            backend_addr,
            max_frame_size: 64 * 1024,
        })
    }
}
