//! Configuracion del proxy. Se carga desde variables de entorno.

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// Direccion donde el proxy escucha conexiones de clientes.
    pub listen_addr: SocketAddr,

    /// Direccion del backend al que el proxy reenvía el trafico.
    pub backend_addr: SocketAddr,

    /// Direccion donde se expone el endpoint HTTP de metricas Prometheus.
    pub metrics_addr: SocketAddr,

    /// Tamano maximo de un frame de datos (bytes de payload). Default: 64 KiB.
    pub max_frame_size: usize,

    /// Ruta al archivo de clave de firma ML-DSA-65 del servidor (`server.sk`).
    /// La clave de verificacion (`server.vk`) se lee del mismo directorio.
    pub signing_key_path: PathBuf,
}

impl Config {
    /// Carga la configuracion desde variables de entorno.
    ///
    /// Variables:
    ///   LISTEN_ADDR        — default: 0.0.0.0:8443
    ///   BACKEND_ADDR       — default: 127.0.0.1:8080
    ///   METRICS_ADDR       — default: 0.0.0.0:8444
    ///   SIGNING_KEY_PATH   — default: ./keys/server.sk
    pub fn from_env() -> anyhow::Result<Self> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
            .parse()?;

        let backend_addr = std::env::var("BACKEND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()?;

        let metrics_addr = std::env::var("METRICS_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8444".to_string())
            .parse()?;

        let signing_key_path = std::env::var("SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "./keys/server.sk".to_string())
            .into();

        Ok(Self {
            listen_addr,
            backend_addr,
            metrics_addr,
            max_frame_size: 64 * 1024,
            signing_key_path,
        })
    }
}
