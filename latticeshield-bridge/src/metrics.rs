//! Subsistema de metricas Prometheus.
//!
//! Expone cinco familias de metricas via el facade `metrics`:
//!   - latticeshield_connections_total       (counter)
//!   - latticeshield_connections_active      (gauge)
//!   - latticeshield_handshake_duration_seconds (histogram)
//!   - latticeshield_bytes_transmitted_total (counter)
//!   - latticeshield_channel_errors_total    (counter)

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub const CONNECTIONS_TOTAL: &str = "latticeshield_connections_total";
pub const CONNECTIONS_ACTIVE: &str = "latticeshield_connections_active";
pub const HANDSHAKE_DURATION: &str = "latticeshield_handshake_duration_seconds";
pub const BYTES_TRANSMITTED: &str = "latticeshield_bytes_transmitted_total";
pub const CHANNEL_ERRORS: &str = "latticeshield_channel_errors_total";

/// Inicializa el recorder Prometheus y registra los descriptores de las cinco metricas.
///
/// Debe llamarse una sola vez al arrancar el proceso, antes de cualquier instruccion.
pub fn init() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("error inicializando Prometheus recorder: {e}"))?;

    describe_counter!(CONNECTIONS_TOTAL, "Total de conexiones TCP recibidas por el proxy");
    describe_gauge!(CONNECTIONS_ACTIVE, "Conexiones activas (post-handshake) en este momento");
    describe_histogram!(
        HANDSHAKE_DURATION,
        "Duracion del handshake PQC hibrido en segundos"
    );
    describe_counter!(BYTES_TRANSMITTED, "Bytes de payload transmitidos desde el backend al cliente");
    describe_counter!(CHANNEL_ERRORS, "Errores en el canal cifrado AES-256-GCM");

    Ok(handle)
}

/// Guard RAII que mantiene el gauge `connections_active` actualizado.
///
/// Crear un `ActiveGuard` incrementa el gauge; al salir de scope (Drop) lo decrementa.
pub struct ActiveGuard;

impl ActiveGuard {
    pub fn new() -> Self {
        metrics::gauge!(CONNECTIONS_ACTIVE).increment(1.0);
        ActiveGuard
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        metrics::gauge!(CONNECTIONS_ACTIVE).decrement(1.0);
        metrics::counter!(CONNECTIONS_TOTAL, "status" => "success").increment(1);
    }
}
