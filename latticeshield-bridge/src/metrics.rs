//! Subsistema de metricas Prometheus.
//!
//! Expone cinco familias de metricas via el facade `metrics`:
//!   - latticeshield_connections_total       (counter)
//!   - latticeshield_connections_active      (gauge)
//!   - latticeshield_handshake_duration_seconds (histogram)
//!   - latticeshield_bytes_transmitted_total (counter)
//!   - latticeshield_channel_errors_total    (counter)
//!
//! Also provides `MetricsState` — parallel `AtomicU64` counters that can be
//! read back for control-plane heartbeat reporting (the `metrics` crate facade
//! has no read-back API).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Serialize;

pub const CONNECTIONS_TOTAL: &str = "latticeshield_connections_total";
pub const CONNECTIONS_ACTIVE: &str = "latticeshield_connections_active";
pub const HANDSHAKE_DURATION: &str = "latticeshield_handshake_duration_seconds";
pub const BYTES_TRANSMITTED: &str = "latticeshield_bytes_transmitted_total";
pub const CHANNEL_ERRORS: &str = "latticeshield_channel_errors_total";
pub const KEY_ROTATIONS_TOTAL: &str = "latticeshield_key_rotations_total";

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
    describe_counter!(KEY_ROTATIONS_TOTAL, "Total number of session key rotations performed");

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

// ── MetricsState — parallel AtomicU64 counters for heartbeat read-back ─────────

/// Snapshot of all metric counters, serializable to JSON.
#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub connections_active: u64,
    pub connections_total: u64,
    pub bytes_transmitted_total: u64,
    pub channel_errors_total: u64,
    pub key_rotations_total: u64,
}

/// Parallel atomic counters for heartbeat reporting.
/// The `metrics` crate has no read-back API — these AtomicU64s are
/// updated at the same sites as the Prometheus facade macros.
pub struct MetricsState {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub bytes_transmitted_total: AtomicU64,
    pub channel_errors_total: AtomicU64,
    pub key_rotations_total: AtomicU64,
}

impl MetricsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            bytes_transmitted_total: AtomicU64::new(0),
            channel_errors_total: AtomicU64::new(0),
            key_rotations_total: AtomicU64::new(0),
        })
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_active: self.connections_active.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            bytes_transmitted_total: self.bytes_transmitted_total.load(Ordering::Relaxed),
            channel_errors_total: self.channel_errors_total.load(Ordering::Relaxed),
            key_rotations_total: self.key_rotations_total.load(Ordering::Relaxed),
        }
    }
}

/// RAII guard: increments `connections_active` on creation, decrements on drop.
pub struct MetricsActiveGuard(Arc<MetricsState>);

impl MetricsActiveGuard {
    pub fn new(state: &Arc<MetricsState>) -> Self {
        state.connections_active.fetch_add(1, Ordering::Relaxed);
        MetricsActiveGuard(Arc::clone(state))
    }
}

impl Drop for MetricsActiveGuard {
    fn drop(&mut self) {
        self.0.connections_active.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod metrics_state_tests {
    use super::*;

    #[test]
    fn metrics_state_new_all_zeros() {
        let state = MetricsState::new();
        assert_eq!(state.connections_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.connections_active.load(Ordering::Relaxed), 0);
        assert_eq!(state.bytes_transmitted_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.channel_errors_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_state_increments_correctly() {
        let state = MetricsState::new();
        state.connections_total.fetch_add(1, Ordering::Relaxed);
        state.bytes_transmitted_total.fetch_add(1024, Ordering::Relaxed);
        assert_eq!(state.connections_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.bytes_transmitted_total.load(Ordering::Relaxed), 1024);
        assert_eq!(state.connections_active.load(Ordering::Relaxed), 0);
        assert_eq!(state.channel_errors_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_active_guard_increment_decrement() {
        let state = MetricsState::new();
        assert_eq!(state.connections_active.load(Ordering::Relaxed), 0);
        {
            let _guard = MetricsActiveGuard::new(&state);
            assert_eq!(state.connections_active.load(Ordering::Relaxed), 1);
        }
        assert_eq!(state.connections_active.load(Ordering::Relaxed), 0);
        // connections_total is NOT mutated by MetricsActiveGuard
        assert_eq!(state.connections_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_state_snapshot_returns_current_values() {
        let state = MetricsState::new();
        state.connections_total.fetch_add(7, Ordering::Relaxed);
        state.connections_active.fetch_add(2, Ordering::Relaxed);
        state.bytes_transmitted_total.fetch_add(4096, Ordering::Relaxed);
        state.channel_errors_total.fetch_add(3, Ordering::Relaxed);
        let snap = state.snapshot();
        assert_eq!(snap.connections_total, 7);
        assert_eq!(snap.connections_active, 2);
        assert_eq!(snap.bytes_transmitted_total, 4096);
        assert_eq!(snap.channel_errors_total, 3);
    }

    #[test]
    fn metrics_state_new_key_rotations_zero() {
        let state = MetricsState::new();
        assert_eq!(state.key_rotations_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_snapshot_includes_key_rotations() {
        let state = MetricsState::new();
        state.key_rotations_total.fetch_add(3, Ordering::Relaxed);
        let snap = state.snapshot();
        assert_eq!(snap.key_rotations_total, 3);
    }

    #[tokio::test]
    async fn metrics_state_shared_across_threads() {
        let state = MetricsState::new();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                s.connections_total.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(state.connections_total.load(Ordering::Relaxed), 4);
    }
}
