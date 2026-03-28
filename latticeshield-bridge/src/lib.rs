//! Public API surface of latticeshield-bridge for use by latticeshield-cli.
//! Only key management modules are exposed — runtime modules stay crate-private.

pub mod identity;
pub mod tls;
pub mod vk_share;

// ── Integration-test surface (cfg(test) does not cover integration tests in tests/) ──
// These modules are exposed for integration tests only. They are not part of the
// stable public API and may change without notice.
pub mod config;
pub mod metrics;
pub mod session;
pub mod ws;
