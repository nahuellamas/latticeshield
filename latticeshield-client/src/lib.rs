/// Crate library root — exposes internal modules for integration tests.
/// The binary entry point (main.rs) uses these same modules via `mod` declarations.
pub mod client_session;
pub mod config;
pub mod identity;
pub mod pool;
pub mod server;
