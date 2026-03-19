//! Public API surface of latticeshield-bridge for use by latticeshield-cli.
//! Only key management modules are exposed — runtime modules stay crate-private.

pub mod identity;
pub mod tls;
pub mod vk_share;
