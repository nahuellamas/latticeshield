// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored

// The common module is included in multiple test files; not every item is used
// in every file. Suppress dead-code warnings that are spurious across test targets.
#![allow(dead_code)]

pub mod mock_grpc;
pub mod mock_http;
pub mod mock_tcp;
pub mod pqc_stack;

pub use pqc_stack::spawn_stack;
