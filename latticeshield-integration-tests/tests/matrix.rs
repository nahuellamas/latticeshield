// Run ignored tests with: cargo test -p latticeshield-integration-tests -- --ignored
//
// # Reconnect Classification Matrix
//
// Documents the observed behavior of each application protocol when the PQC
// bridge session is aborted mid-connection. Classifications are machine-verified
// by the per-protocol tests in this crate.
//
// | Protocol   | Classification | Notes                                                             |
// |------------|----------------|-------------------------------------------------------------------|
// | HTTP       | OK             | Stateless; new TCP connection through PQC tunnel succeeds         |
// | TCP raw    | BROKEN         | Connection is terminal; no transparent reconnect possible         |
// | PostgreSQL | STATE_LOSS     | Open transaction is rolled back; new connection succeeds          |
// | Redis      | STATE_LOSS     | PubSub subscriptions lost; re-subscribe on new connection works   |
// | gRPC       | STATE_LOSS     | Open stream errors; new channel + stream succeeds                 |
//
// Classification definitions:
//   OK         — client library reconnects transparently; application sees no error
//   STATE_LOSS — connection errors; application-level state lost; new connection ok
//   BROKEN     — socket is terminal; no reconnect without application restart

/// Placeholder test that allows `cargo test` to include this file.
#[test]
fn noop() {}
