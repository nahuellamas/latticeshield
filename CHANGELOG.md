# Changelog

All notable changes to LatticeShield will be documented in this file.

## [Unreleased]

### Changed

- `session::handle()` now reads `[server].handshake_timeout_secs` for the PQC TCP handshake
  timeout instead of `[websocket].handshake_timeout_secs`. Deployments that relied on the
  WebSocket timeout field to control TCP behavior must add `[server] handshake_timeout_secs`
  to their config. The default remains 10 s.

### Added

- `[server].handshake_timeout_secs` (default `10`) — explicit PQC TCP handshake timeout.
  Previously the TCP path accidentally read `[websocket].handshake_timeout_secs`; that
  coupling is now removed. Both fields still default to 10 s so default deployments are
  unaffected.
- `[server].max_connections_per_ip` (default `50`) — per-source-IP connection cap on the
  PQC TCP accept loop, mirroring `[websocket].max_connections_per_ip`. Excess connections
  are dropped before any PQC operation is performed and a `warn!` log entry is emitted.
- Security headers on the `/metrics` endpoint: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store`,
  `Content-Security-Policy: default-src 'none'`. No new dependencies added.
