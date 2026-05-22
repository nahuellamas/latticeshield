# Changelog

All notable changes to LatticeShield will be documented in this file.

## [Unreleased]

### Security

- **BREAKING**: TLS listener now enforces TLS 1.3 only (`[tls].enabled = true`). TLS 1.2
  clients will be rejected at handshake. This applies to the standard HTTPS listener on port
  8440 — the PQC listener on 8443 and WebSocket listener on 8446 were unaffected as they
  already required TLS 1.3+ via rustls defaults.
- Cloud heartbeat responses are now signature-verified with ML-DSA-65 before dispatching
  `BridgeCommand::Rotate`. Set `[control_plane].cloud_vk_path` to the cloud's verifying key
  file to enable. Without this config the bridge behaves as before (backward compatible).
  Wire format (when verification is enabled):
  ```json
  {
    "signed_payload": "{\"pending_commands\":[{\"type\":\"Rotate\"}],\"ts\":1735776000}",
    "response_signature": "<base64 ML-DSA-65 signature over signed_payload.as_bytes()>"
  }
  ```
  The cloud serializes the inner payload ONCE and signs the exact bytes — bridge verifies
  over the same byte string so no JSON-canonicalization mismatch is possible. The `ts`
  field (unix seconds) anchors freshness: bridge rejects responses with `|now - ts| > 300s`
  to prevent replay of captured signed responses.
- QUIC listener now enforces `[server].max_connections_per_ip` per source IP, consistent
  with TCP and WebSocket listeners.
- `RegistrationPayload` no longer includes `backend_addr`, preventing internal topology
  disclosure to the cloud control plane.
- Emits a startup `warn!` when `[control_plane].install_token` is set in TOML. Prefer the
  `$INSTALL_TOKEN` environment variable in production.
- QUIC listener limits concurrent bidirectional streams to 100 per connection via
  `TransportConfig::max_concurrent_bidi_streams`.

## [0.3.3] - 2026-05-22

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
