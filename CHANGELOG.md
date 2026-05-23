# Changelog

All notable changes to LatticeShield will be documented in this file.

## [Unreleased]

## [0.3.6] - 2026-05-22

### Security

- **`.gitignore`** hardened to prevent secret-leak via `git add .` after the
  README quickstart. Previously only `/etc/latticeshield/keys/` was ignored,
  so a user running `latticeshield-bridge keygen ./keys` from the repo root
  could accidentally commit their private ML-DSA-65 signing key. Added:
  `keys/`, `*.sk`, `.env.*`, `latticeshield-js/dist/`, `*.log`, `.idea/`,
  `.vscode/`.

### CI / Release

- `release.yml` `publish-npm`: Node 20 → 22 + `npm install -g npm@latest`.
  npm Trusted Publishing requires Node 22.14+ and npm CLI 11.5.1+ per the
  official docs. v0.3.5 publish failed previously because of authentication;
  v0.3.6 ships the upgraded toolchain plus a `NODE_AUTH_TOKEN` bootstrap
  path that gracefully migrates to Trusted Publishing after the first
  successful publish (full migration steps in the workflow comments).
- `publish-npm` job uses a short-lived (≤1 day) Granular Access Token
  scoped only to `@latticeshield/*` for first publish. After this release
  lands on npm, the migration to OIDC trusted publishing removes all
  standing credentials.

## [0.3.5] - 2026-05-22

### Fixed

- **CI / npm publish**: `@latticeshield/js` build switched from `vite build`
  to `tsc`. The v0.3.4 release workflow failed at the publish-npm step because
  vite 8.x rolldown requires an explicit `build.lib` configuration for library
  builds (which was never created — the SDD that added publish-npm never ran
  `npm run build` locally). The tsconfig already had `declaration: true` and
  `outDir: ./dist`, so plain `tsc` emits both `.js` and `.d.ts` files with no
  extra dev dependencies needed.
- `scripts/sri.mjs` postbuild now skips gracefully when the wasm file is not
  present (e.g. CI publish jobs that don't run `wasm-pack build`). The SRI
  hash is for self-hosting users who serve the wasm themselves; missing wasm
  in CI is expected and no longer breaks the publish flow.

## [0.3.4] - 2026-05-22

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

### Fixed

- Heartbeat response body buffering capped at 1 MiB — rejects oversized cloud responses
  by both `Content-Length` (pre-buffer) and actual byte count (post-buffer). Prevents OOM
  via a hostile cloud endpoint.
- Cloud signature `ts` overflow-safe: `checked_sub` + `saturating_abs` guards against
  `ts = i64::MIN` panicking in debug builds and silently wrapping in release builds.
  Both profiles now reject extreme `ts` values cleanly.
- Coherent fail-closed across malformed-cloud-response branches: base64 decode failure
  and signature parse failure now both `Ok(default())` + `warn!` instead of propagating
  `Err` from the heartbeat task.

### CI / Release

- `release.yml` `publish-npm` job now depends on `[build, upload-release]` — npm publish
  will not fire if binary cross-compilation or GitHub Release upload fails. Prevents
  releasing `@latticeshield/js` with no matching bridge binaries for the tag.

### Docker

- Builder image switched from `rust:1.87-slim` to `rust:1.87-alpine` (~0–14 high CVEs vs
  ~23 high CVEs in the Debian-based slim variant). Runtime image unchanged
  (`gcr.io/distroless/static-debian12:nonroot`). Multi-arch ready —
  `docker buildx build --platform linux/amd64,linux/arm64 .` works.
- `.dockerignore` aligned with `.gitignore`: prevents TLS material (`*.pem`, `*.key`,
  `*.crt`), env files (`.env`), and local tooling state (`.claude/`, `.engram/`, etc.)
  from entering the docker build context.

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
