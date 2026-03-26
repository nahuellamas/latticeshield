# LatticeShield

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/tests-308_passing-brightgreen?style=for-the-badge" alt="308 tests passing">
  <img src="https://img.shields.io/badge/no_FFI-pure_Rust-blue?style=for-the-badge" alt="No FFI — pure Rust">
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768_%2B_ML--DSA--65-blueviolet?style=for-the-badge" alt="PQC: ML-KEM-768 + ML-DSA-65">
  <img src="https://img.shields.io/badge/license-UNLICENSED-lightgrey?style=for-the-badge" alt="UNLICENSED">
</p>

A quantum-safe reverse proxy written in pure Rust. Adds a hybrid post-quantum cryptography (PQC) layer — **X25519 + ML-KEM-768** — as a transparent encryption layer between clients and backend services, with no FFI, no OpenSSL, no `oqs-rs`.

## What's New

### CI/Release Pipeline and One-Command Install (2026-03-26)

LatticeShield now ships pre-built binaries for Linux (x86_64 and arm64) and macOS (Intel and Apple Silicon). Install with a single command — no Rust, no compiler, no manual file copying required:

```sh
curl -fsSL https://raw.githubusercontent.com/nahuellamas/latticeshield/main/install.sh | bash
```

The script detects your platform, downloads the right binary, verifies its SHA-256 checksum against the release manifest, and installs it to `/usr/local/bin`. Every pull request and push to main now runs an automated check — formatting, linting, dependency audit, and all 308 tests — before code can be merged. Ready-to-use service files for systemd (Linux) and launchd (macOS) are included under `contrib/` so you can run the bridge as a hardened system service in two commands.

### Security Enforcement — Client Auth, Encrypted Key Rotation, and Dead Code Removal (2026-03-26)

The bridge now requires that every connecting client prove its identity before the session is accepted. Before this release, client verification was optional and off by default, meaning the bridge would accept connections from anyone who knew the server's address. Now the bridge refuses to start unless it is either given a key to check clients against, or explicitly told that open access is intentional — via `require_client_auth = false` in the config file. We also closed a gap where the secret used to agree on a new encryption key mid-session traveled in the clear inside the channel; that secret is now itself encrypted with the same lock that protects all other traffic. Finally, we removed an unused internal component (an anti-replay filter for one-time entry tickets that were never implemented) that added complexity without providing any real security benefit.

### Replay-proof DATA frames — Framing v3 (2026-03-25)

Every encrypted data frame now carries a sequence number that the receiver must see strictly increasing. If an attacker records a frame and replays it later, the bridge rejects it immediately — the sequence number would not be greater than the last accepted one. The sequence number is mathematically tied to the encrypted content (using the same authentication tag that protects the data), so tampering with it is also detectable. This closes the last theoretical replay gap in the encrypted channel.

### Pre-production Hardening (2026-03-25)

The bridge now shuts down cleanly when the operating system asks it to stop. Before this release, a `systemctl restart` or a Kubernetes rolling update would cut all active connections mid-transfer. Now the bridge stops accepting new connections, waits for in-flight sessions to finish (up to 30 seconds by default, configurable via `SHUTDOWN_TIMEOUT_SECS`), and only then exits — so no connection is dropped abruptly. We also fixed a bug where a single internal error could cascade into a full crash of the key-distribution endpoint, and stabilized a test that was occasionally failing on slow machines.

### Hybrid Post-Quantum TLS and Cloud Command Wiring (2026-03-24)

The bridge now uses post-quantum-safe encryption when talking to the cloud management server. Before this release, status updates and registration requests traveled over standard TLS, which a future quantum computer could break. Now the bridge negotiates a hybrid key exchange (that means: two independent mathematical locks — one classical, one quantum-resistant — must both be broken to read the data). Additionally, when the cloud sends a "rotate keys" instruction inside a status-update response, the bridge now actually performs the rotation across all active client sessions instead of just logging it. Operators can see rotation events in their monitoring dashboards.

### Signed Heartbeats and Cloud Onboarding Token (2026-03-20)

The bridge now proves its identity to the cloud management server on every status update it sends. Before this release, any process that knew the bridge's ID could send fake status updates — there was no way for the server to tell real updates from imposters. Now every update carries a digital signature (that means: a mathematical proof, like a wax seal, that only this specific bridge can produce). The cloud can verify that seal without storing any secret. Operators can also configure a one-time onboarding token (a short secret code the cloud issues when you register a new bridge) so that only bridges holding that code can claim an agent slot — the token never appears in any log file, no matter the log level.

### Admin Post-Quantum Channel on `:8445` (2026-03-20)

The bridge now exposes an optional dedicated admin channel for the control plane. When enabled, it listens on `:8445` (TCP) and requires **mutual ML-DSA-65 authentication** — both sides must prove their identity using post-quantum digital signatures before any data flows. This replaces the classical bearer-token approach for admin traffic and gives the control plane a cryptographically strong proof that it is talking to the real bridge, and vice versa. The channel is disabled by default and does not open any port unless explicitly enabled in the config file.

### Secure Key Distribution via vk-share (2026-03-19)

The bridge can now hand out its digital ID card — the proof that it is a trusted server — to new client operators without requiring manual file transfers. An admin runs `latticeshield vk-share` to create a one-time download link with a 10-minute expiry, shares that link with the client operator, and the client operator uses it to fetch the key over a standard secure web connection. The link stops working after one use or after 10 minutes, whichever comes first.

### Connection Pool in the Client Agent (2026-03-16)

We added a connection pool so that the client agent no longer waits to open a fresh connection to the server every time a request arrives. Now a small number of connections are kept ready in the background, so requests start faster and the agent handles more simultaneous traffic without slowing down. Old configuration files continue to work with no changes.

### Unified `latticeshield` Command (2026-03-12)

We added a single `latticeshield` command so that you can generate all your security keys — for the server, the client, and TLS certificates — without needing to know which internal program to call. Previously, key generation was split across two different programs; now everything lives under one roof with a guided welcome screen.

## Deployment Model

LatticeShield follows a **sidecar model**: each component runs on a different server, and the PQC channel protects the entire network path between them.

```
Customer frontend server              Customer backend server
[latticeshield-client]  ──── PQC ────  [latticeshield-bridge :8443]
        |                                         |
  User application                        127.0.0.1:8080 (local)
  (plain TCP :9090)                               |
                                           [Customer API]
```

- `latticeshield-bridge` runs on the **backend server**, next to the API it protects. `backend_addr` should always point to `127.0.0.1` (or a private-network address) — the local TCP connection never leaves the machine.
- `latticeshield-client` runs on the **frontend / client server**. It accepts plain TCP from the user application and forwards it through the PQC channel.
- The PQC channel (ML-KEM-768 + X25519 + ML-DSA-65 + AES-256-GCM) protects the entire network path between the two servers. No plaintext ever traverses the public internet.

**What the PQC channel guarantees:**

| Guarantee | Mechanism |
|---|---|
| Nobody in the middle can read the data | AES-256-GCM encrypted channel, session key derived via HKDF from hybrid KEM |
| Nobody can impersonate the server | ML-DSA-65 signed ServerHello, verified against a pre-shared VerifyingKey |
| Harvest-now-decrypt-later attacks are defeated | Hybrid ML-KEM-768 + X25519: an attacker must break both algorithms to recover the session key |

## Why

Classical key exchange (ECDH, RSA) is vulnerable to future quantum computers via Shor's algorithm. LatticeShield implements the hybrid model recommended by NIST and IETF: combine a classical algorithm (X25519) with a post-quantum one (ML-KEM-768, formerly Kyber). If either is broken, the session remains secure.

## Architecture

```
User Application (plain TCP)
  |
  | plain TCP (:9090)
  |
latticeshield-client          Standard HTTPS client (curl, browser)
  |                              |
  | PQC handshake (:8443)        | HTTPS / TLS (:8440)
  |                              |
  +------------------------------+
                 |
        latticeshield-bridge
                 |
                 | plain TCP
                 |
          Backend Service
```

`latticeshield-client` is the local proxy agent: it accepts plain TCP from the user application, performs the PQC handshake with the bridge, and relays data through an AES-256-GCM encrypted channel. User applications need zero changes.

`latticeshield-bridge` runs three independent listeners:

| Port | Protocol | Client |
|------|----------|--------|
| `:8443` | Custom PQC (X25519 + ML-KEM-768 + AES-256-GCM) | `latticeshield-client` agent |
| `:8440` | Standard TLS / HTTPS (rustls 0.23) | curl, browsers, any HTTPS client |
| `:8441` | QUIC / UDP (quinn 0.11) | QUIC-capable clients |
| `:8444` | Plain HTTP (Prometheus metrics) | Monitoring systems |
| `:8445` | Admin PQC channel — mutual ML-DSA-65 auth (opt-in) | Control plane (cloud admin) |

Backends require no changes — the proxy is transparent.

## Cryptographic Design

### Hybrid Handshake

The handshake follows [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/):

1. Server generates ephemeral X25519 keypair + ML-KEM-768 keypair.
2. Server sends `ClientHello`: X25519 public key, ML-KEM encapsulation key, random nonce.
3. Client performs X25519 DH + ML-KEM encapsulation. Sends back X25519 public key + ML-KEM ciphertext.
4. Both sides derive the session key:

```
SessionKey = HKDF-SHA256(
  ikm  = x25519_shared_secret || kem_shared_secret,
  salt = nonce,
  info = "latticeshield-v1-session-key"
)
```

Security property: an attacker must break **both** X25519 (classically hard) and ML-KEM-768 (quantum-hard) to compromise the session.

### Key Zeroization

`SessionKey` implements `ZeroizeOnDrop` — the 32-byte key material is wiped from memory as soon as it goes out of scope.

### Anti-Replay (DATA frames)

Every DATA frame carries an 8-byte monotonic sequence number authenticated as AEAD AAD. The receiver requires each incoming `seq` to be strictly greater than the last accepted value. Replayed frames are rejected with `FrameError::Replay`; any tampering with the sequence number produces an AEAD authentication failure. Counters reset to zero on every `rotate_key()` call (new epoch, new counter).

## Workspace Structure

```
latticeshield/
├── Cargo.toml                   # Workspace root — all dependencies centralized
├── deny.toml                    # cargo-deny: blocks oqs-rs, openssl, unsafe advisories
├── latticeshield-crypto/        # Cryptographic engine (shared by bridge + client)
│   └── src/
│       ├── lib.rs
│       ├── handshake.rs         # Hybrid X25519 + ML-KEM-768 + HKDF-SHA256 + server auth
│       ├── signing.rs           # ML-DSA-65 sign/verify (OTA + server authentication)
│       └── channel.rs           # AES-256-GCM frame format + HKDF ratchet + monotonic seq (shared transport)
├── latticeshield-bridge/        # Server-side proxy agent (also exposes [lib] for identity + tls)
│   └── src/
│       ├── main.rs              # Entry point — config load + server startup (deprecated keygen subcommands removed)
│       ├── server.rs            # Three listeners: PQC + TLS + QUIC
│       ├── session.rs           # PQC handshake (server) + AES-GCM relay + key rotation
│       ├── tls.rs               # rustls ServerConfig, TlsAcceptor, self-signed cert gen
│       ├── http_relay.rs        # HTTP/1.1 relay for TLS listener (httparse + tokio::io::copy)
│       ├── quic.rs              # QUIC relay (quinn 0.11) — raw bidi stream → TCP
│       ├── identity.rs          # ServerIdentity + ClientVerifyingIdentity: load/generate ML-DSA-65 keypairs
│       ├── config.rs            # TOML config — BridgeConfig + ValidConfig + AuthConfig + AdminConfig
│       ├── metrics.rs           # Prometheus /metrics endpoint + MetricsState
│       ├── control_plane.rs     # Heartbeat to remote control plane
│       └── admin.rs             # Admin PQC channel (:8445) — mutual ML-DSA-65 auth (opt-in)
├── latticeshield-client/        # Client-side proxy agent
│   └── src/
│       ├── main.rs              # Entry point — tracing init, config load, server startup
│       ├── server.rs            # TCP listener on listen_addr, connection pool construction + warmer spawn, tokio::spawn per connection, graceful shutdown
│       ├── pool.rs              # Pre-warmed TCP connection pool — acquire(), warm_loop(), shutdown()
│       ├── client_session.rs    # PQC handshake (client) + mutual auth signing + pool acquire + stale conn retry + AES-GCM relay
│       ├── identity.rs          # load_verifying_key() + ClientIdentity (load/generate/zeroize) + SHA-256 fingerprint
│       └── config.rs            # TOML config — ClientConfig + ValidClientConfig + ReconnectConfig + PoolConfig
└── latticeshield-cli/           # Unified CLI — single entry point for all setup and key operations
    └── src/
        └── main.rs              # Binary `latticeshield` — keygen server/client/tls + vk-info + ASCII banner
```

## Configuration

### Admin PQC Channel (`[admin]`)

The admin channel is disabled by default. To enable it, add an `[admin]` section to the bridge config file:

```toml
[admin]
enabled = true
listen_addr = "0.0.0.0:8445"
control_plane_vk_path = "./keys/cp.vk"
# Optional — defaults shown below
rate_limit_per_second = 5
handshake_timeout_secs = 10
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Set to `true` to open the admin listener |
| `listen_addr` | `0.0.0.0:8445` | Address and port for the admin PQC channel |
| `control_plane_vk_path` | *(required when enabled)* | Path to the control plane's ML-DSA-65 verifying key |
| `rate_limit_per_second` | `5` | Max handshake attempts per second from a single IP |
| `handshake_timeout_secs` | `10` | Seconds before an incomplete handshake is aborted |

#### Generating the admin keypair

```sh
latticeshield-bridge admin-keygen ./keys
```

This writes `admin.sk` (0o600) and `admin.vk` (0o644) to `./keys`. The bridge loads `admin.sk` at startup to sign its side of the mutual handshake. The control plane must hold a copy of `admin.vk`, and the bridge must hold a copy of the control plane's `cp.vk` (set in `control_plane_vk_path`).

## Security Constraints

| Constraint | Reason |
|---|---|
| Pure Rust — no FFI | Eliminates entire class of memory-safety bugs at the boundary |
| No `oqs-rs` | C FFI wrapper; rejected in favor of native Rust implementations |
| No `openssl` | Legacy C library; rejected via `cargo-deny` |
| `libcrux-ml-dsa 0.0.7` instead of `ml-dsa` | `ml-dsa 0.0.4` has RUSTSEC-2025-0144 (timing side-channel) + CVE-2026-24850. Using audited libcrux alternative until RustCrypto publishes `ml-dsa 0.1.0` stable |
| Pre-shared server VerifyingKey | Server's ML-DSA-65 VK is distributed out-of-band — never transmitted on the wire, preventing MITM key substitution |
| Pre-shared client VerifyingKey | Client's ML-DSA-65 VK is pre-shared to the bridge (one authorized keypair per bridge). Bridge rejects any unsigned or wrongly-signed ClientResponse |
| `require_client_auth = true` by default | Bridge refuses to start if `[auth].client_vk_path` is not set. Set `require_client_auth = false` in the `[auth]` section to allow unauthenticated clients (opt-out) |
| Session-bound client signature | Client signs `ClientResponse bytes \|\| ServerHello bytes` — the signature covers the server's per-session nonce, making replay attacks across sessions impossible |
| `mlock(2)` on SigningKey | Key material stored in heap-allocated `Box<[u8; 4032]>` and memory-locked via `libc::mlock` — never paged to swap |

## Dependencies (key)

| Crate | Version | Purpose |
|---|---|---|
| `ml-kem` | 0.2 | ML-KEM-768 (FIPS 203) — pure Rust |
| `x25519-dalek` | 2 | X25519 ECDH — pure Rust |
| `hkdf` + `sha2` | 0.12 / 0.10 | HKDF-SHA256 key derivation |
| `aes-gcm` | 0.10 | AEAD encryption |
| `tokio` | 1 | Async runtime |
| `quinn` | 0.11 | QUIC transport |
| `rustls` | 0.23 | TLS with post-quantum support (X25519MLKEM768) |
| `reqwest` | 0.12 | HTTP client for control plane (rustls backend, hybrid PQ key exchange) |
| `axum` | 0.7 | Control plane HTTP API |
| `zeroize` | 1 | Secure key material cleanup |

## Requirements

- Rust 1.75+ (edition 2021, resolver v2)
- Tested with Rust 1.94.0

## Build

```sh
cargo build
```

```sh
cargo test
```

```sh
# Release — LTO enabled, binary stripped
cargo build --release
```

## Tests

308 unit + integration tests across all four crates — all passing.

### latticeshield-crypto (39 tests)

| Module | Tests |
|---|---|
| `handshake` | Hybrid handshake, server auth (signed ServerHello, pre-shared VK, tamper detection), mutual auth (signed ClientResponse roundtrip, wrong VK, tampered CR, wrong ServerHello) |
| `signing` | ML-DSA-65 keygen, sign, verify, hedged randomness, serialization round-trips |
| `channel` | Frame format (DATA 0x01, KEY_ROTATE 0x02), read/write roundtrips, encrypted KEY_ROTATE wire format (61B: GCM nonce + encrypted nonce + tag), tampered KEY_ROTATE AEAD failure, error types, `rotate_key` HKDF ratchet (deterministic, chained), seq monotonic increment, replay rejection, post-rotation seq reset, tampered-seq AEAD failure, sequential receive |

### latticeshield-bridge (202 tests)

| Module | Tests |
|---|---|
| `config` | TOML load/defaults/validation, TLS config, QUIC config, control plane config, key rotation config, auth config, admin config (enabled/disabled/field validation/port collision), port collision detection |
| `tls` | `build_server_config`, `build_acceptor`, cert/key loading, self-signed generation (feature-gated) |
| `http_relay` | HTTP head parsing (complete/partial/oversized), GET forwarding, POST with body, backend down → 502 |
| `quic` | `build_endpoint`, `relay_stream` end-to-end, backend down → error, normal connection close |
| `identity` | ServerIdentity: generate_and_save (files, permissions, sizes), load roundtrip, error paths. ClientVerifyingIdentity: load roundtrip, wrong size rejected |
| `metrics` | Prometheus families, HTTP `/metrics` endpoint, session/byte counters, connection gauge, key rotations counter |
| `control_plane` | Registration success/failure, heartbeat URL, capabilities payload |
| `admin` | Mutual ML-DSA-65 handshake (full round-trip), wrong client key rejected, `get-metrics` / `rotate` / `get-vk-token` command dispatch |
| `server` | BridgeCommand dispatch: Rotate increments rotate_tx + key_rotations_total, Unknown ignored, multiple Rotates accumulate correctly |
| `session` (integration) | Full PQC handshake + relay, mutual auth (with/without client auth, wrong VK rejection), tampered response rejection, key uniqueness, POST `/rotate`, time-based and byte-threshold key rotation |

### latticeshield-client (92 tests)

| Module | Tests |
|---|---|
| `pool` | acquire from non-empty pool (no connect), acquire from empty pool (fresh connect fallback), acquire fails when bridge down, idle timeout eviction, partial eviction, max_size cap respected, warm_size=0 makes no connects, TCP_NODELAY set on warmed and fallback streams, shutdown drains connections with FIN, shutdown with empty pool |
| `config` | TOML defaults, custom values, missing file, bad TOML, invalid addrs, out-of-range max_frame_size, empty vk_path, client_sk_path, reconnect section, pool section defaults, explicit pool values, warm_size > max_size rejected, max_size=0 rejected, idle_timeout_secs=0 rejected, warm_size=0 accepted |
| `identity` | ServerVK: load roundtrip, wrong size, nonexistent file, fingerprint. ClientIdentity: load roundtrip, wrong permissions rejected, wrong size, generate_and_save (files, permissions 0o600/0o644) |
| `client_session` | Bridge connect refused → EOF, tampered signature → Ok(()), stale pooled conn → fresh connect retry, stale and fresh both fail → Ok(()), auth failure does not retry, pool.acquire() error → user EOF |
| `server` | Listener binds and accepts connections, shutdown stops warmer |
| integration | Full PQC relay round-trip (client ↔ mock bridge ↔ echo backend), KEY_ROTATE survives relay, pool-enabled session flow |

### latticeshield-cli (7 tests)

| Test | What it verifies |
|---|---|
| `keygen_server_creates_files` | `keygen server` produces `server.sk` (4032B, 0o600) and `server.vk` (1952B, 0o644) |
| `keygen_client_creates_files` | `keygen client` produces `client.sk` (4032B, 0o600) and `client.vk` (1952B, 0o644) |
| `keygen_tls_creates_files` | `keygen tls` produces `tls.crt` and `tls.key` |
| `vk_info_server_vk` | `vk-info server.vk` prints File, Size (1952), SHA-256 (64 hex chars) |
| `vk_info_client_vk` | `vk-info client.vk` prints File, Size (1952), SHA-256 |
| `vk_info_nonexistent` | `vk-info` with missing file exits non-zero |
| `help_shows_banner` | `--help` output includes "LatticeShield" |

## Roadmap

### Completed

| Month | Milestone |
|---|---|
| 1–3 | Cryptographic engine — hybrid handshake (X25519 + ML-KEM-768), anti-replay, ML-DSA-65 OTA signing, Prometheus observability |
| 4 | Server authentication — ML-DSA-65 signed ServerHello, pre-shared VK model, mlock on signing key |
| 5 | Bridge server auth — `ServerIdentity` load/generate, `--keygen` subcommand, file permission enforcement |
| 6 | Config file (TOML), control plane heartbeat, session key rotation |
| 7 | TLS listener (rustls 0.23, `:8440`) + QUIC listener (quinn 0.11, `:8441`) — standard HTTPS/QUIC clients without agent |
| 8–9 | Client agent — local PQC proxy, mutual ML-DSA-65 auth (signed ClientResponse), reconnect/backoff |
| 10 | Unified CLI `latticeshield` — `keygen server/client/tls`, `vk-info`, ASCII banner |
| 11 | Connection pool in client — proactive warming, lazy close, pure tokio |
| 12 | `server_vk` in registration payload + `latticeshield vk-share` — one-time VK distribution link (10-min expiry, single-use) |
| 13 | Admin PQC channel (`:8445`) — mutual ML-DSA-65 auth, opt-in `[admin]` config section, `admin-keygen` subcommand |
| 14 | Cloud Integration Foundation — signed heartbeats (ML-DSA-65), `HeartbeatResponse` + `BridgeCommand` parsing, `install_token` for automated onboarding, token redaction in logs |
| 15 | Hybrid TLS + Command Wiring — post-quantum-safe outbound HTTPS for bridge→cloud (reqwest + rustls, X25519MLKEM768), `BridgeCommand::Rotate` wired to actual key rotation |
| 16 | Pre-production Hardening — graceful shutdown (SIGTERM/SIGINT drain with configurable timeout), Mutex poison recovery in `vk_share.rs`, flaky test eliminated in `control_plane` and `session` |
| 17 | Sequence Numbers + Framing v3 — monotonic `seq` (u64 BE) field in DATA frames authenticated as AEAD AAD; receiver rejects replays; `FrameError` enum; `rotate_key()` resets both counters; closes G1/D4 |
| 18 | Security Enforcement — `require_client_auth = true` by default with explicit opt-out via `[auth]` section (G2); KEY_ROTATE nonce encrypted with AES-256-GCM (61-byte wire format) instead of plaintext (G4); `AntiReplayFilter` dead code removed — 0-RTT tickets never implemented (G5); env-var race in `control_plane` tests eliminated |
| 19 | CI/Release Pipeline — GitHub Actions CI gate (fmt + clippy + deny + test on every push/PR); release workflow cross-compiles 3 binaries × 4 targets (linux-x64/arm64, darwin-x64/arm64), merges per-target SHA-256 checksums into a single manifest, publishes to GitHub Releases on tag push; `install.sh` one-command install with platform detection + checksum verification + privilege-aware install; `contrib/systemd/` and `contrib/launchd/` service files with hardened configuration; `metrics-exporter-prometheus` and `latticeshield-cli reqwest` dep fixes to remove transitive native-tls/OpenSSL |

### Upcoming

| Month | Milestone |
|---|---|
| 20+ | **Post-launch Improvements** — `Zeroizing<Vec<u8>>` for `ikm` in `derive_session_key` (G8), nonce-misuse-resistant AEAD (AES-GCM-SIV) for high-frame sessions, cloud-side heartbeat signature verification |

## License

UNLICENSED — private project.
