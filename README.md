# LatticeShield

A quantum-safe reverse proxy written in pure Rust. Adds a hybrid post-quantum cryptography (PQC) layer — **X25519 + ML-KEM-768** — as a transparent encryption layer between clients and backend services, with no FFI, no OpenSSL, no `oqs-rs`.

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

### Anti-Replay (0-RTT)

A sliding-window filter (`AntiReplayFilter`) tracks consumed session tickets. Each 32-byte ticket can only be used once per time window. The window resets automatically; tickets from a previous window are discarded.

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
│       ├── channel.rs           # AES-256-GCM frame format + HKDF ratchet (shared transport)
│       └── anti_replay.rs       # 0-RTT anti-replay filter
├── latticeshield-bridge/        # Server-side proxy agent
│   └── src/
│       ├── main.rs              # Entry point — keygen / tls-keygen / quic-keygen subcommands
│       ├── server.rs            # Three listeners: PQC + TLS + QUIC
│       ├── session.rs           # PQC handshake (server) + AES-GCM relay + key rotation
│       ├── tls.rs               # rustls ServerConfig, TlsAcceptor, self-signed cert gen
│       ├── http_relay.rs        # HTTP/1.1 relay for TLS listener (httparse + tokio::io::copy)
│       ├── quic.rs              # QUIC relay (quinn 0.11) — raw bidi stream → TCP
│       ├── identity.rs          # ServerIdentity: load/generate ML-DSA-65 keypair
│       ├── config.rs            # TOML config — BridgeConfig + ValidConfig
│       ├── metrics.rs           # Prometheus /metrics endpoint + MetricsState
│       └── control_plane.rs     # Heartbeat to remote control plane
└── latticeshield-client/        # Client-side proxy agent
    └── src/
        ├── main.rs              # Entry point — vk-info subcommand, tracing init
        ├── server.rs            # TCP listener on listen_addr, tokio::spawn per connection
        ├── client_session.rs    # PQC handshake (client) + AES-GCM relay
        ├── identity.rs          # load_verifying_key() + SHA-256 fingerprint
        └── config.rs            # TOML config — ClientConfig + ValidClientConfig
```

## Security Constraints

| Constraint | Reason |
|---|---|
| Pure Rust — no FFI | Eliminates entire class of memory-safety bugs at the boundary |
| No `oqs-rs` | C FFI wrapper; rejected in favor of native Rust implementations |
| No `openssl` | Legacy C library; rejected via `cargo-deny` |
| `libcrux-ml-dsa 0.0.7` instead of `ml-dsa` | `ml-dsa 0.0.4` has RUSTSEC-2025-0144 (timing side-channel) + CVE-2026-24850. Using audited libcrux alternative until RustCrypto publishes `ml-dsa 0.1.0` stable |
| Pre-shared VerifyingKey | Server's ML-DSA-65 VK is distributed out-of-band — never transmitted on the wire, preventing MITM key substitution |
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
| `rustls` | 0.23 | TLS with post-quantum support |
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

143 unit + integration tests across all three crates — all passing.

### latticeshield-crypto (35 tests)

| Module | Tests |
|---|---|
| `handshake` | Hybrid handshake, server auth (signed ServerHello, pre-shared VK, tamper detection) |
| `signing` | ML-DSA-65 keygen, sign, verify, hedged randomness, serialization round-trips |
| `channel` | Frame format (DATA 0x01, KEY_ROTATE 0x02), read/write roundtrips, error types, `rotate_key` HKDF ratchet (deterministic, chained) |
| `anti_replay` | Accept once, reject duplicate, window expiry |

### latticeshield-bridge (88 tests)

| Module | Tests |
|---|---|
| `config` | TOML load/defaults/validation, TLS config, QUIC config, control plane config, key rotation config, port collision detection |
| `tls` | `build_server_config`, `build_acceptor`, cert/key loading, self-signed generation (feature-gated) |
| `http_relay` | HTTP head parsing (complete/partial/oversized), GET forwarding, POST with body, backend down → 502 |
| `quic` | `build_endpoint`, `relay_stream` end-to-end, backend down → error, normal connection close |
| `identity` | generate_and_save (files, permissions 0o600/0o644, sizes), load roundtrip, error paths |
| `metrics` | Prometheus families, HTTP `/metrics` endpoint, session/byte counters, connection gauge, key rotations counter |
| `control_plane` | Registration success/failure, heartbeat URL, capabilities payload |
| `session` (integration) | Full PQC handshake + relay, tampered response rejection, key uniqueness, POST `/rotate` endpoint, time-based and byte-threshold key rotation, full relay after rotation |

### latticeshield-client (20 tests)

| Module | Tests |
|---|---|
| `config` | TOML defaults, custom values, missing file, bad TOML, invalid addrs, out-of-range max_frame_size, empty vk_path |
| `identity` | load roundtrip, wrong size, nonexistent file, fingerprint length, fingerprint determinism |
| `client_session` | Bridge connect refused → user gets EOF, tampered signature → Ok(()) |
| `server` | Listener binds and accepts connections |
| integration | Full PQC relay round-trip (client ↔ mock bridge ↔ echo backend), KEY_ROTATE survives relay, `vk-info` binary output |

## Roadmap

| Month | Milestone | Status |
|---|---|---|
| 1 | Cryptographic engine — hybrid handshake + anti-replay | Complete |
| 2 | TCP proxy bridge + AES-256-GCM relay | Complete |
| 3 | ML-DSA-65 OTA signing + Prometheus observability | Complete |
| 4–5 | Server authentication — signed ServerHello, pre-shared VK, mlock | Complete |
| 6 | Config file (toml), control plane heartbeat, session key rotation | Complete |
| 7 | TLS listener (rustls 0.23) + QUIC listener (quinn 0.11), standard HTTPS/QUIC clients without agent | Complete |
| 8 | Client agent — latticeshield-client (local proxy, PQC client-side, server.vk distribution) | Complete |
| 9+ | eBPF/XDP, OTA updater, Dashboard SaaS | Planned |

## License

UNLICENSED — private project.
