# LatticeShield

A quantum-safe reverse proxy written in pure Rust. Adds a hybrid post-quantum cryptography (PQC) layer — **X25519 + ML-KEM-768** — as a transparent encryption layer between clients and backend services, with no FFI, no OpenSSL, no `oqs-rs`.

## Why

Classical key exchange (ECDH, RSA) is vulnerable to future quantum computers via Shor's algorithm. LatticeShield implements the hybrid model recommended by NIST and IETF: combine a classical algorithm (X25519) with a post-quantum one (ML-KEM-768, formerly Kyber). If either is broken, the session remains secure.

## Architecture

```
Client
  |
  | (hybrid handshake: X25519 + ML-KEM-768)
  |
LatticeShield Proxy
  |
  | (plain TLS or internal transport)
  |
Backend Service
```

The proxy is transparent — backends require no changes.

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
├── latticeshield-crypto/        # Cryptographic engine (Month 1 — complete)
│   └── src/
│       ├── lib.rs
│       ├── handshake.rs         # Hybrid X25519 + ML-KEM-768 + HKDF-SHA256
│       └── anti_replay.rs       # 0-RTT anti-replay filter
└── latticeshield-bridge/        # Proxy agent — HTTP/QUIC transport (Month 2+)
```

## Security Constraints

| Constraint | Reason |
|---|---|
| Pure Rust — no FFI | Eliminates entire class of memory-safety bugs at the boundary |
| No `oqs-rs` | C FFI wrapper; rejected in favor of native Rust implementations |
| No `openssl` | Legacy C library; rejected via `cargo-deny` |
| `ml-dsa` deferred to Month 3+ | Advisory RUSTSEC-2025-0144 (timing side-channel). Will evaluate `libcrux-ml-dsa` as audited alternative |
| `rustls` with `prefer-post-quantum` | Enables native X25519MLKEM768 in TLS — no manual TLS hybrid implementation needed |

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

`latticeshield-crypto` ships 6 unit tests:

| Test | What it verifies |
|---|---|
| `handshake_produces_matching_session_keys` | Client and server derive identical session keys |
| `session_keys_are_unique_per_handshake` | Two independent handshakes produce different keys |
| `tampered_kem_ciphertext_fails_decapsulation` | ML-KEM ciphertext type is opaque — cannot be mutated accidentally |
| `valid_ticket_accepted_once` | Anti-replay: first use accepted, second use rejected |
| `different_tickets_all_accepted` | Independent tickets are all accepted |
| `window_expiry_resets_filter` | Anti-replay window resets correctly |

## Roadmap

| Month | Milestone |
|---|---|
| 1 | Cryptographic engine — hybrid handshake + anti-replay (complete) |
| 2 | Proxy bridge — HTTP/HTTPS transparent forwarding via QUIC |
| 3 | OTA signing with ML-DSA (pending audit of RUSTSEC-2025-0144) |
| 4+ | Control plane API, observability, deployment packaging |

## License

UNLICENSED — private project.
