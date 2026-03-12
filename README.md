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
├── latticeshield-bridge/        # Server-side proxy agent (also exposes [lib] for identity + tls)
│   └── src/
│       ├── main.rs              # Entry point — keygen / tls-keygen / quic-keygen (deprecated since Mes 10)
│       ├── server.rs            # Three listeners: PQC + TLS + QUIC
│       ├── session.rs           # PQC handshake (server) + AES-GCM relay + key rotation
│       ├── tls.rs               # rustls ServerConfig, TlsAcceptor, self-signed cert gen
│       ├── http_relay.rs        # HTTP/1.1 relay for TLS listener (httparse + tokio::io::copy)
│       ├── quic.rs              # QUIC relay (quinn 0.11) — raw bidi stream → TCP
│       ├── identity.rs          # ServerIdentity + ClientVerifyingIdentity: load/generate ML-DSA-65 keypairs
│       ├── config.rs            # TOML config — BridgeConfig + ValidConfig + AuthConfig
│       ├── metrics.rs           # Prometheus /metrics endpoint + MetricsState
│       └── control_plane.rs     # Heartbeat to remote control plane
├── latticeshield-client/        # Client-side proxy agent
│   └── src/
│       ├── main.rs              # Entry point — vk-info / --client-keygen (deprecated since Mes 10), tracing init
│       ├── server.rs            # TCP listener on listen_addr, tokio::spawn per connection
│       ├── client_session.rs    # PQC handshake (client) + mutual auth signing + reconnect/backoff + AES-GCM relay
│       ├── identity.rs          # load_verifying_key() + ClientIdentity (load/generate/zeroize) + SHA-256 fingerprint
│       └── config.rs            # TOML config — ClientConfig + ValidClientConfig + ReconnectConfig
└── latticeshield-cli/           # Unified CLI — single entry point for all setup and key operations
    └── src/
        └── main.rs              # Binary `latticeshield` — keygen server/client/tls + vk-info + ASCII banner
```

## Security Constraints

| Constraint | Reason |
|---|---|
| Pure Rust — no FFI | Eliminates entire class of memory-safety bugs at the boundary |
| No `oqs-rs` | C FFI wrapper; rejected in favor of native Rust implementations |
| No `openssl` | Legacy C library; rejected via `cargo-deny` |
| `libcrux-ml-dsa 0.0.7` instead of `ml-dsa` | `ml-dsa 0.0.4` has RUSTSEC-2025-0144 (timing side-channel) + CVE-2026-24850. Using audited libcrux alternative until RustCrypto publishes `ml-dsa 0.1.0` stable |
| Pre-shared server VerifyingKey | Server's ML-DSA-65 VK is distributed out-of-band — never transmitted on the wire, preventing MITM key substitution |
| Pre-shared client VerifyingKey | Client's ML-DSA-65 VK is pre-shared to the bridge (one authorized keypair per bridge). Bridge rejects any unsigned or wrongly-signed ClientResponse |
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

176 unit + integration tests across all four crates — all passing.

### latticeshield-crypto (39 tests)

| Module | Tests |
|---|---|
| `handshake` | Hybrid handshake, server auth (signed ServerHello, pre-shared VK, tamper detection), mutual auth (signed ClientResponse roundtrip, wrong VK, tampered CR, wrong ServerHello) |
| `signing` | ML-DSA-65 keygen, sign, verify, hedged randomness, serialization round-trips |
| `channel` | Frame format (DATA 0x01, KEY_ROTATE 0x02), read/write roundtrips, error types, `rotate_key` HKDF ratchet (deterministic, chained) |
| `anti_replay` | Accept once, reject duplicate, window expiry |

### latticeshield-bridge (97 tests)

| Module | Tests |
|---|---|
| `config` | TOML load/defaults/validation, TLS config, QUIC config, control plane config, key rotation config, auth config, port collision detection |
| `tls` | `build_server_config`, `build_acceptor`, cert/key loading, self-signed generation (feature-gated) |
| `http_relay` | HTTP head parsing (complete/partial/oversized), GET forwarding, POST with body, backend down → 502 |
| `quic` | `build_endpoint`, `relay_stream` end-to-end, backend down → error, normal connection close |
| `identity` | ServerIdentity: generate_and_save (files, permissions, sizes), load roundtrip, error paths. ClientVerifyingIdentity: load roundtrip, wrong size rejected |
| `metrics` | Prometheus families, HTTP `/metrics` endpoint, session/byte counters, connection gauge, key rotations counter |
| `control_plane` | Registration success/failure, heartbeat URL, capabilities payload |
| `session` (integration) | Full PQC handshake + relay, mutual auth (with/without client auth, wrong VK rejection), tampered response rejection, key uniqueness, POST `/rotate`, time-based and byte-threshold key rotation |

### latticeshield-client (33 tests)

| Module | Tests |
|---|---|
| `config` | TOML defaults, custom values, missing file, bad TOML, invalid addrs, out-of-range max_frame_size, empty vk_path, client_sk_path, reconnect section |
| `identity` | ServerVK: load roundtrip, wrong size, nonexistent file, fingerprint. ClientIdentity: load roundtrip, wrong permissions rejected, wrong size, generate_and_save (files, permissions 0o600/0o644) |
| `client_session` | Bridge connect refused → EOF, tampered signature → Ok(()), reconnect succeeds on 2nd attempt, reconnect exhausts max_retries, auth failure does not trigger reconnect |
| `server` | Listener binds and accepts connections |
| integration | Full PQC relay round-trip (client ↔ mock bridge ↔ echo backend), KEY_ROTATE survives relay, `vk-info` binary output |

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

| Month | Milestone | Status |
|---|---|---|
| 1 | Cryptographic engine — hybrid handshake + anti-replay | Complete |
| 2 | TCP proxy bridge + AES-256-GCM relay | Complete |
| 3 | ML-DSA-65 OTA signing + Prometheus observability | Complete |
| 4–5 | Server authentication — signed ServerHello, pre-shared VK, mlock | Complete |
| 6 | Config file (toml), control plane heartbeat, session key rotation | Complete |
| 7 | TLS listener (rustls 0.23) + QUIC listener (quinn 0.11), standard HTTPS/QUIC clients without agent | Complete |
| 8 | Client agent — latticeshield-client (local proxy, PQC client-side, server.vk distribution) | Complete |
| 9 | Mutual auth (ML-DSA-65 signed ClientResponse) + reconnect/backoff in client | Complete |
| 10 | Unified CLI `latticeshield` — `keygen server/client/tls`, `vk-info`, ASCII banner, deprecation warnings in old subcommands | Complete |
| 11 | Connection pool in client — lazy close + proactive warming (no new deps, pure tokio) | Planned |
| 12 | Distribution: pre-compiled binaries (GitHub Actions) + systemd service files + `curl \| sh` installer | Planned |
| 13 | Control Plane SaaS: tenant registry, VK distribution API, bridge management backend | Planned |
| 14 | Web dashboard: real-time metrics, session status, tenant overview | Planned |
| 15 | eBPF/XDP rate limiter (Linux, opt-in, enterprise feature) | Planned |

---

## Product Vision — Installation & Distribution

> ⚠️ **NOTA IMPORTANTE**: Todo este circuito requiere una revisión completa de UI/UX antes de implementarse — flujo del operador del bridge, flujo del usuario final, flujo de distribución del server.vk, onboarding en el control plane, y cada pantalla/comando que el usuario toca. No implementar Mes 12-13 sin ese ejercicio previo.

### Roles

**LatticeShield (nosotros)** — proveemos el software (bridge + client) y el control plane SaaS central.

**Empresa cliente** — instala el bridge en su propio servidor. Su backend no se modifica.

**Usuario final** — instala el client localmente. Su app no se modifica — solo apunta a `localhost:9090`.

---

### Flujo del operador del bridge (Empresa cliente)

```
1. Se registra en latticeshield.io → recibe api_token

2. En su servidor Linux:
   curl -sSL https://install.latticeshield.io | sh --token <api_token>

3. El script automáticamente:
   ├── Detecta arquitectura (x86_64 / ARM64)
   ├── Descarga el binario correcto de GitHub Releases
   ├── Genera server.sk + server.vk + cert.pem (via latticeshield keygen)
   ├── Registra el bridge en el control plane (guarda server.vk)
   ├── Crea /etc/latticeshield/config.toml (pregunta: backend_addr)
   ├── Instala latticeshield-bridge.service en systemd
   └── Arranca el bridge → bridge activo en :8443

4. El cliente no necesita distribuir server.vk manualmente —
   el control plane lo almacena y lo sirve a los clients que lo pidan.
```

El bridge es **su infraestructura** — en su servidor, bajo su control. El backend existente (Node.js, Python, etc.) no se toca. El bridge se pone delante apuntando al backend.

```
Servidor del cliente (ejemplo — convive con lo que ya tiene):
├── nginx         :80/:443   → no se toca
├── su app        :3000      → no se toca
├── PostgreSQL    :5432      → no se toca
└── ls-bridge     :8443/:8440/:8441  → nuevo, apunta a :3000
```

---

### Flujo del usuario final

```
1. Recibe de Empresa X: "usá latticeshield para conectarte a nuestro servicio"

2. Instala el client:
   curl -sSL https://install.latticeshield.io/client | sh

3. Setup interactivo:
   latticeshield client setup --tenant empresa-x
   → el control plane entrega el server.vk de Empresa X automáticamente
   → no necesita archivos, no necesita entender criptografía

4. Arranca el client:
   latticeshield client start
   → escuchando en 127.0.0.1:9090

5. Apunta su app a localhost:9090 en vez de al backend directo
   → tráfico cifrado PQC de extremo a extremo, transparente para la app
```

---

### Control Plane SaaS (Mes 13)

API HTTPS central que:
- **Registro de bridges**: recibe el `POST /register` que `control_plane.rs` ya envía
- **VK Registry**: almacena el `server.vk` de cada bridge por tenant
- **Heartbeat receiver**: recibe el estado y métricas de cada bridge activo
- **Client VK delivery**: cuando un client hace `setup --tenant X`, le entrega el `server.vk` correcto
- **Tenant management**: vos ves todos tus clientes, sus bridges, versiones, estado

El bridge ya tiene `control_plane.rs` implementado — solo falta el servidor que recibe esos requests.

---

### Lo que ya está construido

| Pieza | Estado |
|-------|--------|
| Bridge (PQC + TLS + QUIC) | ✅ Mes 1–7 |
| Client (PQC handshake + relay) | ✅ Mes 8 |
| Server auth (bridge firma con ML-DSA-65) | ✅ Mes 4–5 |
| Mutual auth (client también se autentica) | ✅ Mes 9 |
| Prometheus metrics | ✅ Mes 3 |
| `control_plane.rs` (heartbeat sender) | ✅ Mes 6 |
| CLI keygen unificado (`latticeshield keygen` + `vk-info`) | ✅ Mes 10 |
| Connection pool (lazy close + proactive warming) | ⏳ Mes 11 |
| Binarios + installer (`curl \| sh`) | ⏳ Mes 12 |
| **Control Plane SaaS** (receptor de heartbeats + VK registry) | ⏳ Mes 13 |
| **Web dashboard** | ⏳ Mes 14 |

## License

UNLICENSED — private project.
