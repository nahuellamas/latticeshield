# LatticeShield

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust 1.75+">
  <img src="https://img.shields.io/badge/tests-550_passing-brightgreen?style=for-the-badge" alt="550 tests passing">
  <img src="https://img.shields.io/badge/no_FFI-pure_Rust-blue?style=for-the-badge" alt="No FFI — pure Rust">
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768_%2B_ML--DSA--65-blueviolet?style=for-the-badge" alt="PQC: ML-KEM-768 + ML-DSA-65">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge" alt="Apache-2.0">
</p>

> A quantum-safe reverse proxy written in **pure Rust** — no FFI, no OpenSSL, no `oqs-rs`.

Add post-quantum encryption to any TCP service **without changing your application code**. LatticeShield runs as a sidecar: your clients connect to the bridge, traffic is encrypted in transit with a hybrid **X25519 + ML-KEM-768 + AES-256-GCM** channel, decrypted at the bridge, and forwarded to your backend over localhost. The bridge also authenticates itself to clients with **ML-DSA-65** signatures so clients can cryptographically verify they are talking to the real server.

**[→ Get running in 10 minutes](QUICKSTART.md)**

---

## Table of Contents

- [Why post-quantum now?](#why-post-quantum-now)
- [How it works](#how-it-works)
- [Quickstart](#quickstart)
- [Listeners & ports](#listeners--ports)
- [Configuration reference](#configuration-reference)
  - [\[server\]](#server)
  - [\[crypto\]](#crypto)
  - [\[auth\]](#auth)
  - [\[tls\]](#tls)
  - [\[quic\]](#quic)
  - [\[websocket\]](#websocket)
  - [\[admin\]](#admin)
  - [\[control\_plane\]](#control_plane)
  - [\[key\_rotation\]](#key_rotation)
  - [\[logging\]](#logging)
  - [\[metrics\]](#metrics)
  - [Environment variables](#environment-variables)
- [CLI reference](#cli-reference)
- [Browser SDK](#browser-sdk-latticeshieldjs)
- [VK-share](#vk-share)
- [Security design](#security-design)
- [Prometheus metrics](#prometheus-metrics)
- [Workspace structure](#workspace-structure)
- [Building from source](#building-from-source)
- [Tests](#tests)
- [What's New](#whats-new)
- [Contributing](#contributing)
- [License](#license)

---

## Why post-quantum now?

NIST finalized three post-quantum cryptography standards in 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). Classical ECDH and RSA are broken by Shor's algorithm on a sufficiently large quantum computer. "Harvest now, decrypt later" attacks are already happening: adversaries collect encrypted traffic today intending to decrypt it once quantum hardware matures.

LatticeShield uses a **hybrid model** (X25519 + ML-KEM-768) so sessions are protected by both classical and post-quantum algorithms simultaneously. Breaking the session requires breaking both — classical cryptography keeps you safe today; post-quantum keeps your historical traffic safe when quantum hardware arrives.

---

## How it works

```
┌───────────────┐    encrypted (PQC)    ┌──────────────────┐    plain TCP    ┌─────────────┐
│    Client     │ ─────────────────────▶│  LatticeShield   │────────────────▶│   Backend   │
│  (your app)   │◀───────────────────── │     Bridge       │◀────────────────│   Service   │
└───────────────┘                       └──────────────────┘                 └─────────────┘
                    wss:// / TCP / TLS / QUIC                  127.0.0.1:8080
```

| What the bridge guarantees | What it does NOT change |
|---|---|
| Traffic between client and bridge is quantum-safe encrypted | Your **backend** receives plain TCP — zero backend code changes |
| The server is cryptographically authenticated (ML-DSA-65) | Your existing HTTP, gRPC, or custom protocol passes through unchanged |
| Clients can optionally prove their identity too (mutual auth) | The bridge is transparent — it relays bytes, not HTTP |
| Every session uses fresh ephemeral keys (perfect forward secrecy) | No kernel modules, no eBPF, no sidecars that need root |

> **Note**: clients connect via the SDK (`@latticeshield/js` for browsers, `latticeshield-client` for server-side) or any TCP client that implements the PQC handshake. Only the backend service requires no changes.

---

## Quickstart

The idea is simple: your app keeps running exactly as it is. The bridge sits in front of it, handles all the encryption, and forwards plain bytes to your app over localhost. Clients talk to the bridge on `:8443`; your backend keeps listening on `:8080`. The backend needs no changes — clients use the SDK or the `latticeshield-client` proxy to speak the PQC handshake.

### 1. Install

```sh
curl -fsSL https://raw.githubusercontent.com/nahuellamas/latticeshield/main/install.sh | bash
```

Downloads the pre-built binary for your platform (Linux x86_64/arm64 or macOS Intel/Apple Silicon).

### 2. Generate a keypair

```sh
latticeshield-bridge keygen ./keys
```

This creates two files: `server.sk` (private, mode 0600) and `server.vk` (public, 1952 bytes). The bridge uses `server.sk` to sign a hello message at the start of every session. Clients use `server.vk` to verify that signature — this is the only thing that stops an impostor from pretending to be your bridge. Treat `server.sk` like a password: never commit it, never copy it over HTTP.

### 3. Write a config

```sh
cat > config.toml << 'EOF'
[server]
listen_addr      = "0.0.0.0:8443"    # clients connect here
backend_addr     = "127.0.0.1:8080"  # your app is already here

[crypto]
signing_key_path = "./keys/server.sk"
EOF
```

`backend_addr` is wherever your app is listening right now. The bridge decrypts client traffic and forwards raw bytes to your app — no code changes, no new dependencies on the backend side.

### 4. Start the bridge

```sh
latticeshield-bridge run --config config.toml
```

The bridge is now accepting connections on `:8443`. Every client gets a fresh quantum-safe encrypted channel. Your app on `:8080` sees nothing different — just bytes arriving from localhost.

### 5. Distribute the verifying key to clients

```sh
# Option A — copy to a specific host
scp ./keys/server.vk client-host:./keys/server.vk

# Option B — bake into a Docker image
COPY keys/server.vk /etc/latticeshield/server.vk

# Option C — browser clients: use VK-share (see below)
```

Every client needs `server.vk` before it can connect. Ship it out-of-band — SSH, config management, Docker image, whatever fits your deployment. Never fetch it over the same connection it protects; that would defeat the authentication entirely. A client that has the wrong VK (or no VK) will reject the handshake.

> **Mutual client authentication** is off by default — the config above has no `[auth]` section so the bridge accepts any client. A `WARN` is logged at startup to remind you. For production deployments with mutual auth enabled see **[QUICKSTART.md](QUICKSTART.md)**.

---

## Listeners & ports

| Protocol | Default port | Section | Enable |
|---|---|---|---|
| PQC TCP | `0.0.0.0:8443` | `[server]` | Always on |
| TLS/HTTPS | `0.0.0.0:8440` | `[tls]` | `tls.enabled = true` |
| QUIC (UDP) | `0.0.0.0:8441` | `[quic]` | `quic.enabled = true` |
| WebSocket (WSS) | `0.0.0.0:8446` | `[websocket]` | `websocket.enabled = true` |
| Prometheus metrics | `0.0.0.0:8444` | `[metrics]` | Always on (plain HTTP) |
| Admin PQC | `0.0.0.0:8445` | `[admin]` | `admin.enabled = true` |

All ports must be distinct. The bridge validates for collisions at startup and refuses to start if any two listeners share a port.

---

## Configuration reference

Full example — every section shown with its defaults:

```toml
[server]
listen_addr             = "0.0.0.0:8443"
backend_addr            = "127.0.0.1:8080"
max_frame_size          = 65536
handshake_timeout_secs  = 10
max_connections_per_ip  = 50

[crypto]
signing_key_path        = "./keys/server.sk"

[auth]
client_vk_path          = "./keys/client.vk"   # omit to disable mutual auth
# require_client_auth   = false                 # default: true

[tls]
enabled                 = false
listen_addr             = "0.0.0.0:8440"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"

[quic]
enabled                 = false
listen_addr             = "0.0.0.0:8441"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"

[websocket]
enabled                 = false
listen_addr             = "0.0.0.0:8446"
cert_path               = "./keys/tls.crt"
key_path                = "./keys/tls.key"
allowed_origins         = ["https://app.example.com"]
handshake_timeout_secs  = 10
max_connections_per_ip  = 100

[admin]
enabled                        = false
listen_addr                    = "127.0.0.1:8445"
control_plane_vk_path          = "./keys/admin.vk"
rate_limit_per_second          = 5
handshake_timeout_secs         = 10

[control_plane]
enabled                  = false
endpoint                 = "https://cp.example.com"
agent_name               = ""           # defaults to $HOSTNAME
heartbeat_interval_secs  = 30
install_token            = ""           # or set $INSTALL_TOKEN env var

[key_rotation]
enabled              = false
max_bytes_per_key    = 10737418240     # 10 GiB
max_seconds_per_key  = 86400           # 24 h

[logging]
level = "info"                          # trace | debug | info | warn | error

[metrics]
listen_addr             = "0.0.0.0:8444"
```

### [server]

| Field | Default | Validation | Description |
|---|---|---|---|
| `listen_addr` | `"0.0.0.0:8443"` | valid socket addr | Address the PQC TCP listener binds to |
| `backend_addr` | `"127.0.0.1:8080"` | valid socket addr | Destination backend — receives plain TCP |
| `max_frame_size` | `65536` | 1024–16 777 216 | Maximum AES-256-GCM frame size in bytes |
| `handshake_timeout_secs` | `10` | ≥ 1 | Seconds allowed to complete the PQC handshake. Applies only to the handshake phase — relay has no timeout |
| `max_connections_per_ip` | `50` | ≥ 1 | Per-source-IP connection cap. Excess connections are dropped immediately to prevent CPU exhaustion from ML-DSA-65 signature generation under flood |

### [crypto]

| Field | Default | Required | Description |
|---|---|---|---|
| `signing_key_path` | `"./keys/server.sk"` | yes | Path to the ML-DSA-65 signing key (binary, 4032 bytes). Generated by `keygen`. The file must have mode `0600` — the bridge refuses to load a key with looser permissions |

The verifying key (`server.vk`) is loaded automatically from the same directory as `signing_key_path`. It is distributed to clients out-of-band — it is never transmitted over the wire. See [VK-share](#vk-share) for how to distribute the verifying key to browser clients automatically.

### [auth]

| Field | Default | Required | Description |
|---|---|---|---|
| `client_vk_path` | — | no | Path to the client's ML-DSA-65 verifying key (1952 bytes). When present, the bridge requires every client to prove its identity during the PQC handshake |
| `require_client_auth` | `true` | — | When `client_vk_path` is omitted, set this to `false` explicitly to suppress the startup warning. Omitting this field while also omitting `client_vk_path` logs a `WARN` at startup |

Omitting the `[auth]` section entirely disables mutual authentication. A `WARN` is emitted at startup to remind operators that client identity is not being verified.

### [tls]

| Field | Default | Required | Description |
|---|---|---|---|
| `enabled` | `false` | — | Activate the TLS/HTTPS relay listener |
| `listen_addr` | `"0.0.0.0:8440"` | — | TCP address for the TLS listener |
| `cert_path` | `"./keys/tls.crt"` | when enabled | PEM certificate |
| `key_path` | `"./keys/tls.key"` | when enabled | PEM private key |

Generate a self-signed cert for development: `latticeshield-bridge tls-keygen ./keys`

### [quic]

| Field | Default | Required | Description |
|---|---|---|---|
| `enabled` | `false` | — | Activate the QUIC (UDP) listener |
| `listen_addr` | `"0.0.0.0:8441"` | — | UDP address for the QUIC endpoint |
| `cert_path` | — | when enabled | PEM certificate (can reuse TLS cert) |
| `key_path` | — | when enabled | PEM private key |

Each QUIC bidirectional stream maps to one fresh TCP connection to the backend.

### [websocket]

| Field | Default | Required | Description |
|---|---|---|---|
| `enabled` | `false` | — | Activate the WSS listener for browser SDK clients |
| `listen_addr` | `"0.0.0.0:8446"` | — | TCP address |
| `cert_path` | — | when enabled | PEM certificate |
| `key_path` | — | when enabled | PEM private key |
| `allowed_origins` | `[]` | — | Array of allowed `Origin` headers e.g. `["https://app.example.com", "http://localhost:3000"]`. Empty array accepts all origins and emits a `WARN` log — use only in development |
| `handshake_timeout_secs` | `10` | — | PQC handshake timeout for WebSocket connections |
| `max_connections_per_ip` | `100` | — | Per-IP WebSocket connection cap |

Origins are normalized per RFC 6454 (`scheme://host:port`). The comparison is exact after normalization — paths, query strings, and fragments are rejected.

### [admin]

The admin channel accepts a single PQC-authenticated TCP connection, reads one JSON command, responds, and closes. Mutual ML-DSA-65 authentication is mandatory.

| Field | Default | Required | Description |
|---|---|---|---|
| `enabled` | `false` | — | Activate the admin listener |
| `listen_addr` | `"127.0.0.1:8445"` | — | TCP address. Default is loopback — change only if the control plane runs on a separate host, and firewall accordingly |
| `control_plane_vk_path` | — | when enabled | ML-DSA-65 verifying key of the control plane |
| `rate_limit_per_second` | `5` | — | Max admin commands per second |
| `handshake_timeout_secs` | `10` | — | PQC handshake timeout |

Generate an admin keypair: `latticeshield-bridge admin-keygen ./keys`  
Place `admin.vk` in `control_plane_vk_path` on the bridge; keep `admin.sk` on the control plane.

### [control_plane]

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Send periodic heartbeats to the control plane |
| `endpoint` | `""` | Control plane URL e.g. `https://cp.example.com` |
| `agent_name` | `""` | Bridge identifier. Defaults to `$HOSTNAME` if empty |
| `heartbeat_interval_secs` | `30` | Seconds between heartbeats (floor: 5) |
| `install_token` | `""` | Registration token. Also readable from `$INSTALL_TOKEN` |

Heartbeat failures are non-fatal — the bridge continues serving traffic if the control plane is unreachable.

### [key_rotation]

| Field | Default | Validation | Description |
|---|---|---|---|
| `enabled` | `false` | — | Enable automatic AES session key rotation |
| `max_bytes_per_key` | `10737418240` | ≥ 1 MiB | Bytes encrypted before rotating (10 GiB default) |
| `max_seconds_per_key` | `86400` | ≥ 60 | Seconds before forcing rotation (24 h default) |

Key rotation uses HKDF-SHA256 ratcheting: the new key is derived from the current key + a random 32-byte nonce. The old key is zeroized immediately. Rotation can also be triggered manually via the admin channel (`Rotate` command).

### [logging]

| Field | Default | Description |
|---|---|---|
| `level` | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error`. Overridden by `$RUST_LOG` |

### [metrics]

| Field | Default | Description |
|---|---|---|
| `listen_addr` | `"0.0.0.0:8444"` | Address for the Prometheus metrics HTTP server. Always active — cannot be disabled |

The endpoint responds on `GET /metrics` with Prometheus text format. It returns security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, and a strict CSP). Do not expose this port to the public internet without an authentication proxy in front of it.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | — | Overrides `[logging].level`. Supports per-module filters e.g. `RUST_LOG=latticeshield_bridge=debug` |
| `INSTALL_TOKEN` | — | Overrides `[control_plane].install_token` |
| `SHUTDOWN_TIMEOUT_SECS` | `30` | Seconds to wait for active sessions to drain on SIGTERM/SIGINT before forcing shutdown |
| `LATTICE_VK_TOKEN_MAX` | `1000` | Maximum entries in the in-memory VK-share token store |
| `HOSTNAME` | — | Used as `agent_name` when `[control_plane].agent_name` is empty |

---

## CLI reference

### `latticeshield-bridge` — the proxy daemon

```sh
# Start the bridge
latticeshield-bridge run [--config <path>]          # default: ./config.toml

# Generate ML-DSA-65 server keypair
latticeshield-bridge keygen <dir>
# → <dir>/server.sk  (permissions 0600)
# → <dir>/server.vk  (permissions 0644)

# Generate self-signed TLS certificate (development)
latticeshield-bridge tls-keygen <dir>
# → <dir>/tls.crt
# → <dir>/tls.key

# Generate admin channel ML-DSA-65 keypair
latticeshield-bridge admin-keygen <dir>
# → <dir>/admin.sk  (permissions 0600)
# → <dir>/admin.vk  (permissions 0644)
```

### `latticeshield` — unified key management CLI

```sh
# Generate keypairs
latticeshield keygen server <dir>   # server.sk (0600) + server.vk (0644)
latticeshield keygen client <dir>   # client.sk (0600) + client.vk (0644)
latticeshield keygen tls <dir>      # tls.crt + tls.key (self-signed, dev only)

# Inspect a verifying key
latticeshield vk-info ./keys/server.vk
# → File, Size (1952 bytes), SHA-256 fingerprint

# Request a one-time VK download URL via the PQC admin channel
latticeshield vk-share \
  --admin-addr 127.0.0.1:8445 \
  --bridge-vk  ./keys/server.vk \
  --admin-sk   ./keys/admin.sk
# → One-time VK download URL + token + expiry
```

### `latticeshield-client` — server-side PQC client proxy

```sh
latticeshield-client --config ./latticeshield-client.toml
```

Accepts local TCP connections and forwards them to the bridge using the full PQC handshake — for server-to-server scenarios where you can't modify the originating service.

---

## Browser SDK (`@latticeshield/js`)

Browsers can connect to LatticeShield directly — no plugin, no native agent. The bridge WebSocket listener (`:8446`) speaks the same hybrid PQC handshake as the Rust client. All crypto runs inside a Web Worker backed by a WASM module so session keys never touch the main thread.

```sh
npm install @latticeshield/js
```

```ts
import { PQCSession } from '@latticeshield/js';

const session = new PQCSession({
  bridgeUrl:      'wss://bridge.example.com:8446',
  serverVkBytes:  SERVER_VK,   // Uint8Array(1952) — pin at build time
});

await session.connect();
await session.send(new TextEncoder().encode('hello'));
session.on('message', (data) => console.log(data));
```

**React hook** with automatic exponential-backoff reconnect (1 s × 2ⁿ, cap 30 s, 3 retries):

```ts
import { usePQCSession } from '@latticeshield/js';

const { status, send, lastMessage, error } = usePQCSession({
  bridgeUrl:     'wss://bridge.example.com:8446',
  serverVkBytes: SERVER_VK,
});
```

**CSP requirements:**
```http
Content-Security-Policy:
  script-src  'self' 'wasm-unsafe-eval';
  worker-src  'self' blob:;
  connect-src 'self' wss://bridge.example.com:8446;
```

The `serverVkBytes` must be pinned at build time — never fetched at runtime. See [`latticeshield-js/README.md`](latticeshield-js/README.md) for the full API reference, SRI hashing, and VK distribution guide.

---

## VK-share

Browser clients need the server verifying key (`server.vk`) before they can open a session. Hardcoding the 1952-byte key at build time is the most secure option, but LatticeShield also provides a **VK-share** mechanism for dynamic distribution: the bridge generates a short-lived one-time URL that a client can use to retrieve the key over HTTPS.

### How it works

1. A control-plane operator sends a `GetVkToken` command to the admin channel (`:8445`). The bridge returns a random token.
2. The client fetches `GET https://bridge.example.com:8440/vk/<token>` — the TLS listener serves the raw verifying key bytes.
3. The token is single-use and expires after 10 minutes. If the token is unknown or expired the bridge returns `404`. The token store is capped at 1000 entries; new requests return `429` when the cap is reached.

### When to use VK-share

VK-share is designed for scenarios where baking the key at build time is impractical — for example, a SaaS product where tenants each have their own bridge instance and the browser app discovers the correct key at runtime. For fixed deployments (your own infrastructure, your own clients), distributing `server.vk` out-of-band and pinning it at build time is simpler and has a smaller attack surface.

### Requirements

The TLS listener (`[tls]`) must be enabled — VK-share is served over HTTPS, not plain HTTP.

```sh
# Request a one-time VK download URL via the PQC admin channel
# (requires admin channel enabled + admin keypair generated)
latticeshield vk-share \
  --admin-addr 127.0.0.1:8445 \
  --bridge-vk  ./keys/server.vk \
  --admin-sk   ./keys/admin.sk
# One-time VK download URL:
#   https://bridge.example.com:8440/vk/a3f8...
# Token: a3f8...
# Expires in: 10 minutes (600 seconds)

# Client fetches the verifying key
curl https://bridge.example.com:8440/vk/a3f8...
# → raw 1952-byte binary (application/octet-stream)
```

---

## Security design

### Cryptographic primitives

| Role | Algorithm | Standard |
|---|---|---|
| Key encapsulation | ML-KEM-768 | NIST FIPS 203 |
| Classical key exchange | X25519 | RFC 7748 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Server/client signatures | ML-DSA-65 | NIST FIPS 204 |
| Signing domain separator | `"latticeshield-v1"` | FIPS 204 §5.2 |

All primitives are pure Rust — no C FFI, no OpenSSL, no `oqs-rs`. Crypto crates: [`libcrux-ml-dsa`](https://crates.io/crates/libcrux-ml-dsa) (=0.0.8, ML-DSA-65), [`ml-kem`](https://crates.io/crates/ml-kem) (ML-KEM-768), [`x25519-dalek`](https://crates.io/crates/x25519-dalek), [`aes-gcm`](https://crates.io/crates/aes-gcm), [`hkdf`](https://crates.io/crates/hkdf).

> ⚠️ **No third-party security audit has been performed.** The cryptographic primitives use audited upstream crates; the protocol design and integration code are self-reviewed only.

### Handshake flow (server-auth, no mutual auth)

```
Server                                     Client
  │                                           │
  │  server_hello_signed (4557 B)             │
  │  = X25519_pub(32) + ML-KEM_EK(1184)       │
  │    + nonce(32) + ML-DSA-65_sig(3309)      │
  │ ─────────────────────────────────────────▶│
  │                                           │  parse + verify ML-DSA-65 sig
  │                                           │  encapsulate ML-KEM-768
  │                                           │  X25519 DH
  │                                           │  HKDF(x25519_secret || kem_secret, nonce)
  │  client_response (1120 B)                 │
  │  = X25519_pub(32) + ML-KEM_CT(1088)       │
  │◀─────────────────────────────────────────│
  │  decapsulate ML-KEM                       │
  │  X25519 DH                                │
  │  HKDF → same SessionKey ──────────────────┤
  │                                           │
  │◀════ AES-256-GCM encrypted relay ════════▶│
```

### Wire format constants

| Constant | Bytes | Description |
|---|---|---|
| `SERVER_HELLO_SIGNED_LEN` | 4557 | Signed server hello (VK **not** on wire — pre-shared) |
| `CLIENT_RESPONSE_LEN` | 1120 | Client key-exchange response |
| `VERIFYING_KEY_LEN` | 1952 | ML-DSA-65 public key |
| `SIGNING_KEY_LEN` | 4032 | ML-DSA-65 private key |
| `SIGNATURE_LEN` | 3309 | ML-DSA-65 signature |
| `KEY_ROTATE_FRAME_LEN` | 61 | Key rotation frame: tag(1)+nonce(12)+enc\_nonce(32)+tag(16) |

### DATA frame (v3)

```
[0x01][4B len][8B seq u64-BE][12B AES-GCM nonce][ciphertext][16B GCM tag]
```

The `seq` field is included as AES-GCM AAD — tampering with the sequence number is detected as an authentication failure. Out-of-order or replayed frames are rejected immediately (`FrameError::Replay`).

### Security constraints

| Constraint | Reason |
|---|---|
| Pure Rust, no FFI | Eliminates entire classes of memory unsafety in the crypto path |
| VK pre-shared, not on wire | Prevents MITM substituting the verifying key on first connect |
| `wss://` required for browser | Plain `ws://` would expose the PQC handshake to a network attacker |
| `SigningKey` memory-locked | `mlock(2)` prevents the private key from being swapped to disk |
| Signing context `"latticeshield-v1"` | Domain-separates signatures across versions and implementations |
| Per-IP connection cap | Limits CPU cost of ML-DSA-65 verification under connection floods |
| Handshake-only timeout | Relay has no timeout — streaming use-cases are not penalized |

---

## Prometheus metrics

Exposed at `http://<metrics_addr>/metrics` (plain HTTP, no auth).

| Metric | Type | Description |
|---|---|---|
| `latticeshield_connections_total` | Counter | Total accepted connections |
| `latticeshield_connections_active` | Gauge | Currently open sessions |
| `latticeshield_handshake_duration_seconds` | Histogram | PQC handshake latency |
| `latticeshield_bytes_transmitted_total` | Counter | Total encrypted bytes relayed |
| `latticeshield_channel_errors_total` | Counter | AES-GCM / framing errors |
| `latticeshield_key_rotations_total` | Counter | Session key rotation events |

The `/metrics` endpoint returns `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, and a strict `Content-Security-Policy`.

---

## Workspace structure

```
latticeshield/
├── latticeshield-crypto/   # ML-KEM-768, X25519, ML-DSA-65, AES-256-GCM, HKDF
├── latticeshield-bridge/   # Reverse proxy binary + all listeners + config
├── latticeshield-client/   # Server-side PQC client proxy (server-to-server)
├── latticeshield-cli/      # Unified key management CLI (`latticeshield` binary)
├── latticeshield-wasm/     # latticeshield-crypto compiled to WASM (for browsers)
└── latticeshield-js/       # @latticeshield/js npm package (PQCSession, usePQCSession)
```

---

## Building from source

```sh
# Requires Rust 1.75+
cargo build --release -p latticeshield-bridge   # reverse proxy daemon
cargo build --release -p latticeshield          # key management CLI
cargo build --release -p latticeshield-client   # server-side PQC client proxy

# Build the browser WASM module (requires wasm-pack)
wasm-pack build --target bundler latticeshield-wasm

# Build the JS SDK
cd latticeshield-js && npm install && npm run build
```

---

## Tests

```sh
cargo test --workspace                    # 457 Rust tests
cd latticeshield-js && npm test           # 93 TypeScript tests
```

| Crate / Package | Tests | Coverage highlights |
|---|---|---|
| `latticeshield-bridge` | 355 (135 unit lib + 209 unit main + 11 integration) | Config validation, TCP/WebSocket/TLS integration, per-IP cap, admin channel |
| `latticeshield-client` | 49 (47 unit + 2 integration) | Client proxy lifecycle, PQC handshake, config |
| `latticeshield-crypto` | 45 | Handshake vectors, anti-replay, key rotation, signing domain separation |
| `latticeshield-cli` | 7 | Key management CLI integration |
| `latticeshield-wasm` | 1 | WASM↔Rust wire format parity |
| `latticeshield-js` | 93 | PQCSession lifecycle, VK copy, unexpected close, framing, nonce layout |

---

## What's New

### v0.3.1 — Browser SDK Auto-Reconnect + CLI Fixes (2026-05-14)

Fixed two bugs that made auto-reconnect permanently broken in `@latticeshield/js`. The server verification key was silently zeroed after the first handshake (Transferable buffer detachment), and unexpected WebSocket drops were not detected (no `close` event emitted). The `usePQCSession` React hook already had full reconnect logic — it now fires correctly. Also fixes a `seqToNonce` nonce layout mismatch (bytes 4–11 instead of 0–7) that caused decryption failures from the second frame onwards.

`latticeshield vk-share` was rewritten to use the real PQC admin channel (`--admin-addr`, `--bridge-vk`, `--admin-sk`) instead of a plain HTTP Bearer token endpoint that did not exist. Admin channel default bind changed from `0.0.0.0:8445` to `127.0.0.1:8445` — loopback-only by default, explicit config required for remote access.

### v0.3.0 — Security Hardening (2026-05-13)

Closes 9 pending security audit findings. Introduces ML-DSA-65 domain separation (`latticeshield-v1` signing context), WebSocket origin normalization (RFC 6454), VK token store DoS protection (cap 1000, eviction, HTTP 429), `/metrics` security response headers, per-IP TCP connection cap, dedicated PQC handshake timeout, and fixes a broken key-fetch function in the JS SDK. Version bump 0.2.0 → 0.3.0 (breaking: signing context change).

---

## Contributing

Pull requests are welcome. Before opening one:

1. `cargo test --workspace` — all Rust tests must pass
2. `cd latticeshield-js && npm test` — all TypeScript tests must pass
3. `cargo fmt --check` — code must be formatted
4. `cargo clippy -- -D warnings` — no new warnings

For changes larger than a bug fix, open an issue first so the approach can be discussed before you write code. The project follows [Conventional Commits](https://www.conventionalcommits.org/). Do not include AI attribution in commit messages.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
