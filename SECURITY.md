# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Yes     |
| < 0.3   | ❌ No      |

Only the latest release receives security fixes. Upgrade to the current version before reporting.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use one of the following channels:

- **GitHub private disclosure** (preferred): [Report a vulnerability](https://github.com/nahuellamas/latticeshield/security/advisories/new)
- **Email**: nahuellamas@gmail.com — include "LATTICESHIELD SECURITY" in the subject line

### What to include

- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested fix, if you have one

### Response timeline

| Event | Target |
|-------|--------|
| Acknowledgement | Within 72 hours |
| Initial assessment | Within 7 days |
| Fix or mitigation | Within 30 days for critical, 90 days for others |
| Public disclosure | Coordinated with reporter after fix is released |

## Scope

In scope:
- `latticeshield-crypto` — handshake, channel encryption, signing
- `latticeshield-bridge` — all listeners (PQC, TLS, QUIC, WebSocket, admin)
- `latticeshield-wasm` — WASM crypto bindings
- `@latticeshield/js` — browser SDK

Out of scope:
- Vulnerabilities in upstream dependencies (report directly to the dependency maintainer)
- Issues requiring physical access to the host machine
- Social engineering attacks

## Cryptographic Scope

LatticeShield uses post-quantum algorithms standardized by NIST (ML-KEM-768, ML-DSA-65) combined with classical X25519. If you find a weakness in the hybrid construction, key derivation (HKDF-SHA256), or authenticated encryption (AES-256-GCM) as implemented here, that is especially important — please report it.

## Hall of Fame

Responsible disclosures that lead to a fix will be credited in the release notes unless the reporter requests anonymity.
