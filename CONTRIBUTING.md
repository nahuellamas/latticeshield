# Contributing to LatticeShield

Thank you for your interest in contributing. LatticeShield is a post-quantum cryptography project — contributions are welcome, but the bar for correctness is high. Please read this guide before opening a PR.

## Before You Start

- **Security changes** — read [SECURITY.md](SECURITY.md) first. Do not open public issues or PRs for vulnerabilities.
- **Large features** — open an issue first to discuss scope and approach. Don't spend days on a PR that won't be merged.
- **Bug fixes and small improvements** — go ahead and open a PR directly.

## Development Setup

### Rust (bridge, crypto, client, CLI, WASM)

Requires Rust 1.75+.

```sh
# Run all tests
~/.cargo/bin/cargo test --workspace

# Lint
~/.cargo/bin/cargo fmt --check
~/.cargo/bin/cargo clippy -- -D warnings

# Dependency audit
~/.cargo/bin/cargo deny check
```

### TypeScript (browser SDK)

Requires Node.js 18+.

```sh
cd latticeshield-js
npm install
npm run typecheck
npm test
```

## Pull Request Guidelines

- **One concern per PR** — a fix is a fix, a feature is a feature. Don't mix them.
- **Tests required** — every change to `latticeshield-crypto` or `latticeshield-bridge` must include tests. No exceptions.
- **No unsafe Rust** — the codebase has zero `unsafe` blocks. Keep it that way unless there is an extraordinary reason.
- **No new FFI dependencies** — LatticeShield is intentionally pure Rust with no OpenSSL, no oqs-rs, no C bindings. New crypto dependencies must be pure Rust.
- **Commit messages** — use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `test:`.
- **CI must pass** — formatting, clippy, deny, and all tests must be green before review.

## Cryptographic Contributions

Changes to `latticeshield-crypto` or any handshake/channel code require extra care:

- Explain the cryptographic rationale in the PR description, not just the code change.
- Reference the relevant NIST standard or academic paper if applicable.
- Do not change wire format constants (`SERVER_HELLO_LEN`, `CLIENT_RESPONSE_LEN`, etc.) without a versioning plan.
- Domain separation strings (e.g. `b"latticeshield-v1"`) are part of the security contract — changes are breaking.

## What We Won't Merge

- Dependencies that introduce FFI or link against system crypto libraries.
- Changes that weaken the hybrid construction (dropping either X25519 or ML-KEM-768).
- New features without tests.
- Code that passes CI but is clearly untested in practice.

## License

By submitting a pull request you agree that your contribution is licensed under the [Apache-2.0 License](LICENSE).
