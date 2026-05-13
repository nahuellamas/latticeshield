# latticeshield-wasm — What It Does

## In Plain English

This is the browser-ready version of the LatticeShield security math. Browsers cannot run regular software directly, but they can run a special format called WebAssembly — think of it as a very small, very fast virtual machine built into every modern browser. This package compiles the same security math used by the Rust desktop agent into that format, so a web page can perform the same quantum-resistant handshake without any plugins or native apps.

## What It Does For You

- Lets any modern browser connect to the LatticeShield gateway using the same level of quantum-resistant protection as the desktop agent.
- Runs entirely inside the browser's built-in security sandbox (that means: it cannot access your file system, your camera, or anything outside the page).
- Exposes simple functions a JavaScript developer can call to generate keys, sign messages, and verify server identity — without needing to understand the underlying math.
- Produces the same wire-compatible handshake bytes as the Rust clients, so the bridge treats a browser connection exactly like any other client.

## How It Fits Together

latticeshield-wasm is the cryptographic core for browser clients. The `@latticeshield/js` package (the npm package that web developers install) loads this compiled module inside a Web Worker (that means: a background thread inside the browser) and calls its functions. The math itself is identical to what `latticeshield-crypto` does — the only difference is that `latticeshield-wasm` does not use any operating-system-specific features (like locking memory pages), because browsers do not expose those. This is why it exists as a separate package rather than a direct import of `latticeshield-crypto`.

## What Changed in This Release

- Every digital signature produced by the browser client now carries the label `latticeshield-v1`. Before this change the label was empty, which left a gap where signatures from different systems could be confused. The label is identical to the one added to the Rust desktop client — both sides must use the same label or the handshake fails. This is a breaking change (version 0.3.0) and browser clients must be updated alongside the bridge.
- A test now checks that the label bytes are exactly `latticeshield-v1` in this package as well as in the main Rust crypto package. If the two ever drift apart, the test fails immediately.

---
*Last updated: 2026-05-13 — latticeshield-mes24-security-hardening*
