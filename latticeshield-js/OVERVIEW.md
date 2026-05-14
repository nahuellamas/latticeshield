# latticeshield-js — What It Does

## In Plain English

This is the browser half of LatticeShield. It lets any web page or web application connect
to a LatticeShield bridge server with the same quantum-safe encryption that native desktop
apps use — no browser plugin, no native agent, nothing to install. The page connects
automatically, sends and receives data through the encrypted tunnel, and reconnects by itself
if the connection drops.

## What It Does For You

- Connects your browser page to a LatticeShield bridge with post-quantum encryption
- Keeps all encryption keys isolated in a background worker, away from your page's code
- Sends and receives binary or text data through the secure tunnel with a simple API
- Automatically reconnects if the server restarts or the network drops — with exponential backoff
- Provides a React hook (`usePQCSession`) for state-driven UI integration
- Rejects any connection that tries to use plain WebSocket (no `wss://`, no tunnel)

## How It Fits Together

`latticeshield-js` is the client-side counterpart to the bridge's WebSocket listener.
When a browser page wants to send data securely, it creates a session through this package.
The session talks to the bridge (the Rust reverse proxy), which decrypts the traffic and
forwards it to whatever backend service sits behind it — a REST API, a database proxy, an
internal tool. The `latticeshield-wasm` package provides the low-level cryptographic
operations; this package handles everything else: the connection lifecycle, key management,
error handling, and the React integration layer.

## What Changed in This Release

- Fixed a bug where the session did not detect unexpected WebSocket drops — reconnects
  never fired because the `'close'` event was not emitted after a network drop or bridge restart
- Fixed a bug where the server verification key (used to authenticate the bridge) was
  silently erased after the first handshake, making every reconnect attempt fail with a
  cryptographic error
- Added `SessionClosedError` — a typed error class that callers can use to distinguish
  session-closed errors from other failures
- The `usePQCSession` React hook now actually reconnects automatically (the logic existed
  before but could never trigger)

---
*Last updated: 2026-05-14 — latticeshield-browser-autoreconnect*
