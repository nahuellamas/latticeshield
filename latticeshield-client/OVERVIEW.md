# latticeshield-client — What It Does

## In Plain English

This is the user-side agent — like a personal bodyguard that rides along with your application. It runs on your local machine, accepts plain unencrypted connections from your app, wraps every byte in quantum-resistant encryption, and forwards it securely to the bridge on the server. Your application never needs to know any of this is happening — it just talks to a local port as if nothing changed. A small pool of ready-made connections (that means: pre-opened lines to the server kept on standby) means requests start almost instantly instead of waiting for a new connection to be set up every time.

## What It Does For You

- Makes any existing application quantum-safe without modifying it — just point the app at `localhost:9090` instead of the real server.
- Keeps a small set of connections ready in the background so that each request starts immediately without waiting for a new line to the server to open up.
- Verifies the server's identity before sending any data, so your app never accidentally talks to an impostor.
- Proves your client's identity to the server using unforgeable digital signatures (that means: math that only your specific key can produce), so the server only accepts connections from authorized clients.
- Automatically recovers from stale connections (that means: lines that were left open but were quietly closed by the server) without the user noticing anything.
- Shuts down cleanly when stopped, closing all standby connections gracefully so the server is not left with dangling open lines.
- Loads your private key securely and prevents the operating system from writing it to disk (that means: the key never appears in swap or hibernation files).

## How It Fits Together

latticeshield-client is the companion to latticeshield-bridge — one runs on the user's machine, the other on the server. The client depends on latticeshield-crypto for all the encryption math. latticeshield-cli can generate the key files that the client needs to prove its identity. The client also exposes a library interface (that means: functions other programs can call) used by latticeshield-cli for key generation and fingerprinting (that means: producing a short identifier from a key so you can confirm you have the right one).

## What Changed in This Release

- Added a connection pool that keeps a configurable number of ready-made connections to the server in the background. Requests skip the connection setup step and start faster, especially under load.
- The pool cleans itself up automatically — connections that have been sitting idle too long are quietly replaced so your app never receives a dead line.
- Added a new optional `[pool]` section to the configuration file. Leaving it out is fine — the pool runs with sensible defaults (4 maximum connections, 30-second idle limit, 2 pre-warmed connections).
- The client now shuts down gracefully when it receives a stop signal (that means: when you press Ctrl+C or when the operating system asks it to stop), closing all standby connections cleanly before exiting.
- Removed outdated setup subcommands (`client-keygen`, `vk-info`) that were replaced by the `latticeshield` command in the previous release.

---
*Last updated: 2026-03-16 — latticeshield-mes11-pool*
