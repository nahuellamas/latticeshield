# latticeshield-client — What It Does

## In Plain English

This is the user-side agent — like a personal bodyguard that rides along with your application. It runs on your local machine, accepts plain unencrypted connections from your app, wraps every byte in quantum-resistant encryption, and forwards it securely to the bridge on the server. Your application never needs to know any of this is happening — it just talks to a local port as if nothing changed. If the connection drops, the client automatically reconnects and picks up where it left off.

## What It Does For You

- Makes any existing application quantum-safe without modifying it — just point the app at `localhost:9090` instead of the real server.
- Verifies the server's identity before sending any data, so your app never accidentally talks to an impostor.
- Proves your client's identity to the server using unforgeable digital signatures (that means: math that only your specific key can produce), so the server only accepts connections from authorized clients.
- Automatically retries after a lost connection, with increasing wait times between attempts so it does not flood the server.
- Loads your private key securely and prevents the operating system from writing it to disk (that means: the key never appears in swap or hibernation files).

## How It Fits Together

latticeshield-client is the companion to latticeshield-bridge — one runs on the user's machine, the other on the server. The client depends on latticeshield-crypto for all the encryption math. latticeshield-cli can generate the key files that the client needs to prove its identity. The client also exposes a library interface (that means: functions other programs can call) used by latticeshield-cli for key generation and fingerprinting (that means: producing a short identifier from a key so you can confirm you have the right one).

## What Changed in This Release

- Old key generation subcommands (`client-keygen`, `vk-info`) now print a deprecation warning (that means: a notice that this approach is outdated and will be removed) pointing operators to the new `latticeshield` command instead.

---
*Last updated: 2026-03-12 — latticeshield-mes10-cli*
