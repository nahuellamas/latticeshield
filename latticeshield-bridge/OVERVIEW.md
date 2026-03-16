# latticeshield-bridge — What It Does

## In Plain English

This is the server-side gateway — like a security guard at the entrance of a building. It sits in front of your existing backend service and intercepts all incoming connections. It checks the identity of connecting clients, negotiates a shared secret (that means: the two parties agree on a private code that only they know), and then relays the encrypted traffic to your backend without your backend needing to know anything about encryption. Standard web browsers and command-line tools can also connect to it directly over regular secure web connections.

## What It Does For You

- Acts as a transparent (that means: invisible and requiring no changes) security layer in front of any existing service.
- Accepts connections from three types of clients: the LatticeShield agent, standard HTTPS web clients like browsers or curl, and QUIC (that means: a newer, faster connection protocol used by modern browsers) clients — all on separate ports.
- Publishes live metrics (that means: a real-time count of connections, bytes, and errors) to a monitoring endpoint so you can watch what is happening.
- Generates and manages its own signing keys so it can prove its identity to connecting clients.
- Reports its status to a central control plane (that means: a management service that tracks all deployed gateways) periodically.

## How It Fits Together

latticeshield-bridge is the server half of the system. It depends on latticeshield-crypto for all security math and exposes a library interface (that means: a set of functions other programs can call) used by latticeshield-cli to generate keys without starting the full server. latticeshield-client connects to it from the user's machine to establish an encrypted tunnel (that means: a private channel through which data flows safely). The backend service sits behind the bridge and never sees raw internet traffic.

## What Changed in This Release

- Removed outdated setup subcommands (`keygen`, `tls-keygen`, `quic-keygen`) that were replaced by the `latticeshield` command in the previous release. Starting the bridge now goes directly to loading the configuration and running the server, with no extra steps.

---
*Last updated: 2026-03-16 — latticeshield-mes11-pool*
