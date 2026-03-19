# latticeshield-bridge — What It Does

## In Plain English

This is the server-side gateway — like a security guard at the entrance of a building. It sits in front of your existing backend service and intercepts all incoming connections. It checks the identity of connecting clients, negotiates a shared secret (that means: the two parties agree on a private code that only they know), and then relays the encrypted traffic to your backend without your backend needing to know anything about encryption. Standard web browsers and command-line tools can also connect to it directly over regular secure web connections.

## What It Does For You

- Acts as a transparent (that means: invisible and requiring no changes) security layer in front of any existing service.
- Accepts connections from three types of clients: the LatticeShield agent, standard HTTPS web clients like browsers or curl, and QUIC (that means: a newer, faster connection protocol used by modern browsers) clients — all on separate ports.
- Publishes live metrics (that means: a real-time count of connections, bytes, and errors) to a monitoring endpoint so you can watch what is happening.
- Generates and manages its own signing keys so it can prove its identity to connecting clients.
- Reports its status to a management server (that means: a central service that tracks all deployed gateways) periodically, including its own digital ID card so the management server can store and display it for operator reference.
- Issues one-time secure download links so new client operators can safely obtain the server's digital ID card without manual file transfers.

## How It Fits Together

latticeshield-bridge is the server half of the system. It depends on latticeshield-crypto for all security math and exposes a library interface (that means: a set of functions other programs can call) used by latticeshield-cli to generate keys without starting the full server. latticeshield-client connects to it from the user's machine to establish an encrypted tunnel (that means: a private channel through which data flows safely). The backend service sits behind the bridge and never sees raw internet traffic.

## What Changed in This Release

- The bridge now includes its digital ID card in every status report sent to the management server. This lets operators view and confirm the server's identity from a central location.
- A new key distribution feature was added. An admin can call a new management endpoint to generate a one-time download link. That link is valid for 10 minutes and can only be used once. A client operator visits the link over a standard secure web connection (port 8440) and receives the server's digital ID card as a file they can save locally. The link cannot be reused after the first download.
- The management endpoint that creates download links requires a secret admin password (set via the `LATTICESHIELD_ADMIN_TOKEN` environment variable). This prevents unauthorized parties from generating links even if they can reach the management port.
- Tokens are kept in memory only. They do not survive a bridge restart. This is intentional — each distribution session is fresh.

---
*Last updated: 2026-03-19 — latticeshield-mes12-vk-share*
