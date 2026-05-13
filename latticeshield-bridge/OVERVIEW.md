# latticeshield-bridge — What It Does

## In Plain English

This is the server-side gateway — like a security guard at the entrance of a building. It sits in front of your existing backend service and intercepts all incoming connections. It checks the identity of connecting clients, negotiates a shared secret (that means: the two parties agree on a private code that only they know), and then relays the encrypted traffic to your backend without your backend needing to know anything about encryption. Standard web browsers and command-line tools can also connect to it directly over regular secure web connections.

## What It Does For You

- Acts as a transparent (that means: invisible and requiring no changes) security layer in front of any existing service.
- Accepts connections from three types of clients: the LatticeShield agent, standard HTTPS web clients like browsers or curl, and QUIC (that means: a newer, faster connection protocol used by modern browsers) clients — all on separate ports.
- Publishes live metrics (that means: a real-time count of connections, bytes, and errors) to a monitoring endpoint so you can watch what is happening.
- Generates and manages its own signing keys so it can prove its identity to connecting clients.
- Reports its status to a management server (that means: a central service that tracks all deployed gateways) periodically, and every report carries a digital signature so the management server can confirm it came from the real bridge.
- Issues one-time secure download links so new client operators can safely obtain the server's digital ID card without manual file transfers.
- Accepts a one-time onboarding code (that means: a short secret issued by the management server) during first registration so only authorized bridges can join the fleet.
- Communicates with the management server using quantum-resistant encryption (that means: even a future quantum computer cannot read the traffic between the bridge and the cloud).
- Executes operational commands from the management server, such as rotating encryption keys across all active client sessions.

## How It Fits Together

latticeshield-bridge is the server half of the system. It depends on latticeshield-crypto for all security math and exposes a library interface (that means: a set of functions other programs can call) used by latticeshield-cli to generate keys without starting the full server. latticeshield-client connects to it from the user's machine to establish an encrypted tunnel (that means: a private channel through which data flows safely). The backend service sits behind the bridge and never sees raw internet traffic. The bridge also phones home (that means: sends periodic status updates) to a cloud management server to report its health and receive operational instructions — this connection is now protected with the same quantum-resistant math used between client and bridge.

## What Changed in This Release

- The bridge now checks that every WebSocket origin entry in the config is a real URL with a scheme. If any entry is malformed the bridge refuses to start and tells you exactly which entry is wrong — you find out immediately on restart, not during the first real connection.
- Two origins that point to the same place are now always treated as the same: for example, `https://app.example.com` and `https://app.example.com:443` are equivalent. Before this change they would be treated as different, silently rejecting valid connections.
- The list of one-time download tokens for the server identity card is now capped at 1000 active entries. If that limit is ever reached, new requests get a clear "too many requests" response instead of the bridge quietly consuming more and more memory. The cap is adjustable via the `LATTICE_VK_TOKEN_MAX` environment variable.
- The connection timer that protects against slow clients who never finish the opening handshake now only covers the handshake itself. Before this change the same timer covered the entire session, which meant long-lived transfers could be cut off unexpectedly. Transfers can now run as long as needed.
- When the bridge starts with client authentication turned off, it now logs a warning that says so clearly. Before this change, running in open-access mode was completely silent.
- The bridge now logs its signing context (`latticeshield-v1`) at startup alongside the version number, so operators can confirm which cryptographic protocol version is running.

---
*Last updated: 2026-05-13 — latticeshield-mes24-security-hardening*
