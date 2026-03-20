# latticeshield-bridge — What It Does

## In Plain English

This is the server-side gateway — like a security guard at the entrance of a building. It sits in front of your existing backend service and intercepts all incoming connections. It checks the identity of connecting clients, negotiates a shared secret (that means: the two parties agree on a private code that only they know), and then relays the encrypted traffic to your backend without your backend needing to know anything about encryption. Standard web browsers and command-line tools can also connect to it directly over regular secure web connections.

## What It Does For You

- Acts as a transparent (that means: invisible and requiring no changes) security layer in front of any existing service.
- Accepts connections from three types of clients: the LatticeShield agent, standard HTTPS web clients like browsers or curl, and QUIC (that means: a newer, faster connection protocol used by modern browsers) clients — all on separate ports.
- Publishes live metrics (that means: a real-time count of connections, bytes, and errors) to a monitoring endpoint so you can watch what is happening.
- Generates and manages its own signing keys so it can prove its identity to connecting clients.
- Reports its status to a management server (that means: a central service that tracks all deployed gateways) periodically, and every report now carries a digital signature so the management server can confirm it came from the real bridge.
- Issues one-time secure download links so new client operators can safely obtain the server's digital ID card without manual file transfers.
- Accepts a one-time onboarding code (that means: a short secret issued by the management server) during first registration so only authorized bridges can join the fleet.

## How It Fits Together

latticeshield-bridge is the server half of the system. It depends on latticeshield-crypto for all security math and exposes a library interface (that means: a set of functions other programs can call) used by latticeshield-cli to generate keys without starting the full server. latticeshield-client connects to it from the user's machine to establish an encrypted tunnel (that means: a private channel through which data flows safely). The backend service sits behind the bridge and never sees raw internet traffic. The bridge also phones home (that means: sends periodic status updates) to a cloud management server to report its health and receive operational instructions.

## What Changed in This Release

- Every status update sent to the management server now carries a digital seal (that means: a signature that only this bridge can produce, using the same key it uses to prove its identity to clients). The management server can verify the seal without storing any secret of its own.
- The management server can now send instructions back to the bridge inside the status-update response. The first supported instruction is a key rotation request (that means: a command to generate a fresh encryption key, limiting how much data any single key ever protects).
- Operators can now set a one-time onboarding code in the config file or as an environment variable. This code is sent once when the bridge registers with the management server. The management server uses it to confirm the bridge is legitimate before assigning it an identity. The code never appears in log files at any detail level — it is always hidden.
- When no onboarding code is configured and the management server connection is enabled, the bridge logs a reminder so operators know the registration endpoint is open without extra protection.

---
*Last updated: 2026-03-20 — latticeshield-mes14-cloud-integration*
