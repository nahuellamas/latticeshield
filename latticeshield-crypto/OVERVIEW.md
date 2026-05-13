# latticeshield-crypto — What It Does

## In Plain English

This is the security engine of LatticeShield — like the lock-and-key mechanism inside a safe. It handles the math that makes your connections private and tamper-proof, even against future quantum computers. It does the work of agreeing on a shared secret between two parties (like two people meeting in a room and agreeing on a secret code), verifying that both sides are who they claim to be, and encrypting every byte that flows through.

## What It Does For You

- Protects your data against both today's classical attacks and tomorrow's quantum computer attacks, by combining two independent lock mechanisms.
- Verifies that the server (gateway) is genuinely the server you trust, using unforgeable digital signatures (that means: a mathematical proof that only the real server could have produced).
- Ensures that once a session ends, even if an attacker recorded everything, they cannot decrypt it — each session uses a fresh secret that is thrown away afterward.
- Prevents replayed messages from being accepted twice — each request can only be processed once.
- Securely erases all key material from memory the moment it is no longer needed, so a memory dump cannot reveal secrets.

## How It Fits Together

latticeshield-crypto is the foundation that all other crates depend on. latticeshield-bridge (the server gateway) and latticeshield-client (the user-side agent) both import this crate to perform handshakes (that means: the initial negotiation where two parties agree on how to encrypt the conversation), verify identities, and encrypt traffic. It has no network code of its own — it is a pure math library that the other crates call into.

## What Changed in This Release

- Every digital signature the bridge produces now carries a label that says "this signature belongs to LatticeShield version 1." This is called domain separation — it means a signature made by LatticeShield cannot be mistaken for, or accepted by, a different system that happens to use the same type of signature math with no label. Before this change the label was empty, which left a gap where signatures from different systems or products could theoretically be confused. The label is `latticeshield-v1`. This is a breaking change — bridges and clients must be upgraded together (version 0.3.0).
- A regression test now checks that the label bytes are exactly `latticeshield-v1`. If someone accidentally changes the label in a future edit, the test fails immediately and visibly before any release goes out.
- A second test confirms that a signature made with the old empty label is correctly rejected by the new verifier. The incompatibility between versions 0.2.x and 0.3.x is real and intentional, and this test proves it.

---
*Last updated: 2026-05-13 — latticeshield-mes24-security-hardening*
