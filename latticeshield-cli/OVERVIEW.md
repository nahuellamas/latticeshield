# latticeshield-cli — What It Does

## In Plain English

This is the single command you run when setting up LatticeShield. Think of it as the installer wizard — it generates all the key files (that means: the digital credentials that prove who you are) your server and client need before they can talk to each other. Before this existed, you had to know which of two different programs to run depending on what kind of key you needed. Now there is one command with a clear menu for everything, including securely handing out the server's digital ID card to new clients.

## What It Does For You

- Generates server keys with a single command, creating the files the bridge needs to prove its identity to clients.
- Generates client keys with a single command, creating the files the client agent needs to prove its identity to the bridge.
- Generates a TLS certificate (that means: a standard web security credential used by browsers and curl to verify the server) that covers both the regular web listener and the fast QUIC (that means: a modern connection protocol) listener.
- Displays a fingerprint (that means: a short unique identifier derived from a key) for any key file, so you can confirm two parties are using the same key without sharing the key itself.
- Contacts a running bridge to create a one-time download link for the server's digital ID card, making it easy to set up new client operators without manual file transfers.
- Shows a welcome screen with a guided list of available commands when run with no arguments.

## How It Fits Together

latticeshield-cli is a thin front-door for the whole system. It does not run any server or handle any network connections during key generation — it only generates files or coordinates with a running bridge. Under the hood it calls the key generation functions from latticeshield-bridge and latticeshield-client, so the output is always compatible with those programs. The `vk-share` command is the only one that requires a running bridge — it contacts the bridge's management port to generate a download link, then prints that link so you can share it with the client operator.

## What Changed in This Release

- New `latticeshield vk-share` command added. It contacts a running bridge management server (default: `http://127.0.0.1:8444`), requests a one-time download link for the server's digital ID card, and prints the link and a fingerprint. The client operator then visits that link once to receive the ID card file. Use `--bridge <url>` to point to a bridge at a non-default address.

---
*Last updated: 2026-03-19 — latticeshield-mes12-vk-share*
