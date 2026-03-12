# latticeshield-cli — What It Does

## In Plain English

This is the single command you run when setting up LatticeShield. Think of it as the installer wizard — it generates all the key files (that means: the digital credentials that prove who you are) your server and client need before they can talk to each other. Before this existed, you had to know which of two different programs to run depending on what kind of key you needed. Now there is one command with a clear menu for everything.

## What It Does For You

- Generates server keys with a single command, creating the files the bridge needs to prove its identity to clients.
- Generates client keys with a single command, creating the files the client agent needs to prove its identity to the bridge.
- Generates a TLS certificate (that means: a standard web security credential used by browsers and curl to verify the server) that covers both the regular web listener and the fast QUIC (that means: a modern connection protocol) listener.
- Displays a fingerprint (that means: a short unique identifier derived from a key) for any key file, so you can confirm two parties are using the same key without sharing the key itself.
- Shows a welcome screen with a guided list of available commands when run with no arguments.

## How It Fits Together

latticeshield-cli is a thin front-door for the whole system. It does not run any server or handle any network connections — it only generates files. Under the hood it calls the key generation functions from latticeshield-bridge and latticeshield-client, so the output is always compatible with those programs. Operators run this once during initial setup, then hand off the generated files to the bridge and client configurations.

## What Changed in This Release

- New crate introduced in Mes 10 — everything in this crate is new.
- Provides `latticeshield keygen server <dir>` to generate server credential files.
- Provides `latticeshield keygen client <dir>` to generate client credential files.
- Provides `latticeshield keygen tls <dir>` to generate a web security certificate for the bridge.
- Provides `latticeshield vk-info <path>` to display the fingerprint and size of any key file.
- Shows a styled ASCII welcome banner when run with no arguments.

---
*Last updated: 2026-03-12 — latticeshield-mes10-cli*
