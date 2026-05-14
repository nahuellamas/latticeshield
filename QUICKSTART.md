# Quickstart

Get LatticeShield running between two servers in under 10 minutes.

LatticeShield protects any TCP connection between two machines. The typical setup is:

- **Backend server** — runs `latticeshield-bridge` next to your API (e.g. a Node.js server, a Rust service, a database proxy)
- **Client server** — runs `latticeshield-client` next to whatever needs to talk to that API (e.g. a frontend server, another microservice, a worker)

The two machines could be a frontend + backend, two microservices, two cloud VMs, or a local dev machine talking to a staging API. What matters is that they can reach each other over the network.

## What you need

- Two Linux or macOS machines (or VMs) that can reach each other over the network
- A service already running on the **backend machine** that listens on a local port (e.g. an API on `127.0.0.1:8080`)

---

## Step 1 — Install the bridge on the backend server

```sh
curl -fsSL https://raw.githubusercontent.com/nahuellamas/latticeshield/main/install.sh | bash
```

This installs `latticeshield-bridge`, `latticeshield-client`, and the `latticeshield` CLI to `/usr/local/bin`.

---

## Step 2 — Generate server keys

```sh
latticeshield keygen server ./keys
```

This creates:
- `./keys/server.sk` — signing key (keep this private, permissions `0600`)
- `./keys/server.vk` — verifying key (distribute to clients)

---

## Step 3 — Configure the bridge

Create `config.toml` on the backend server:

```toml
[server]
listen_addr  = "0.0.0.0:8443"
backend_addr = "127.0.0.1:8080"

[crypto]
signing_key_path = "./keys/server.sk"

[auth]
require_client_auth = false  # set to true once you have a client VK
```

---

## Step 4 — Start the bridge

```sh
latticeshield-bridge run --config config.toml
```

You should see:

```
INFO latticeshield_bridge: PQC listener started addr=0.0.0.0:8443
```

---

## Step 5 — Install the client on the frontend server

```sh
curl -fsSL https://raw.githubusercontent.com/nahuellamas/latticeshield/main/install.sh | bash
```

---

## Step 6 — Copy the server verifying key to the frontend server

```sh
scp backend-server:./keys/server.vk ./keys/server.vk
```

---

## Step 7 — Configure the client

Create `client.toml` on the frontend server:

```toml
[client]
listen_addr  = "127.0.0.1:9090"
bridge_addr  = "<backend-server-ip>:8443"
server_vk_path = "./keys/server.vk"
```

---

## Step 8 — Start the client

```sh
latticeshield-client --config client.toml
```

You should see:

```
INFO latticeshield_client: PQC client proxy started addr=127.0.0.1:9090
```

---

## Step 9 — Test it

From the frontend server, send traffic through the PQC tunnel:

```sh
curl http://127.0.0.1:9090/your-api-endpoint
```

Traffic flows: `curl → latticeshield-client (plain TCP) → PQC tunnel → latticeshield-bridge → backend API`.

---

## Next steps

- **Enable mutual client auth** — see [README.md](../README.md#security-constraints) for `[auth]` config
- **Add TLS for HTTPS clients** — add a `[tls]` section to the bridge config
- **Enable WebSocket support** — add a `[websocket]` section for browser clients
- **Run as a system service** — see `contrib/systemd/` (Linux) or `contrib/launchd/` (macOS)
- **Distribute the server VK securely** — use `latticeshield vk-share` instead of `scp`
