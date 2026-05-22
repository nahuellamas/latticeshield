# Multi-stage Dockerfile for latticeshield-bridge
#
# Stage 1: Build a statically linked binary using musl libc.
# Stage 2: Copy the binary into a minimal distroless image.
#
# Build:
#   docker build -t latticeshield-bridge .
#
# Run (requires a config file and keypair):
#   docker run --rm \
#     -v /path/to/config.toml:/etc/latticeshield/config.toml:ro \
#     -v /path/to/keys:/keys:ro \
#     -e SIGNING_KEY_PATH=/keys/server.sk \
#     -p 8443:8443 \
#     latticeshield-bridge run --config /etc/latticeshield/config.toml

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl \
    --package latticeshield-bridge

# ── Stage 2: runtime (distroless static) ─────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder \
    /src/target/x86_64-unknown-linux-musl/release/latticeshield-bridge \
    /usr/local/bin/latticeshield-bridge

# PQC TCP listener (default)
EXPOSE 8443
# Standard TLS listener (optional)
EXPOSE 8440
# QUIC/UDP listener (optional)
EXPOSE 8441
# Admin PQC channel (optional)
EXPOSE 8445
# WebSocket listener (optional)
EXPOSE 8446
# Prometheus metrics
EXPOSE 9091

ENTRYPOINT ["/usr/local/bin/latticeshield-bridge"]
CMD ["run"]
