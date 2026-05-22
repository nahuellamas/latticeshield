# Multi-stage Dockerfile for latticeshield-bridge
#
# Stage 1 builder: Alpine-based rust image (musl libc by default, ~0 high CVEs
# in the toolchain layer at last check vs. ~23 high CVEs on rust:1.87-slim).
# Stage 2 runtime: distroless/static — no shell, no package manager, nonroot.
#
# Multi-arch: this Dockerfile builds natively for whichever platform docker is
# invoked on. For amd64 + arm64 in one shot use:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t latticeshield-bridge .
#
# Build (single-arch, local):
#   docker build -t latticeshield-bridge .
#
# Run (requires a config file and keypair):
#   docker run --rm \
#     -v /path/to/config.toml:/etc/latticeshield/config.toml:ro \
#     -v /path/to/keys:/keys:ro \
#     -e SIGNING_KEY_PATH=/keys/server.sk \
#     -p 8443:8443 \
#     latticeshield-bridge run --config /etc/latticeshield/config.toml

# ── Stage 1: builder (Alpine = musl by default → static binary ready for distroless) ─
FROM rust:1.87-alpine AS builder

# musl-dev for the C runtime headers; pkgconf because some -sys crates probe for it.
# cmake/make/perl are required by aws-lc-sys (transitive via rustls aws_lc_rs feature)
# to build the bundled AWS-LC C sources when no prebuilt is selected.
RUN apk add --no-cache \
    musl-dev \
    pkgconf \
    cmake \
    make \
    perl

WORKDIR /src
COPY . .

# Alpine's default Rust target is `<arch>-unknown-linux-musl` — no `--target` needed.
# Build only the bridge package so the dev-only integration-tests crate (which pulls
# prost-build → protoc) is skipped.
RUN cargo build --release --package latticeshield-bridge

# ── Stage 2: runtime (distroless static) ─────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder \
    /src/target/release/latticeshield-bridge \
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
