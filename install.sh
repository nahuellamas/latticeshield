#!/usr/bin/env bash
set -euo pipefail

REPO="nahuellamas/latticeshield"
INSTALL_DIR="/usr/local/bin"
BINS=("latticeshield-bridge" "latticeshield-client" "latticeshield")

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

detect_target() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "${os}-${arch}" in
        Linux-x86_64)   echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64)  echo "aarch64-unknown-linux-gnu" ;;
        Darwin-x86_64)  echo "x86_64-apple-darwin" ;;
        Darwin-arm64)   echo "aarch64-apple-darwin" ;;
        *)
            error "Unsupported platform: ${os}-${arch}"
            error "Supported: Linux x86_64/aarch64, macOS x86_64/arm64"
            exit 1
            ;;
    esac
}

get_latest_tag() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

sha256_of() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "${file}" | awk '{print $1}'
    else
        shasum -a 256 "${file}" | awk '{print $1}'
    fi
}

verify_checksum() {
    local file="$1"
    local expected actual
    expected=$(grep "  ${file}$" checksums.txt | awk '{print $1}')
    if [[ -z "${expected}" ]]; then
        error "No checksum entry found for ${file} in checksums.txt"
        exit 1
    fi
    actual=$(sha256_of "${file}")
    if [[ "${expected}" != "${actual}" ]]; then
        error "Checksum mismatch for ${file}"
        error "  Expected: ${expected}"
        error "  Actual:   ${actual}"
        exit 1
    fi
}

install_bin() {
    local src="$1" dst="$2"
    if install -m 755 "${src}" "${dst}" 2>/dev/null; then
        return 0
    fi
    sudo install -m 755 "${src}" "${dst}"
}

main() {
    local target tag base_url tmpdir
    target=$(detect_target)

    info "Detected platform: ${target}"
    info "Fetching latest release tag..."
    tag=$(get_latest_tag)

    if [[ -z "${tag}" ]]; then
        error "Could not determine latest release tag. Check your internet connection."
        exit 1
    fi

    info "Installing LatticeShield ${tag}..."
    base_url="https://github.com/${REPO}/releases/download/${tag}"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "${tmpdir}"' EXIT
    cd "${tmpdir}"

    info "Downloading checksums.txt..."
    curl -fsSL "${base_url}/checksums.txt" -o checksums.txt

    for bin in "${BINS[@]}"; do
        local artifact="${bin}-${target}"
        info "Downloading ${bin}..."
        curl -fsSL "${base_url}/${artifact}" -o "${artifact}"

        info "Verifying checksum..."
        verify_checksum "${artifact}"

        info "Installing ${bin}..."
        install_bin "${artifact}" "${INSTALL_DIR}/${bin}"
        info "  ✓ ${INSTALL_DIR}/${bin}"
    done

    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo ""
        info "macOS: If Gatekeeper blocks the binaries, run:"
        for bin in "${BINS[@]}"; do
            echo "    xattr -d com.apple.quarantine ${INSTALL_DIR}/${bin}"
        done
    fi

    echo ""
    info "LatticeShield ${tag} installed successfully!"
    info "  latticeshield-bridge  → bridge proxy (server side)"
    info "  latticeshield-client  → client proxy (sidecar)"
    info "  latticeshield         → key management CLI"
}

main "$@"
