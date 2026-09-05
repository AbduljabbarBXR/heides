#!/usr/bin/env bash
# HEIDES installer.
# Download the release binary for this platform and put it on PATH.
#   curl -fsSL https://raw.githubusercontent.com/AbduljabbarBXR/heides/main/scripts/install.sh | bash
#   HEIDES_VERSION=0.6.0 curl -fsSL ... | bash
set -euo pipefail

REPO="AbduljabbarBXR/heides"
VERSION="${HEIDES_VERSION:-latest}"
BIN_DIR="${HEIDES_BIN_DIR:-$HOME/.local/bin}"

detect() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  if [ "$(uname -o 2>/dev/null)" = "Android" ]; then
    if [ "$arch" != "aarch64" ] && [ "$arch" != "arm64" ]; then
      echo "unsupported android arch $arch" >&2; exit 1
    fi
    ASSET="heides-aarch64-linux-android"
    return
  fi
  case "$os" in
    linux) os="unknown-linux-gnu" ;;
    darwin) os="apple-darwin" ;;
    mingw*|msys*|cygwin*) os="pc-windows-msvc" ;;
    *) echo "unsupported os $os" >&2; exit 1 ;;
  esac
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) echo "unsupported arch $arch" >&2; exit 1 ;;
  esac
  ASSET="heides-$arch-$os"
  if [ "$os" = "pc-windows-msvc" ]; then
    ASSET="$ASSET.exe"
  fi
}

url_for() {
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/$REPO/releases/latest/download/$ASSET"
  else
    echo "https://github.com/$REPO/releases/download/v$VERSION/$ASSET"
  fi
}

main() {
  detect
  mkdir -p "$BIN_DIR"
  local dest="$BIN_DIR/heides"
  echo "fetching $ASSET"
  curl -fsSL "$(url_for)" -o "$dest.tmp"
  chmod +x "$dest.tmp"
  mv "$dest.tmp" "$dest"
  echo "installed to $dest"
  "$dest" version
  echo
  echo "Add $BIN_DIR to PATH if it is missing, then register the MCP server in your agent."
}

main
