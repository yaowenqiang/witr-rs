#!/bin/sh
# witr-rs installer: downloads the release binary for this platform from
# GitHub Releases, verifies its sha256 and installs it to ~/.local/bin
# (override with WITR_INSTALL_DIR=/some/dir).
#
#   curl -fsSL https://raw.githubusercontent.com/yaowenqiang/witr-rs/main/install.sh | sh
#
# Windows: download witr-rs-x86_64-pc-windows-msvc.zip from Releases instead.
set -eu

REPO="yaowenqiang/witr-rs"
PREFIX="${WITR_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
    Darwin)
        case "$arch" in
            x86_64) target="x86_64-apple-darwin" ;;
            arm64 | aarch64) target="aarch64-apple-darwin" ;;
            *) echo "unsupported macOS architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    Linux)
        case "$arch" in
            x86_64) target="x86_64-unknown-linux-musl" ;;
            aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
            *) echo "unsupported Linux architecture: $arch" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "unsupported OS: $os — on Windows grab the .zip from https://github.com/$REPO/releases" >&2
        exit 1
        ;;
esac

asset="witr-rs-$target.tar.gz"
base="https://github.com/$REPO/releases/latest/download"

fetch() {
    # fetch URL DEST — curl or wget, whichever exists
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "need curl or wget to download" >&2
        exit 1
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $asset ..."
fetch "$base/$asset" "$tmp/$asset"

# releases carry a combined sha256sums.txt (per-asset .sha256 sidecars are
# not attached); either file works for verification
if fetch "$base/sha256sums.txt" "$tmp/sha256sums.txt" 2>/dev/null; then
    expected=$(grep " $asset\$" "$tmp/sha256sums.txt" | cut -d' ' -f1 | tr -d '[:space:]')
else
    echo "warning: checksum list unavailable, skipping verification"
    expected=""
fi
if [ -n "$expected" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
    else
        actual=""
        echo "warning: no sha256 tool found, skipping verification"
    fi
    if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
        echo "checksum mismatch!" >&2
        echo "  expected $expected" >&2
        echo "  actual   $actual" >&2
        exit 1
    fi
    [ -n "$actual" ] && echo "checksum ok"
fi

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$PREFIX"
install -m 755 "$tmp/witr-rs-$target/witr-rs" "$PREFIX/witr-rs"

case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) echo "note: $PREFIX is not on your PATH — add it to your shell rc" ;;
esac
echo "installed: $PREFIX/witr-rs ($("$PREFIX/witr-rs" --version 2>/dev/null || echo 'version unknown'))"
