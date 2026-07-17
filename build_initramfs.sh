#!/bin/bash
set -e

# =========================================================================
# Initramfs Builder Script (Runs inside Container)
# =========================================================================
# This script compiles rustyrouter statically and packages it as an initramfs.
# =========================================================================

echo "[build] Ensuring x86_64-unknown-linux-musl target is installed..."
rustup target add x86_64-unknown-linux-musl

echo "[build] Compiling rustyrouter (Static MUSL Release)..."
cargo build --release --target x86_64-unknown-linux-musl

BINARY="target/x86_64-unknown-linux-musl/release/rustyrouter"
if [ ! -f "$BINARY" ]; then
    echo "[build] ERROR: Compilation failed, binary not found."
    exit 1
fi

echo "[build] Creating initramfs archive..."
STAGING=$(mktemp -d -t rustyrouter-staging-XXXXXX)
trap 'rm -rf "$STAGING"' EXIT

# Copy the binary to the staging folder as 'init'
cp "$BINARY" "$STAGING/init"
chmod +x "$STAGING/init"

# Create essential mount point directories
mkdir -p "$STAGING/proc"
mkdir -p "$STAGING/sys"
mkdir -p "$STAGING/dev"
mkdir -p "$STAGING/run"

# Pack the staging folder into the cpio archive
INITRAMFS_OUT="target/initramfs.cpio.gz"
mkdir -p target
(cd "$STAGING" && find . -print0 | cpio --null -ov --format=newc | gzip -9 > "$OLDPWD/$INITRAMFS_OUT")

echo "[build] Initramfs archived successfully at: $INITRAMFS_OUT"
