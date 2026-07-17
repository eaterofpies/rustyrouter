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

# Copy local modules directory if present
if [ -d "host/modules" ]; then
    echo "[build] Copying local kernel modules from host/modules/ to /lib/modules..."
    mkdir -p "$STAGING/lib/modules"
    cp -r host/modules/* "$STAGING/lib/modules/"
fi

# Find any kernel version installed in the container's /lib/modules
KVER=$(ls /lib/modules 2>/dev/null | head -n 1)
if [ -n "$KVER" ]; then
    echo "[build] Found container kernel modules for $KVER. Copying required drivers..."
    TARGET_DIR="$STAGING/lib/modules/$KVER"
    mkdir -p "$TARGET_DIR"
    
    MODULES=(
        "failover"
        "net_failover"
        "virtio_net"
        "nfnetlink"
        "libcrc32c"
        "nf_defrag_ipv4"
        "nf_defrag_ipv6"
        "nf_tables"
        "nf_conntrack"
        "nf_nat"
        "nft_ct"
        "nft_chain_nat"
        "nft_masq"
    )
    
    for mod in "${MODULES[@]}"; do
        found=$(find "/lib/modules/$KVER" -name "${mod}.ko" -o -name "${mod}.ko.zst" -o -name "${mod}.ko.xz" -o -name "${mod}.ko.gz" 2>/dev/null | head -n 1)
        if [ -n "$found" ]; then
            dest_file="$TARGET_DIR/${mod}.ko"
            if [[ "$found" == *.zst ]]; then
                zstd -d -c "$found" > "$dest_file"
            elif [[ "$found" == *.xz ]]; then
                xz -d -c "$found" > "$dest_file"
            elif [[ "$found" == *.gz ]]; then
                gunzip -c "$found" > "$dest_file"
            else
                cp "$found" "$dest_file"
            fi
            chmod 644 "$dest_file"
        fi
    done
fi

# Pack the staging folder into the cpio archive
INITRAMFS_OUT="target/initramfs.cpio.gz"
mkdir -p target
(cd "$STAGING" && find . -print0 | cpio --null -ov --format=newc | gzip -9 > "$OLDPWD/$INITRAMFS_OUT")

echo "[build] Initramfs archived successfully at: $INITRAMFS_OUT"
