#!/bin/bash
set -e

# =========================================================================
# QEMU Test Runner Script (Runs on Host)
# =========================================================================
# This script boots the pre-compiled initramfs inside QEMU.
# It assumes target/initramfs.cpio.gz has already been built.
# =========================================================================

# Step 1: Detect/Assign Linux Kernel
KERNEL=""
if [ -n "$1" ]; then
    KERNEL="$1"
fi

if [ -z "$KERNEL" ]; then
    echo "[qemu] Searching for a local Linux kernel in /boot..."
    for k in /boot/vmlinuz-$(uname -r) /boot/vmlinuz-* /boot/vmlinux-*; do
        if [ -f "$k" ] && [[ ! "$k" =~ "rescue" ]] && [[ ! "$k" =~ "fallback" ]]; then
            KERNEL="$k"
            break
        fi
    done
fi

if [ -z "$KERNEL" ] || [ ! -f "$KERNEL" ]; then
    echo "[qemu] ERROR: Could not find a valid Linux kernel."
    echo "Please specify the path to a kernel image manually:"
    echo "  $0 /boot/vmlinuz-XYZ"
    exit 1
fi

echo "[qemu] Using Linux kernel: $KERNEL"

# Step 2: Ensure Initramfs is Built/Updated
INITRAMFS_OUT="target/initramfs.cpio.gz"
echo "[qemu] Ensuring initramfs is built and up-to-date..."
make "$INITRAMFS_OUT"

echo "[qemu] Booting QEMU VM (Ctrl+A then X to exit QEMU)..."
echo "===================================================="
qemu-system-x86_64 \
  -kernel "$KERNEL" \
  -initrd "$INITRAMFS_OUT" \
  -append "console=ttyS0 quiet panic=-1 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24" \
  -netdev user,id=wan0,net=10.0.2.0/24 \
  -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
  -netdev socket,id=lan0,listen=127.0.0.1:1234 \
  -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
  -nographic
