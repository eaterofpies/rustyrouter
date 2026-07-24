#!/bin/bash
set -e

# =========================================================================
# QEMU Interactive Test Runner (Supports all architectures)
# =========================================================================
# Detect target architecture (defaults to x86_64)
ARCH=${ARCH:-x86_64}

# Ensure the kernel is downloaded and the initramfs archive is compiled
make target/${ARCH}/initramfs.cpio.gz ARCH=${ARCH}

KERNEL="target/${ARCH}/test_boot/vmlinuz"
INITRAMFS="target/${ARCH}/initramfs.cpio.gz"

if [ ! -f "$KERNEL" ]; then
    echo "[qemu] ERROR: Kernel image not found at $KERNEL."
    exit 1
fi

echo "[qemu] Booting interactive router VM for ${ARCH}..."
echo "Press Ctrl+A then X to exit QEMU"
echo "===================================================="

if [ "$ARCH" = "x86_64" ]; then
    exec qemu-system-x86_64 \
      -m 256 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -append "console=ttyS0 quiet panic=-1 net.ifnames=0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24" \
      -netdev user,id=wan0,net=10.0.2.0/24 \
      -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=lan0,net=192.168.1.0/24 \
      -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
      -nographic
elif [ "$ARCH" = "arm64" ]; then
    exec qemu-system-aarch64 \
      -M virt \
      -cpu cortex-a53 \
      -m 256 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -append "console=ttyAMA0 quiet panic=-1 net.ifnames=0 rustyrouter.wan=eth1 rustyrouter.lan=eth0 rustyrouter.lan_ip=192.168.1.1/24" \
      -netdev user,id=wan0,net=10.0.2.0/24 \
      -device virtio-net-device,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=lan0,net=192.168.1.0/24 \
      -device virtio-net-device,netdev=lan0,mac=52:54:00:12:34:57 \
      -nographic
elif [ "$ARCH" = "armhf" ]; then
    exec qemu-system-arm \
      -M virt \
      -cpu cortex-a7 \
      -m 256 \
      -kernel "$KERNEL" \
      -initrd "$INITRAMFS" \
      -append "console=ttyAMA0 quiet panic=-1 net.ifnames=0 rustyrouter.wan=eth1 rustyrouter.lan=eth0 rustyrouter.lan_ip=192.168.1.1/24" \
      -netdev user,id=wan0,net=10.0.2.0/24 \
      -device virtio-net-device,netdev=wan0,mac=52:54:00:12:34:56 \
      -netdev user,id=lan0,net=192.168.1.0/24 \
      -device virtio-net-device,netdev=lan0,mac=52:54:00:12:34:57 \
      -nographic
else
    echo "[qemu] ERROR: Unsupported architecture: $ARCH"
    exit 1
fi
