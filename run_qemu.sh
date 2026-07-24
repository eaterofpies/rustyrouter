#!/bin/bash
# run_qemu.sh - Boot the router system in QEMU emulating a Raspberry Pi 3 Model B

# Ensure boot files have been staged first
if [ ! -f "target/pi_boot/pi_initramfs.cpio.gz" ] || [ ! -f "target/pi_boot/kernel8.img" ] || [ ! -f "target/rustyrouter.img" ]; then
    echo "Staged boot files not found. Please run 'make image' first."
    exit 1
fi

echo "Booting router in QEMU Raspi3b machine (press Ctrl+A then X to exit)..."

# Run QEMU with raspi3b machine, loading kernel/DTB/initrd, mounting SD card,
# and attaching a USB Ethernet adapter as eth1 (LAN). On-board Ethernet is eth0 (WAN).
qemu-system-aarch64 \
    -M raspi3b \
    -cpu cortex-a53 \
    -m 1024 \
    -kernel target/pi_boot/kernel8.img \
    -dtb target/pi_boot/bcm2710-rpi-3-b-plus.dtb \
    -initrd target/pi_boot/pi_initramfs.cpio.gz \
    -drive file=target/rustyrouter.img,if=sd,format=raw \
    -device usb-net,netdev=lan0 \
    -netdev user,id=lan0 \
    -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0 dwc_otg.lpm_enable=0 dwc_otg.fiq_enable=0 dwc_otg.fiq_fsm_enable=0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24" \
    -nographic
