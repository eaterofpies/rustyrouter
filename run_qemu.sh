#!/bin/bash
# run_qemu.sh - Boot the router system in QEMU based on built target architecture

if [ ! -f "target/pi_boot/pi_initramfs.cpio.gz" ] || [ ! -f "target/rustyrouter.img" ]; then
    echo "Staged boot files not found. Please run 'make image' first."
    exit 1
fi

if [ -f "target/pi_boot/kernel8.img" ]; then
    echo "Booting router in QEMU AArch64 (Pi 3)..."
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
elif [ -f "target/pi_boot/kernel.img" ]; then
    echo "Booting router in QEMU ARM32 (Pi Zero W / raspi2b emulation)..."
    qemu-system-arm \
        -M raspi2b \
        -m 1024 \
        -kernel target/pi_boot/kernel.img \
        -dtb target/pi_boot/bcm2708-rpi-zero-w.dtb \
        -initrd target/pi_boot/pi_initramfs.cpio.gz \
        -drive file=target/rustyrouter.img,if=sd,format=raw \
        -device usb-net,netdev=lan0 \
        -netdev user,id=lan0 \
        -append "console=ttyAMA0,115200 root=/dev/ram0 rdinit=/init quiet net.ifnames=0 dwc_otg.lpm_enable=0 dwc_otg.fiq_enable=0 dwc_otg.fiq_fsm_enable=0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24" \
        -nographic
else
    echo "No valid Raspberry Pi kernel found in target/pi_boot/."
    exit 1
fi
