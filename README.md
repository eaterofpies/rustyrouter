# rustyrouter

`rustyrouter` is a lightweight, self-contained NATting router written in Rust, designed to run as the initialization process (PID 1) in a minimalist Linux container or virtual machine. 

It manages virtual filesystems, signal forwarding, orphan reaping, and launches an asynchronous network controller managing routing, firewall, and local network services without requiring any userspace helper utilities (such as `ip`, `iptables`, or `dnsmasq`).

---

## Warning & Disclaimer
> [!WARNING]
> **DO NOT TRUST OR USE THIS SOFTWARE IN PRODUCTION.**
> This project is an experimental prototype and learning exercise. It has not undergone formal security audits. Under no circumstances should this software be trusted to secure any real-world networks or production systems.

---

## Key Features

- **Init Process (PID 1)**: Mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`), reaps orphaned processes, handles termination signals, and monitors ACPI power button events to gracefully power down the virtual machine.
- **Kernel-Space NAT & Routing**: Interacts directly with the Linux kernel using Netlink sockets (`NETLINK_ROUTE` and `NETLINK_NETFILTER`) to manage interface states, IP assignments, default routes, and Source NAT (Masquerading).
- **Stateful Firewall**: Implements an `nftables` input filter chain that drops all unsolicited incoming traffic on the WAN interface by default.
- **Embedded Network Services**:
  - **DHCP Client (WAN)**: Handles dynamic leases and unicast renewals on the WAN interface over raw sockets.
  - **DHCP Server (LAN)**: Manages LAN lease allocations, address conflicts, and lease release/decline requests.
  - **DNS Forwarder/Proxy (LAN)**: Listens for DNS queries on the LAN interface and forwards them to the dynamic DNS servers obtained from the WAN lease.

---

## Getting Started

### Prerequisites

You need a Rust toolchain and the target `x86_64-unknown-linux-musl` installed:
```bash
rustup target add x86_64-unknown-linux-musl
```
You will also need `cpio`, `qemu-system-x86_64`, and standard build utilities (`make`, `gcc`).

### Building and Packaging

Compile the static release binary and package it into a compressed `cpio` initramfs archive:
```bash
make
```
This generates `target/initramfs.cpio.gz` which contains the statically linked `rustyrouter` binary mapped to `/init` and required Linux kernel modules.

### Testing

#### 1. Integration Test Suite
To run the automated integration tests that boot the target image inside a micro-QEMU VM to verify routing and services:
```bash
cargo test
```

#### 2. Interactive QEMU Emulation
To boot the image interactively inside QEMU and inspect console output:
```bash
make qemu
```
*Press `Ctrl+A` then `X` to exit the QEMU console.*
