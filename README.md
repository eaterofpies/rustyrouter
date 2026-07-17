# rustyrouter

`rustyrouter` is a lightweight, self-contained NATting router written in Rust, designed to run as the initialization process (PID 1) in a minimalist Linux container or virtual machine.

---

## Warning & Disclaimer
** DO NOT TRUST OR USE THIS SOFTWARE IN PRODUCTION.**

This project is an experimental prototype and learning exercise. It has not undergone security audits, lacks comprehensive error handling, and does not contain all standard security mitigations required for production-grade routing. Under no circumstances should this software be deployed on a real network or trusted to secure any systems.

---

## Key Features
- **Init Process (PID 1)**: Mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`), reaps orphaned processes, handles termination signals, and monitors `/dev/input/event*` via the `evdev` crate to gracefully poweroff the VM on ACPI power button events.
- **Kernel-Space NAT & Routing**: Interacts directly with the Linux kernel using Netlink sockets (`NETLINK_ROUTE` and `NETLINK_NETFILTER`) to manage interface states, IP assignments, default routes, and Source NAT (Masquerading).
- **Stateful Firewall**: Implements an `nftables` input filter chain that drops all unsolicited incoming traffic on the WAN interface by default.
- **Embedded Network Services**:
  - DHCP Client (WAN interface) over raw `AF_PACKET` sockets.
  - DHCP Server (LAN interface) over raw `AF_PACKET` sockets.
  - DNS Forwarder/Proxy (LAN interface) resolving queries using dynamic DNS server IPs obtained from the WAN DHCP lease.
