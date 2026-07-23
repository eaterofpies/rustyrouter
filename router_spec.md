# Specification: `rustyrouter`

`rustyrouter` is a lightweight, self-contained Rust application designed to run as the initialization process (PID 1) in a minimalist Linux container or virtual machine. It acts as a basic NATting router, providing essential network services (DHCP client/server, DNS forwarding, and IP masquerading) while performing standard init process duties. 

Crucially, **no other files** will be present on the target filesystem other than the Linux kernel and this binary (statically linked). It requires zero external helper utilities (no `iptables`, `nft`, `ip`, `dnsmasq`, `udev`, etc.) and configures itself via kernel command line parameters or automatic interface detection.

---

## 1. System Architecture

The application is designed to run exclusively as the initialization process (PID 1) in a minimalist Linux environment (such as a container or virtual machine). It manages virtual filesystems, signal forwarding, orphan reaping, and launches the asynchronous network controller managing the routing and network services.

```
             [ Start ]
                 │
                 ▼
         [ Init Manager ] ──────────────► [ Orphan Reaper Loop ]
   (Mount VFS, Parse /proc/cmdline)       (Continuous zombie collection)
                 │
                 ▼
     [ Network Initialization ]
      (Enable IPv4 Forwarding)
                 │
                 ▼
       [ Service Controller ]
        ├── DHCP WAN Client (Raw AF_PACKET)
        ├── DHCP LAN Server (Raw AF_PACKET)
        ├── DNS Forwarder (Tokio UDP)
        └── NAT/Netlink Controller
```

---

## 2. Core Requirements

### 2.1 PID 1 (Init) Responsibilities
When running as PID 1:
1. **Virtual Filesystem (VFS) Mounting**:
   - Mount `/proc` (procfs)
   - Mount `/sys` (sysfs)
   - Mount `/dev` (devtmpfs) to access terminal and network devices.
   - Mount `/run` (tmpfs) for transient runtime state.
2. **Signal Handling**:
   - Standard init process signal masking/handling.
   - Traps system termination and shutdown signals (`SIGINT`, `SIGTERM`, `SIGPWR`).
   - Upon receiving any of these signals (e.g. from a supervisor request or direct kill), triggers a clean system shutdown: cleans up Netfilter tables, brings network interface links down, and reboots with poweroff mode (`nix::sys::reboot::reboot(RebootMode::RB_POWER_OFF)`).
3. **Orphan Reaping**:
   - Run a non-blocking or asynchronous reaping loop using `waitpid` to prevent zombie processes.
4. **Configuration Extraction**:
   - Read and parse `/proc/cmdline` to extract network settings (e.g., `rustyrouter.wan=eth0`, `rustyrouter.lan=eth1`, `rustyrouter.lan_ip=192.168.1.1`).
   - If not provided, automatically detect network interfaces (e.g., sort available interfaces and treat the first as WAN and the second as LAN).
5. **Panic & Unrecoverable Error Handling**:
   - Registers a custom panic hook (`std::panic::set_hook`) to intercept Rust panics.
   - If a panic or unrecoverable error occurs, logs the traceback or error message directly to `stdout`.
   - Programmatically triggers a system reboot using the `reboot` system call (via `nix::sys::reboot::reboot(RebootMode::RB_AUTOBOOT)`) to reboot the system rather than exiting (which would cause an unclean kernel panic).
6. **Logging Destination**:
   - Prints all logs and diagnostics directly to standard output/error (`stdout`/`stderr`). Since the kernel maps the console stream to `/dev/console`, the logs print directly into the host's QEMU monitor/serial console.
7. **ACPI Power Button Monitor (evdev)**:
   - Because a minimal initramfs does not run an ACPI daemon (like `acpid`) or a system manager (like `systemd-logind`), the kernel's ACPI poweroff interrupts are not handled by default.
   - To catch QEMU ACPI `system_powerdown` events, the init process actively monitors input nodes `/dev/input/event0` to `/dev/input/event4` (populated automatically by the kernel via `devtmpfs`).
   - It utilizes the portable `evdev` crate's asynchronous event stream API to filter for the standard `KEY_POWER` key-down event, triggering a clean system shutdown and hardware power-off.

### 2.2 Routing, Address, & NAT Configuration (Kernel-Space)

`rustyrouter` relies entirely on the Linux kernel for IP packet routing, forwarding, and connection tracking (NAT/Masquerade). It configures the kernel programmatically using Netlink sockets, requiring no external file dependencies or helper binaries.

#### 2.2.1 IP Forwarding
To allow packets to pass between the interfaces, `rustyrouter` enables IPv4 forwarding in the kernel at startup:
- Writes `"1"` to `/proc/sys/net/ipv4/ip_forward`.

#### 2.2.2 Netlink Interface & Route Management (`NETLINK_ROUTE`)
Using a routing Netlink socket (the standard `rtnetlink` interface), `rustyrouter` performs the following operations asynchronously:
1. **Loopback Interface (`lo`)**:
   - Resolves the index of `lo` and sets its link state to `UP` (equivalent to `ip link set lo up`). The IP address `127.0.0.1/8` is automatically assigned to loopback by the kernel.
2. **LAN Interface Link & Address**:
   - Sets the LAN interface link state to `UP`.
   - Clears existing IP addresses on the LAN interface.
   - Assigns the static IP address (e.g., `192.168.1.1/24`) and adds the subnet route to the routing table.
3. **WAN Interface Link**:
   - Sets the WAN interface link state to `UP`.
4. **Dynamic WAN Routing & Lease Expiry (via DHCP)**:
   - **Lease Obtained**: When the WAN DHCP client obtains a lease:
     - Assigns the leased IP address to the WAN interface (e.g., `10.0.2.15/24`).
     - **Subnet Collision Avoidance**: Compares the leased WAN IP network with the default LAN subnet configuration. If the WAN IP belongs to the LAN network (default `192.168.1.0/24`), `rustyrouter` reconfigures the LAN interface address to `192.168.0.1/24` (subnet `192.168.0.0/24`). If the WAN IP belongs to `192.168.0.0/24`, the LAN interface address shifts to `192.168.1.1/24`. If there is no conflict, it uses the configured default LAN IP (`192.168.1.1/24` or the value from cmdline).
     - Adds a default gateway route (`0.0.0.0/0` via the DHCP-provided gateway IP) on the WAN interface.
     - Automatically updates or replaces the default gateway route if the WAN lease changes.
   - **Lease Lost / Expired**: If the WAN DHCP client loses its lease or it expires:
     - Removes the assigned IP address from the WAN interface.
     - Deletes the default gateway route associated with that lease to prevent routing blackholes.

#### 2.2.3 Netfilter / nftables NAT Configuration (`NETLINK_NETFILTER`)
To enable Source NAT (Masquerading), `rustyrouter` communicates directly with the kernel's `nf_tables` subsystem over a netfilter Netlink socket. It constructs and sends standard netlink messages to build the following netfilter objects:
1. **Table**:
   - Creates a single IPv4 table named `rustyrouter` under the `ip` family.
2. **NAT Configuration (`nat_postrouting` chain)**:
   - Creates a chain named `nat_postrouting` in the `rustyrouter` table.
   - Configures the chain as a base chain of type `nat`, hooked to `postrouting` (`NF_INET_POST_ROUTING`), priority `100` (`NF_IP_PRI_NAT_SRC`), and default policy `accept`.
   - **Masquerade Rule**: Appends a rule matching outbound traffic on the WAN interface (e.g., matching the outgoing interface index `oif`) and targets `masquerade`.
3. **Firewall / Input Filter Configuration (`filter_input` chain)**:
   - Creates a chain named `filter_input` in the `rustyrouter` table.
   - Configures the chain as a base chain of type `filter`, hooked to `input` (`NF_INET_LOCAL_IN`), priority `0` (`NF_IP_PRI_FILTER`), and default policy `drop` (block all traffic by default).
   - **Input Rules**:
     - *Loopback Rule*: Accept all packets where the input interface (`iif`) is `lo`.
     - *LAN Rule*: Accept all packets where the input interface (`iif`) is the LAN interface (allows LAN clients to access DNS, DHCP, and route packets).
     - *Stateful Connection Rule*: Accept packets with connection-tracking state (`ct state`) equal to `established` or `related`. This allows inbound packets that are part of an outbound connection initiated by a LAN client or the router itself.
     - *Default Fallback*: All other unsolicited inbound packets (including all unsolicited traffic arriving on the WAN interface) are silently dropped.

---

### 2.3 Network Services (Embedded)
All services are implemented directly inside the `rustyrouter` binary using async tasks:
1. **DHCP Client (WAN)**:
   - Negotiates IP configuration with the upstream DHCP server using raw packet sockets (`AF_PACKET` / `SOCK_RAW`) bound directly to the WAN interface.
   - This bypasses the kernel TCP/IP stack to send broadcast DISCOVER/REQUEST packets and receive unicast/broadcast OFFER/ACK replies before the interface has an IP address assigned.
   - Parses the IP/UDP/DHCP headers in userspace.
   - Extracts network configurations: IP address, subnet mask, default gateway, and DNS servers (Option 6 of the DHCP lease).
   - Once negotiated, applies the allocated IP, subnet mask, and default gateway to the WAN interface via Netlink, and dynamically updates the DNS Forwarder with the leased DNS server IPs.
2. **DHCP Server (LAN)**:
   - Listens for client discovery packets on port 67 of the LAN interface.
   - Uses raw packet sockets (`AF_PACKET`) to unicast DHCP replies directly to the client's MAC address (since the client does not yet have an IP address and cannot respond to ARP).
   - **Lease Integrity & Eviction**: Manages an in-memory database of active leases using a synchronized `LeaseTable` module to ensure the lease map and IP allocation index remain aligned. Evicts expired leases automatically to reclaim IPs.
   - **Address Validation**: Rejects client requests that fall outside the LAN subnet, match the server's own IP, or conflict with another active lease (returns `DHCPNAK` on conflicts).
   - Hands out IPs to LAN clients, advertising `rustyrouter`'s LAN IP as the gateway and DNS resolver.
3. **DNS Forwarder**:
   - Listens on port 53 (UDP) on the LAN interface.
   - By default, forwards client DNS queries to the DNS server IPs dynamically obtained from the WAN interface's DHCP lease.
   - If no DNS servers are provided in the WAN DHCP lease, falls back to the static DNS servers specified on the kernel command line or a compile-time default (e.g., `8.8.8.8`).
   - **Cache Poisoning & Ephemeral Port Exhaustion Protections**: Uses a single, long-lived client UDP socket for all upstream queries instead of binding temporary ephemeral sockets per request. Generates unique, randomized transaction IDs and checks replies to match, fully rejecting spoofed packets with mismatched upstream source IPs to prevent Kaminsky-style cache poisoning.
   - **UDP Only**: Only UDP DNS proxying is supported. TCP DNS queries (including DNSSEC fallback) are unsupported.
4. **NTP Client (SNTP)**:
   - Synchronizes router system time periodically using SNTP (Simple Network Time Protocol) on UDP port 123 from `pool.ntp.org`.
   - Starts sync loop automatically after a WAN IP and DNS servers are acquired from the DHCP lease.
   - Updates the system clock using standard clock-setting system calls (`clock_settime` via the `nix` crate).
   - Retries with backoff on network failures and performs sync checks every 30 minutes.

### 2.4 Logging & Timestamps
- All standard output and error logs printed by `rustyrouter` must include a standardized timestamp prefix with millisecond resolution.
- Format: `[YYYY-MM-DD HH:MM:SS.mmm] [module] message` (e.g. `[2026-07-18 15:18:30.123] [init] Mounted /proc successfully.`).
---

## 3. Configuration & Startup Parameters

When running as PID 1, `rustyrouter` settings are read from `/proc/cmdline` (the kernel command line). 

Example parameters:
- `rustyrouter.wan=eth0` (Specify the WAN interface)
- `rustyrouter.lan=eth1` (Specify the LAN interface)
- `rustyrouter.lan_ip=192.168.1.1/24` (Specify the static LAN gateway IP and subnet)
- `rustyrouter.dns=8.8.8.8,1.1.1.1` (Optional static DNS resolver fallbacks)

If these parameters are missing or `/proc/cmdline` cannot be read, the router automatically detects the interfaces:
- Scans available interfaces and treats the first non-loopback ethernet-like interface as WAN.
- Treats the second as LAN.
- Defaults the LAN IP to `192.168.1.1/24`.

---

## 4. Technical Stack & Dependencies (Rust)

- **Asynchronous Runtime**: `tokio` (single-threaded executor with `rt`, `macros`, `net`, `time`, `io-util`).
- **System Calls & Signals**: `nix` (using features `mount`, `signal`, `process` to interface with the kernel directly).
- **Netlink / Routing**: `rtnetlink` (to manage link states, addresses, and route tables).
- **Netlink Firewall**: `netlink-packet-netfilter` combined with `netlink-sys` or a pure-Rust netlink wrapper to configure nftables without FFI/C dependencies.
- **DHCP Client & Server**: Raw packet sockets (`AF_PACKET` / `SOCK_RAW`) with a pure-Rust DHCP packet parser/builder.
- **DNS Resolver/Proxy**: Custom minimal UDP proxy forwarding to parsed WAN DNS addresses.

---

## 5. Compilation & Initramfs Packaging

Since `rustyrouter` runs in an environment with no other files, it must be compiled as a fully static binary.

### 5.1 Static Compilation
To ensure the binary does not depend on a dynamic interpreter (`ld-linux.so`) or host libraries (like `libc.so`, `libnftnl.so`, etc.), it must be compiled against the `musl` libc target:
```bash
# Install the MUSL target
rustup target add x86_64-unknown-linux-musl

# Build the static release binary
cargo build --release --target x86_64-unknown-linux-musl
```

Verify that the binary is statically linked:
```bash
file target/x86_64-unknown-linux-musl/release/rustyrouter
# Expected output contains: statically linked

ldd target/x86_64-unknown-linux-musl/release/rustyrouter
# Expected output: not a dynamic executable
```

### 5.2 QEMU-Based Testing & Verification Plan

To verify `rustyrouter`'s behavior as a real PID 1 init process, we boot it in QEMU alongside a second client VM connected over a virtual socket link.

#### 5.2.1 Initramfs Creation
1. Copy the statically compiled binary to a temporary staging folder as `init`:
   ```bash
   mkdir -p staging
   cp target/x86_64-unknown-linux-musl/release/rustyrouter staging/init
   chmod +x staging/init
   ```
2. Pack the directory into a gzipped cpio archive:
   ```bash
   cd staging
   find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
   cd ..
   ```

#### 5.2.2 Running the Router VM
We boot the router VM with two NICs:
*   **eth0 (WAN)**: Connected to QEMU's User Network (which runs a built-in DHCP server providing IP addresses in the `10.0.2.0/24` range and NATting traffic to the host's internet).
*   **eth1 (LAN)**: Connected to a local TCP socket listener (`127.0.0.1:1234`) acting as a virtual switch.

```bash
qemu-system-x86_64 \
  -kernel /path/to/vmlinuz \
  -initrd initramfs.cpio.gz \
  -append "console=ttyS0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24" \
  -netdev user,id=wan0,net=10.0.2.0/24 \
  -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
  -netdev socket,id=lan0,listen=127.0.0.1:1234 \
  -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
  -nographic
```

#### 5.2.3 Running the Client VM
To verify IP allocation, routing, and DNS resolution, boot a standard Linux distribution (e.g. Alpine) in a separate QEMU VM connected to the same socket switch:

```bash
qemu-system-x86_64 \
  -kernel /path/to/vmlinuz-client \
  -initrd /path/to/initramfs-client.img \
  -netdev socket,id=lan_cli,connect=127.0.0.1:1234 \
  -device virtio-net-pci,netdev=lan_cli,mac=52:54:00:12:34:58 \
  -nographic
```

Once booted, the client VM will:
1. Run a standard DHCP client on its interface, which receives an IP address (e.g. `192.168.1.100`), default gateway (`192.168.1.1`), and DNS resolver (`192.168.1.1`) from `rustyrouter`'s server.
2. Direct DNS queries to `192.168.1.1` (forwarded to the upstream gateway `10.0.2.2` by `rustyrouter`).
3. Send ICMP packets or TCP streams out to the Internet, which the kernel of `rustyrouter` NATs and forwards through `eth0`.

