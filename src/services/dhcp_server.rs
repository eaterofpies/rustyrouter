use super::utils::{
    get_interface_mac, open_raw_socket, parse_dhcp_payload, read_raw_packet, send_raw_packet,
};
use crate::packet::build_raw_packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

const LAN_LEASE_SECS: u32 = 3600;
const SERVER_RESTART_DELAY_SECS: u64 = 5;

// =========================================================================
// DHCP Server (LAN)
// =========================================================================
#[derive(Debug, Clone)]
struct ClientLease {
    ip: Ipv4Addr,
    expiry: Instant,
}

/// Encapsulates the lease map and IP allocation index as a single unit.
///
/// Both fields are private. All mutations go through methods on this struct,
/// so the two data structures are guaranteed to remain consistent: an IP is
/// always in `allocated_ips` if and only if there is a corresponding entry
/// in `by_mac`.
struct LeaseTable {
    by_mac: HashMap<MacAddr, ClientLease>,
    /// O(1) index of currently allocated IPs. Always kept in sync with `by_mac`.
    allocated_ips: HashSet<Ipv4Addr>,
}

impl LeaseTable {
    fn new() -> Self {
        Self {
            by_mac: HashMap::new(),
            allocated_ips: HashSet::new(),
        }
    }

    /// Returns the active lease for this MAC address, if one exists.
    fn get(&self, mac: &MacAddr) -> Option<&ClientLease> {
        self.by_mac.get(mac)
    }

    /// Inserts or replaces the lease for `mac`, updating the IP index atomically.
    fn insert(&mut self, mac: MacAddr, lease: ClientLease) {
        // If this MAC already has a lease, release its old IP from the index.
        if let Some(old) = self.by_mac.get(&mac) {
            self.allocated_ips.remove(&old.ip);
        }
        self.allocated_ips.insert(lease.ip);
        self.by_mac.insert(mac, lease);
    }

    /// Removes the lease for `mac` and updates the IP index atomically.
    /// Returns the removed lease, or `None` if no lease existed.
    fn remove(&mut self, mac: &MacAddr) -> Option<ClientLease> {
        let lease = self.by_mac.remove(mac)?;
        self.allocated_ips.remove(&lease.ip);
        Some(lease)
    }

    /// Returns `true` if `ip` is not currently held by any client.
    fn is_ip_available(&self, ip: Ipv4Addr) -> bool {
        !self.allocated_ips.contains(&ip)
    }

    /// Returns `true` if `ip` is actively leased to a MAC *other* than `client_mac`.
    fn is_ip_taken_by_other(&self, ip: Ipv4Addr, client_mac: MacAddr) -> bool {
        self.by_mac.iter().any(|(mac, l)| {
            l.ip == ip && l.expiry > Instant::now() && *mac != client_mac
        })
    }

    /// Finds the first available host IP in `net`, excluding `server_ip`.
    fn next_available_ip(&self, net: ipnet::Ipv4Net, server_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        net.hosts()
            .find(|&ip| ip != server_ip && self.is_ip_available(ip))
    }

    /// Number of active leases. Used in tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_mac.len()
    }
}

/// Fixed server configuration derived from the LAN interface at startup.
/// Passed by reference throughout the server loop to avoid repeating
/// individual fields as function arguments.
struct ServerConfig {
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    server_mac: MacAddr,
    net: ipnet::Ipv4Net,
}

async fn setup_server_socket(
    lan_interface: &str,
) -> Result<(MacAddr, RawFd, AsyncFd<RawFd>), String> {
    let mac = get_interface_mac(lan_interface)
        .await
        .map_err(|e| format!("Failed to get MAC address: {}", e))?;
    let raw_fd =
        open_raw_socket(lan_interface).map_err(|e| format!("Failed to open raw socket: {}", e))?;
    let async_sock = AsyncFd::new(raw_fd).map_err(|e| {
        unsafe {
            libc::close(raw_fd);
        }
        format!("Failed to wrap raw socket: {}", e)
    })?;
    Ok((mac, raw_fd, async_sock))
}

pub async fn start_dhcp_server(lan_interface: String, lan_ip: String) {
    println!(
        "[dhcp-server] Starting LAN DHCP server on {}...",
        lan_interface
    );

    // Invalid LAN config is a hard failure — do not silently fall back to a default.
    let net: ipnet::Ipv4Net = match lan_ip.parse() {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "[dhcp-server] ERROR: Invalid LAN IP configuration '{}': {}. Aborting.",
                lan_ip, e
            );
            return;
        }
    };

    let server_ip = net.addr();
    let subnet_mask = net.netmask();

    let start_ip = Ipv4Addr::from(u32::from(net.network()) + 1);
    let end_ip = Ipv4Addr::from(u32::from(net.broadcast()) - 1);
    println!(
        "[dhcp-server] Dynamic lease pool: {} to {}",
        start_ip, end_ip
    );

    let mut leases = LeaseTable::new();

    loop {
        let (mac, raw_fd, async_sock) = match setup_server_socket(&lan_interface).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!(
                    "[dhcp-server] ERROR: {}. Retrying in {}s...",
                    e, SERVER_RESTART_DELAY_SECS
                );
                tokio::time::sleep(Duration::from_secs(SERVER_RESTART_DELAY_SECS)).await;
                continue;
            }
        };

        let config = ServerConfig {
            server_ip,
            subnet_mask,
            server_mac: mac,
            net,
        };

        run_server_loop(&async_sock, &config, &mut leases).await;

        unsafe {
            libc::close(raw_fd);
        }
        println!(
            "[dhcp-server] Socket closed. Restarting server loop in {}s...",
            SERVER_RESTART_DELAY_SECS
        );
        tokio::time::sleep(Duration::from_secs(SERVER_RESTART_DELAY_SECS)).await;
    }
}

async fn run_server_loop(
    async_sock: &AsyncFd<RawFd>,
    config: &ServerConfig,
    leases: &mut LeaseTable,
) {
    let mut buf = [0u8; 2048];
    loop {
        let bytes_read = match read_raw_packet(async_sock, &mut buf).await {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[dhcp-server] Socket read error: {}. Recreating socket.", e);
                break;
            }
        };

        process_incoming_packet(bytes_read, &buf, async_sock, config, leases).await;
    }
}

async fn process_incoming_packet(
    bytes_read: usize,
    buf: &[u8; 2048],
    async_sock: &AsyncFd<RawFd>,
    config: &ServerConfig,
    leases: &mut LeaseTable,
) {
    let dhcp = match parse_dhcp_payload(&buf[..bytes_read], dhcproto::v4::SERVER_PORT) {
        Some(d) => d,
        None => return,
    };

    if dhcp.opcode() != dhcproto::v4::Opcode::BootRequest {
        return;
    }

    let chaddr = dhcp.chaddr();
    let client_mac = match <[u8; 6]>::try_from(&chaddr[..dhcp.hlen() as usize]) {
        Ok(bytes) => MacAddr::from(bytes),
        Err(_) => return,
    };

    // Server-side anti-spoofing MAC check
    let eth = match EthernetPacket::new(&buf[..bytes_read]) {
        Some(e) => e,
        None => return,
    };
    let src_mac = eth.get_source();
    if dhcp.giaddr().is_unspecified() && src_mac != client_mac {
        eprintln!(
            "[dhcp-server] WARNING: Dropping spoofed DHCP packet: L2 source MAC ({}) does not match chaddr ({})!",
            src_mac, client_mac
        );
        return;
    }

    let msg_type = match dhcp.opts().get(dhcproto::v4::OptionCode::MessageType) {
        Some(dhcproto::v4::DhcpOption::MessageType(mtype)) => *mtype,
        _ => return,
    };

    match msg_type {
        dhcproto::v4::MessageType::Discover => {
            handle_dhcp_discover(async_sock, config, &dhcp, client_mac, leases).await;
        }
        dhcproto::v4::MessageType::Request => {
            handle_dhcp_request(async_sock, config, &dhcp, client_mac, leases).await;
        }
        dhcproto::v4::MessageType::Decline => {
            handle_dhcp_decline(client_mac, leases);
        }
        dhcproto::v4::MessageType::Release => {
            handle_dhcp_release(client_mac, leases);
        }
        _ => {}
    }
}

fn handle_dhcp_decline(client_mac: MacAddr, leases: &mut LeaseTable) {
    if let Some(lease) = leases.remove(&client_mac) {
        println!(
            "[dhcp-server] Received DHCPDECLINE from client MAC: {}. Removed lease for IP: {}.",
            client_mac, lease.ip
        );
    }
}

fn handle_dhcp_release(client_mac: MacAddr, leases: &mut LeaseTable) {
    if let Some(lease) = leases.remove(&client_mac) {
        println!(
            "[dhcp-server] Received DHCPRELEASE from client MAC: {}. Released lease for IP: {}.",
            client_mac, lease.ip
        );
    }
}

/// Builds and encodes the common DHCPOFFER / DHCPACK payload, differing only
/// in `msg_type`. Returns the encoded bytes or an error string.
fn build_dhcp_reply_payload(
    msg_type: dhcproto::v4::MessageType,
    dhcp: &dhcproto::v4::Message,
    leased_ip: Ipv4Addr,
    config: &ServerConfig,
) -> Result<Vec<u8>, String> {
    use dhcproto::v4::{DhcpOption, Message, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_xid(dhcp.xid());
    reply.set_flags(dhcp.flags());
    reply.set_yiaddr(leased_ip);
    reply.set_siaddr(config.server_ip);
    reply.set_chaddr(dhcp.chaddr());

    reply.opts_mut().insert(DhcpOption::MessageType(msg_type));
    reply
        .opts_mut()
        .insert(DhcpOption::ServerIdentifier(config.server_ip));
    reply
        .opts_mut()
        .insert(DhcpOption::SubnetMask(config.subnet_mask));
    reply
        .opts_mut()
        .insert(DhcpOption::Router(vec![config.server_ip]));
    reply
        .opts_mut()
        .insert(DhcpOption::DomainNameServer(vec![config.server_ip]));
    reply
        .opts_mut()
        .insert(DhcpOption::AddressLeaseTime(LAN_LEASE_SECS));

    let mut payload = Vec::new();
    reply
        .encode(&mut Encoder::new(&mut payload))
        .map_err(|e| format!("Failed to encode DHCP reply: {}", e))?;
    Ok(payload)
}

async fn send_dhcp_nak(
    async_sock: &AsyncFd<RawFd>,
    dhcp: &dhcproto::v4::Message,
    client_mac: MacAddr,
    config: &ServerConfig,
) {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut nak = Message::default();
    nak.set_opcode(Opcode::BootReply);
    nak.set_xid(dhcp.xid());
    nak.set_chaddr(dhcp.chaddr());
    nak.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Nak));
    nak.opts_mut()
        .insert(DhcpOption::ServerIdentifier(config.server_ip));

    let mut payload = Vec::new();
    if let Err(e) = nak.encode(&mut Encoder::new(&mut payload)) {
        eprintln!("[dhcp-server] ERROR: Failed to encode DHCPNAK: {}", e);
        return;
    }

    let (dest_mac, dest_ip) =
        get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, Ipv4Addr::BROADCAST);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );
    send_raw_packet(async_sock, &frame).await;
}

async fn handle_dhcp_discover(
    async_sock: &AsyncFd<RawFd>,
    config: &ServerConfig,
    dhcp: &dhcproto::v4::Message,
    client_mac: MacAddr,
    leases: &mut LeaseTable,
) {
    println!(
        "[dhcp-server] Received DHCPDISCOVER from client MAC: {}",
        client_mac
    );

    // Re-offer the same IP if this client already has a lease.
    let leased_ip = if let Some(existing) = leases.get(&client_mac) {
        existing.ip
    } else {
        let Some(ip) = leases.next_available_ip(config.net, config.server_ip) else {
            eprintln!("[dhcp-server] DHCP IP pool exhausted!");
            return;
        };
        leases.insert(
            client_mac,
            ClientLease {
                ip,
                expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
            },
        );
        ip
    };

    let payload =
        match build_dhcp_reply_payload(dhcproto::v4::MessageType::Offer, dhcp, leased_ip, config)
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[dhcp-server] ERROR: {}", e);
                return;
            }
        };

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );

    send_raw_packet(async_sock, &frame).await;
    println!(
        "[dhcp-server] Sent DHCPOFFER of IP: {} to client.",
        leased_ip
    );
}

async fn handle_dhcp_request(
    async_sock: &AsyncFd<RawFd>,
    config: &ServerConfig,
    dhcp: &dhcproto::v4::Message,
    client_mac: MacAddr,
    leases: &mut LeaseTable,
) {
    use dhcproto::v4::{DhcpOption, OptionCode};

    println!(
        "[dhcp-server] Received DHCPREQUEST from client MAC: {}",
        client_mac
    );

    let requested_ip_opt = match dhcp.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };

    let leased_ip = if let Some(req_ip) = requested_ip_opt {
        req_ip
    } else if let Some(existing) = leases.get(&client_mac) {
        existing.ip
    } else {
        return;
    };

    if !validate_requested_ip(leased_ip, client_mac, config, leases) {
        eprintln!(
            "[dhcp-server] WARNING: Client {} requested invalid or conflicting IP {}. Sending NAK.",
            client_mac, leased_ip
        );
        send_dhcp_nak(async_sock, dhcp, client_mac, config).await;
        return;
    }

    leases.insert(
        client_mac,
        ClientLease {
            ip: leased_ip,
            expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
        },
    );

    let payload =
        match build_dhcp_reply_payload(dhcproto::v4::MessageType::Ack, dhcp, leased_ip, config) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[dhcp-server] ERROR: {}", e);
                return;
            }
        };

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );

    send_raw_packet(async_sock, &frame).await;
    println!("[dhcp-server] Sent DHCPACK of IP: {} to client.", leased_ip);
}

/// Returns true if `leased_ip` is valid for the requesting client:
/// - Within the server's subnet
/// - Not the server's own IP
/// - Not actively leased to a different MAC
fn validate_requested_ip(
    leased_ip: Ipv4Addr,
    client_mac: MacAddr,
    config: &ServerConfig,
    leases: &LeaseTable,
) -> bool {
    if leased_ip == config.server_ip || !config.net.contains(&leased_ip) {
        return false;
    }
    !leases.is_ip_taken_by_other(leased_ip, client_mac)
}

fn get_dest_mac_ip(
    broadcast: bool,
    client_mac: MacAddr,
    leased_ip: Ipv4Addr,
) -> (MacAddr, Ipv4Addr) {
    if broadcast {
        (MacAddr::broadcast(), Ipv4Addr::BROADCAST)
    } else {
        (client_mac, leased_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(cidr: &str) -> ServerConfig {
        let net: ipnet::Ipv4Net = cidr.parse().unwrap();
        ServerConfig {
            server_ip: net.addr(),
            subnet_mask: net.netmask(),
            server_mac: MacAddr::new(0, 0, 0, 0, 0, 1),
            net,
        }
    }

    fn allocate(leases: &mut LeaseTable, mac: MacAddr, net: ipnet::Ipv4Net, server_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        if let Some(existing) = leases.get(&mac) {
            return Some(existing.ip);
        }
        let ip = leases.next_available_ip(net, server_ip)?;
        leases.insert(mac, ClientLease {
            ip,
            expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
        });
        Some(ip)
    }

    #[test]
    fn test_lease_table_basic_allocation() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);

        // First allocation
        let ip1 = allocate(&mut leases, client1, net, server_ip);
        assert!(ip1.is_some());
        let ip1 = ip1.unwrap();
        assert_ne!(ip1, server_ip);
        assert!(net.hosts().any(|h| h == ip1));
        assert!(!leases.is_ip_available(ip1));

        // Same client gets same IP
        let ip2 = allocate(&mut leases, client1, net, server_ip);
        assert_eq!(ip2, Some(ip1));
        assert_eq!(leases.len(), 1);

        // Different client gets a different IP
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip3 = allocate(&mut leases, client2, net, server_ip);
        assert!(ip3.is_some());
        let ip3 = ip3.unwrap();
        assert_ne!(ip3, ip1);
        assert_ne!(ip3, server_ip);
        assert!(!leases.is_ip_available(ip3));
    }

    /// Simulates the discover allocation path from `handle_dhcp_discover`:
    /// check existing lease first, only scan for a new IP if none exists.
    fn discover_ip(
        leases: &mut LeaseTable,
        mac: MacAddr,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        if let Some(existing) = leases.get(&mac) {
            return Some(existing.ip);
        }
        let ip = leases.next_available_ip(net, server_ip)?;
        leases.insert(mac, ClientLease {
            ip,
            expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
        });
        Some(ip)
    }

    /// Regression test for the bug where a re-discovering client was allocated
    /// a fresh IP instead of having its existing lease re-offered.
    ///
    /// Before the fix, `next_available_ip` was called first. When the pool was
    /// not exhausted this returned a *different* IP, and `LeaseTable::insert`
    /// would evict the old lease and assign the new one — meaning a client's
    /// IP changed on every DISCOVER.
    #[test]
    fn test_discover_reoffers_existing_lease_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        // First DISCOVER: allocates an IP from the (non-exhausted) pool.
        let ip_first = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert_ne!(ip_first, server_ip);
        assert_eq!(leases.len(), 1);

        // Second DISCOVER from the same client: must return the *same* IP,
        // not a new one, even though free IPs are available in the pool.
        let ip_second = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert_eq!(ip_second, ip_first, "re-DISCOVER must re-offer the same IP");

        // The lease table must still contain exactly one entry.
        assert_eq!(leases.len(), 1);

        // The originally allocated IP must still be marked as taken.
        assert!(!leases.is_ip_available(ip_first));
    }

    /// Ensures that when the pool is fully exhausted an existing client's
    /// DISCOVER still succeeds (re-offer), while a new client gets None.
    #[test]
    fn test_discover_exhausted_pool_reoffers_existing_client() {
        // /30: only .2 is available (server is .1)
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();

        let existing_client = MacAddr::new(1, 2, 3, 4, 5, 6);
        let new_client     = MacAddr::new(1, 2, 3, 4, 5, 7);

        // Allocate the only available IP to the existing client.
        let ip = discover_ip(&mut leases, existing_client, net, server_ip).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 2));

        // Pool is now exhausted — a new client must get None.
        assert_eq!(discover_ip(&mut leases, new_client, net, server_ip), None);

        // The existing client must still get its IP re-offered.
        let ip_reoffered = discover_ip(&mut leases, existing_client, net, server_ip).unwrap();
        assert_eq!(ip_reoffered, ip, "existing client must be re-offered its lease IP even when pool is exhausted");
    }

    #[test]
    fn test_lease_table_pool_exhaustion() {
        // /30: usable hosts are .1 and .2; server_ip is .1, so only .2 is available
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let ip1 = allocate(&mut leases, client1, net, server_ip);
        assert_eq!(ip1, Some(Ipv4Addr::new(192, 168, 1, 2)));

        // Pool exhausted for a second client
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip2 = allocate(&mut leases, client2, net, server_ip);
        assert_eq!(ip2, None);
    }

    #[test]
    fn test_lease_table_remove_frees_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let ip = allocate(&mut leases, client, net, server_ip).unwrap();
        assert!(!leases.is_ip_available(ip));

        // Decline removes the lease and frees the IP atomically
        handle_dhcp_decline(client, &mut leases);
        assert_eq!(leases.len(), 0);
        assert!(leases.is_ip_available(ip));

        // Re-allocation returns the same IP
        let ip2 = allocate(&mut leases, client, net, server_ip).unwrap();
        assert_eq!(ip2, ip);
        assert_eq!(leases.len(), 1);

        // Release also frees the IP atomically
        handle_dhcp_release(client, &mut leases);
        assert_eq!(leases.len(), 0);
        assert!(leases.is_ip_available(ip));
    }

    #[test]
    fn test_validate_requested_ip_rejects_server_ip() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(!validate_requested_ip(config.server_ip, client, &config, &leases));
    }

    #[test]
    fn test_validate_requested_ip_rejects_out_of_subnet() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(!validate_requested_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            client,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_rejects_conflicting_lease() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 2);

        leases.insert(client1, ClientLease {
            ip: contested_ip,
            expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
        });

        // Another client cannot claim it
        assert!(!validate_requested_ip(contested_ip, client2, &config, &leases));
        // But the owning client can renew it
        assert!(validate_requested_ip(contested_ip, client1, &config, &leases));
    }

    #[test]
    fn test_validate_requested_ip_accepts_valid() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(validate_requested_ip(
            Ipv4Addr::new(192, 168, 1, 100),
            client,
            &config,
            &leases
        ));
    }
}
