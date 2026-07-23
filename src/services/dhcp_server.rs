use super::utils::{
    get_interface_mac, open_raw_socket, parse_dhcp_payload, read_raw_packet, send_raw_packet,
};
use crate::packet::build_raw_packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use std::collections::HashMap;
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

    let mut leases: HashMap<MacAddr, ClientLease> = HashMap::new();

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
    leases: &mut HashMap<MacAddr, ClientLease>,
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
    leases: &mut HashMap<MacAddr, ClientLease>,
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

fn handle_dhcp_decline(client_mac: MacAddr, leases: &mut HashMap<MacAddr, ClientLease>) {
    if let Some(lease) = leases.remove(&client_mac) {
        println!(
            "[dhcp-server] Received DHCPDECLINE from client MAC: {}. Removed lease for IP: {}.",
            client_mac, lease.ip
        );
    }
}

fn handle_dhcp_release(client_mac: MacAddr, leases: &mut HashMap<MacAddr, ClientLease>) {
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
    leases: &mut HashMap<MacAddr, ClientLease>,
) {
    println!(
        "[dhcp-server] Received DHCPDISCOVER from client MAC: {}",
        client_mac
    );

    let leased_ip = match get_or_allocate_ip(client_mac, leases, config.net, config.server_ip) {
        Some(ip) => ip,
        None => {
            eprintln!("[dhcp-server] DHCP IP pool exhausted!");
            return;
        }
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
    leases: &mut HashMap<MacAddr, ClientLease>,
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
    leases: &HashMap<MacAddr, ClientLease>,
) -> bool {
    if leased_ip == config.server_ip || !config.net.contains(&leased_ip) {
        return false;
    }
    !leases.iter().any(|(mac, l)| {
        l.ip == leased_ip && l.expiry > Instant::now() && *mac != client_mac
    })
}

fn get_or_allocate_ip(
    client_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
    net: ipnet::Ipv4Net,
    server_ip: Ipv4Addr,
) -> Option<Ipv4Addr> {
    if let Some(lease) = leases.get(&client_mac) {
        return Some(lease.ip);
    }

    let ip = net.hosts().filter(|&ip| ip != server_ip).find(|&ip| {
        !leases
            .values()
            .any(|l| l.ip == ip && l.expiry > Instant::now())
    })?;

    leases.insert(
        client_mac,
        ClientLease {
            ip,
            expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
        },
    );
    Some(ip)
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

    #[test]
    fn test_get_or_allocate_ip_basic() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = HashMap::new();
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);

        // 1. First allocation
        let ip1 = get_or_allocate_ip(client1, &mut leases, net, server_ip);
        assert!(ip1.is_some());
        let ip1 = ip1.unwrap();
        assert_ne!(ip1, server_ip);
        assert!(net.hosts().any(|h| h == ip1));

        // 2. Subsequent allocation for same client should return same IP
        let ip2 = get_or_allocate_ip(client1, &mut leases, net, server_ip);
        assert_eq!(ip2, Some(ip1));
        assert_eq!(leases.len(), 1);

        // 3. Different client should get a different IP
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip3 = get_or_allocate_ip(client2, &mut leases, net, server_ip);
        assert!(ip3.is_some());
        let ip3 = ip3.unwrap();
        assert_ne!(ip3, ip1);
        assert_ne!(ip3, server_ip);
    }

    #[test]
    fn test_get_or_allocate_ip_exhaustion() {
        // A /30 subnet has 4 IPs: .0 (net), .1 (host), .2 (host), .3 (broadcast)
        // Usable hosts: .1, .2
        // If server_ip is .1, then only .2 is available!
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = HashMap::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let ip1 = get_or_allocate_ip(client1, &mut leases, net, server_ip);
        assert_eq!(ip1, Some(Ipv4Addr::new(192, 168, 1, 2)));

        // Try to allocate for a second client — pool is exhausted
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip2 = get_or_allocate_ip(client2, &mut leases, net, server_ip);
        assert_eq!(ip2, None);
    }

    #[test]
    fn test_handle_decline_and_release() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = HashMap::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let ip = get_or_allocate_ip(client, &mut leases, net, server_ip).unwrap();
        assert_eq!(leases.len(), 1);

        handle_dhcp_decline(client, &mut leases);
        assert_eq!(leases.len(), 0);

        let ip2 = get_or_allocate_ip(client, &mut leases, net, server_ip).unwrap();
        assert_eq!(ip2, ip);
        assert_eq!(leases.len(), 1);

        handle_dhcp_release(client, &mut leases);
        assert_eq!(leases.len(), 0);
    }

    #[test]
    fn test_validate_requested_ip_rejects_server_ip() {
        let config = make_config("192.168.1.1/24");
        let leases = HashMap::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(!validate_requested_ip(
            config.server_ip,
            client,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_rejects_out_of_subnet() {
        let config = make_config("192.168.1.1/24");
        let leases = HashMap::new();
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
        let mut leases = HashMap::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 2);

        // client1 holds a live lease on the IP
        leases.insert(
            client1,
            ClientLease {
                ip: contested_ip,
                expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
            },
        );

        // client2 should not be allowed to claim it
        assert!(!validate_requested_ip(
            contested_ip,
            client2,
            &config,
            &leases
        ));

        // but client1 renewing its own lease is allowed
        assert!(validate_requested_ip(
            contested_ip,
            client1,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_accepts_valid() {
        let config = make_config("192.168.1.1/24");
        let leases = HashMap::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(validate_requested_ip(
            Ipv4Addr::new(192, 168, 1, 100),
            client,
            &config,
            &leases
        ));
    }
}
