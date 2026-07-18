use crate::packet::build_raw_packet;
use pnet::util::MacAddr;
use pnet::packet::ethernet::EthernetPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use super::utils::{get_interface_mac, open_raw_socket, parse_dhcp_payload, read_raw_packet, send_raw_packet};

// =========================================================================
// DHCP Server (LAN)
// =========================================================================
#[derive(Debug, Clone)]
struct ClientLease {
    ip: Ipv4Addr,
    expiry: Instant,
}

async fn setup_server_socket(lan_interface: &str) -> Result<(MacAddr, RawFd, AsyncFd<RawFd>), String> {
    let mac = get_interface_mac(lan_interface).await
        .map_err(|e| format!("Failed to get MAC address: {}", e))?;
    let raw_fd = open_raw_socket(lan_interface)
        .map_err(|e| format!("Failed to open raw socket: {}", e))?;
    let async_sock = AsyncFd::new(raw_fd)
        .map_err(|e| {
            unsafe { libc::close(raw_fd); }
            format!("Failed to wrap raw socket: {}", e)
        })?;
    Ok((mac, raw_fd, async_sock))
}

pub async fn start_dhcp_server(
    lan_interface: String,
    lan_ip: String,
) {
    println!("[dhcp-server] Starting LAN DHCP server on {}...", lan_interface);

    // Parse LAN IP (e.g. 192.168.1.1/24)
    let net: ipnet::Ipv4Net = lan_ip.parse().unwrap_or_else(|_| {
        "192.168.1.1/24".parse().unwrap()
    });
    let server_ip = net.addr();
    let subnet_mask = net.netmask();

    let start_ip = Ipv4Addr::from(u32::from(net.network()) + 1);
    let end_ip = Ipv4Addr::from(u32::from(net.broadcast()) - 1);
    println!("[dhcp-server] Dynamic lease pool: {} to {}", start_ip, end_ip);

    let mut leases: HashMap<MacAddr, ClientLease> = HashMap::new();

    loop {
        let (mac, raw_fd, async_sock) = match setup_server_socket(&lan_interface).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[dhcp-server] ERROR: {}. Retrying in 5s...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        run_server_loop(
            &async_sock,
            server_ip,
            subnet_mask,
            mac,
            &mut leases,
            net,
        ).await;

        unsafe { libc::close(raw_fd); }
        println!("[dhcp-server] Socket closed. Restarting server loop in 5s...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_server_loop(
    async_sock: &AsyncFd<RawFd>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
    net: ipnet::Ipv4Net,
) {
    let mut buf = [0u8; 2048];
    loop {
        let bytes_read = match read_raw_packet(async_sock, &mut buf).await {
            Ok(n) => n,
            Err(_) => break, // Socket error, recreate socket
        };

        process_incoming_packet(
            bytes_read,
            &buf,
            async_sock,
            server_ip,
            subnet_mask,
            mac,
            leases,
            net,
        ).await;
    }
}

async fn process_incoming_packet(
    bytes_read: usize,
    buf: &[u8; 2048],
    async_sock: &AsyncFd<RawFd>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    server_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
    net: ipnet::Ipv4Net,
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
        eprintln!("[dhcp-server] WARNING: Dropping spoofed DHCP packet: L2 source MAC ({}) does not match chaddr ({})!", src_mac, client_mac);
        return;
    }

    let msg_type = match dhcp.opts().get(dhcproto::v4::OptionCode::MessageType) {
        Some(dhcproto::v4::DhcpOption::MessageType(mtype)) => *mtype,
        _ => return,
    };

    match msg_type {
        dhcproto::v4::MessageType::Discover => {
            handle_dhcp_discover(
                async_sock,
                server_ip,
                subnet_mask,
                server_mac,
                &dhcp,
                client_mac,
                leases,
                net,
            ).await;
        }
        dhcproto::v4::MessageType::Request => {
            handle_dhcp_request(
                async_sock,
                server_ip,
                subnet_mask,
                server_mac,
                &dhcp,
                client_mac,
                leases,
            ).await;
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

fn handle_dhcp_decline(
    client_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
) {
    if let Some(lease) = leases.remove(&client_mac) {
        println!("[dhcp-server] Received DHCPDECLINE from client MAC: {}. Removed lease for IP: {}.", client_mac, lease.ip);
    }
}

fn handle_dhcp_release(
    client_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
) {
    if let Some(lease) = leases.remove(&client_mac) {
        println!("[dhcp-server] Received DHCPRELEASE from client MAC: {}. Released lease for IP: {}.", client_mac, lease.ip);
    }
}

async fn handle_dhcp_discover(
    async_sock: &AsyncFd<RawFd>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    server_mac: MacAddr,
    dhcp: &dhcproto::v4::Message,
    client_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
    net: ipnet::Ipv4Net,
) {
    use dhcproto::{Encoder, Encodable};
    use dhcproto::v4::{Message, DhcpOption, MessageType, Opcode};

    println!("[dhcp-server] Received DHCPDISCOVER from client MAC: {}", client_mac);

    let leased_ip = match get_or_allocate_ip(client_mac, leases, net, server_ip) {
        Some(ip) => ip,
        None => {
            eprintln!("[dhcp-server] DHCP IP pool exhausted!");
            return;
        }
    };

    let mut offer = Message::default();
    offer.set_opcode(Opcode::BootReply);
    offer.set_xid(dhcp.xid());
    offer.set_flags(dhcp.flags());
    offer.set_yiaddr(leased_ip);
    offer.set_siaddr(server_ip);
    offer.set_chaddr(dhcp.chaddr());

    offer.opts_mut().insert(DhcpOption::MessageType(MessageType::Offer));
    offer.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
    offer.opts_mut().insert(DhcpOption::SubnetMask(subnet_mask));
    offer.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
    offer.opts_mut().insert(DhcpOption::DomainNameServer(vec![server_ip]));
    offer.opts_mut().insert(DhcpOption::AddressLeaseTime(3600));

    let mut offer_payload = Vec::new();
    offer.encode(&mut Encoder::new(&mut offer_payload)).unwrap();

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);

    let offer_frame = build_raw_packet(
        server_mac,
        dest_mac,
        server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &offer_payload,
    );

    send_raw_packet(async_sock, &offer_frame).await;
    println!("[dhcp-server] Sent DHCPOFFER of IP: {} to client.", leased_ip);
}

async fn handle_dhcp_request(
    async_sock: &AsyncFd<RawFd>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    server_mac: MacAddr,
    dhcp: &dhcproto::v4::Message,
    client_mac: MacAddr,
    leases: &mut HashMap<MacAddr, ClientLease>,
) {
    use dhcproto::{Encoder, Encodable};
    use dhcproto::v4::{Message, DhcpOption, MessageType, OptionCode, Opcode};

    println!("[dhcp-server] Received DHCPREQUEST from client MAC: {}", client_mac);

    let requested_ip_opt = match dhcp.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };

    let leased_ip = if let Some(req_ip) = requested_ip_opt {
        req_ip
    } else if let Some(copy) = leases.get(&client_mac) {
        copy.ip
    } else {
        return;
    };

    leases.insert(client_mac, ClientLease {
        ip: leased_ip,
        expiry: Instant::now() + Duration::from_secs(3600),
    });

    let mut ack = Message::default();
    ack.set_opcode(Opcode::BootReply);
    ack.set_xid(dhcp.xid());
    ack.set_flags(dhcp.flags());
    ack.set_yiaddr(leased_ip);
    ack.set_siaddr(server_ip);
    ack.set_chaddr(dhcp.chaddr());

    ack.opts_mut().insert(DhcpOption::MessageType(MessageType::Ack));
    ack.opts_mut().insert(DhcpOption::ServerIdentifier(server_ip));
    ack.opts_mut().insert(DhcpOption::SubnetMask(subnet_mask));
    ack.opts_mut().insert(DhcpOption::Router(vec![server_ip]));
    ack.opts_mut().insert(DhcpOption::DomainNameServer(vec![server_ip]));
    ack.opts_mut().insert(DhcpOption::AddressLeaseTime(3600));

    let mut ack_payload = Vec::new();
    ack.encode(&mut Encoder::new(&mut ack_payload)).unwrap();

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);

    let ack_frame = build_raw_packet(
        server_mac,
        dest_mac,
        server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &ack_payload,
    );

    send_raw_packet(async_sock, &ack_frame).await;
    println!("[dhcp-server] Sent DHCPACK of IP: {} to client.", leased_ip);
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

    let ip = net.hosts()
        .filter(|&ip| ip != server_ip)
        .find(|&ip| !leases.values().any(|l| l.ip == ip && l.expiry > Instant::now()))?;

    leases.insert(client_mac, ClientLease {
        ip,
        expiry: Instant::now() + Duration::from_secs(3600),
    });
    Some(ip)
}

fn get_dest_mac_ip(broadcast: bool, client_mac: MacAddr, leased_ip: Ipv4Addr) -> (MacAddr, Ipv4Addr) {
    if broadcast {
        (MacAddr::broadcast(), Ipv4Addr::BROADCAST)
    } else {
        (client_mac, leased_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_or_allocate_ip_basic() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr(); // 192.168.1.1
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
        let server_ip = net.addr(); // 192.168.1.1
        let mut leases = HashMap::new();
        
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let ip1 = get_or_allocate_ip(client1, &mut leases, net, server_ip);
        assert_eq!(ip1, Some(Ipv4Addr::new(192, 168, 1, 2)));

        // Try to allocate for a second client
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip2 = get_or_allocate_ip(client2, &mut leases, net, server_ip);
        assert_eq!(ip2, None); // Exhausted!
    }

    #[test]
    fn test_handle_decline_and_release() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = HashMap::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        // Allocate
        let ip = get_or_allocate_ip(client, &mut leases, net, server_ip).unwrap();
        assert_eq!(leases.len(), 1);

        // Decline should remove lease
        handle_dhcp_decline(client, &mut leases);
        assert_eq!(leases.len(), 0);

        // Allocate again
        let ip2 = get_or_allocate_ip(client, &mut leases, net, server_ip).unwrap();
        assert_eq!(ip2, ip);
        assert_eq!(leases.len(), 1);

        // Release should remove lease
        handle_dhcp_release(client, &mut leases);
        assert_eq!(leases.len(), 0);
    }
}
