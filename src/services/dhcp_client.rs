use crate::packet::build_raw_packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use super::utils::{get_interface_mac, open_raw_socket, parse_dhcp_payload, SharedWanLease, WanLease};

#[derive(Debug, Clone, PartialEq)]
enum ClientState {
    Discovering {
        xid: u32,
        last_sent: std::time::Instant,
        retry_delay_secs: u32,
    },
    Requesting {
        xid: u32,
        offered_ip: Ipv4Addr,
        server_ip: Option<Ipv4Addr>,
        server_mac: MacAddr,
        last_sent: std::time::Instant,
        retry_delay_secs: u32,
    },
    Bound {
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        server_ip: Option<Ipv4Addr>,
        server_mac: MacAddr,
        lease_secs: u32,
        bound_at: std::time::Instant,
        renew_sent: Option<std::time::Instant>,
        renew_xid: u32,
    },
}

// =========================================================================
// DHCP Client (WAN)
// =========================================================================
pub async fn start_dhcp_client(
    wan_interface: String,
    lease_state: SharedWanLease,
) {
    println!("[dhcp-client] Starting WAN DHCP client on {}...", wan_interface);

    let mac = match get_interface_mac(&wan_interface).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[dhcp-client] ERROR: Failed to get MAC address for {}: {}", wan_interface, e);
            return;
        }
    };
    println!("[dhcp-client] Interface {} MAC address: {}", wan_interface, mac);

    loop {
        let raw_fd = match open_raw_socket(&wan_interface) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("[dhcp-client] ERROR: Failed to open raw socket: {}. Retrying in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let async_sock = match AsyncFd::new(raw_fd) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[dhcp-client] ERROR: Failed to wrap raw socket: {}. Retrying in 5s...", e);
                unsafe { libc::close(raw_fd); }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        run_client_loop(&async_sock, mac, &lease_state, &wan_interface).await;
        unsafe { libc::close(raw_fd); }
        println!("[dhcp-client] Socket closed. Restarting client loop in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn calculate_next_delay(current_delay: u32) -> u32 {
    let doubled = current_delay * 2;
    if doubled > 64 {
        64
    } else {
        doubled
    }
}

fn get_jittered_duration(base_secs: u32) -> std::time::Duration {
    let jitter = (rand::random::<f64>() * 2.0) - 1.0;
    let secs = base_secs as f64 + jitter;
    if secs < 1.0 {
        std::time::Duration::from_secs(1)
    } else {
        std::time::Duration::from_secs_f64(secs)
    }
}

async fn run_client_loop(
    async_sock: &AsyncFd<RawFd>,
    mac: MacAddr,
    lease_state: &SharedWanLease,
    wan_interface: &str,
) {
    let mut state = ClientState::Discovering {
        xid: rand::random::<u32>(),
        last_sent: std::time::Instant::now() - std::time::Duration::from_secs(10),
        retry_delay_secs: 4,
    };
    let mut buf = [0u8; 2048];

    loop {
        handle_state_tick(async_sock, mac, &mut state, lease_state, wan_interface).await;

        let read_res = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_raw_packet(async_sock, &mut buf)
        ).await;

        let bytes_read = match read_res {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break, // Socket error, recreate socket
            Err(_) => continue, // Timeout, tick again
        };

        handle_incoming_packet(bytes_read, &buf, &mut state, lease_state, wan_interface).await;
    }
}

async fn handle_state_tick(
    async_sock: &AsyncFd<RawFd>,
    mac: MacAddr,
    state: &mut ClientState,
    lease_state: &SharedWanLease,
    wan_interface: &str,
) {
    match state {
        ClientState::Discovering { xid, last_sent, retry_delay_secs } => {
            let threshold = get_jittered_duration(*retry_delay_secs);
            if last_sent.elapsed() >= threshold {
                send_discover(async_sock, mac, *xid).await;
                *last_sent = std::time::Instant::now();
                *retry_delay_secs = calculate_next_delay(*retry_delay_secs);
            }
        }
        ClientState::Requesting { xid, offered_ip, server_ip, server_mac: _, last_sent, retry_delay_secs } => {
            let threshold = get_jittered_duration(*retry_delay_secs);
            if last_sent.elapsed() >= threshold {
                send_request(
                    async_sock,
                    mac,
                    MacAddr::broadcast(),
                    *xid,
                    *offered_ip,
                    *server_ip,
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                ).await;
                *last_sent = std::time::Instant::now();
                *retry_delay_secs = calculate_next_delay(*retry_delay_secs);
            }
        }
        ClientState::Bound {
            ip,
            mask,
            gateway: _,
            server_ip,
            server_mac,
            lease_secs,
            bound_at,
            renew_sent,
            renew_xid,
        } => {
            let elapsed = bound_at.elapsed().as_secs() as u32;
            if elapsed >= *lease_secs {
                println!("[dhcp-client] Lease expired!");
                deconfigure_wan(wan_interface, *ip, *mask);
                let mut lease = lease_state.lock().unwrap();
                *lease = WanLease::default();
                *state = ClientState::Discovering {
                    xid: rand::random::<u32>(),
                    last_sent: std::time::Instant::now() - std::time::Duration::from_secs(10),
                    retry_delay_secs: 4,
                };
                return;
            }

            let renewal_threshold_secs = *lease_secs / 2;
            let rebinding_threshold_secs = (*lease_secs as f64 * 0.875) as u32;

            if elapsed >= renewal_threshold_secs {
                handle_renewal_tick(
                    async_sock,
                    mac,
                    *ip,
                    *server_ip,
                    *server_mac,
                    elapsed,
                    *lease_secs,
                    rebinding_threshold_secs,
                    *renew_xid,
                    renew_sent,
                ).await;
            }
        }
    }
}

async fn handle_renewal_tick(
    async_sock: &AsyncFd<RawFd>,
    mac: MacAddr,
    ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
    server_mac: MacAddr,
    elapsed: u32,
    lease_secs: u32,
    rebinding_threshold_secs: u32,
    renew_xid: u32,
    renew_sent: &mut Option<std::time::Instant>,
) {
    let in_rebinding = elapsed >= rebinding_threshold_secs;
    let (retry_interval, dest_mac, dest_ip) = if in_rebinding {
        let remaining_to_expiry = if lease_secs > elapsed { lease_secs - elapsed } else { 0 };
        let interval = if remaining_to_expiry > 60 { remaining_to_expiry / 2 } else { 60 };
        (interval, MacAddr::broadcast(), Ipv4Addr::BROADCAST)
    } else {
        let remaining_to_rebinding = rebinding_threshold_secs - elapsed;
        let interval = if remaining_to_rebinding > 60 { remaining_to_rebinding / 2 } else { 60 };
        (interval, server_mac, server_ip.unwrap_or(Ipv4Addr::BROADCAST))
    };

    let should_send = match renew_sent {
        None => true,
        Some(t) => t.elapsed().as_secs() as u32 >= retry_interval,
    };

    if should_send {
        if in_rebinding {
            println!("[dhcp-client] REBINDING: sending broadcast DHCPREQUEST...");
        } else {
            println!("[dhcp-client] RENEWING: sending unicast DHCPREQUEST to server...");
        }
        send_request(
            async_sock,
            mac,
            dest_mac,
            renew_xid,
            ip,
            None,
            ip,
            dest_ip,
        ).await;
        *renew_sent = Some(std::time::Instant::now());
    }
}

async fn handle_incoming_packet(
    bytes_read: usize,
    buf: &[u8; 2048],
    state: &mut ClientState,
    lease_state: &SharedWanLease,
    wan_interface: &str,
) {
    let dhcp = match parse_dhcp_payload(&buf[..bytes_read], dhcproto::v4::CLIENT_PORT) {
        Some(d) => d,
        None => return,
    };

    let expected_xid = match state {
        ClientState::Discovering { xid, .. } => *xid,
        ClientState::Requesting { xid, .. } => *xid,
        ClientState::Bound { renew_xid, .. } => *renew_xid,
    };

    if dhcp.xid() != expected_xid {
        return;
    }

    let msg_type = match dhcp.opts().get(dhcproto::v4::OptionCode::MessageType) {
        Some(dhcproto::v4::DhcpOption::MessageType(m)) => *m,
        _ => return,
    };

    let eth = pnet::packet::ethernet::EthernetPacket::new(&buf[..bytes_read]).unwrap();
    let server_mac = eth.get_source();

    if msg_type == dhcproto::v4::MessageType::Offer {
        if let ClientState::Discovering { xid, .. } = state {
            let offered_ip = dhcp.yiaddr();
            let server_ip = get_server_identifier(&dhcp);
            println!("[dhcp-client] Received DHCPOFFER for IP: {}, server: {:?}", offered_ip, server_ip);
            *state = ClientState::Requesting {
                xid: *xid,
                offered_ip,
                server_ip,
                server_mac,
                last_sent: std::time::Instant::now() - std::time::Duration::from_secs(10),
                retry_delay_secs: 4,
            };
        }
    }

    if msg_type == dhcproto::v4::MessageType::Ack {
        handle_ack_received(dhcp, server_mac, state, lease_state, wan_interface);
    }
}

fn handle_ack_received(
    dhcp: dhcproto::v4::Message,
    server_mac: MacAddr,
    state: &mut ClientState,
    lease_state: &SharedWanLease,
    wan_interface: &str,
) {
    println!("[dhcp-client] Received DHCPACK!");
    let (mask, gateway, dns_servers, lease_secs) = parse_lease_options(&dhcp);
    let ip = dhcp.yiaddr();
    let server_ip = get_server_identifier(&dhcp);

    // Check if we need to configure/reconfigure
    let mut lease = lease_state.lock().unwrap();
    let changed = lease.ip != Some(ip)
        || lease.mask != Some(mask)
        || lease.gateway != gateway
        || lease.dns_servers != dns_servers;

    if changed {
        lease.ip = Some(ip);
        lease.mask = Some(mask);
        lease.gateway = gateway;
        lease.dns_servers = dns_servers;
        println!("[dhcp-client] Lease parameters updated: {:?}", *lease);
        configure_wan(wan_interface, ip, mask, gateway);
    }

    *state = ClientState::Bound {
        ip,
        mask,
        gateway,
        server_ip,
        server_mac,
        lease_secs,
        bound_at: std::time::Instant::now(),
        renew_sent: None,
        renew_xid: rand::random::<u32>(),
    };
}

async fn send_discover(async_sock: &AsyncFd<RawFd>, mac: MacAddr, xid: u32) {
    use dhcproto::{Encoder, Encodable};
    use dhcproto::v4::{Message, DhcpOption, MessageType, OptionCode, Opcode, Flags};

    let mut discover = Message::default();
    discover.set_opcode(Opcode::BootRequest);
    discover.set_xid(xid);
    discover.set_flags(Flags::default().set_broadcast());
    discover.set_chaddr(&[mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]);
    
    discover.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
    discover.opts_mut().insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
    ]));

    let mut discover_payload = Vec::new();
    discover.encode(&mut Encoder::new(&mut discover_payload)).unwrap();

    let eth_frame = build_raw_packet(
        mac,
        MacAddr::broadcast(),
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        dhcproto::v4::CLIENT_PORT,
        dhcproto::v4::SERVER_PORT,
        &discover_payload,
    );

    send_raw_frame(async_sock, &eth_frame).await;
    println!("[dhcp-client] Sent DHCPDISCOVER.");
}

async fn send_request(
    async_sock: &AsyncFd<RawFd>,
    mac: MacAddr,
    dest_mac: MacAddr,
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
    ciaddr: Ipv4Addr,
    dest_ip: Ipv4Addr,
) {
    use dhcproto::{Encoder, Encodable};
    use dhcproto::v4::{Message, DhcpOption, MessageType, Opcode, Flags};

    let mut request = Message::default();
    request.set_opcode(Opcode::BootRequest);
    request.set_xid(xid);
    request.set_ciaddr(ciaddr);
    request.set_chaddr(&[mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]);

    if ciaddr.is_unspecified() {
        request.set_flags(Flags::default().set_broadcast());
        request.opts_mut().insert(DhcpOption::RequestedIpAddress(requested_ip));
        if let Some(srv) = server_ip {
            request.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
        }
    }

    request.opts_mut().insert(DhcpOption::MessageType(MessageType::Request));

    let mut req_payload = Vec::new();
    request.encode(&mut Encoder::new(&mut req_payload)).unwrap();

    let req_frame = build_raw_packet(
        mac,
        dest_mac,
        ciaddr,
        dest_ip,
        dhcproto::v4::CLIENT_PORT,
        dhcproto::v4::SERVER_PORT,
        &req_payload,
    );

    send_raw_frame(async_sock, &req_frame).await;
    println!("[dhcp-client] Sent DHCPREQUEST (ciaddr: {}, dest_ip: {}).", ciaddr, dest_ip);
}

fn deconfigure_wan(wan_interface: &str, ip: Ipv4Addr, mask: Ipv4Addr) {
    let prefix_len = mask.octets().iter().map(|&x| x.count_ones()).sum::<u32>() as u8;
    println!("[dhcp-client] Deconfiguring WAN interface: removing IP {}/{}", ip, prefix_len);
    let ip_cmd = format!("ip addr del {}/{} dev {}", ip, prefix_len, wan_interface);
    let _ = std::process::Command::new("sh").arg("-c").arg(&ip_cmd).status();
    let route_cmd = format!("ip route flush dev {}", wan_interface);
    let _ = std::process::Command::new("sh").arg("-c").arg(&route_cmd).status();
}

fn configure_wan(wan_interface: &str, ip: Ipv4Addr, mask: Ipv4Addr, gateway: Option<Ipv4Addr>) {
    let prefix_len = mask.octets().iter().map(|&x| x.count_ones()).sum::<u32>() as u8;
    println!("[dhcp-client] Configuring WAN interface: IP={}/{}, Gateway={:?}", ip, prefix_len, gateway);
    
    let flush_cmd = format!("ip addr flush dev {}", wan_interface);
    let _ = std::process::Command::new("sh").arg("-c").arg(&flush_cmd).status();

    let ip_cmd = format!("ip addr add {}/{} dev {}", ip, prefix_len, wan_interface);
    let _ = std::process::Command::new("sh").arg("-c").arg(&ip_cmd).status();

    if let Some(gw) = gateway {
        let route_cmd = format!("ip route add default via {} dev {}", gw, wan_interface);
        let _ = std::process::Command::new("sh").arg("-c").arg(&route_cmd).status();
    }
}

fn get_server_identifier(dhcp: &dhcproto::v4::Message) -> Option<Ipv4Addr> {
    match dhcp.opts().get(dhcproto::v4::OptionCode::ServerIdentifier) {
        Some(dhcproto::v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

fn parse_lease_options(dhcp: &dhcproto::v4::Message) -> (Ipv4Addr, Option<Ipv4Addr>, Vec<Ipv4Addr>, u32) {
    use dhcproto::v4::DhcpOption;
    use dhcproto::v4::OptionCode;

    let mask = match dhcp.opts().get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(m)) => *m,
        _ => Ipv4Addr::new(255, 255, 255, 0),
    };
    
    let gateway = match dhcp.opts().get(OptionCode::Router) {
        Some(DhcpOption::Router(routers)) if !routers.is_empty() => Some(routers[0]),
        _ => None,
    };

    let dns = match dhcp.opts().get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(list)) => list.clone(),
        _ => Vec::new(),
    };

    let lease_secs = match dhcp.opts().get(OptionCode::AddressLeaseTime) {
        Some(DhcpOption::AddressLeaseTime(t)) => *t,
        _ => 3600,
    };

    (mask, gateway, dns, lease_secs)
}

fn try_read_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::recv(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }) {
        Ok(res) => res.map(Some),
        Err(_would_block) => Ok(None),
    }
}

async fn read_raw_packet(async_sock: &AsyncFd<std::os::unix::io::RawFd>, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    loop {
        let mut guard = match async_sock.readable().await {
            Ok(g) => g,
            Err(e) => return Err(e),
        };

        match try_read_raw(&mut guard, buf) {
            Ok(Some(n)) => return Ok(n),
            Ok(None) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn try_write_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    frame: &[u8],
) -> Result<Option<isize>, std::io::Error> {
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::send(inner.as_raw_fd(), frame.as_ptr() as *const libc::c_void, frame.len(), 0)
        };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }) {
        Ok(res) => res.map(Some),
        Err(_would_block) => Ok(None),
    }
}

async fn send_raw_frame(async_sock: &AsyncFd<std::os::unix::io::RawFd>, frame: &[u8]) {
    loop {
        let mut guard = match async_sock.writable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        match try_write_raw(&mut guard, frame) {
            Ok(Some(_)) => break,
            Ok(None) => continue,
            Err(_) => break,
        }
    }
}
