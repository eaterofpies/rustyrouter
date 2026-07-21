use super::utils::{SharedWanLease, WanLease, get_interface_mac};
use futures_util::TryStreamExt;
use nix::sys::socket::{setsockopt, sockopt};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket as StdUdpSocket;
use tokio::net::UdpSocket;

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
        last_sent: std::time::Instant,
        retry_delay_secs: u32,
    },
    Bound {
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        server_ip: Option<Ipv4Addr>,
        lease_secs: u32,
        bound_at: std::time::Instant,
        renew_sent: Option<std::time::Instant>,
        renew_xid: u32,
    },
}

struct DhcpClient {
    socket: UdpSocket,
    mac: MacAddr,
    lease_state: SharedWanLease,
    wan_interface: String,
}

impl DhcpClient {
    fn new(
        socket: UdpSocket,
        mac: MacAddr,
        lease_state: SharedWanLease,
        wan_interface: String,
    ) -> Self {
        Self {
            socket,
            mac,
            lease_state,
            wan_interface,
        }
    }

    async fn run(&self) {
        let mut state = ClientState::Discovering {
            xid: rand::random::<u32>(),
            last_sent: std::time::Instant::now() - std::time::Duration::from_secs(10),
            retry_delay_secs: 4,
        };
        let mut buf = [0u8; 2048];

        loop {
            self.handle_state_tick(&mut state).await;

            let read_res = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                self.socket.recv_from(&mut buf),
            )
            .await;

            let bytes_read = match read_res {
                Ok(Ok((n, _src_addr))) => n,
                Ok(Err(_)) => break, // Socket error, recreate socket
                Err(_) => continue,  // Timeout, tick again
            };

            self.handle_incoming_packet(bytes_read, &buf, &mut state)
                .await;
        }
    }

    async fn handle_state_tick(&self, state: &mut ClientState) {
        match state {
            ClientState::Discovering {
                xid,
                last_sent,
                retry_delay_secs,
            } => {
                let threshold = get_jittered_duration(*retry_delay_secs);
                if last_sent.elapsed() >= threshold {
                    self.send_discover(*xid).await;
                    *last_sent = std::time::Instant::now();
                    *retry_delay_secs = calculate_next_delay(*retry_delay_secs);
                }
            }
            ClientState::Requesting {
                xid,
                offered_ip,
                server_ip,
                last_sent,
                retry_delay_secs,
            } => {
                let threshold = get_jittered_duration(*retry_delay_secs);
                if last_sent.elapsed() >= threshold {
                    self.send_request(
                        *xid,
                        *offered_ip,
                        *server_ip,
                        Ipv4Addr::UNSPECIFIED,
                        Ipv4Addr::BROADCAST,
                    )
                    .await;
                    *last_sent = std::time::Instant::now();
                    *retry_delay_secs = calculate_next_delay(*retry_delay_secs);
                }
            }
            ClientState::Bound {
                ip,
                mask,
                gateway: _,
                server_ip,
                lease_secs,
                bound_at,
                renew_sent,
                renew_xid,
            } => {
                let elapsed = bound_at.elapsed().as_secs() as u32;
                if elapsed >= *lease_secs {
                    println!("[dhcp-client] Lease expired!");
                    if let Err(e) = deconfigure_wan(&self.wan_interface, *ip, *mask).await {
                        println!(
                            "[dhcp-client] ERROR: Failed to deconfigure WAN interface via netlink: {}",
                            e
                        );
                    }
                    let mut lease = self.lease_state.lock().unwrap();
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
                    self.handle_renewal_tick(
                        *ip,
                        *server_ip,
                        elapsed,
                        *lease_secs,
                        rebinding_threshold_secs,
                        *renew_xid,
                        renew_sent,
                    )
                    .await;
                }
            }
        }
    }

    async fn handle_renewal_tick(
        &self,
        ip: Ipv4Addr,
        server_ip: Option<Ipv4Addr>,
        elapsed: u32,
        lease_secs: u32,
        rebinding_threshold_secs: u32,
        renew_xid: u32,
        renew_sent: &mut Option<std::time::Instant>,
    ) {
        let in_rebinding = elapsed >= rebinding_threshold_secs;
        let (retry_interval, dest_ip) = if in_rebinding {
            let remaining_to_expiry = lease_secs.saturating_sub(elapsed);
            let interval = std::cmp::max(remaining_to_expiry / 2, 60);
            (interval, Ipv4Addr::BROADCAST)
        } else {
            let remaining_to_rebinding = rebinding_threshold_secs.saturating_sub(elapsed);
            let interval = std::cmp::max(remaining_to_rebinding / 2, 60);
            (interval, server_ip.unwrap_or(Ipv4Addr::BROADCAST))
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
            self.send_request(renew_xid, ip, None, ip, dest_ip).await;
            *renew_sent = Some(std::time::Instant::now());
        }
    }

    async fn handle_incoming_packet(
        &self,
        bytes_read: usize,
        buf: &[u8; 2048],
        state: &mut ClientState,
    ) {
        use dhcproto::v4::Message;
        use dhcproto::{Decodable, Decoder};

        let dhcp = match Message::decode(&mut Decoder::new(&buf[..bytes_read])) {
            Ok(d) => d,
            Err(_) => return,
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

        if msg_type == dhcproto::v4::MessageType::Offer
            && let ClientState::Discovering { xid, .. } = state
        {
            let offered_ip = dhcp.yiaddr();
            let server_ip = get_server_identifier(&dhcp);
            println!(
                "[dhcp-client] Received DHCPOFFER for IP: {}, server: {:?}",
                offered_ip, server_ip
            );
            *state = ClientState::Requesting {
                xid: *xid,
                offered_ip,
                server_ip,
                last_sent: std::time::Instant::now() - std::time::Duration::from_secs(10),
                retry_delay_secs: 4,
            };
        }

        if msg_type == dhcproto::v4::MessageType::Ack {
            self.handle_ack_received(dhcp, state).await;
        }
    }

    async fn handle_ack_received(&self, dhcp: dhcproto::v4::Message, state: &mut ClientState) {
        println!("[dhcp-client] Received DHCPACK!");
        let (mask, gateway, dns_servers, lease_secs) = parse_lease_options(&dhcp);
        let ip = dhcp.yiaddr();
        let server_ip = get_server_identifier(&dhcp);

        // Check if we need to configure/reconfigure
        let changed = {
            let mut lease = self.lease_state.lock().unwrap();
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
            }
            changed
        };

        if changed && let Err(e) = configure_wan(&self.wan_interface, ip, mask, gateway).await {
            println!(
                "[dhcp-client] ERROR: Failed to configure WAN interface via netlink: {}",
                e
            );
        }

        *state = ClientState::Bound {
            ip,
            mask,
            gateway,
            server_ip,
            lease_secs,
            bound_at: std::time::Instant::now(),
            renew_sent: None,
            renew_xid: rand::random::<u32>(),
        };
    }

    async fn send_discover(&self, xid: u32) {
        use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
        use dhcproto::{Encodable, Encoder};

        let mut discover = Message::default();
        discover.set_opcode(Opcode::BootRequest);
        discover.set_xid(xid);
        discover.set_flags(Flags::default().set_broadcast());
        discover.set_chaddr(&self.mac.octets());

        discover
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        discover
            .opts_mut()
            .insert(DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
            ]));

        let mut discover_payload = Vec::new();
        if let Err(e) = discover.encode(&mut Encoder::new(&mut discover_payload)) {
            println!(
                "[dhcp-client] ERROR: Failed to encode DHCPDISCOVER payload: {}",
                e
            );
            return;
        }

        if let Err(e) = self
            .socket
            .send_to(&discover_payload, "255.255.255.255:67")
            .await
        {
            println!("[dhcp-client] ERROR: Failed to send DHCPDISCOVER: {}", e);
        } else {
            println!("[dhcp-client] Sent DHCPDISCOVER.");
        }
    }

    async fn send_request(
        &self,
        xid: u32,
        requested_ip: Ipv4Addr,
        server_ip: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) {
        use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode};
        use dhcproto::{Encodable, Encoder};

        let mut request = Message::default();
        request.set_opcode(Opcode::BootRequest);
        request.set_xid(xid);
        request.set_ciaddr(ciaddr);
        request.set_chaddr(&self.mac.octets());

        if ciaddr.is_unspecified() {
            request.set_flags(Flags::default().set_broadcast());
            request
                .opts_mut()
                .insert(DhcpOption::RequestedIpAddress(requested_ip));
            if let Some(srv) = server_ip {
                request.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
            }
        }

        request
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));

        let mut req_payload = Vec::new();
        if let Err(e) = request.encode(&mut Encoder::new(&mut req_payload)) {
            println!(
                "[dhcp-client] ERROR: Failed to encode DHCPREQUEST payload: {}",
                e
            );
            return;
        }

        let dest_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(dest_ip, 67));
        if let Err(e) = self.socket.send_to(&req_payload, dest_addr).await {
            println!("[dhcp-client] ERROR: Failed to send DHCPREQUEST: {}", e);
        } else {
            println!(
                "[dhcp-client] Sent DHCPREQUEST (ciaddr: {}, dest_ip: {}).",
                ciaddr, dest_ip
            );
        }
    }
}

// =========================================================================
// DHCP Client (WAN) - helper functions
// =========================================================================
pub async fn start_dhcp_client(wan_interface: String, lease_state: SharedWanLease) {
    println!(
        "[dhcp-client] Starting WAN DHCP client on {}...",
        wan_interface
    );

    let mac = match get_interface_mac(&wan_interface).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "[dhcp-client] ERROR: Failed to get MAC address for {}: {}",
                wan_interface, e
            );
            return;
        }
    };
    println!(
        "[dhcp-client] Interface {} MAC address: {}",
        wan_interface, mac
    );

    loop {
        // Create standard UDP socket (completely standard socket, no raw socket at all!)
        let socket = match make_client_socket(&wan_interface) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[dhcp-client] ERROR: Failed to create client socket: {}. Retrying in 5s...",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let client = DhcpClient::new(socket, mac, lease_state.clone(), wan_interface.clone());
        client.run().await;
        println!("[dhcp-client] Socket closed or client loop exited. Restarting in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

fn calculate_next_delay(current_delay: u32) -> u32 {
    let doubled = current_delay * 2;
    if doubled > 64 { 64 } else { doubled }
}

fn get_jittered_duration(base_secs: u32) -> std::time::Duration {
    let jitter = (rand::random::<f64>() * 2.0) - 1.0;
    let secs = base_secs as f64 + jitter;
    std::cmp::max(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs_f64(secs),
    )
}

async fn deconfigure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix_len = mask.octets().iter().map(|&x| x.count_ones()).sum::<u32>() as u8;
    println!(
        "[dhcp-client] Deconfiguring WAN interface via netlink: removing IP {}/{}",
        ip, prefix_len
    );

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(wan_interface.to_string())
        .execute();
    let link = match links.try_next().await? {
        Some(l) => l,
        None => return Err(format!("Interface {} not found", wan_interface).into()),
    };
    let index = link.header.index;

    // Filter and delete the matching address
    let mut addresses = handle.address().get().execute();
    while let Some(addr) = addresses.try_next().await? {
        if addr.header.index == index {
            let mut matches_ip = false;
            for nla in addr.attributes.iter() {
                if let rtnetlink::packet_route::address::AddressAttribute::Local(ip_attr) = nla
                    && ip_attr == &std::net::IpAddr::V4(ip)
                {
                    matches_ip = true;
                    break;
                }
            }
            if matches_ip {
                let _ = handle.address().del(addr).execute().await;
            }
        }
    }
    Ok(())
}

async fn configure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prefix_len = mask.octets().iter().map(|&x| x.count_ones()).sum::<u32>() as u8;
    println!(
        "[dhcp-client] Configuring WAN interface via netlink: IP={}/{}, Gateway={:?}",
        ip, prefix_len, gateway
    );

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(wan_interface.to_string())
        .execute();
    let link = match links.try_next().await? {
        Some(l) => l,
        None => return Err(format!("Interface {} not found", wan_interface).into()),
    };
    let index = link.header.index;

    // Flush existing addresses on WAN first
    let mut addresses = handle.address().get().execute();
    while let Some(addr) = addresses.try_next().await? {
        if addr.header.index == index {
            let _ = handle.address().del(addr).execute().await;
        }
    }

    // Set link state UP (if not already)
    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    // Add new IP
    handle
        .address()
        .add(index, std::net::IpAddr::V4(ip), prefix_len)
        .execute()
        .await?;

    // Add default route
    if let Some(gw) = gateway {
        let route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
            .gateway(gw)
            .output_interface(index)
            .build();
        let _ = handle.route().add(route).execute().await;
    }

    Ok(())
}

fn get_server_identifier(dhcp: &dhcproto::v4::Message) -> Option<Ipv4Addr> {
    match dhcp.opts().get(dhcproto::v4::OptionCode::ServerIdentifier) {
        Some(dhcproto::v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

fn parse_lease_options(
    dhcp: &dhcproto::v4::Message,
) -> (Ipv4Addr, Option<Ipv4Addr>, Vec<Ipv4Addr>, u32) {
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

fn make_client_socket(interface_name: &str) -> std::io::Result<UdpSocket> {
    // Bind to 0.0.0.0 because the client doesn't have an IP address yet.
    let std_socket = StdUdpSocket::bind("0.0.0.0:68")?;

    // Allow broadcast on the interface
    setsockopt(&std_socket, sockopt::Broadcast, &true).map_err(std::io::Error::from)?;

    // Bind to the physical interface (e.g. "eth0") to rx packets where the packet doesn't match the interface IP
    setsockopt(
        &std_socket,
        sockopt::BindToDevice,
        &interface_name.to_string().into(),
    )
    .map_err(std::io::Error::from)?;

    // Bypass kernel routing tables for unconfigured interfaces
    setsockopt(&std_socket, sockopt::DontRoute, &true).map_err(std::io::Error::from)?;

    // Set the socket to non-blocking mode for tokio
    std_socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(std_socket)?;
    Ok(socket)
}
