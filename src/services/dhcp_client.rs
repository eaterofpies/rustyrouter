use super::utils::{SharedWanLease, WanLease, get_interface_mac};
use futures_util::TryStreamExt;
use nix::sys::socket::{setsockopt, sockopt};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket as StdUdpSocket;
use tokio::net::UdpSocket;

const DEFAULT_LEASE_SECS: u32 = 3600;
const MAX_RETRY_DELAY_SECS: u32 = 64;
const INITIAL_RETRY_DELAY_SECS: u32 = 4;
const DEFAULT_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

struct DhcpOffer {
    offered_ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
}

struct DhcpAck {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    lease_secs: u32,
    dns_servers: Vec<Ipv4Addr>,
}

enum ParseAckResult {
    Ack(DhcpAck),
    Nak,
    None,
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
        loop {
            // 1. Discovering Phase: Send DISCOVER, await OFFER
            let (xid, offer) = match self.discover_phase().await {
                Ok(res) => res,
                Err(e) => {
                    println!(
                        "[dhcp-client] Discover phase failed: {}. Retrying in 5s...",
                        e
                    );
                    self.deconfigure().await;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            // 2. Requesting Phase: Send REQUEST, await ACK
            let ack = match self.request_phase(xid, offer).await {
                Ok(res) => res,
                Err(e) => {
                    println!(
                        "[dhcp-client] Request phase failed: {}. Restarting negotiation in 5s...",
                        e
                    );
                    self.deconfigure().await;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            // 3. Bound Phase: Configure IP, wait, and periodically renew
            if let Err(e) = self.bound_phase(ack).await {
                println!(
                    "[dhcp-client] Bound phase exited: {}. Restarting negotiation...",
                    e
                );
            }
        }
    }

    async fn discover_phase(
        &self,
    ) -> Result<(u32, DhcpOffer), Box<dyn std::error::Error + Send + Sync>> {
        let xid = rand::random::<u32>();
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_discover(xid).await;
            let timeout = get_jittered_duration(retry_delay_secs);

            if let Some(offer) = self.wait_for_offer(xid, timeout).await? {
                println!(
                    "[dhcp-client] Received DHCPOFFER for IP: {}, server: {:?}",
                    offer.offered_ip, offer.server_ip
                );
                return Ok((xid, offer));
            }

            retry_delay_secs = calculate_next_delay(retry_delay_secs);
        }
    }

    async fn request_phase(
        &self,
        xid: u32,
        offer: DhcpOffer,
    ) -> Result<DhcpAck, Box<dyn std::error::Error + Send + Sync>> {
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_request(
                xid,
                offer.offered_ip,
                offer.server_ip,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST,
            )
            .await;
            let timeout = get_jittered_duration(retry_delay_secs);

            if let Some(ack_res) = self.wait_for_ack(xid, timeout).await? {
                match ack_res {
                    ParseAckResult::Ack(ack) => {
                        println!("[dhcp-client] Received DHCPACK for IP: {}", ack.ip);
                        return Ok(ack);
                    }
                    ParseAckResult::Nak => {
                        println!("[dhcp-client] Received DHCPNAK!");
                        return Err("DHCPNAK received".into());
                    }
                    ParseAckResult::None => {}
                }
            }

            retry_delay_secs = calculate_next_delay(retry_delay_secs);
        }
    }

    async fn bound_phase(
        &self,
        ack: DhcpAck,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut ip = ack.ip;
        let mut mask = ack.mask;
        let mut gateway = ack.gateway;
        let mut dns_servers = ack.dns_servers;
        let mut lease_secs = ack.lease_secs;
        let mut server_ip = ack.server_ip;

        self.apply_lease_config(ip, mask, gateway, &dns_servers)
            .await?;
        let mut bound_at = std::time::Instant::now();

        loop {
            let elapsed = bound_at.elapsed().as_secs() as u32;
            if elapsed >= lease_secs {
                println!("[dhcp-client] Lease expired!");
                self.deconfigure().await;
                return Err("Lease expired".into());
            }

            // T1 Renewal time is lease_secs / 2
            let t1_secs = lease_secs / 2;
            if elapsed < t1_secs {
                let sleep_duration = std::time::Duration::from_secs((t1_secs - elapsed) as u64);
                tokio::time::sleep(sleep_duration).await;
                continue;
            }

            // T2 Rebinding time is 87.5% of lease (RFC 2131 section 4.4.5)
            let t2_secs = (lease_secs as f64 * 0.875) as u32;

            // Perform lease renewal phase
            match self
                .renew_lease(ip, t2_secs, lease_secs, server_ip, bound_at)
                .await
            {
                Ok(new_ack) => {
                    ip = new_ack.ip;
                    mask = new_ack.mask;
                    gateway = new_ack.gateway;
                    dns_servers = new_ack.dns_servers;
                    lease_secs = new_ack.lease_secs;
                    server_ip = new_ack.server_ip;

                    self.apply_lease_config(ip, mask, gateway, &dns_servers)
                        .await?;
                    bound_at = std::time::Instant::now();
                }
                Err(e) => {
                    self.deconfigure().await;
                    return Err(e);
                }
            }
        }
    }

    async fn renew_lease(
        &self,
        ip: Ipv4Addr,
        t2_secs: u32,
        lease_secs: u32,
        server_ip: Option<Ipv4Addr>,
        bound_at: std::time::Instant,
    ) -> Result<DhcpAck, Box<dyn std::error::Error + Send + Sync>> {
        let renew_xid = rand::random::<u32>();
        let mut renew_sent: Option<std::time::Instant> = None;

        loop {
            let current_elapsed = bound_at.elapsed().as_secs() as u32;
            if current_elapsed >= lease_secs {
                return Err("Lease expired during renewal".into());
            }

            let in_rebinding = current_elapsed >= t2_secs;
            let (retry_interval, dest_ip) = if in_rebinding {
                let remaining = lease_secs.saturating_sub(current_elapsed);
                let interval = std::cmp::max(remaining / 2, 60);
                (interval, Ipv4Addr::BROADCAST)
            } else {
                let remaining = t2_secs.saturating_sub(current_elapsed);
                let interval = std::cmp::max(remaining / 2, 60);
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
                renew_sent = Some(std::time::Instant::now());
            }

            let listen_timeout = std::time::Duration::from_secs(retry_interval as u64);
            if let Some(ack_res) = self.wait_for_ack(renew_xid, listen_timeout).await? {
                match ack_res {
                    ParseAckResult::Ack(new_ack) => {
                        println!("[dhcp-client] Renewal successful!");
                        return Ok(new_ack);
                    }
                    ParseAckResult::Nak => {
                        println!("[dhcp-client] Renewal NAK'd!");
                        return Err("Lease renewal NAK'd".into());
                    }
                    ParseAckResult::None => {}
                }
            }
        }
    }

    async fn wait_for_offer(
        &self,
        xid: u32,
        timeout: std::time::Duration,
    ) -> Result<Option<DhcpOffer>, std::io::Error> {
        let start = std::time::Instant::now();
        let mut buf = [0u8; 2048];

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Some(n) = self.receive_packet(&mut buf, remaining).await? else {
                break; // Timeout
            };

            if let Some(offer) = parse_offer(&buf[..n], xid) {
                return Ok(Some(offer));
            }
        }
        Ok(None)
    }

    async fn wait_for_ack(
        &self,
        xid: u32,
        timeout: std::time::Duration,
    ) -> Result<Option<ParseAckResult>, std::io::Error> {
        let start = std::time::Instant::now();
        let mut buf = [0u8; 2048];

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Some(n) = self.receive_packet(&mut buf, remaining).await? else {
                break; // Timeout
            };

            let res = parse_ack_nak(&buf[..n], xid);
            if !matches!(res, ParseAckResult::None) {
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    async fn receive_packet(
        &self,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<Option<usize>, std::io::Error> {
        let Ok(recv_res) = tokio::time::timeout(timeout, self.socket.recv_from(buf)).await else {
            return Ok(None); // Timeout occurred
        };

        let (n, _src) = recv_res?;
        Ok(Some(n))
    }

    async fn send_dhcp_message(
        &self,
        message: dhcproto::v4::Message,
        dest_ip: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use dhcproto::{Encodable, Encoder};
        let mut payload = Vec::new();
        message.encode(&mut Encoder::new(&mut payload))?;

        let dest_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            dest_ip,
            dhcproto::v4::SERVER_PORT,
        ));
        self.socket.send_to(&payload, dest_addr).await?;
        Ok(())
    }

    async fn apply_lease_config(
        &self,
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        dns_servers: &[Ipv4Addr],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                lease.dns_servers = dns_servers.to_vec();
                println!("[dhcp-client] Lease parameters updated: {:?}", *lease);
            }
            changed
        };

        if changed {
            configure_wan(&self.wan_interface, ip, mask, gateway).await?;
        }
        Ok(())
    }

    async fn deconfigure(&self) {
        let (ip, mask) = {
            let mut lease = self.lease_state.lock().unwrap();
            let ip = lease.ip;
            let mask = lease.mask;
            *lease = WanLease::default();
            (ip, mask)
        };

        if let Some(ip) = ip
            && let Some(mask) = mask
            && let Err(e) = deconfigure_wan(&self.wan_interface, ip, mask).await
        {
            println!(
                "[dhcp-client] ERROR: Failed to deconfigure WAN interface via netlink: {}",
                e
            );
        }
    }

    async fn send_discover(&self, xid: u32) {
        use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};

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

        if let Err(e) = self.send_dhcp_message(discover, Ipv4Addr::BROADCAST).await {
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

        if let Err(e) = self.send_dhcp_message(request, dest_ip).await {
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
    if doubled > MAX_RETRY_DELAY_SECS {
        MAX_RETRY_DELAY_SECS
    } else {
        doubled
    }
}

fn get_jittered_duration(base_secs: u32) -> std::time::Duration {
    let jitter = (rand::random::<f64>() * 2.0) - 1.0;
    let secs = base_secs as f64 + jitter;
    std::cmp::max(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs_f64(secs),
    )
}

fn parse_offer(buf: &[u8], xid: u32) -> Option<DhcpOffer> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
    use dhcproto::{Decodable, Decoder};

    let dhcp = Message::decode(&mut Decoder::new(buf)).ok()?;
    if dhcp.xid() != xid {
        return None;
    }
    let msg_type = dhcp.opts().get(OptionCode::MessageType)?;
    if let DhcpOption::MessageType(MessageType::Offer) = msg_type {
        let offered_ip = dhcp.yiaddr();
        let server_ip = get_server_identifier(&dhcp);
        Some(DhcpOffer {
            offered_ip,
            server_ip,
        })
    } else {
        None
    }
}

fn parse_ack_nak(buf: &[u8], xid: u32) -> ParseAckResult {
    use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
    use dhcproto::{Decodable, Decoder};

    let dhcp = match Message::decode(&mut Decoder::new(buf)) {
        Ok(d) => d,
        Err(_) => return ParseAckResult::None,
    };
    if dhcp.xid() != xid {
        return ParseAckResult::None;
    }
    match dhcp.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(MessageType::Ack)) => {
            let (mask, gateway, dns_servers, lease_secs) = parse_lease_options(&dhcp);
            ParseAckResult::Ack(DhcpAck {
                ip: dhcp.yiaddr(),
                mask,
                gateway,
                server_ip: get_server_identifier(&dhcp),
                lease_secs,
                dns_servers,
            })
        }
        Some(DhcpOption::MessageType(MessageType::Nak)) => ParseAckResult::Nak,
        _ => ParseAckResult::None,
    }
}

async fn deconfigure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            if matches_ip && let Err(e) = handle.address().del(addr).execute().await {
                println!("[dhcp-client] WARNING: Failed to delete IP address: {}", e);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(gw)
            .output_interface(index)
            .build();
        if let Err(e) = handle.route().add(route).execute().await {
            println!("[dhcp-client] WARNING: Failed to add default route: {}", e);
        }
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
        _ => DEFAULT_SUBNET_MASK,
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
        _ => DEFAULT_LEASE_SECS,
    };

    (mask, gateway, dns, lease_secs)
}

fn make_client_socket(interface_name: &str) -> std::io::Result<UdpSocket> {
    // Bind to 0.0.0.0 because the client doesn't have an IP address yet.
    let std_socket = StdUdpSocket::bind(("0.0.0.0", dhcproto::v4::CLIENT_PORT))?;

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

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{DhcpOption, Message, MessageType};
    use dhcproto::{Encodable, Encoder};

    const MOCK_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const MOCK_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const DEFAULT_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
    const DNS_IP_1: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const DNS_IP_2: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);

    fn encode_msg(msg: &Message) -> Vec<u8> {
        let mut buf = Vec::new();
        msg.encode(&mut Encoder::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn test_parse_offer_valid() {
        let mut msg = Message::default();
        msg.set_xid(0x12345678);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg.opts_mut()
            .insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let buf = encode_msg(&msg);
        let res = parse_offer(&buf, 0x12345678).unwrap();
        assert_eq!(res.offered_ip, MOCK_CLIENT_IP);
        assert_eq!(res.server_ip, Some(MOCK_SERVER_IP));
    }

    #[test]
    fn test_parse_offer_mismatched_xid() {
        let mut msg = Message::default();
        msg.set_xid(0x11111111);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));

        let buf = encode_msg(&msg);
        let res = parse_offer(&buf, 0x22222222);
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_offer_missing_server_id() {
        let mut msg = Message::default();
        msg.set_xid(0x12345678);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let buf = encode_msg(&msg);
        let res = parse_offer(&buf, 0x12345678).unwrap();
        assert_eq!(res.offered_ip, MOCK_CLIENT_IP);
        assert_eq!(res.server_ip, None);
    }

    #[test]
    fn test_parse_ack_valid() {
        let mut msg = Message::default();
        msg.set_xid(0xabcdef);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        msg.opts_mut().insert(DhcpOption::SubnetMask(DEFAULT_MASK));
        msg.opts_mut()
            .insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
        msg.opts_mut()
            .insert(DhcpOption::DomainNameServer(vec![DNS_IP_1, DNS_IP_2]));
        msg.opts_mut().insert(DhcpOption::AddressLeaseTime(1800));
        msg.opts_mut()
            .insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let buf = encode_msg(&msg);
        let res = parse_ack_nak(&buf, 0xabcdef);
        if let ParseAckResult::Ack(ack) = res {
            assert_eq!(ack.ip, MOCK_CLIENT_IP);
            assert_eq!(ack.mask, DEFAULT_MASK);
            assert_eq!(ack.gateway, Some(MOCK_SERVER_IP));
            assert_eq!(ack.dns_servers, vec![DNS_IP_1, DNS_IP_2]);
            assert_eq!(ack.lease_secs, 1800);
            assert_eq!(ack.server_ip, Some(MOCK_SERVER_IP));
        } else {
            panic!("Expected Ack");
        }
    }

    #[test]
    fn test_parse_nak() {
        let mut msg = Message::default();
        msg.set_xid(0x9999);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Nak));

        let buf = encode_msg(&msg);
        let res = parse_ack_nak(&buf, 0x9999);
        assert!(matches!(res, ParseAckResult::Nak));
    }

    #[test]
    fn test_parse_lease_options_missing_fields() {
        let mut msg = Message::default();
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));

        let (mask, gateway, dns, lease_secs) = parse_lease_options(&msg);
        assert_eq!(mask, DEFAULT_MASK);
        assert_eq!(gateway, None);
        assert!(dns.is_empty());
        assert_eq!(lease_secs, DEFAULT_LEASE_SECS);
    }
}
