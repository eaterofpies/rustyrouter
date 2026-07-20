use dhcproto::Decodable;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::time::sleep;

#[path = "../src/packet.rs"]
mod packet;

const MOCK_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const MOCK_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const MOCK_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const MOCK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
const MOCK_SERVER_MAC: MacAddr = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

// RAII QEMU process cleaner to prevent leaks
struct QemuKillGuard(u32);
impl Drop for QemuKillGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg(self.0.to_string())
            .status();
    }
}

#[tokio::test]
async fn test_wan_dhcp_and_ping() {
    // 1. Build the target initramfs first (only need to build once)
    let build_status = Command::new("./build_initramfs.sh")
        .status()
        .await
        .expect("Failed to run build_initramfs.sh");
    assert!(build_status.success(), "Failed to build initramfs");

    // 2. Bind the UDP socket on the host exactly once
    let socket = UdpSocket::bind("127.0.0.1:2345")
        .await
        .expect("Failed to bind UDP socket on host");
    let socket = Arc::new(socket);

    // 3. Start our mock DHCP/Ping server in a background task
    let server_handle = tokio::spawn(async move { run_mock_dhcp_server(socket).await });

    // 4. Find kernel
    let default_kernel = "/boot/vmlinuz-6.12.95+deb13-cloud-amd64";
    let mut kernel = if std::path::Path::new(default_kernel).exists() {
        default_kernel.to_string()
    } else {
        "".to_string()
    };
    if kernel.is_empty() {
        for entry in std::fs::read_dir("/boot").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap().to_string_lossy();
                if name.starts_with("vmlinuz-")
                    && !name.contains("rescue")
                    && !name.contains("fallback")
                {
                    kernel = path.to_string_lossy().into_owned();
                    break;
                }
            }
        }
    }
    assert!(!kernel.is_empty(), "No Linux kernel found in /boot");

    // 5. Launch QEMU
    println!("[test] Launching QEMU VM...");
    let mut qemu_child = Command::new("qemu-system-x86_64")
        .args(&[
            "-kernel", &kernel,
            "-initrd", "target/initramfs.cpio.gz",
            "-append", "console=ttyS0 quiet panic=-1 net.ifnames=0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24",
            "-netdev", "socket,id=wan0,udp=127.0.0.1:2345,localaddr=127.0.0.1:2346",
            "-device", "virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56,romfile=",
            "-netdev", "socket,id=lan0,listen=127.0.0.1:1234",
            "-device", "virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57,romfile=",
            "-nographic",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn QEMU");

    // Capture child process ID for RAII kill guard
    let qemu_kill_guard = qemu_child.id().map(|id| QemuKillGuard(id));

    // Stream QEMU stdout/stderr
    let stdout = qemu_child.stdout.take().unwrap();
    let stderr = qemu_child.stderr.take().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("[qemu-stdout] {}", line);
        }
    });
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("[qemu-stderr] {}", line);
        }
    });

    // 6. Await test server verification with timeout (up to 30s)
    println!("[test] Awaiting DHCP lease negotiation and Ping reply...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let poll_interval = Duration::from_secs(1);
    let success = loop {
        if server_handle.is_finished() {
            break server_handle.await.unwrap_or(false);
        }
        if tokio::time::Instant::now() >= deadline {
            println!("[test] Attempt timed out.");
            break false;
        }
        sleep(poll_interval).await;
    };

    // Clean up QEMU
    drop(qemu_kill_guard);
    let _ = qemu_child.kill().await;

    assert!(success, "Integration test failed.");
}

async fn run_mock_dhcp_server(socket: Arc<UdpSocket>) -> bool {
    let mut buf = vec![0u8; 2048];
    let xid;
    let client_mac;
    let mut peer_addr;

    // 1. Receive DHCPDISCOVER
    println!("[isp-test] Waiting for DHCPDISCOVER...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(30);

    loop {
        if start.elapsed() >= timeout_dur {
            println!("[isp-test] Timeout waiting for DHCPDISCOVER");
            return false;
        }
        let recv_result = tokio::select! {
            res = socket.recv_from(&mut buf) => Some(res),
            _ = sleep(Duration::from_millis(100)) => None,
        };
        let (len, addr) = match recv_result {
            Some(Ok((len, addr))) => (len, addr),
            Some(Err(e)) => {
                println!("[isp-test] Error waiting for DHCPDISCOVER: {}", e);
                return false;
            }
            None => continue,
        };
        peer_addr = addr;

        let discover_frame = &buf[..len];
        if let Ok(dhcp_discover) = parse_dhcp_message(discover_frame) {
            use dhcproto::v4::MessageType;
            let msg_type = dhcp_discover
                .opts()
                .get(dhcproto::v4::OptionCode::MessageType);
            if let Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Discover)) = msg_type {
                client_mac = MacAddr(
                    dhcp_discover.chaddr()[0],
                    dhcp_discover.chaddr()[1],
                    dhcp_discover.chaddr()[2],
                    dhcp_discover.chaddr()[3],
                    dhcp_discover.chaddr()[4],
                    dhcp_discover.chaddr()[5],
                );
                xid = dhcp_discover.xid();
                break;
            }
        }
    }

    println!("[isp-test] Discovered QEMU peer at {:?}", peer_addr);

    // 2. Send DHCPOFFER
    println!("[isp-test] Sending DHCPOFFER...");
    let offer_payload = build_dhcp_offer(xid, client_mac);
    let offer_frame = packet::build_raw_packet(
        MOCK_SERVER_MAC,
        client_mac,
        MOCK_SERVER_IP,
        Ipv4Addr::BROADCAST,
        67,
        68,
        &offer_payload,
    );
    if socket.send_to(&offer_frame, peer_addr).await.is_err() {
        return false;
    }

    // 3. Wait for DHCPREQUEST
    println!("[isp-test] Waiting for DHCPREQUEST...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(5);
    loop {
        if start.elapsed() >= timeout_dur {
            println!("[isp-test] Timeout waiting for DHCPREQUEST");
            return false;
        }
        let recv_result = tokio::select! {
            res = socket.recv_from(&mut buf) => Some(res),
            _ = sleep(Duration::from_millis(100)) => None,
        };
        let (len, from_addr) = match recv_result {
            Some(Ok((len, from_addr))) => (len, from_addr),
            Some(Err(e)) => {
                println!("[isp-test] Error waiting for DHCPREQUEST: {}", e);
                return false;
            }
            None => continue,
        };
        if from_addr != peer_addr {
            continue;
        }
        let request_frame = &buf[..len];
        if let Ok(dhcp_request) = parse_dhcp_message(request_frame) {
            use dhcproto::v4::MessageType;
            let msg_type = dhcp_request
                .opts()
                .get(dhcproto::v4::OptionCode::MessageType);
            if let Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Request)) = msg_type {
                if dhcp_request.xid() == xid {
                    break;
                }
            }
        }
    }
    println!("[isp-test] Received DHCPREQUEST.");

    // 4. Send DHCPACK
    println!("[isp-test] Sending DHCPACK...");
    let ack_payload = build_dhcp_ack(xid, client_mac);
    let ack_frame = packet::build_raw_packet(
        MOCK_SERVER_MAC,
        client_mac,
        MOCK_SERVER_IP,
        Ipv4Addr::BROADCAST,
        67,
        68,
        &ack_payload,
    );
    if socket.send_to(&ack_frame, peer_addr).await.is_err() {
        return false;
    }

    // 5. Send ICMP Echo Request (Ping) and wait for ICMP Echo Reply in a loop
    println!(
        "[isp-test] Sending ICMP Echo Request to {}...",
        MOCK_CLIENT_IP
    );
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(20);

    loop {
        if start.elapsed() >= timeout_dur {
            println!("[isp-test] Timeout waiting for ICMP Echo Reply");
            return false;
        }

        let icmp_request = build_icmp_echo_request(
            MOCK_SERVER_MAC,
            client_mac,
            MOCK_SERVER_IP,
            MOCK_CLIENT_IP,
            0x1234,
            0,
        );
        if socket.send_to(&icmp_request, peer_addr).await.is_err() {
            return false;
        }

        let recv_result = tokio::select! {
            res = socket.recv_from(&mut buf) => Some(res),
            _ = sleep(Duration::from_millis(100)) => None,
        };
        if let Some(Ok((reply_len, from_addr))) = recv_result {
            if from_addr == peer_addr {
                let reply_frame = &buf[..reply_len];
                
                // Handle ARP requests
                if let Some(arp_reply) = handle_arp_request(reply_frame).ok().flatten() {
                    println!("[isp-test] Received ARP Request, sending ARP Reply...");
                    let _ = socket.send_to(&arp_reply, peer_addr).await;
                    continue;
                }

                if let Some(true) = verify_icmp_reply(reply_frame).ok() {
                    println!("[isp-test] SUCCESS: Received valid ICMP Echo Reply!");
                    return true;
                } else {
                    println!("[isp-test] Received non-ping packet on WAN");
                }
            }
        }
    }
}

fn parse_dhcp_message(frame: &[u8]) -> Result<dhcproto::v4::Message, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Err("Packet too short".into());
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Err("Not an IPv4 packet".into());
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return Err("Not a UDP packet".into());
    }
    let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).ok_or("Malformed UDP packet")?;

    let dhcp = dhcproto::v4::Message::decode(&mut dhcproto::Decoder::new(udp.payload()))?;
    Ok(dhcp)
}

fn build_dhcp_offer(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut offer = Message::default();
    offer.set_opcode(Opcode::BootReply);
    offer.set_xid(xid);
    offer.set_yiaddr(MOCK_CLIENT_IP);
    offer.set_siaddr(MOCK_SERVER_IP);
    offer.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = offer.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Offer));
    opts.insert(DhcpOption::SubnetMask(MOCK_SUBNET_MASK));
    opts.insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
    opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![
        MOCK_DNS_SERVER,
    ]));
    opts.insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
    opts.insert(DhcpOption::AddressLeaseTime(3600));

    let mut payload = Vec::new();
    offer.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_dhcp_ack(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut ack = Message::default();
    ack.set_opcode(Opcode::BootReply);
    ack.set_xid(xid);
    ack.set_yiaddr(MOCK_CLIENT_IP);
    ack.set_siaddr(MOCK_SERVER_IP);
    ack.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = ack.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Ack));
    opts.insert(DhcpOption::SubnetMask(MOCK_SUBNET_MASK));
    opts.insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
    opts.insert(dhcproto::v4::DhcpOption::DomainNameServer(vec![
        MOCK_DNS_SERVER,
    ]));
    opts.insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
    opts.insert(DhcpOption::AddressLeaseTime(3600));

    let mut payload = Vec::new();
    ack.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_icmp_echo_request(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let icmp_header_len = 8;

    let total_len = eth_header_len + ip_header_len + icmp_header_len;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dest_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length((ip_header_len / 4) as u8);
        ip.set_total_length((ip_header_len + icmp_header_len) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);

        let mut icmp = MutableEchoRequestPacket::new(ip.payload_mut()).unwrap();
        icmp.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
        icmp.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
        icmp.set_identifier(identifier);
        icmp.set_sequence_number(sequence);

        let checksum = pnet::util::checksum(icmp.packet(), 1);
        icmp.set_checksum(checksum);
    }

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    buf
}

fn verify_icmp_reply(frame: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(false);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Ok(false);
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Icmp {
        return Ok(false);
    }
    let icmp = pnet::packet::icmp::IcmpPacket::new(ip.payload()).ok_or("Malformed ICMP packet")?;

    Ok(icmp.get_icmp_type() == pnet::packet::icmp::IcmpTypes::EchoReply)
}

fn build_arp_reply(
    sender_mac: MacAddr,
    target_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::ethernet::EtherTypes;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let arp_header_len = MutableArpPacket::minimum_packet_size();
    let total_len = eth_header_len + arp_header_len;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(target_mac);
        eth.set_source(sender_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(pnet::packet::arp::ArpOperations::Reply);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);
    }

    buf
}

fn handle_arp_request(frame: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth = pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Arp {
        return Ok(None);
    }
    let arp = pnet::packet::arp::ArpPacket::new(eth.payload()).ok_or("Malformed ARP packet")?;
    if arp.get_operation() == pnet::packet::arp::ArpOperations::Request {
        let target_ip = arp.get_target_proto_addr();
        if target_ip == MOCK_SERVER_IP {
            let arp_reply = build_arp_reply(
                MOCK_SERVER_MAC,
                arp.get_sender_hw_addr(),
                MOCK_SERVER_IP,
                arp.get_sender_proto_addr(),
            );
            return Ok(Some(arp_reply));
        }
    }
    Ok(None)
}
