use dhcproto::Decodable;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::sleep;

#[path = "../src/packet.rs"]
mod packet;

const MOCK_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const MOCK_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const MOCK_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const MOCK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
const MOCK_SERVER_MAC: MacAddr = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
const LAN_CLIENT_MAC: MacAddr = MacAddr(0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);

// Sample DNS query payload (google.com A record request)
const DNS_QUERY: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x01, 0x00, // Flags: Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // google.com
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
];

// Sample DNS response payload (google.com A record response: 8.8.8.8)
const DNS_RESPONSE: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x81, 0x80, // Flags: Standard query response, No error
    0x00, 0x01, // Questions: 1
    0x00, 0x01, // Answer RRs: 1
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
    0x01, // Type: A
    0x00, 0x01, // Class: IN
    0xc0, 0x0c, // Pointer to name
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
    0x00, 0x00, 0x00, 0x3c, // TTL: 60s
    0x00, 0x04, // Length: 4
    0x08, 0x08, 0x08, 0x08, // IP: 8.8.8.8
];

// RAII QEMU process cleaner to prevent leaks
struct QemuKillGuard(u32);
impl Drop for QemuKillGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg(self.0.to_string())
            .status();
    }
}

// Unified UNIX socket stream wrapper with 32-bit big-endian length prefix framing
struct UnixStreamMock {
    stream: tokio::net::UnixStream,
}

impl UnixStreamMock {
    fn new(stream: tokio::net::UnixStream) -> Self {
        Self { stream }
    }

    async fn send_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let len = frame.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(frame).await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn recv_dhcp_packet(&mut self) -> std::io::Result<dhcproto::v4::Message> {
        loop {
            let frame = self.recv_frame().await?;
            if let Ok(dhcp) = parse_dhcp_message(&frame) {
                return Ok(dhcp);
            }
        }
    }
}

// Environment structure holding running QEMU and verified mocks
struct TestEnv {
    _qemu_guard: QemuKillGuard,
    _qemu_child: tokio::process::Child,
    _wan_isp_handle: tokio::task::JoinHandle<bool>,
    wan_verification_rx: tokio::sync::mpsc::Receiver<String>,
    lan_client: UnixStreamMock,
    leased_ip: Option<Ipv4Addr>,
    router_lan_mac: MacAddr,
}

#[tokio::test]
async fn test_all_router_features() {
    // 1. Run the unified startup stage (socket bind, QEMU boot, DHCP, ARP)
    let mut env = startup_stage().await;

    // 2. Run the logical test stages sequentially
    println!("\n=== STAGE 1: DHCP and ARP Verification ===");
    test_1_wan_and_lan_dhcp(&env).await;

    println!("\n=== STAGE 2: NAT Routing (Masquerading) Verification ===");
    test_2_nat_routing(&mut env).await;

    println!("\n=== STAGE 3: DNS Forwarding Verification ===");
    test_3_dns_forwarding(&mut env).await;

    // 3. Tear down VM cleanly
    println!("\n=== Cleaning up QEMU VM... ===");
    drop(env._qemu_guard);
    let _ = env._qemu_child.kill().await;
    let _ = env._wan_isp_handle.await;

    // Cleanup socket files
    let _ = std::fs::remove_file("/workspaces/rustyrouter/target/wan.sock");
    let _ = std::fs::remove_file("/workspaces/rustyrouter/target/lan.sock");

    println!("\n=== All integration test stages completed successfully! ===");
}

async fn startup_stage() -> TestEnv {
    // A. Build the target initramfs first (only need to build once)
    let build_status = Command::new("./build_initramfs.sh")
        .status()
        .await
        .expect("Failed to run build_initramfs.sh");
    assert!(build_status.success(), "Failed to build initramfs");

    // Ensure target directory exists
    let _ = std::fs::create_dir_all("/workspaces/rustyrouter/target");

    // Remove any existing socket files
    let _ = std::fs::remove_file("/workspaces/rustyrouter/target/wan.sock");
    let _ = std::fs::remove_file("/workspaces/rustyrouter/target/lan.sock");

    // B. Bind the WAN UNIX socket listener
    let wan_listener = UnixListener::bind("/workspaces/rustyrouter/target/wan.sock")
        .expect("Failed to bind WAN UNIX socket");

    // MPSC Channel to coordinate mock WAN ISP and mock LAN client test steps
    let (verification_tx, verification_rx) = tokio::sync::mpsc::channel::<String>(100);

    // C. Start our mock WAN ISP gateway in a background task
    let wan_isp_handle = tokio::spawn(async move {
        let (stream, _) = wan_listener
            .accept()
            .await
            .expect("Failed to accept WAN connection from QEMU");
        let mock = UnixStreamMock::new(stream);
        run_mock_wan_isp(mock, verification_tx).await
    });

    // D. Find kernel
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

    // E. Launch QEMU pointing to UNIX domain sockets
    println!("[test-env] Launching QEMU VM...");
    let mut qemu_child = Command::new("qemu-system-x86_64")
        .args([
            "-kernel", &kernel,
            "-initrd", "target/initramfs.cpio.gz",
            "-append", "console=ttyS0 quiet panic=-1 net.ifnames=0 rustyrouter.wan=eth0 rustyrouter.lan=eth1 rustyrouter.lan_ip=192.168.1.1/24",
            "-netdev", "stream,id=wan0,server=off,addr.type=unix,addr.path=/workspaces/rustyrouter/target/wan.sock",
            "-device", "virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56,romfile=",
            "-netdev", "stream,id=lan0,server=on,addr.type=unix,addr.path=/workspaces/rustyrouter/target/lan.sock",
            "-device", "virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57,romfile=",
            "-nographic",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn QEMU");

    // Capture child process ID for RAII kill guard
    let qemu_kill_guard = qemu_child.id().map(QemuKillGuard);

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

    // F. Await WAN DHCP lease negotiation
    println!("[test-env] Awaiting WAN DHCP lease negotiation...");
    let mut rx = verification_rx;
    let mut wan_dhcp_done = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(35) {
        if let Some(msg) = rx.recv().await
            && msg == "WAN_DHCP_DONE"
        {
            wan_dhcp_done = true;
            break;
        }
    }
    assert!(
        wan_dhcp_done,
        "WAN DHCP lease timed out during startup stage"
    );
    println!("[test-env] WAN DHCP lease acquired successfully!");

    // G. Connect LAN client mock to the QEMU-created socket
    println!("[test-env] Connecting LAN client mock...");
    let mut lan_stream = None;
    let start_lan = std::time::Instant::now();
    while start_lan.elapsed() < Duration::from_secs(10) {
        if std::path::Path::new("/workspaces/rustyrouter/target/lan.sock").exists()
            && let Ok(stream) =
                tokio::net::UnixStream::connect("/workspaces/rustyrouter/target/lan.sock").await
        {
            lan_stream = Some(stream);
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let lan_stream = lan_stream.expect("Failed to connect to QEMU LAN unix socket");
    let mut lan_client = UnixStreamMock::new(lan_stream);

    // DHCP DISCOVER
    let discover_payload = build_dhcp_discover_lan(0x5678, LAN_CLIENT_MAC);
    let discover_frame = packet::build_raw_packet(
        LAN_CLIENT_MAC,
        MacAddr::broadcast(),
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::BROADCAST,
        68,
        67,
        &discover_payload,
    );
    lan_client
        .send_frame(&discover_frame)
        .await
        .expect("Failed to send LAN DHCPDISCOVER");

    // DHCPOFFER
    let dhcp_offer = lan_client
        .recv_dhcp_packet()
        .await
        .expect("Failed to receive DHCPOFFER");
    assert_eq!(dhcp_offer.xid(), 0x5678);
    let offered_ip = dhcp_offer.yiaddr();
    println!("[test-env] LAN Offered IP: {}", offered_ip);

    // DHCPREQUEST
    let request_payload = build_dhcp_request_lan(
        0x5678,
        LAN_CLIENT_MAC,
        offered_ip,
        Ipv4Addr::new(192, 168, 1, 1),
    );
    let request_frame = packet::build_raw_packet(
        LAN_CLIENT_MAC,
        MacAddr::broadcast(),
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::BROADCAST,
        68,
        67,
        &request_payload,
    );
    lan_client
        .send_frame(&request_frame)
        .await
        .expect("Failed to send LAN DHCPREQUEST");

    // DHCPACK
    let dhcp_ack = lan_client
        .recv_dhcp_packet()
        .await
        .expect("Failed to receive DHCPACK");
    assert_eq!(dhcp_ack.xid(), 0x5678);
    let leased_ip = dhcp_ack.yiaddr();
    println!("[test-env] LAN Client Bound to IP: {}", leased_ip);

    // Resolve Router Gateway MAC (192.168.1.1) via ARP
    let arp_req = build_arp_request(LAN_CLIENT_MAC, leased_ip, Ipv4Addr::new(192, 168, 1, 1));
    lan_client
        .send_frame(&arp_req)
        .await
        .expect("Failed to send LAN ARP request");

    let mut router_lan_mac = MacAddr::zero();
    let start_arp = std::time::Instant::now();
    while start_arp.elapsed() < Duration::from_secs(5) {
        let frame = lan_client
            .recv_frame()
            .await
            .expect("Failed to read ARP reply");
        if let Some((sender_mac, sender_ip)) = parse_arp_reply(&frame, leased_ip).ok().flatten()
            && sender_ip == Ipv4Addr::new(192, 168, 1, 1)
        {
            router_lan_mac = sender_mac;
            break;
        }
    }
    assert_ne!(
        router_lan_mac,
        MacAddr::zero(),
        "Failed to resolve Gateway MAC via ARP"
    );
    println!("[test-env] Resolved Router LAN MAC: {}", router_lan_mac);

    TestEnv {
        _qemu_guard: qemu_kill_guard.unwrap(),
        _qemu_child: qemu_child,
        _wan_isp_handle: wan_isp_handle,
        wan_verification_rx: rx,
        lan_client,
        leased_ip: Some(leased_ip),
        router_lan_mac,
    }
}

async fn test_1_wan_and_lan_dhcp(env: &TestEnv) {
    assert!(env.leased_ip.is_some(), "LAN client IP was not leased");
    assert_ne!(
        env.router_lan_mac,
        MacAddr::zero(),
        "Router LAN MAC was not resolved"
    );
    println!("[test] DHCP and ARP startup verified successfully.");
}

async fn test_2_nat_routing(env: &mut TestEnv) {
    let leased_ip = env.leased_ip.unwrap();

    // Send ICMP Ping to 8.8.8.8 and expect ICMP Reply back
    println!("[test] Sending ICMP Echo Request to 8.8.8.8...");
    let mut ping_success = false;
    let start = std::time::Instant::now();
    let mut last_send = std::time::Instant::now() - Duration::from_secs(1);

    while start.elapsed() < Duration::from_secs(10) {
        if last_send.elapsed() >= Duration::from_secs(1) {
            let ping_req = build_icmp_echo_request(
                LAN_CLIENT_MAC,
                env.router_lan_mac,
                leased_ip,
                Ipv4Addr::new(8, 8, 8, 8),
                0x4321,
                1,
            );
            let _ = env.lan_client.send_frame(&ping_req).await;
            last_send = std::time::Instant::now();
        }

        if let Ok(Ok(frame)) =
            tokio::time::timeout(Duration::from_millis(100), env.lan_client.recv_frame()).await
            && let Some(true) = verify_icmp_reply(&frame).ok()
        {
            ping_success = true;
            break;
        }
    }
    assert!(
        ping_success,
        "LAN client failed to receive ICMP Echo Reply from 8.8.8.8"
    );

    // Verify WAN mock server received it too
    let mut icmp_verified = false;
    let start_wan = std::time::Instant::now();
    while start_wan.elapsed() < Duration::from_secs(5) {
        tokio::select! {
            Some(msg) = env.wan_verification_rx.recv() => {
                if msg == "ICMP_VERIFIED" {
                    icmp_verified = true;
                    break;
                }
            }
            _ = sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(
        icmp_verified,
        "WAN mock server did not verify NATed ICMP Request"
    );
    println!("[test] NAT Masquerading routing verified successfully.");
}

async fn test_3_dns_forwarding(env: &mut TestEnv) {
    let leased_ip = env.leased_ip.unwrap();

    // Send DNS Query for google.com to 192.168.1.1:53 and expect DNS Response back
    println!("[test] Sending DNS query for google.com to 192.168.1.1:53...");
    let mut dns_success = false;
    let start = std::time::Instant::now();
    let mut last_send = std::time::Instant::now() - Duration::from_secs(1);

    while start.elapsed() < Duration::from_secs(10) {
        if last_send.elapsed() >= Duration::from_secs(1) {
            let dns_query_frame = build_udp_packet(
                LAN_CLIENT_MAC,
                env.router_lan_mac,
                leased_ip,
                Ipv4Addr::new(192, 168, 1, 1),
                12345,
                53,
                DNS_QUERY,
            );
            let _ = env.lan_client.send_frame(&dns_query_frame).await;
            last_send = std::time::Instant::now();
        }

        if let Ok(Ok(frame)) =
            tokio::time::timeout(Duration::from_millis(100), env.lan_client.recv_frame()).await
            && let Some((_src_ip, _dest_ip, src_port, dest_port, payload)) =
                parse_dns_request(&frame).ok().flatten()
            && src_port == 53
            && dest_port == 12345
            && payload == DNS_RESPONSE
        {
            dns_success = true;
            break;
        }
    }
    assert!(
        dns_success,
        "LAN client failed to receive valid DNS response"
    );

    // Verify WAN mock server received it too
    let mut dns_verified = false;
    let start_wan = std::time::Instant::now();
    while start_wan.elapsed() < Duration::from_secs(5) {
        tokio::select! {
            Some(msg) = env.wan_verification_rx.recv() => {
                if msg == "DNS_VERIFIED" {
                    dns_verified = true;
                    break;
                }
            }
            _ = sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(
        dns_verified,
        "WAN mock server did not verify forwarded DNS query"
    );
    println!("[test] DNS UDP forwarding verified successfully.");
}

async fn run_mock_wan_isp(
    mut mock: UnixStreamMock,
    verification_tx: tokio::sync::mpsc::Sender<String>,
) -> bool {
    let xid;
    let client_mac;

    // 1. Receive DHCPDISCOVER
    println!("[isp-test] Waiting for DHCPDISCOVER...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(30);

    loop {
        if start.elapsed() >= timeout_dur {
            println!("[isp-test] Timeout waiting for DHCPDISCOVER");
            return false;
        }
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] Connection closed while waiting for DHCPDISCOVER");
                return false;
            }
            Err(_) => continue, // Timeout
        };

        if let Ok(dhcp_discover) = parse_dhcp_message(&frame) {
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

    println!("[isp-test] Discovered QEMU peer WAN Interface");

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
    if mock.send_frame(&offer_frame).await.is_err() {
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
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] Connection closed while waiting for DHCPREQUEST");
                return false;
            }
            Err(_) => continue, // Timeout
        };
        if let Ok(dhcp_request) = parse_dhcp_message(&frame) {
            use dhcproto::v4::MessageType;
            let msg_type = dhcp_request
                .opts()
                .get(dhcproto::v4::OptionCode::MessageType);
            if let Some(dhcproto::v4::DhcpOption::MessageType(MessageType::Request)) = msg_type
                && dhcp_request.xid() == xid
            {
                break;
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
    if mock.send_frame(&ack_frame).await.is_err() {
        return false;
    }

    // Notify coordinator that WAN DHCP setup is finished
    let _ = verification_tx.send("WAN_DHCP_DONE".to_string()).await;

    // 5. WAN Loop to handle ARP, ICMP transit, and DNS queries
    println!("[isp-test] Entering WAN verification event loop...");
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(30);

    loop {
        if start.elapsed() >= timeout_dur {
            break;
        }
        let frame = match tokio::time::timeout(Duration::from_millis(100), mock.recv_frame()).await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => {
                println!("[isp-test] WAN socket connection closed. Exiting verification event loop.");
                break;
            }
            Err(_) => continue, // Timeout
        };

        if let Some(eth) = pnet::packet::ethernet::EthernetPacket::new(&frame) {
            println!(
                "[isp-test] Received WAN frame: len={}, ethertype=0x{:04x}",
                frame.len(),
                eth.get_ethertype().0
            );
        }

        // A. Handle ARP requests for WAN gateway / DNS server
        if let Some(arp_reply) = handle_arp_request(&frame).ok().flatten() {
            let _ = mock.send_frame(&arp_reply).await;
            continue;
        }

        // B. Handle ICMP request to 8.8.8.8 (checks NAT masquerading)
        if let Some((src_ip, dest_ip)) = parse_icmp_request(&frame).ok().flatten() {
            if dest_ip == Ipv4Addr::new(8, 8, 8, 8) {
                if src_ip == MOCK_CLIENT_IP {
                    println!("[isp-test] Verified NATed ICMP Request from WAN client!");
                    let _ = verification_tx.send("ICMP_VERIFIED".to_string()).await;
                }
                // Send ICMP Echo Reply back from 8.8.8.8 to the NATed client IP
                let icmp_reply =
                    build_icmp_echo_reply(MOCK_SERVER_MAC, client_mac, dest_ip, src_ip, 0x4321, 1);
                let _ = mock.send_frame(&icmp_reply).await;
            }
            continue;
        }

        // C. Handle DNS request to 10.0.2.3:53 (checks DNS forwarding)
        if let Some((src_ip, dest_ip, src_port, dest_port, payload)) =
            parse_dns_request(&frame).ok().flatten()
        {
            if dest_ip == MOCK_DNS_SERVER && dest_port == 53 {
                if src_ip == MOCK_CLIENT_IP && payload == DNS_QUERY {
                    println!("[isp-test] Verified DNS Forwarder query on WAN!");
                    let _ = verification_tx.send("DNS_VERIFIED".to_string()).await;
                }
                println!(
                    "[isp-test] Sending DNS Reply to {}:{} from {}:{} with client MAC: {}",
                    src_ip, src_port, dest_ip, dest_port, client_mac
                );
                // Send DNS Reply from 10.0.2.3:53 back to the NATed source
                let dns_reply = build_udp_packet(
                    MOCK_SERVER_MAC,
                    client_mac,
                    dest_ip,   // 10.0.2.3 (source)
                    src_ip,    // 10.0.2.15 (destination)
                    dest_port, // 53 (source port)
                    src_port,  // router's ephemeral port (destination port)
                    DNS_RESPONSE,
                );
                let _ = mock.send_frame(&dns_reply).await;
            }
            continue;
        }
    }

    true
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

fn build_dhcp_discover_lan(xid: u32, client_mac: MacAddr) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut disc = Message::default();
    disc.set_opcode(Opcode::BootRequest);
    disc.set_xid(xid);
    disc.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = disc.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Discover));
    opts.insert(DhcpOption::ParameterRequestList(vec![
        dhcproto::v4::OptionCode::SubnetMask,
        dhcproto::v4::OptionCode::Router,
        dhcproto::v4::OptionCode::DomainNameServer,
    ]));

    let mut payload = Vec::new();
    disc.encode(&mut Encoder::new(&mut payload)).unwrap();
    payload
}

fn build_dhcp_request_lan(
    xid: u32,
    client_mac: MacAddr,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
) -> Vec<u8> {
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};

    let mut req = Message::default();
    req.set_opcode(Opcode::BootRequest);
    req.set_xid(xid);
    req.set_chaddr(&[
        client_mac.0,
        client_mac.1,
        client_mac.2,
        client_mac.3,
        client_mac.4,
        client_mac.5,
    ]);

    let opts = req.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Request));
    opts.insert(DhcpOption::RequestedIpAddress(requested_ip));
    opts.insert(DhcpOption::ServerIdentifier(server_ip));

    let mut payload = Vec::new();
    req.encode(&mut Encoder::new(&mut payload)).unwrap();
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

fn build_icmp_echo_reply(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
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

        let mut icmp = MutableEchoReplyPacket::new(ip.payload_mut()).unwrap();
        icmp.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoReply);
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
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::ethernet::EtherTypes;
    use pnet::packet::ethernet::MutableEthernetPacket;

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

fn build_arp_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::arp::ArpHardwareTypes;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::ethernet::EtherTypes;
    use pnet::packet::ethernet::MutableEthernetPacket;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let arp_header_len = MutableArpPacket::minimum_packet_size();
    let total_len = eth_header_len + arp_header_len;
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(sender_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(pnet::packet::arp::ArpOperations::Request);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    buf
}

fn handle_arp_request(frame: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Arp {
        return Ok(None);
    }
    let arp = pnet::packet::arp::ArpPacket::new(eth.payload()).ok_or("Malformed ARP packet")?;
    if arp.get_operation() == pnet::packet::arp::ArpOperations::Request {
        let target_ip = arp.get_target_proto_addr();
        if target_ip == MOCK_SERVER_IP || target_ip == MOCK_DNS_SERVER {
            let arp_reply = build_arp_reply(
                MOCK_SERVER_MAC,
                arp.get_sender_hw_addr(),
                target_ip,
                arp.get_sender_proto_addr(),
            );
            return Ok(Some(arp_reply));
        }
    }
    Ok(None)
}

fn parse_arp_reply(
    frame: &[u8],
    expected_target_ip: Ipv4Addr,
) -> Result<Option<(MacAddr, Ipv4Addr)>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Arp {
        return Ok(None);
    }
    let arp = pnet::packet::arp::ArpPacket::new(eth.payload()).ok_or("Malformed ARP packet")?;
    if arp.get_operation() == pnet::packet::arp::ArpOperations::Reply
        && arp.get_target_proto_addr() == expected_target_ip
    {
        return Ok(Some((
            arp.get_sender_hw_addr(),
            arp.get_sender_proto_addr(),
        )));
    }
    Ok(None)
}

fn parse_icmp_request(
    frame: &[u8],
) -> Result<Option<(Ipv4Addr, Ipv4Addr)>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Ok(None);
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Icmp {
        return Ok(None);
    }
    let icmp = pnet::packet::icmp::IcmpPacket::new(ip.payload()).ok_or("Malformed ICMP packet")?;
    if icmp.get_icmp_type() == pnet::packet::icmp::IcmpTypes::EchoRequest {
        return Ok(Some((ip.get_source(), ip.get_destination())));
    }
    Ok(None)
}

fn parse_dns_request(
    frame: &[u8],
) -> Result<Option<(Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>)>, Box<dyn std::error::Error>> {
    if frame.len() < 42 {
        return Ok(None);
    }
    let eth =
        pnet::packet::ethernet::EthernetPacket::new(frame).ok_or("Malformed Ethernet frame")?;
    if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return Ok(None);
    }
    let ip = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()).ok_or("Malformed IPv4 packet")?;
    if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return Ok(None);
    }
    let udp = pnet::packet::udp::UdpPacket::new(ip.payload()).ok_or("Malformed UDP packet")?;
    Ok(Some((
        ip.get_source(),
        ip.get_destination(),
        udp.get_source(),
        udp.get_destination(),
        udp.payload().to_vec(),
    )))
}

fn build_udp_packet(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use pnet::packet::MutablePacket;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;

    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let udp_header_len = MutableUdpPacket::minimum_packet_size();

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dest_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length((ip_header_len / 4) as u8);
        ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);

        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dest_port);
        udp.set_length((udp_header_len + payload.len()) as u16);
        udp.set_payload(payload);

        // Set UDP checksum to 0 to bypass kernel validation
        udp.set_checksum(0);
    }

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    buf
}
