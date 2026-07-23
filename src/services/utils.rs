use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

// =========================================================================
// Shared WAN Lease Info
// =========================================================================
#[derive(Debug, Clone, Default)]
pub struct WanLease {
    pub ip: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub type SharedWanLease = Arc<Mutex<WanLease>>;

// =========================================================================
// Helper Functions for Raw Sockets
// =========================================================================
pub async fn get_interface_mac(ifname: &str) -> Result<pnet::util::MacAddr, String> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| format!("Failed to open netlink connection: {}", e))?;
    tokio::spawn(connection);

    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(ifname.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(format!("Interface {} not found", ifname)),
        Err(e) => return Err(format!("Netlink request failed: {}", e)),
    };

    for attr in link.attributes {
        let mac_vec = match attr {
            rtnetlink::packet_route::link::LinkAttribute::Address(v) => v,
            _ => continue,
        };
        if mac_vec.len() == 6 {
            return Ok(pnet::util::MacAddr(
                mac_vec[0], mac_vec[1], mac_vec[2], mac_vec[3], mac_vec[4], mac_vec[5],
            ));
        }
    }

    Err(format!(
        "No hardware address attribute found for interface {}",
        ifname
    ))
}

pub fn open_raw_socket(ifname: &str) -> Result<RawFd, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::os::unix::io::IntoRawFd;

    // Create the packet raw socket
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from((libc::ETH_P_ALL as u16).to_be() as i32)),
    )
    .map_err(|e| format!("socket(AF_PACKET) failed: {}", e))?;

    // Enable nonblocking mode in pure Rust
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set nonblocking mode: {}", e))?;

    // Resolve interface name to its index
    let c_ifname = std::ffi::CString::new(ifname).unwrap();
    let if_index = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if if_index == 0 {
        return Err(format!("Interface not found: {}", ifname));
    }

    // Set up Link-Layer address struct
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    // Wrap in SockAddr and bind
    let mut storage = socket2::SockAddrStorage::zeroed();
    let sockaddr = unsafe {
        let storage_ptr = &mut storage as *mut socket2::SockAddrStorage as *mut u8;
        std::ptr::copy_nonoverlapping(
            &addr as *const libc::sockaddr_ll as *const u8,
            storage_ptr,
            std::mem::size_of::<libc::sockaddr_ll>(),
        );
        SockAddr::new(
            storage,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    socket
        .bind(&sockaddr)
        .map_err(|e| format!("bind(AF_PACKET) failed: {}", e))?;

    Ok(socket.into_raw_fd())
}

pub fn parse_dhcp_payload(buf: &[u8], expected_port: u16) -> Option<dhcproto::v4::Message> {
    use dhcproto::v4::Message;
    use dhcproto::{Decodable, Decoder};
    use pnet::packet::Packet;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;

    let eth_pkt = EthernetPacket::new(buf)?;
    if eth_pkt.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return None;
    }
    let ip_pkt = Ipv4Packet::new(eth_pkt.payload())?;
    if ip_pkt.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return None;
    }
    let udp_pkt = UdpPacket::new(ip_pkt.payload())?;
    if udp_pkt.get_destination() != expected_port {
        return None;
    }
    Message::decode(&mut Decoder::new(udp_pkt.payload())).ok()
}

pub fn try_read_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    use std::os::unix::io::AsRawFd;
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::recv(
                inner.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
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

pub async fn read_raw_packet(
    async_sock: &tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>,
    buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    loop {
        let mut guard = async_sock.readable().await?;
        if let Some(n) = try_read_raw(&mut guard, buf)? {
            return Ok(n);
        }
    }
}

pub fn try_write_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    frame: &[u8],
) -> Result<Option<isize>, std::io::Error> {
    use std::os::unix::io::AsRawFd;
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::send(
                inner.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
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

pub async fn send_raw_packet(
    async_sock: &tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>,
    frame: &[u8],
) {
    loop {
        let mut guard = match async_sock.writable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        match try_write_raw(&mut guard, frame) {
            Ok(None) => continue,
            _ => break,
        }
    }
}

pub fn get_timestamp_prefix() -> String {
    let now = chrono::Utc::now();
    now.format("[%Y-%m-%dT%H:%M:%S%.3fZ] ").to_string()
}

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DNS_PORT: u16 = 53;
const LOCAL_DNS_BIND: &str = "127.0.0.1:0";

pub async fn resolve_dns_a_record(host: &str) -> Result<std::net::Ipv4Addr, String> {
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let socket = UdpSocket::bind(LOCAL_DNS_BIND)
        .await
        .map_err(|e| format!("Failed to bind DNS query socket: {}", e))?;

    // Generate unique randomized transaction ID
    let query_id = rand::random::<u16>();

    // Build DNS standard query for the host (A record)
    let mut builder = dns_parser::Builder::new_query(query_id, true);
    builder.add_question(
        host,
        false,
        dns_parser::QueryType::A,
        dns_parser::QueryClass::IN,
    );
    let query = builder
        .build()
        .map_err(|_| "Failed to build DNS query packet".to_string())?;

    let dns_server = std::net::SocketAddr::new(std::net::IpAddr::V4(LOCALHOST), DNS_PORT);

    socket
        .send_to(&query, dns_server)
        .await
        .map_err(|e| format!("Failed to send DNS query: {}", e))?;

    let mut buf = [0u8; 512];
    let recv_res = timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await;
    let (len, _) = match recv_res {
        Ok(Ok((l, addr))) => {
            if addr == dns_server {
                (l, addr)
            } else {
                return Err("Received packet from unexpected source".to_string());
            }
        }
        Ok(Err(e)) => return Err(format!("Socket receive error: {}", e)),
        Err(_) => return Err("DNS query timed out".to_string()),
    };

    let packet = dns_parser::Packet::parse(&buf[..len])
        .map_err(|e| format!("Failed to parse DNS response: {}", e))?;

    if packet.header.id != query_id {
        return Err("Transaction ID mismatch".to_string());
    }

    let mut resolved_ip = None;
    for answer in packet.answers {
        if let dns_parser::RData::A(ip) = answer.data {
            resolved_ip = Some(ip.0);
            break;
        }
    }

    resolved_ip.ok_or_else(|| format!("No A record resolved for {}", host))
}
