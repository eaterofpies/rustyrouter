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
    
    Err(format!("No hardware address attribute found for interface {}", ifname))
}

pub fn open_raw_socket(ifname: &str) -> Result<RawFd, String> {
    use socket2::{Domain, Protocol, Socket, Type, SockAddr};
    use std::os::unix::io::IntoRawFd;

    // Create the packet raw socket
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from((libc::ETH_P_ALL as u16).to_be() as i32)),
    ).map_err(|e| format!("socket(AF_PACKET) failed: {}", e))?;

    // Enable nonblocking mode in pure Rust
    socket.set_nonblocking(true)
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

    socket.bind(&sockaddr)
        .map_err(|e| format!("bind(AF_PACKET) failed: {}", e))?;

    Ok(socket.into_raw_fd())
}

pub fn parse_dhcp_payload(buf: &[u8], expected_port: u16) -> Option<dhcproto::v4::Message> {
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;
    use dhcproto::{Decoder, Decodable};
    use dhcproto::v4::Message;

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
