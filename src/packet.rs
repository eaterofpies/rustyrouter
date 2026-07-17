use pnet::packet::MutablePacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

/// Building raw packets is necessary for DHCP because during the initial IP discovery phase,
/// the client interface does not yet have an assigned IP address. Standard TCP/UDP sockets
/// require a bound IP to send/receive data through the kernel network stack.
/// To bypass this and communicate with the server before an IP is assigned, we must construct
/// raw Ethernet, IPv4, and UDP headers in-place and write them directly into a raw packet socket
/// targeting Layer 2 MAC addresses.
pub fn build_raw_packet(
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let eth_header_len = MutableEthernetPacket::minimum_packet_size();
    let ip_header_len = MutableIpv4Packet::minimum_packet_size();
    let udp_header_len = MutableUdpPacket::minimum_packet_size();

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    let mut buf = vec![0u8; total_len];

    // Use explicit scoped blocks to satisfy the Rust borrow checker.
    // The first block mutably borrows `buf` to write the Ethernet, IP, and UDP headers.
    // Drop these mutable borrows (by exiting the block) before we can borrow `buf`
    // again to calculate the checksum
    {
        // 1. Ethernet Header
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dest_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        // 2. IPv4 Header
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length((ip_header_len / 4) as u8);
        ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);

        // 3. UDP Header
        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dest_port);
        udp.set_length((udp_header_len + payload.len()) as u16);
        udp.set_payload(payload);
    }

    // 4. IP Checksum (computed over the written header bytes in-place)
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    buf
}
