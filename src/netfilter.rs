use rustables::{Batch, Chain, MsgType, ProtocolFamily, Table, Hook, HookClass, Rule, ChainPolicy, ChainType};
use rustables::expr::{Meta, MetaType, Cmp, CmpOp, Masquerade, Immediate, VerdictKind, Conntrack, ConntrackKey, ConnTrackState};

fn pad_interface_name(name: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(16);
    bytes[..len].copy_from_slice(&name_bytes[..len]);
    bytes
}

pub fn configure_firewall(
    wan_iface: &str,
    lan_iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[netfilter] Configuring NAT and firewall rules...");

    let table = Table::new(ProtocolFamily::Ipv4).with_name("rustyrouter");

    // 1. Delete pre-existing table to flush old state (ignore error if it doesn't exist)
    let mut del_batch = Batch::new();
    del_batch.add(&table, MsgType::Del);
    let _ = del_batch.send();

    // 2. Build Table and Chains
    let nat_chain = Chain::new(&table)
        .with_name("nat_postrouting")
        .with_hook(Hook::new(HookClass::PostRouting, 100))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept);

    let filter_chain = Chain::new(&table)
        .with_name("filter_input")
        .with_hook(Hook::new(HookClass::In, 0))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Drop);

    // 3. Rule: Masquerade outgoing traffic on WAN interface
    let mut masq_rule = Rule::new(&nat_chain)?;
    masq_rule.add_expr(Meta::new(MetaType::OifName));
    masq_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(wan_iface)));
    masq_rule.add_expr(Masquerade::default());

    // 4. Rule: Accept input on loopback ('lo')
    let mut lo_rule = Rule::new(&filter_chain)?;
    lo_rule.add_expr(Meta::new(MetaType::IifName));
    lo_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name("lo")));
    lo_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 5. Rule: Accept established and related connection tracking states
    let mut ct_rule = Rule::new(&filter_chain)?;
    ct_rule.add_expr(Conntrack::new(ConntrackKey::State));
    let state_mask = ConnTrackState::ESTABLISHED.bits() | ConnTrackState::RELATED.bits();
    ct_rule.add_expr(Cmp::new(CmpOp::Eq, state_mask.to_be_bytes()));
    ct_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 6. Rule: Accept input on LAN interface (needed for local services like DNS/DHCP)
    let mut lan_rule = Rule::new(&filter_chain)?;
    lan_rule.add_expr(Meta::new(MetaType::IifName));
    lan_rule.add_expr(Cmp::new(CmpOp::Eq, pad_interface_name(lan_iface)));
    lan_rule.add_expr(Immediate::new_verdict(VerdictKind::Accept));

    // 6.5. Rule: Accept ICMP on all interfaces (allows external/internal pings)
    let icmp_rule = Rule::new(&filter_chain)?.icmp().accept();

    // 7. Send configuration batch to the kernel
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&nat_chain, MsgType::Add);
    batch.add(&filter_chain, MsgType::Add);
    batch.add(&masq_rule, MsgType::Add);
    batch.add(&lo_rule, MsgType::Add);
    batch.add(&lan_rule, MsgType::Add);
    batch.add(&icmp_rule, MsgType::Add);
    batch.add(&ct_rule, MsgType::Add);

    batch.send()?;
    println!("[netfilter] NAT and firewall rules configured successfully.");

    Ok(())
}
