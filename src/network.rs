use rtnetlink::Handle;
use std::net::IpAddr;
use std::str::FromStr;

pub async fn configure_network(
    wan_iface: &str,
    lan_iface: &str,
    lan_ip_cidr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Enable IPv4 Packet Forwarding
    println!("[network] Enabling IPv4 forwarding...");
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

    // 2. Open rtnetlink connection
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // 3. Configure Loopback ('lo') (Link UP only, kernel auto-assigns 127.0.0.1/8)
    println!("[network] Configuring loopback interface (lo)...");
    if let Err(e) = configure_interface(&handle, "lo", None).await {
        eprintln!("[network] Warning: Failed to configure loopback: {}", e);
    }

    // 4. Configure LAN interface
    println!(
        "[network] Configuring LAN interface ({}) with IP {}...",
        lan_iface, lan_ip_cidr
    );
    configure_interface(&handle, lan_iface, Some(lan_ip_cidr)).await?;

    // 5. Configure WAN interface (Link UP only)
    println!(
        "[network] Configuring WAN interface ({}) link UP...",
        wan_iface
    );
    configure_interface(&handle, wan_iface, None).await?;

    Ok(())
}

async fn configure_interface(
    handle: &Handle,
    name: &str,
    ip_cidr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get link index by name
    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(format!("Interface {} not found", name).into()),
        Err(e) => return Err(e.into()),
    };
    let index = link.header.index;

    // Set link state to UP
    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    // If an IP/CIDR is specified, assign it to the link index
    if let Some(cidr) = ip_cidr {
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip_str = parts[0];
        let prefix = if parts.len() > 1 {
            parts[1].parse::<u8>()?
        } else {
            24
        };
        let ip = IpAddr::from_str(ip_str)?;

        // Attempt to assign the address. If it's already assigned (EEXIST), ignore the error.
        match handle.address().add(index, ip, prefix).execute().await {
            Ok(_) => println!("[network] Successfully assigned {} to {}", cidr, name),
            Err(rtnetlink::Error::NetlinkError(msg)) if msg.code.map(|c| c.get()) == Some(-17) => {
                // Address already exists (EEXIST), ignore silently
            }
            Err(e) => {
                println!(
                    "[network] Address assignment message for {} ({}): {}",
                    name, cidr, e
                );
            }
        }
    }

    Ok(())
}
