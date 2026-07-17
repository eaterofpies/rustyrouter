use crate::system::SystemOps;
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub wan_interface: String,
    pub lan_interface: String,
    pub lan_ip: String,
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Self {
        // 1. Check environment variable overrides first (useful for testing/dev namespaces)
        let wan = env::var("RUSTYROUTER_WAN").ok();
        let lan = env::var("RUSTYROUTER_LAN").ok();
        let lan_ip = env::var("RUSTYROUTER_LAN_IP").ok();

        if let (Some(w), Some(l), Some(ip)) = (wan, lan, lan_ip) {
            println!("[config] Using environment variable overrides");
            return RouterConfig {
                wan_interface: w,
                lan_interface: l,
                lan_ip: ip,
            };
        }

        // 2. Parse from /proc/cmdline
        let mut parsed_wan = None;
        let mut parsed_lan = None;
        let mut parsed_lan_ip = None;

        if let Ok(cmdline) = sys.read_cmdline() {
            println!("[config] Read /proc/cmdline: {}", cmdline.trim());
            for arg in cmdline.split_whitespace() {
                if let Some(val) = arg.strip_prefix("rustyrouter.wan=") {
                    parsed_wan = Some(val.to_string());
                } else if let Some(val) = arg.strip_prefix("rustyrouter.lan=") {
                    parsed_lan = Some(val.to_string());
                } else if let Some(val) = arg.strip_prefix("rustyrouter.lan_ip=") {
                    parsed_lan_ip = Some(val.to_string());
                }
            }
        } else {
            println!("[config] Failed to read /proc/cmdline, using automatic fallback");
        }

        // 3. Apply parsed config or automatic fallbacks
        RouterConfig {
            wan_interface: parsed_wan.unwrap_or_else(|| "eth0".to_string()),
            lan_interface: parsed_lan.unwrap_or_else(|| "eth1".to_string()),
            lan_ip: parsed_lan_ip.unwrap_or_else(|| "192.168.1.1/24".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::mock::MockSystem;

    #[test]
    fn test_config_parsing_defaults() {
        let sys = MockSystem::new();
        let config = RouterConfig::parse(&sys);

        assert_eq!(config.wan_interface, "eth0");
        assert_eq!(config.lan_interface, "eth1");
        assert_eq!(config.lan_ip, "192.168.1.1/24");
    }

    #[test]
    fn test_config_parsing_from_cmdline() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "BOOT_IMAGE=/boot/vmlinuz console=ttyS0 rustyrouter.wan=wan0 rustyrouter.lan=lan0 rustyrouter.lan_ip=10.0.0.1/24 quiet".to_string();

        let config = RouterConfig::parse(&sys);
        assert_eq!(config.wan_interface, "wan0");
        assert_eq!(config.lan_interface, "lan0");
        assert_eq!(config.lan_ip, "10.0.0.1/24");
    }
}
