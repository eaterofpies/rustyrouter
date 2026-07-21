mod config;
mod netfilter;
mod network;
mod packet;
mod reaper;
mod services;
mod signal;
mod system;

use config::RouterConfig;
use nix::sys::reboot::RebootMode;
use nix::unistd::Pid;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use system::{RealSystem, SystemOps, mount_virtual_filesystems, register_panic_handler};

async fn start_power_button_monitor<S: SystemOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    println!("[init] Starting ACPI power button monitor...");
    for i in 0..5 {
        let path = format!("/dev/input/event{}", i);
        if let Ok(device) = evdev::Device::open(&path) {
            println!("[init] Monitoring power button input device: {}", path);
            let sys_clone = sys.clone();
            let shutdown_clone = shutdown_flag.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = device.into_event_stream() {
                    use futures_util::StreamExt;
                    while let Some(Ok(event)) = stream.next().await {
                        if event.event_type() == evdev::EventType::KEY
                            && event.code() == evdev::KeyCode::KEY_POWER.code()
                            && event.value() == 1
                        {
                            println!(
                                "\n[acpi] Power button pressed. Triggering system shutdown..."
                            );
                            shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                            let _ = sys_clone.reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF);
                            break;
                        }
                    }
                }
            });
        }
    }
}

#[tokio::main]
async fn main() {
    let sys = Arc::new(RealSystem);

    // For PID 1, redirect standard descriptors (0, 1, 2) to /dev/console
    if sys.getpid() == Pid::from_raw(1)
        && let Ok(console) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/console")
    {
        use std::os::unix::io::AsRawFd;
        let fd = console.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }

    println!("====================================================");
    println!("Starting rustyrouter (PID 1 Init Daemon)");
    println!("====================================================");

    // 1. Register Panic Hook (Emergency Reboot)
    register_panic_handler(sys.clone());

    // 2. Mount Filesystems if running as PID 1
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = mount_virtual_filesystems(sys.as_ref()) {
            eprintln!("[init] FATAL: {}", e);
            let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
            return;
        }
        system::load_required_modules();
    } else {
        println!(
            "[init] Running in standard user environment (PID {}). Skipping VFS mounts.",
            sys.getpid()
        );
    }

    // 3. Load Configuration
    let config = RouterConfig::parse(sys.as_ref());
    println!("[init] Configuration loaded: {:?}", config);

    // 4. Configure Network Interfaces (lo, LAN, WAN)
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) =
            network::configure_network(&config.wan_interface, &config.lan_interface, &config.lan_ip)
                .await
        {
            eprintln!(
                "[init] ERROR: Failed to configure network interfaces: {}",
                e
            );
        }

        if let Err(e) = netfilter::configure_firewall(&config.wan_interface, &config.lan_interface)
        {
            eprintln!("[init] FATAL: Failed to configure firewall: {}", e);
            let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
            return;
        }
    }

    // 5. Lifecycle coordination flag
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // 5. Spawn Core Tasks
    let reaper_sys = sys.clone();
    let reaper_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        reaper::start_orphan_reaper(reaper_sys, reaper_shutdown).await;
    });

    let sig_sys = sys.clone();
    let sig_shutdown = shutdown_flag.clone();
    let sig_handle = tokio::spawn(async move {
        signal::start_signal_monitor(sig_sys, sig_shutdown).await;
    });

    // Spawn ACPI Power Button Monitor
    let power_sys = sys.clone();
    let power_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        start_power_button_monitor(power_sys, power_shutdown).await;
    });

    // Shared state for the DHCP lease obtained on WAN
    let lease_state = Arc::new(std::sync::Mutex::new(services::WanLease::default()));

    // Spawn DHCP WAN Client
    let client_wan = config.wan_interface.clone();
    let client_lease = lease_state.clone();
    tokio::spawn(async move {
        services::start_dhcp_client(client_wan, client_lease).await;
    });

    // Spawn DHCP LAN Server
    let server_lan = config.lan_interface.clone();
    let server_lan_ip = config.lan_ip.clone();
    tokio::spawn(async move {
        services::start_dhcp_server(server_lan, server_lan_ip).await;
    });

    // Spawn DNS Forwarder
    let dns_lease = lease_state.clone();
    tokio::spawn(async move {
        services::start_dns_forwarder(dns_lease).await;
    });

    println!("[init] System startup completed successfully. Entering main event loop.");

    // Keep the main thread alive waiting for the signal handler to finish
    let _ = sig_handle.await;
}
