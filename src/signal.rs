use crate::system::SystemOps;
use nix::sys::reboot::RebootMode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, Duration};

pub async fn start_signal_monitor<S: SystemOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    println!("[init] Starting system signal monitor...");

    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to bind SIGINT");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind SIGTERM");
    let mut sigpwr = signal(SignalKind::from_raw(libc::SIGPWR)).expect("Failed to bind SIGPWR");

    let received_signal = tokio::select! {
        _ = sigint.recv() => "SIGINT (Interrupt)",
        _ = sigterm.recv() => "SIGTERM (Termination)",
        _ = sigpwr.recv() => "SIGPWR (Power Down)",
    };

    println!("[init] Received system signal: {}", received_signal);
    println!("[init] Performing clean shutdown...");

    shutdown_flag.store(true, Ordering::Relaxed);

    // Placeholder for interface and firewall teardown
    println!("[init] Tearing down interfaces and rules...");

    sleep(Duration::from_millis(500)).await;

    println!("[init] Executing system poweroff...");
    if let Err(e) = sys.reboot(RebootMode::RB_POWER_OFF) {
        eprintln!("[init] Poweroff failed: {}. Falling back to default reboot.", e);
        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
    }
}
