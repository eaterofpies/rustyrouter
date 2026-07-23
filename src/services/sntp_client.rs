use super::utils::WanLease;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds

const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes

pub async fn start_sntp_client(lease_state: Arc<Mutex<WanLease>>) {
    println!("[sntp-client] Starting NTP time synchronization service...");

    let mut current_retry_delay = RETRY_INTERVAL;

    loop {
        // 1. Wait until we have a WAN IP to ensure internet connectivity
        let has_wan = {
            let lease = lease_state.lock().unwrap();
            lease.ip.is_some()
        };

        if !has_wan {
            tokio::time::sleep(Duration::from_secs(5)).await;
            current_retry_delay = RETRY_INTERVAL; // Reset delay when WAN is lost
            continue;
        }

        // 2. Perform SNTP sync using rsntp library
        match sync_time().await {
            Ok(time_now) => {
                println!(
                    "[sntp-client] Successfully synchronized system time: {}",
                    time_now
                );
                current_retry_delay = RETRY_INTERVAL; // Reset delay on success
                tokio::time::sleep(SYNC_INTERVAL).await;
            }
            Err(e) => {
                eprintln!(
                    "[sntp-client] Time synchronization failed: {}. Retrying in {}s...",
                    e,
                    current_retry_delay.as_secs()
                );
                tokio::time::sleep(current_retry_delay).await;

                // Double the retry delay up to MAX_RETRY_INTERVAL
                current_retry_delay = std::cmp::min(current_retry_delay * 2, MAX_RETRY_INTERVAL);
            }
        }
    }
}

async fn sync_time() -> Result<chrono::DateTime<chrono::Utc>, String> {
    // Resolve pool.ntp.org manually via local DNS forwarder
    let ntp_server_ip = super::utils::resolve_dns_a_record("pool.ntp.org").await?;
    let ntp_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ntp_server_ip), 123);

    // Synchronize using standard rsntp client
    let client = rsntp::AsyncSntpClient::new();
    let result = client
        .synchronize(ntp_addr)
        .await
        .map_err(|e| format!("NTP synchronization failed: {:?}", e))?;

    // Convert datetime using rsntp's integrated chrono feature
    let chrono_dt = result
        .datetime()
        .into_chrono_datetime()
        .map_err(|e| format!("Failed to convert NTP datetime: {}", e))?;

    let unix_secs = chrono_dt.timestamp();
    let nanosecs = chrono_dt.timestamp_subsec_nanos();

    // Update system clock via nix::time
    let timespec =
        nix::sys::time::TimeSpec::new(unix_secs as libc::time_t, nanosecs as libc::c_long);
    nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, timespec)
        .map_err(|e| format!("Failed to set system clock: {}", e))?;

    Ok(chrono_dt)
}
