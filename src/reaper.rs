use crate::system::SystemOps;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, Duration};

pub async fn start_orphan_reaper<S: SystemOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    println!("[reaper] Starting orphan process reaper task...");
    
    let mut sigchld_stream = match signal(SignalKind::child()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[reaper] Error creating SIGCHLD stream: {}. Falling back to polling.", e);
            while !shutdown_flag.load(Ordering::Relaxed) {
                reap_zombies(sys.as_ref());
                sleep(Duration::from_millis(500)).await;
            }
            return;
        }
    };

    while !shutdown_flag.load(Ordering::Relaxed) {
        tokio::select! {
            _ = sigchld_stream.recv() => {
                reap_zombies(sys.as_ref());
            }
            _ = sleep(Duration::from_secs(5)) => {
                reap_zombies(sys.as_ref());
            }
        }
    }
}

pub fn reap_zombies<S: SystemOps>(sys: &S) {
    loop {
        match sys.waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) => {
                println!("[reaper] Reaped child process (PID {}) which exited with status {}", pid, code);
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                println!("[reaper] Reaped child process (PID {}) which terminated with signal {}", pid, sig);
            }
            Ok(WaitStatus::StillAlive) => {
                break;
            }
            Err(nix::Error::ECHILD) => {
                break;
            }
            Err(e) => {
                eprintln!("[reaper] waitpid error: {}", e);
                break;
            }
            _ => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::mock::MockSystem;

    #[test]
    fn test_zombie_reaping() {
        let sys = MockSystem::new();
        
        {
            let mut results = sys.waitpid_results.lock().unwrap();
            results.push(Ok(WaitStatus::Exited(Pid::from_raw(42), 0)));
            results.push(Ok(WaitStatus::Signaled(Pid::from_raw(43), nix::sys::signal::Signal::SIGKILL, false)));
            results.push(Err(nix::Error::ECHILD));
        }

        reap_zombies(&sys);

        let results = sys.waitpid_results.lock().unwrap();
        assert_eq!(results.len(), 0);
    }
}
