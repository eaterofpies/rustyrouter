use nix::mount::MsFlags;
use nix::sys::reboot::RebootMode;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::fs;
use std::panic;
use std::sync::Arc;
use std::time::Duration;

pub trait SystemOps: Send + Sync + 'static {
    fn mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: &str,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<(), nix::Error>;

    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error>;

    fn waitpid(&self, pid: Option<Pid>, options: Option<WaitPidFlag>) -> Result<WaitStatus, nix::Error>;

    fn read_cmdline(&self) -> Result<String, std::io::Error>;

    fn getpid(&self) -> Pid;
}

pub struct RealSystem;

impl SystemOps for RealSystem {
    fn mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: &str,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<(), nix::Error> {
        if self.getpid() != Pid::from_raw(1) {
            println!("[sys] Skipping mount of {} -> {} (not PID 1)", fstype, target);
            return Ok(());
        }
        nix::mount::mount(source, target, Some(fstype), flags, data)
    }

    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
        nix::sys::reboot::reboot(mode).map(|_| ())
    }

    fn waitpid(&self, pid: Option<Pid>, options: Option<WaitPidFlag>) -> Result<WaitStatus, nix::Error> {
        nix::sys::wait::waitpid(pid, options)
    }

    fn read_cmdline(&self) -> Result<String, std::io::Error> {
        fs::read_to_string("/proc/cmdline")
    }

    fn getpid(&self) -> Pid {
        nix::unistd::getpid()
    }
}

pub fn mount_virtual_filesystems<S: SystemOps>(sys: &S) -> Result<(), String> {
    println!("[init] Mounting virtual filesystems...");

    sys.mount(None, "/proc", "proc", MsFlags::empty(), None)
        .map_err(|e| format!("Failed to mount /proc: {}", e))?;
    println!("[init] Mounted /proc successfully.");

    sys.mount(None, "/sys", "sysfs", MsFlags::empty(), None)
        .map_err(|e| format!("Failed to mount /sys: {}", e))?;
    println!("[init] Mounted /sys successfully.");

    sys.mount(None, "/dev", "devtmpfs", MsFlags::empty(), None)
        .map_err(|e| format!("Failed to mount /dev: {}", e))?;
    println!("[init] Mounted /dev successfully.");

    sys.mount(None, "/run", "tmpfs", MsFlags::empty(), None)
        .map_err(|e| format!("Failed to mount /run: {}", e))?;
    println!("[init] Mounted /run successfully.");

    Ok(())
}

pub fn register_panic_handler<S: SystemOps>(sys: Arc<S>) {
    panic::set_hook(Box::new(move |info| {
        eprintln!("====================================================");
        eprintln!("CRITICAL: RUSTYROUTER PANICKED!");
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            eprintln!("Panic Cause: {}", s);
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            eprintln!("Panic Cause: {}", s);
        } else {
            eprintln!("Panic Cause: Unknown");
        }
        if let Some(loc) = info.location() {
            eprintln!("Location: {}:{}:{}", loc.file(), loc.line(), loc.column());
        }
        eprintln!("====================================================");
        eprintln!("[init] Triggering emergency reboot...");

        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);

        // Fail-safe infinite loop in case reboot hangs (only if we are PID 1)
        if sys.getpid() == Pid::from_raw(1) {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }));
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    pub struct MockSystem {
        pub pid: Pid,
        pub cmdline_content: String,
        pub mount_calls: Mutex<Vec<(Option<String>, String, String, MsFlags)>>,
        pub reboot_call: Mutex<Option<RebootMode>>,
        pub waitpid_results: Mutex<Vec<Result<WaitStatus, nix::Error>>>,
    }

    impl MockSystem {
        pub fn new() -> Self {
            MockSystem {
                pid: Pid::from_raw(1),
                cmdline_content: "".to_string(),
                mount_calls: Mutex::new(Vec::new()),
                reboot_call: Mutex::new(None),
                waitpid_results: Mutex::new(Vec::new()),
            }
        }
    }

    impl SystemOps for MockSystem {
        fn mount(
            &self,
            source: Option<&str>,
            target: &str,
            fstype: &str,
            flags: MsFlags,
            _data: Option<&str>,
        ) -> Result<(), nix::Error> {
            self.mount_calls.lock().unwrap().push((
                source.map(|s| s.to_string()),
                target.to_string(),
                fstype.to_string(),
                flags,
            ));
            Ok(())
        }

        fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
            *self.reboot_call.lock().unwrap() = Some(mode);
            Ok(())
        }

        fn waitpid(&self, _pid: Option<Pid>, _options: Option<WaitPidFlag>) -> Result<WaitStatus, nix::Error> {
            let mut list = self.waitpid_results.lock().unwrap();
            if list.is_empty() {
                Ok(WaitStatus::StillAlive)
            } else {
                list.remove(0)
            }
        }

        fn read_cmdline(&self) -> Result<String, std::io::Error> {
            if self.cmdline_content.is_empty() {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No cmdline mock"))
            } else {
                Ok(self.cmdline_content.clone())
            }
        }

        fn getpid(&self) -> Pid {
            self.pid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockSystem;
    use super::*;

    #[test]
    fn test_vfs_mounting() {
        let sys = MockSystem::new();
        let result = mount_virtual_filesystems(&sys);

        assert!(result.is_ok());
        let calls = sys.mount_calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].1, "/proc");
        assert_eq!(calls[0].2, "proc");
        assert_eq!(calls[1].1, "/sys");
        assert_eq!(calls[1].2, "sysfs");
        assert_eq!(calls[2].1, "/dev");
        assert_eq!(calls[2].2, "devtmpfs");
        assert_eq!(calls[3].1, "/run");
        assert_eq!(calls[3].2, "tmpfs");
    }

    #[test]
    fn test_emergency_reboot_on_panic() {
        let mut sys = MockSystem::new();
        // Set PID to non-1 so it returns from panic hook without infinite sleeping
        sys.pid = Pid::from_raw(99);
        let sys = Arc::new(sys);

        register_panic_handler(sys.clone());

        let handle = std::thread::spawn(move || {
            panic!("Test panic exception");
        });

        let _ = handle.join(); // This will return immediately now

        let reboot_called = sys.reboot_call.lock().unwrap();
        assert_eq!(*reboot_called, Some(RebootMode::RB_AUTOBOOT));
    }
}

use std::path::Path;

fn find_file_recursive(dir: &Path, filename: &str) -> Option<std::path::PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(found) = check_path(&path, filename) {
            return Some(found);
        }
    }
    None
}

fn check_path(path: &Path, filename: &str) -> Option<std::path::PathBuf> {
    if path.is_dir() {
        return find_file_recursive(path, filename);
    }
    if path.file_name() == Some(std::ffi::OsStr::new(filename)) {
        return Some(path.to_path_buf());
    }
    None
}

fn find_module_file(name: &str) -> Option<std::path::PathBuf> {
    let modules_dir = Path::new("/lib/modules");
    let filename = format!("{}.ko", name);
    find_file_recursive(modules_dir, &filename)
}

fn load_module(path: &Path) -> Result<(), std::io::Error> {
    println!("[init] Loading kernel module: {:?}", path);
    let file = fs::File::open(path)?;
    
    let param = std::ffi::CString::new("").unwrap();
    if let Err(e) = nix::kmod::finit_module(&file, &param, nix::kmod::ModuleInitFlags::empty()) {
        if e != nix::errno::Errno::EEXIST {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    }
    Ok(())
}

fn load_single_module(mod_name: &str) {
    let path = match find_module_file(mod_name) {
        Some(p) => p,
        None => {
            println!("[init] Module {} not found in /lib/modules, assuming built-in or not needed.", mod_name);
            return;
        }
    };

    if let Err(e) = load_module(&path) {
        eprintln!("[init] Failed to load module {}: {}", mod_name, e);
    } else {
        println!("[init] Successfully loaded module {}", mod_name);
    }
}

pub fn load_required_modules() {
    let modules = [
        "failover",
        "net_failover",
        "virtio_net",
        "nfnetlink",
        "libcrc32c",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_tables",
        "nf_conntrack",
        "nf_nat",
        "nft_ct",
        "nft_chain_nat",
        "nft_masq",
    ];

    for mod_name in &modules {
        load_single_module(mod_name);
    }
}
