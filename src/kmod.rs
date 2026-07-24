use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Tracks already-loaded kernel modules in user-space.
/// While the Linux kernel handles duplicate loads safely by returning `EEXIST` (which we catch and ignore),
/// caching loaded modules here prevents redundant disk I/O and expensive decompression CPU cycles (e.g. gzip/xz/zstd).
static LOADED_MODULES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn get_loaded_modules() -> &'static Mutex<HashSet<String>> {
    LOADED_MODULES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Resolves the active kernel release name.
fn get_kernel_release() -> String {
    if let Ok(uts) = nix::sys::utsname::uname()
        && let Some(release) = uts.release().to_str()
    {
        return release.to_string();
    }
    String::new()
}

fn find_module_recursive(dir: &Path, base_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && let Some(found) = find_module_recursive(&path, base_name)
        {
            return Some(found);
        }
        if !path.is_dir()
            && let Some(file_name_str) = path.file_name().and_then(|n| n.to_str())
        {
            let stem = file_name_str.split('.').next().unwrap_or(file_name_str);
            let target_stem = base_name.split('.').next().unwrap_or(base_name);
            if stem == target_stem {
                return Some(path);
            }
        }
    }
    None
}

fn find_module_file(name: &str) -> Option<PathBuf> {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return None;
    }
    let modules_dir = Path::new("/lib/modules").join(kdir);
    let base_name = format!("{}.ko", name);
    find_module_recursive(&modules_dir, &base_name)
}

fn decompress_module(data: &[u8], path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    match extension {
        "xz" => {
            let mut decompressed = Vec::new();
            let mut cursor = std::io::Cursor::new(data);
            lzma_rs::xz_decompress(&mut cursor, &mut decompressed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(decompressed)
        }
        "gz" => {
            use std::io::Read;
            let mut decompressed = Vec::new();
            let mut decoder = flate2::read::GzDecoder::new(data);
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "zst" => {
            let mut decompressed = Vec::new();
            let mut decoder = ruzstd::decoding::FrameDecoder::new();
            decoder
                .decode_all_to_vec(data, &mut decompressed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(decompressed)
        }
        _ => Ok(data.to_vec()),
    }
}

fn load_module(path: &Path) -> Result<(), std::io::Error> {
    println!("[init] Loading kernel module: {:?}", path);
    let raw_data = fs::read(path)?;
    let decompressed_data = decompress_module(&raw_data, path)?;

    let param = std::ffi::CString::new("").unwrap();
    if let Err(e) = nix::kmod::init_module(&decompressed_data, &param)
        && e != nix::errno::Errno::EEXIST
    {
        return Err(std::io::Error::other(e.to_string()));
    }
    Ok(())
}

fn load_single_module(mod_name: &str) {
    let path = match find_module_file(mod_name) {
        Some(p) => p,
        None => {
            println!(
                "[init] Module {} not found in /lib/modules, assuming built-in or not needed.",
                mod_name
            );
            return;
        }
    };

    if let Err(e) = load_module(&path) {
        eprintln!("[init] Failed to load module {}: {}", mod_name, e);
    } else {
        println!("[init] Successfully loaded module {}", mod_name);
    }
}

fn load_module_with_dependencies(mod_name: &str) {
    {
        let loaded = get_loaded_modules().lock().unwrap();
        if loaded.contains(mod_name) {
            return;
        }
    }

    let kdir = get_kernel_release();
    if kdir.is_empty() {
        load_single_module(mod_name);
        return;
    }

    let modules_dir = Path::new("/lib/modules").join(&kdir);
    let dep_file_path = modules_dir.join("modules.dep");

    if !dep_file_path.exists() {
        load_single_module(mod_name);
        return;
    }

    let content = match fs::read_to_string(&dep_file_path) {
        Ok(c) => c,
        Err(_) => {
            load_single_module(mod_name);
            return;
        }
    };

    let mut found = false;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        let mod_path_str = parts[0].trim();
        let mod_path = Path::new(mod_path_str);
        let stem = match mod_path.file_name()
            .and_then(|f| f.to_str())
            .map(|f| f.split('.').next().unwrap_or(f))
        {
            Some(s) => s,
            None => continue,
        };

        if stem == mod_name {
            found = true;
            let mut deps = Vec::new();
            if parts.len() > 1 {
                for dep in parts[1].split_whitespace() {
                    deps.push(dep.trim());
                }
            }
            // Load dependencies in reverse order (right-to-left in modules.dep)
            // to ensure leaf dependencies are loaded before the modules that depend on them.
            for dep in deps.iter().rev() {
                let dep_path = modules_dir.join(dep);
                let dep_stem = dep_path.file_name()
                    .and_then(|f| f.to_str())
                    .map(|f| f.split('.').next().unwrap_or(f))
                    .unwrap_or("");
                
                let loaded = get_loaded_modules().lock().unwrap();
                if !loaded.contains(dep_stem) {
                    drop(loaded);
                    if let Err(e) = load_module(&dep_path) {
                        eprintln!("[init] Failed to load dependency {} ({:?}): {}", dep_stem, dep_path, e);
                    } else {
                        println!("[init] Successfully loaded dependency {}", dep_stem);
                        get_loaded_modules().lock().unwrap().insert(dep_stem.to_string());
                    }
                }
            }

            // Load the module itself
            let full_path = modules_dir.join(mod_path);
            let loaded = get_loaded_modules().lock().unwrap();
            if !loaded.contains(mod_name) {
                drop(loaded);
                if let Err(e) = load_module(&full_path) {
                    eprintln!("[init] Failed to load module {} ({:?}): {}", mod_name, full_path, e);
                } else {
                    println!("[init] Successfully loaded module {}", mod_name);
                    get_loaded_modules().lock().unwrap().insert(mod_name.to_string());
                }
            }
            break;
        }
    }

    if !found {
        load_single_module(mod_name);
    }
}

pub fn load_required_modules() {
    let modules = [
        "virtio_net",
        "virtio_pci",
        "virtio_mmio",
        "nft_masq",
        "nft_chain_nat",
        "nft_ct",
    ];

    for mod_name in &modules {
        load_module_with_dependencies(mod_name);
    }
}

fn parse_args_for_mod_name(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return iter.next().cloned();
        }
        if !arg.starts_with('-') && arg != "modprobe" {
            return Some(arg.clone());
        }
    }
    None
}

fn wildcard_match(pattern: &[char], input: &[char]) -> bool {
    if pattern.is_empty() {
        return input.is_empty();
    }
    if pattern[0] == '*' {
        if pattern.len() == 1 {
            return true;
        }
        for i in 0..=input.len() {
            if wildcard_match(&pattern[1..], &input[i..]) {
                return true;
            }
        }
        return false;
    }
    if input.is_empty() {
        return false;
    }
    if pattern[0] == '?' || pattern[0] == input[0] {
        return wildcard_match(&pattern[1..], &input[1..]);
    }
    false
}

fn resolve_alias(alias_or_name: &str) -> String {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return alias_or_name.to_string();
    }
    let alias_file_path = Path::new("/lib/modules").join(kdir).join("modules.alias");
    if !alias_file_path.exists() {
        return alias_or_name.to_string();
    }

    let content = match fs::read_to_string(&alias_file_path) {
        Ok(c) => c,
        Err(_) => return alias_or_name.to_string(),
    };

    let input_chars: Vec<char> = alias_or_name.chars().collect();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "alias" {
            let pattern = parts[1];
            let module_name = parts[2];
            let pattern_chars: Vec<char> = pattern.chars().collect();
            if wildcard_match(&pattern_chars, &input_chars) {
                println!("[modprobe] Resolved alias {} to module {}", alias_or_name, module_name);
                return module_name.to_string();
            }
        }
    }

    alias_or_name.to_string()
}

pub fn run_as_modprobe(args: Vec<String>) -> Result<(), std::io::Error> {
    let raw_name = match parse_args_for_mod_name(&args) {
        Some(name) => name,
        None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing module name")),
    };

    let mod_name = resolve_alias(&raw_name);
    println!("[modprobe] Request to load module: {}", mod_name);
    load_module_with_dependencies(&mod_name);
    Ok(())
}
