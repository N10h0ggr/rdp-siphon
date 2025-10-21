use std::{io, ptr};
use std::ffi::{c_void, CString};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::UI::Shell::{SHGetFolderPathW, CSIDL_DESKTOPDIRECTORY};

/// Attempts to resolve the address of an exported function from a DLL.
///
/// If the module is not already loaded, this implementation currently returns
/// an error instead of loading it dynamically (the `LoadLibraryA` call is
/// commented out for Windows 11 compatibility).
///
/// # Arguments
/// * `dll_name` - The name of the target DLL (e.g., `"kernel32.dll"`).
/// * `function_name` - The name of the exported function to locate.
///
/// # Returns
/// * `Ok(pointer)` - A pointer to the resolved function.
/// * `Err(String)` - An error message if the lookup fails.
///
/// # Safety
/// This function calls Windows API functions and performs raw pointer
/// operations. The returned pointer must only be called or dereferenced
/// with extreme care.
pub(crate) fn get_address(dll_name: &str, function_name: &str) -> Result<*const c_void, String> {
    // Convert Rust strings to C-compatible strings.
    let dll_c = CString::new(dll_name).map_err(|_| "invalid dll name")?;
    let sym_c = CString::new(function_name).map_err(|_| "invalid function name")?;

    unsafe {
        // Try to get a handle to the already-loaded module.
        let mut hmod = GetModuleHandleA(dll_c.as_ptr() as *const u8);

        // NOTE: For some Windows 11 builds, certain DLLs (like crypt32.dll)
        // are not loaded at startup. LoadLibraryA could be uncommented if needed.
        if hmod.is_null() {
            // Return an error since module loading is disabled here.
            return Err(format!("LoadLibraryA failed for {}", dll_name));
        }

        // Attempt to get the function’s address from the module.
        let proc = GetProcAddress(hmod, sym_c.as_ptr() as *const u8);
        match proc {
            None => Err(format!("GetProcAddress({}, {}) failed", dll_name, function_name)),
            Some(func) => Ok(func as *const c_void),
        }
    }
}

/// Returns the length of a null-terminated UTF-16 string (wide string).
///
/// Equivalent to `wcslen()` in C.
///
/// # Safety
/// The pointer `s` must be valid and point to a readable memory region
/// containing a null-terminated UTF-16 sequence.
#[inline]
pub fn wcslen(mut s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    unsafe {
        // Iterate until the null terminator (0) is found.
        while *s != 0 {
            n += 1;
            s = s.add(1);
        }
    }
    n
}

/// Retrieves the path to the current user's desktop directory.
///
/// Uses the Windows Shell API function `SHGetFolderPathW` to obtain the
/// physical path corresponding to `CSIDL_DESKTOPDIRECTORY`.
///
/// # Returns
/// * `Ok(PathBuf)` - Path to the desktop directory.
/// * `Err(io::Error)` - If the API call fails.
pub fn desktop_path() -> io::Result<PathBuf> {
    let mut buf = [0u16; MAX_PATH as usize];

    // S_OK == 0 indicates success.
    let hr = unsafe {
        SHGetFolderPathW(
            ptr::null_mut(),
            CSIDL_DESKTOPDIRECTORY as i32,
            ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
        )
    };

    // Any non-zero HRESULT indicates failure.
    if hr != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "SHGetFolderPathW failed",
        ));
    }

    // Find the null terminator and convert UTF-16 to a PathBuf.
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(std::ffi::OsString::from_wide(&buf[..len]).into())
}

/// Converts a UTF-8 Rust string (`&str`) into a UTF-16 little-endian byte vector.
///
/// Each UTF-16 code unit is split into two bytes in little-endian order.
#[inline]
pub fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for w in s.encode_utf16() {
        // Split the 16-bit word into two 8-bit bytes (little-endian order).
        let [lo, hi] = w.to_le_bytes();
        out.push(lo);
        out.push(hi);
    }
    out
}

/// Converts a UTF-16 little-endian byte slice back into a `String`.
///
/// If the byte length is odd or too short, returns an empty string.
/// Null-terminated sequences are handled by trimming the trailing `0`.
#[inline]
pub fn utf16le_bytes_to_string(bytes: &[u8]) -> String {
    // Early return for invalid input.
    if bytes.len() < 2 {
        return String::new();
    }

    // Combine every two bytes into a single UTF-16 code unit.
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    // Remove null terminator if present.
    if u16s.last().copied() == Some(0) {
        let _ = u16s.pop();
    }

    // Convert UTF-16 vector into a Rust `String`, replacing invalid sequences.
    String::from_utf16_lossy(&u16s)
}
