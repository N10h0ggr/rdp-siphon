# RDP Siphon

**RDP Siphon** is a Rust-based proof-of-concept DLL designed for educational purposes to explore low-level Windows hooking and credential interception using **hardware breakpoints (HWBP)**.

When injected into an RDP-related process, it installs breakpoint hooks to monitor and extract credential data (server name, username, and password) from memory buffers. The captured credentials are written to a file named `Creds.bin` on the desktop for analysis.

> **Note:** This project is tested on **Windows 10** only. It has not been tested on Windows 11 or Windows Server. The primary compatibility issue observed is missing libraries at `mstsc.exe` startup.

## ⚙️ Technical Overview

* Implements detours for RDP credential functions.
* Uses hardware breakpoints for memory interception (via an external HWBP library).
* Captures UTF-16 strings and byte buffers safely using synchronized data structures.
* Writes extracted credentials in a structured format for offline review.
* DLL entry point (`DllMain`) automatically installs and uninstalls hooks on attach/detach events.

## 🧩 Dependencies

This project depends on my **hardware breakpoint library**, which can be found here:
[https://github.com/N10h0ggr/RustMalDev/tree/main/hooking/hwbp](https://github.com/N10h0ggr/RustMalDev/tree/main/hooking/hwbp)

## 🧱 Compilation

To build the DLL:

```bash
cargo build --release
```

The compiled DLL will be located at:

```
target\release\rdp_siphon.dll
```

If you encounter errors about missing dependencies, ensure your environment includes:

* **Rust (stable)**
* **Windows SDK / Build tools**
* The **HWBP** library available to Cargo (via local path or git dependency)

Example `Cargo.toml` dependency:

```toml
[dependencies]
hwbp = { path = "../path/to/hwbp" }
windows-sys = "0.59"
```

## 🚀 Usage

1. Inject the compiled DLL (`rdp_siphon.dll`) into an RDP-related process (for instance, `mstsc.exe`) using any standard DLL injector. Process Hacker or the newer System Informer are valid for testing.

2. Once loaded, the DLL installs HWBP hooks that intercept RDP credential routines.

3. Start a RDP connection. Captured credentials are written to a file named:

   ```
   Creds.bin
   ```

   This file will be created on the desktop of the active user.

4. To stop capturing, unload or detach the DLL from the target process. Killing the process also unloads the hooks (obviously)

## 🎥 Demo
<p align="center">
  <video controls width="720">
    <source src="https://raw.githubusercontent.com/N10h0ggr/rdp-siphon/main/demo.mp4" type="video/mp4">
    Your browser does not support the video tag.
  </video>
</p>

