package tun

// Windows runtime requirement: wintun.dll
//
// On Windows the wireguard/tun package loads wintun.dll at runtime via
// LoadLibrary. The DLL is NOT bundled — it must be present on disk
// somewhere the loader will find it:
//
//   1. The directory containing the .exe (recommended for distribution).
//   2. Any directory listed in %PATH%.
//
// Download the official Wintun build from https://www.wintun.net/, pick
// the architecture matching the binary (amd64 / arm64) and copy
// wintun.dll next to vpn-server.exe / vpn-client.exe.
//
// Run the binaries from an elevated (Administrator) shell — wintun adapter
// creation and netsh address assignment both require it.
//
// Linux / macOS have no equivalent runtime dependency; the TUN driver is
// in the kernel. They do still need root for adapter creation and
// `ip` / `ifconfig` invocation.
