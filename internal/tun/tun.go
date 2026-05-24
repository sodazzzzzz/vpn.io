// Package tun creates and operates a virtual network adapter (TUN device)
// across Linux, Windows and macOS.
//
// The package exposes a deliberately small synchronous "one packet per
// Read/Write" API, hiding the batched interface of the underlying
// wireguard/tun library. For a learning-grade VPN this trades a small
// amount of throughput for code that reads like a regular byte stream.
//
// IP address configuration is split into [Configure], which shells out to
// OS-specific tools (ip/netsh/ifconfig). The caller must run with the
// privileges those tools require (root on Linux/macOS, Administrator on
// Windows).
//
// On Windows, the underlying wintun.dll must be discoverable — either next
// to the executable or somewhere on PATH. See doc.go for details.
package tun

// Device is the cross-platform handle to an open TUN adapter.
//
// Each successful Read returns exactly one IP packet (no link-layer
// framing). Each Write must contain exactly one IP packet. Concurrent
// Read and Write are safe; concurrent Reads (or concurrent Writes) are
// not — serialize them in the caller.
type Device interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Name() string
	MTU() int
	Close() error
}

// Open creates a new TUN device with the requested name and MTU.
//
// On Linux the kernel may rename the device (e.g. when name is empty or
// already taken); always use the returned Device.Name() afterwards.
// On Windows the name is the adapter's friendly name shown in "Network
// Connections". On macOS the name must match the utunN pattern or be empty.
func Open(name string, mtu int) (Device, error) {
	return openDevice(name, mtu)
}

// Configure assigns an IPv4 address and netmask to dev and brings it up.
//
// gateway is the peer/remote address of the point-to-point link. It is
// required on macOS (utun is strictly point-to-point) and ignored on
// Linux and Windows.
//
// Configure does not install any routes — routing is the caller's
// responsibility (see internal/tunnel for the server- and client-side
// route setup).
func Configure(dev Device, ip, netmask, gateway string) error {
	return configureDevice(dev.Name(), ip, netmask, gateway, dev.MTU())
}
