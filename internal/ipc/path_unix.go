//go:build linux || darwin

package ipc

// DefaultControlPath is the daemon's default control endpoint: a unix-domain
// socket. Packaged services may override it (e.g. /run/vpn-io/helper.sock).
func DefaultControlPath() string { return "/var/run/vpn-io-helper.sock" }
