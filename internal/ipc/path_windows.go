//go:build windows

package ipc

// DefaultControlPath is the daemon's default control endpoint: a named pipe.
func DefaultControlPath() string { return `\\.\pipe\vpn-io-helper` }
