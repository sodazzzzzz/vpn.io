//go:build windows

package ipc

import "net"

// dialControl is not implemented on Windows yet: the named-pipe transport
// (the analogue of the unix socket) lands together with its listener. The
// signature matches the unix build so cmd/vpn-ctl compiles on all targets.
func dialControl(path string) (net.Conn, error) {
	_ = path
	return nil, ErrTransportUnsupported
}
