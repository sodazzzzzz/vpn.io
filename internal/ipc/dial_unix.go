//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
)

// dialControl connects to the daemon's unix-domain control socket.
func dialControl(path string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: connect to %q: %w (is vpn-helper running?)", path, err)
	}
	return conn, nil
}
