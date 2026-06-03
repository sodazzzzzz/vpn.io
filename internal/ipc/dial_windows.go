//go:build windows

package ipc

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// dialControl connects to the daemon's named-pipe control endpoint.
//
// SECURITY TODO: unlike the unix build (which checks the daemon's peer
// credentials to confirm it runs as root or the caller), this does not yet
// verify the pipe server's identity. The pipe's SDDL restricts who may connect,
// but a client should also confirm the server runs as SYSTEM/Administrators to
// defeat a non-privileged process squatting the pipe name before the helper
// starts. Tracked as a follow-up once we can test on Windows.
func dialControl(path string) (net.Conn, error) {
	timeout := dialTimeout
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: connect to %q: %w (is vpn-helper running?)", path, err)
	}
	return conn, nil
}
