//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
	"os"
)

// dialControl connects to the daemon's unix-domain control socket.
//
// The connection carries the client's private key in the ConnectRequest, so
// after connecting we verify the daemon on the other end is owned by root —
// the real daemon — or by us (we can't be phished by our own socket).
// Checking the connected peer's kernel-reported credentials (SO_PEERCRED /
// LOCAL_PEERCRED, the same call the server uses on us) rather than the socket
// file's owner avoids the TOCTOU race a stat-then-dial check would have: the
// file could be swapped between the stat and the dial. The default path under
// /run is additionally protected by directory permissions; this guards custom
// paths in world-writable directories like /tmp.
func dialControl(path string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: connect to %q: %w (is vpn-helper running?)", path, err)
	}
	uconn, ok := conn.(*net.UnixConn)
	if !ok { // net.Dial("unix", ...) always yields *net.UnixConn
		_ = conn.Close()
		return nil, fmt.Errorf("ipc: unexpected connection type %T for %q", conn, path)
	}
	uid, _, err := peerCred(uconn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ipc: cannot verify daemon identity on %q: %w", path, err)
	}
	if !socketOwnerAllowed(uid, uint32(os.Getuid())) {
		_ = conn.Close()
		return nil, fmt.Errorf("ipc: refusing %q: daemon runs as uid %d (not root or you) — possible impersonation", path, uid)
	}
	return conn, nil
}

// socketOwnerAllowed reports whether a daemon running as ownerUID may be
// trusted by a client running as selfUID: root or self only.
func socketOwnerAllowed(ownerUID, selfUID uint32) bool {
	return ownerUID == 0 || ownerUID == selfUID
}
