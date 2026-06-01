//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// dialControl connects to the daemon's unix-domain control socket.
//
// The connection carries the client's private key in the ConnectRequest, so
// before dialing we check the socket isn't an impostor planted by another
// user: it must be owned by root (the real daemon) or by us (we can't be
// phished by our own socket). The default path under /run is already
// protected by directory permissions; this guards custom paths in
// world-writable directories like /tmp. A path that doesn't exist yet falls
// through to DialTimeout, which reports a clear "is vpn-helper running?".
func dialControl(path string) (net.Conn, error) {
	if fi, err := os.Lstat(path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && !socketOwnerAllowed(st.Uid, uint32(os.Getuid())) {
			return nil, fmt.Errorf("ipc: refusing %q: socket owned by uid %d (not root or you) — possible impersonation", path, st.Uid)
		}
	}
	conn, err := net.DialTimeout("unix", path, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: connect to %q: %w (is vpn-helper running?)", path, err)
	}
	return conn, nil
}

// socketOwnerAllowed reports whether a control socket owned by ownerUID may
// be trusted by a client running as selfUID: root or self only.
func socketOwnerAllowed(ownerUID, selfUID uint32) bool {
	return ownerUID == 0 || ownerUID == selfUID
}
