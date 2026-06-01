//go:build darwin

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred returns the user and (primary) group IDs of the process on the
// other end of the unix socket, as recorded by the kernel (LOCAL_PEERCRED).
// macOS reports the peer's effective uid and group list in an xucred; the
// first group entry is the effective gid.
func peerCred(conn *net.UnixConn) (uid, gid uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("ipc: syscall conn: %w", err)
	}
	var (
		xucred *unix.Xucred
		operr  error
	)
	if cerr := raw.Control(func(fd uintptr) {
		xucred, operr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); cerr != nil {
		return 0, 0, fmt.Errorf("ipc: control: %w", cerr)
	}
	if operr != nil {
		return 0, 0, fmt.Errorf("ipc: getsockopt LOCAL_PEERCRED: %w", operr)
	}
	gid = 0
	if xucred.Ngroups > 0 {
		gid = xucred.Groups[0]
	}
	return xucred.Uid, gid, nil
}
