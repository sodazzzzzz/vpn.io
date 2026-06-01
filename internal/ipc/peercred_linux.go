//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred returns the user and group IDs of the process on the other end
// of the unix socket, as recorded by the kernel at connect time
// (SO_PEERCRED). This cannot be spoofed by the peer.
func peerCred(conn *net.UnixConn) (uid, gid uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("ipc: syscall conn: %w", err)
	}
	var (
		ucred *unix.Ucred
		operr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		ucred, operr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil {
		return 0, 0, fmt.Errorf("ipc: control: %w", cerr)
	}
	if operr != nil {
		return 0, 0, fmt.Errorf("ipc: getsockopt SO_PEERCRED: %w", operr)
	}
	return ucred.Uid, ucred.Gid, nil
}
