//go:build linux || darwin

package ipc

import (
	"fmt"
	"log/slog"
	"net"
	"os"
)

// Listen creates a unix-domain socket at path and returns a listener that
// admits only peers permitted by policy. Each accepted connection's peer
// credentials are read from the kernel (SO_PEERCRED on Linux,
// LOCAL_PEERCRED on macOS) and checked before the connection is handed to
// the caller; rejected peers are closed and Accept moves on.
//
// A stale socket file left by a previous run is removed first. The socket
// is created with the given file mode — filesystem permissions are a first
// gate, and the peer-credential check is the authority on top of it.
func Listen(path string, mode os.FileMode, policy Policy, log *slog.Logger) (net.Listener, error) {
	if log == nil {
		log = slog.Default()
	}
	// Remove a leftover socket so net.Listen doesn't fail with "address
	// already in use". Only unlink an existing socket, never a regular file.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: refusing to remove non-socket at %q", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %q: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("ipc: chmod socket: %w", err)
	}

	ul, ok := ln.(*net.UnixListener)
	if !ok { // net.Listen("unix", ...) always returns *net.UnixListener
		_ = ln.Close()
		return nil, fmt.Errorf("ipc: unexpected listener type %T", ln)
	}
	return &authListener{UnixListener: ul, policy: policy, log: log}, nil
}

// authListener filters accepted connections by peer credentials.
type authListener struct {
	*net.UnixListener
	policy Policy
	log    *slog.Logger
}

func (l *authListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, gid, err := peerCred(conn)
		if err != nil {
			l.log.Warn("ipc: cannot read peer credentials; rejecting", "err", err)
			_ = conn.Close()
			continue
		}
		if !l.policy.allow(uid, gid) {
			l.log.Warn("ipc: rejected unauthorized peer", "uid", uid, "gid", gid)
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
