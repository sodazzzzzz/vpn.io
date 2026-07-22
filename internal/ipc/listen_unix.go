//go:build linux || darwin

package ipc

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
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
//
// A custom socket path must sit in a directory only its owner can write to: the
// directory must be owned by root or the current user and not writable by anyone
// else. Otherwise Listen refuses — see checkSocketDirSafe.
func Listen(path string, mode os.FileMode, policy Policy, log *slog.Logger) (net.Listener, error) {
	if log == nil {
		log = slog.Default()
	}
	// Check the socket directory before removing a stale socket: in a directory
	// writable by others, the auto-removal is open to TOCTOU — the socket can be
	// swapped between Lstat and Remove. Refuse explicitly rather than silently
	// delete whatever is there.
	if err := checkSocketDirSafe(filepath.Dir(path)); err != nil {
		return nil, err
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

// checkSocketDirSafe ensures the socket directory can't be used by another user
// to swap in a rogue socket. A directory is safe when it is owned by root or the
// current user and writable by no one but its owner. A group- or world-writable
// directory without the sticky bit (e.g. "mkdir -m 0777", or a 0770 dir with an
// untrusted group) opens a TOCTOU window during the stale-socket auto-removal and
// is rejected. The default /var/run (root, 0755), a private user directory
// (0700), and sticky dirs like /tmp all pass.
func checkSocketDirSafe(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ipc: stat socket dir %q: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ipc: cannot inspect ownership of socket dir %q", dir)
	}
	// A foreign owner could swap both the directory and the socket inside it.
	if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("ipc: socket dir %q is owned by uid %d, expected root or self; use a root-only directory", dir, st.Uid)
	}
	// Group- or world-write without sticky lets someone else replace the socket.
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("ipc: refusing group/world-writable socket dir %q; use a directory writable only by its owner (or sticky)", dir)
	}
	return nil
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
