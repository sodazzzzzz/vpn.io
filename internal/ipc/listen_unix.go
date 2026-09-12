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
// A custom socket path must sit in a directory no unprivileged user can write
// to: the directory must be owned by root or the current user, and writable by
// others only where that write access is root-granted (a root-owned dir's group)
// or neutered by the sticky bit. Otherwise Listen refuses — see
// checkSocketDirSafe.
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
// current user and no unprivileged user can write to it. A world-writable
// directory without the sticky bit (e.g. "mkdir -m 0777") opens a TOCTOU window
// during the stale-socket auto-removal and is rejected; so is a group-writable
// directory of our own (a 0770 dir with an untrusted group).
//
// Group-write is accepted only on a root-owned directory whose group is itself
// root-only — wheel (gid 0) or daemon (gid 1). Nobody but root is in those, so
// the bit grants no write access an unprivileged user could use. It is not
// enough that the OWNER is root: a root-owned directory can carry a group that
// ordinary users are in (staff, admin), and there the bit is a real TOCTOU
// window. This exception is not academic — macOS ships /var/run as root:daemon
// 0775, and that is exactly where the helper puts its control socket, so
// rejecting it kept the daemon from ever starting.
//
// A private user directory (0700) and sticky dirs like /tmp pass as before.
func checkSocketDirSafe(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("ipc: stat socket dir %q: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("ipc: cannot inspect ownership of socket dir %q", dir)
	}
	return checkSocketDirAttrs(dir, st.Uid, st.Gid, fi.Mode())
}

// rootOnlyGroups are the groups no unprivileged user belongs to: wheel (0) and
// daemon (1) on macOS and the BSDs, root (0) on Linux. Group-write is tolerated
// only for these — see checkSocketDirSafe.
var rootOnlyGroups = map[uint32]bool{0: true, 1: true}

// checkSocketDirAttrs holds the decision itself, split out from the stat so the
// matrix (owner × permission bits) is testable without creating directories the
// test process has no right to own.
func checkSocketDirAttrs(dir string, uid, gid uint32, mode os.FileMode) error {
	// A foreign owner could swap both the directory and the socket inside it.
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return fmt.Errorf("ipc: socket dir %q is owned by uid %d, expected root or self; use a root-only directory", dir, uid)
	}
	// The sticky bit stops anyone from touching a file they don't own, so it
	// makes the write bits below harmless.
	if mode&os.ModeSticky != 0 {
		return nil
	}
	perm := mode.Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("ipc: refusing world-writable socket dir %q; use a directory writable only by its owner (or sticky)", dir)
	}
	// See the doc comment: the group bit is safe only when both the owner and
	// the group are root's alone.
	if perm&0o020 != 0 && (uid != 0 || !rootOnlyGroups[gid]) {
		return fmt.Errorf("ipc: refusing group-writable socket dir %q (gid %d); use a directory writable only by its owner (or sticky)", dir, gid)
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
