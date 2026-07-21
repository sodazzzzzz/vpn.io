// Package filelock provides a cross-process advisory exclusive lock, so
// separate processes — the long-lived vpn-bot and the operator's vpn-ca CLI —
// serialise their load-modify-save cycles on a shared JSON store and never lose
// an update (a silently dropped revocation, or a resurrected single-use token).
//
// The lock is taken on a sibling "<path>.lock" file, never on the data file
// itself: the stores replace the data file via temp+rename, which swaps the
// inode and would drop a lock held on it. The .lock file is created once and
// left in place as a stable anchor. The lock is advisory and released by the OS
// when the process exits, so a crash mid-write can't wedge the file forever.
package filelock

import (
	"fmt"
	"os"
	"path/filepath"
)

// Lock is a held advisory lock. Call Unlock to release it.
type Lock struct {
	f *os.File
}

// Acquire opens (creating if needed) "<path>.lock" and takes an exclusive
// advisory lock on it, blocking until no other process holds it. The parent
// directory is created if missing.
func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("filelock: create dir: %w", err)
	}
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("filelock: open %q: %w", lockPath, err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("filelock: lock %q: %w", lockPath, err)
	}
	return &Lock{f: f}, nil
}

// Unlock releases the lock and closes the underlying file. Closing the
// descriptor releases the OS lock on every platform, so the explicit unlock is
// belt-and-suspenders.
func (l *Lock) Unlock() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
