//go:build windows

package filelock

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes a blocking exclusive lock on the first byte of the file via
// LockFileEx. Windows releases the lock when the handle is closed or the
// process exits, mirroring flock's crash safety.
func lockFile(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0,
		new(windows.Overlapped),
	)
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
