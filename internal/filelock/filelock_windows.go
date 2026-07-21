//go:build windows

package filelock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLock attempts a non-blocking exclusive lock on the first byte of the file
// via LockFileEx with LOCKFILE_FAIL_IMMEDIATELY. It reports (false, nil) when
// the lock is held elsewhere (ERROR_LOCK_VIOLATION). Windows releases the lock
// when the handle is closed or the process exits, mirroring flock's crash
// safety.
func tryLock(f *os.File) (bool, error) {
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0,
		new(windows.Overlapped),
	)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return false, nil
	default:
		return false, err
	}
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
