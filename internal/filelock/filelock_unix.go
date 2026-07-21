//go:build unix

package filelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes a blocking exclusive flock. flock locks are per open file
// description and released automatically when the fd is closed or the process
// dies, which is exactly the crash-safe behaviour we want.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
