// Package keyperm checks that private-key files on disk are readable only by
// their owner.
//
// Every key this project writes is created 0600 (see internal/ca,
// internal/profilestore), but keys do not stay where they were written: they get
// scp'd to a VPS, restored from an archive, copied out of a backup by hand. Each
// of those can widen the mode without anyone noticing — an scp'd server.key
// commonly lands 0644 — and a private key the whole machine can read is one
// local account away from being someone else's key.
//
// The check reports rather than enforces. Refusing to start a VPN server over a
// file mode would cut the tunnel for everyone who depends on it, and the people
// best placed to debug that are the ones it just disconnected. A loud warning at
// startup, with the command that fixes it, is the trade this project makes.
package keyperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// Check reports whether the private key at path is readable by anyone other
// than its owner. It returns an empty string when the file is fine, when it
// does not exist (a missing key is the caller's problem to report, with better
// context than this package has), or on Windows.
//
// Windows ignores Unix modes entirely — os.Stat synthesises 0666 there — so a
// mode check would report every key as insecure and teach the operator to
// ignore the warning. Access there is governed by the file's ACL and by the
// directory the installer creates; see docs/SECURITY-KEYS.md.
func Check(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ""
		}
		return fmt.Sprintf("cannot check permissions on %s: %v", path, err)
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return ""
	}
	who := "the group"
	if perm&0o007 != 0 {
		who = "every user on this machine"
	}
	return fmt.Sprintf("private key %s is mode %04o — readable by %s; fix with: chmod 600 %s", path, perm, who, path)
}
