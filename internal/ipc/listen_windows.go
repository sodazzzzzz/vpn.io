//go:build windows

package ipc

import (
	"errors"
	"log/slog"
	"net"
	"os"
)

// ErrTransportUnsupported is returned by Listen on platforms whose local
// IPC transport is not implemented yet.
var ErrTransportUnsupported = errors.New("ipc: named-pipe transport not yet implemented on windows")

// Listen is not yet implemented on Windows: the named-pipe transport (with
// SID-based peer authorization, the analogue of the unix peer-credential
// check) lands in a follow-up. The signature matches the unix build so the
// daemon command compiles on all targets; starting it on Windows fails
// cleanly. The mode/policy parameters are accepted but unused for now.
func Listen(path string, mode os.FileMode, policy Policy, log *slog.Logger) (net.Listener, error) {
	_ = path
	_ = mode
	_ = policy
	_ = log
	return nil, ErrTransportUnsupported
}
