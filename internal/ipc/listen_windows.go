//go:build windows

package ipc

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
)

// pipeSDDL restricts who may open the control pipe — the Windows analogue of
// the unix socket's file mode plus the peer-credential check. It grants:
//   - full control to LocalSystem (SY) and Built-in Administrators (BA), so the
//     privileged helper service can create and own the pipe;
//   - read/write to the interactive user (IU), so the GUI running as the
//     logged-in user can connect.
//
// LIMITATION: IU (NT AUTHORITY\INTERACTIVE) covers EVERY interactive logon
// session, so on a multi-user host (e.g. a Windows Server with several RDP
// users) any logged-in user could drive the tunnel. That is acceptable for the
// single-user personal machines this targets; tightening to a specific user SID
// is a follow-up, alongside the dial-side squat check.
//
// The unix Policy (uid/gid) does not apply on Windows; this ACL is the gate.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen creates the named-pipe control endpoint at path (e.g.
// \\.\pipe\vpn-io-helper), restricted by pipeSDDL. The mode and policy
// arguments are unix concepts and are ignored on Windows — the pipe's security
// descriptor is the authorization gate. The signature matches the unix build so
// cmd/vpn-helper compiles on every target.
func Listen(path string, mode os.FileMode, policy Policy, log *slog.Logger) (net.Listener, error) {
	if log == nil {
		log = slog.Default()
	}
	// NOTE: go-winio's ListenPipe does not expose FILE_FLAG_FIRST_PIPE_INSTANCE,
	// so a second Listen on the same name silently creates another server
	// instance instead of failing the way a second unix net.Listen would. A
	// second vpn-helper therefore won't notice the first, and that same gap is
	// what a pipe-squatter would exploit — both are covered by the dial-side
	// server-identity SECURITY TODO, to be closed with real Windows testing.
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen pipe %q: %w", path, err)
	}
	log.Info("ipc: control pipe listening", "path", path)
	return ln, nil
}
