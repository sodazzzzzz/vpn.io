//go:build windows

package ipc

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/Microsoft/go-winio"

	"github.com/govpn/internal/frame"
)

// frameHeaderSize is the length prefix frame.WriteFrame puts in front of every
// payload — counted in the pipe buffer sizes below so a maximum-size request
// still fits whole.
const frameHeaderSize = 2

// pipeSDDL restricts who may open the control pipe — the Windows analogue of
// the unix socket's file mode plus the peer-credential check. It grants:
//   - full control to LocalSystem (SY) and Built-in Administrators (BA), so the
//     privileged helper service can create and own the pipe;
//   - read/write to the interactive user (IU), so the GUI running as the
//     logged-in user can connect.
//
// IU (NT AUTHORITY\INTERACTIVE) covers EVERY interactive logon session, because
// the descriptor is fixed at service start — before anyone logs in — so it can't
// name the eventual user. That only grants the right to OPEN the pipe: which
// interactive user may actually drive the tunnel is enforced per-connection by
// authorizePeer (authz_windows.go), which admits only the active console-session
// user (plus LocalSystem). So on a multi-user / RDP host a second logged-in user
// can reach the pipe but not command it (#178).
//
// The unix Policy (uid/gid) does not apply on Windows; this ACL plus
// authorizePeer are the gate.
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
	// The unix -allow-uid / -allow-gid policy has no effect here (the pipe's
	// SDDL is the gate). Warn loudly so an operator who passes those flags isn't
	// misled into thinking uid/gid filtering is active.
	if len(policy.AllowUID) > 0 || len(policy.AllowGID) > 0 {
		log.Warn("ipc: -allow-uid/-allow-gid are ignored on Windows; pipe access is governed by its security descriptor (SDDL)")
	}
	// First-instance semantics come from go-winio: ListenPipe creates the first
	// handle with the NT disposition FILE_CREATE (pipe.go), which is the
	// equivalent of FILE_FLAG_FIRST_PIPE_INSTANCE — it fails if the name
	// already exists rather than joining someone else's pipe as an extra
	// server instance. So a second vpn-helper fails loudly, and a squatter that
	// got the name first keeps the helper from starting at all instead of
	// silently sharing it.
	//
	// That is only half the defence: a squatter still owns a pipe the GUI might
	// dial. Clients therefore verify the pipe's owner before sending anything —
	// see verifyPipeServer in dial_windows.go.
	// Give the pipe real buffers. With the zero default, a client write does not
	// complete until the server reads it, which couples the two sides far more
	// tightly than the one-request-per-connection protocol needs — a request as
	// small as a frame header could sit blocked behind whatever the server is
	// doing. A single request must fit in frame.MaxFrameSize (64 KiB), so a
	// buffer that size lets any well-formed request land in one go.
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    frame.MaxFrameSize + frameHeaderSize,
		OutputBufferSize:   frame.MaxFrameSize + frameHeaderSize,
	})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen pipe %q: %w", path, err)
	}
	log.Info("ipc: control pipe listening", "path", path)
	return ln, nil
}
