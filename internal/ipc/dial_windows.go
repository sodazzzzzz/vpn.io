//go:build windows

package ipc

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// dialControl connects to the daemon's named-pipe control endpoint and refuses
// to talk to anything that isn't the privileged helper.
//
// This is the Windows counterpart of the unix build's peer-credential check,
// and it matters more than the name suggests: a ConnectRequest carries
// CACertPEM, CertPEM and — critically — KeyPEM, the user's private key. Handing
// that to whoever happens to own the pipe would let a squatter authenticate to
// the VPN as the user, so the identity check happens before the caller ever
// gets a usable connection.
func dialControl(path string) (net.Conn, error) {
	timeout := dialTimeout
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, fmt.Errorf("ipc: connect to %q: %w (is vpn-helper running?)", path, err)
	}
	if err := verifyPipeServer(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ipc: refusing to use control pipe %q: %w", path, err)
	}
	return conn, nil
}

// verifyPipeServer checks that the pipe just opened is owned by LocalSystem or
// Built-in Administrators — that it was created by the helper service and not
// by an unprivileged process that reached the name first.
//
// The owner of a pipe object is whoever created it, so an ordinary user's
// squatted pipe carries that user's SID and is rejected here. The pipe's own
// SDDL cannot defend against this: a squatter supplies its own descriptor.
//
// Fails closed — any error identifying the peer means no credentials are sent.
func verifyPipeServer(conn net.Conn) error {
	// go-winio's pipe connection exposes the underlying handle through a
	// promoted Fd method. Asserting on the method rather than a concrete type
	// keeps this working if the library reshuffles its unexported types.
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("cannot inspect pipe handle (unexpected connection type %T)", conn)
	}
	sd, err := windows.GetSecurityInfo(
		windows.Handle(h.Fd()),
		windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read pipe security info: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read pipe owner SID: %w", err)
	}
	trusted, err := trustedPipeOwners()
	if err != nil {
		return err
	}
	for _, sid := range trusted {
		if owner.Equals(sid) {
			return nil
		}
	}
	return fmt.Errorf("pipe is owned by %s, not LocalSystem or Administrators — "+
		"another process may be impersonating the helper", owner)
}

// trustedPipeOwners returns the SIDs allowed to own the control pipe. A
// privileged process's default owner is LocalSystem or the Administrators
// group depending on how its token is configured, so both are accepted.
func trustedPipeOwners() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, fmt.Errorf("resolve well-known SID %d: %w", t, err)
		}
		out = append(out, sid)
	}
	return out, nil
}
