//go:build windows

package ipc

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

// ImpersonateNamedPipeClient isn't wrapped by x/sys/windows, so bind it from
// advapi32 directly. It makes the calling thread adopt the identity of the
// process on the other end of the named pipe.
var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

func impersonateNamedPipeClient(pipe windows.Handle) error {
	r1, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r1 == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", err)
	}
	return nil
}

// authorizePeer decides whether the client on a just-accepted control-pipe
// connection may drive the helper (Connect/Disconnect/Status).
//
// The pipe's SDDL lets any interactive user OPEN the pipe — there is no way to
// bake "the primary user" into the descriptor at service start, before anyone
// has logged in (see listen_windows.go). So the real authorization lives here:
// only the user of the ACTIVE CONSOLE SESSION — plus LocalSystem — is allowed.
// On a multi-user / RDP host that stops a second logged-in user from tearing
// down or hijacking the tunnel the console user is running (#178). It complements
// the client-side verifyPipeServer (which stops key theft): this side stops
// tunnel control by the wrong user.
//
// Fails closed: any error identifying the caller, or no active console user,
// means "reject" (only LocalSystem gets through then).
func authorizePeer(conn net.Conn) error {
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("cannot inspect pipe handle (unexpected connection type %T)", conn)
	}

	allowed, err := allowedControlSIDs()
	if err != nil {
		return err
	}
	match, who, err := pipeClientMatches(windows.Handle(h.Fd()), allowed)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("caller %s is not authorized to control the tunnel", who)
	}
	return nil
}

// allowedControlSIDs are the SIDs permitted to drive the helper: LocalSystem
// (the service's own identity / admin tooling) and the active console-session
// user (the person at the machine). A missing console user is not fatal — the
// list just falls back to LocalSystem, so an unattended host stays locked down.
func allowedControlSIDs() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	out := []*windows.SID{system}
	if user, err := activeConsoleUserSID(); err == nil && user != nil {
		out = append(out, user)
	}
	return out, nil
}

// activeConsoleUserSID returns the user SID of the session currently attached to
// the physical console. Requires SeTcbPrivilege for WTSQueryUserToken, which the
// helper has as LocalSystem. The SID is copied into fresh memory so it outlives
// the token buffer it came from.
func activeConsoleUserSID() (*windows.SID, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return nil, fmt.Errorf("no active console session")
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return nil, fmt.Errorf("query console-session user token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read console-session user SID: %w", err)
	}
	return copySID(user.User.Sid)
}

// pipeClientMatches impersonates the pipe client, reads its user SID, and reports
// whether it equals any allowed SID. The client SID is only compared while the
// impersonation token buffer is alive, so it needs no copy.
func pipeClientMatches(pipe windows.Handle, allowed []*windows.SID) (bool, string, error) {
	if err := impersonateNamedPipeClient(pipe); err != nil {
		return false, "", err
	}
	// Impersonation sets the identity on the OS THREAD, not the goroutine. Pin
	// the goroutine to its thread for the duration, or the scheduler could move
	// it mid-check: OpenThreadToken would then read the wrong thread, or — worse —
	// the goroutine could leave this thread still impersonating, and a later
	// request reusing that thread (Server.handle runs one goroutine per accept)
	// would run with the client's identity instead of LocalSystem. RevertToSelf
	// then UnlockOSThread, strictly in that order.
	runtime.LockOSThread()
	defer func() {
		_ = windows.RevertToSelf()
		runtime.UnlockOSThread()
	}()

	var token windows.Token
	// openAsSelf=true: open the thread token against the process token
	// (LocalSystem), not the impersonation token — so this succeeds regardless of
	// the client's privileges.
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return false, "", fmt.Errorf("open impersonation token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, "", fmt.Errorf("read client user SID: %w", err)
	}
	client := user.User.Sid
	for _, a := range allowed {
		if client.Equals(a) {
			return true, client.String(), nil
		}
	}
	return false, client.String(), nil
}

// copySID duplicates a SID into memory independent of any token buffer, via its
// canonical string form (StringToSid allocates a fresh SID).
func copySID(sid *windows.SID) (*windows.SID, error) {
	return windows.StringToSid(sid.String())
}
