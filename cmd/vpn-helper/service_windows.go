//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// isService reports whether the process was started by the Windows Service
// Control Manager (as opposed to a console).
func isService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// daemonService adapts the daemon's run function to svc.Handler.
type daemonService struct {
	run func(context.Context) error
}

// Execute is called by the SCM. It runs the daemon and maps a Stop/Shutdown
// control to a context cancel, then waits for the daemon to tear the tunnel
// down before reporting Stopped.
func (s *daemonService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The daemon stopped on its own (typically a fatal error).
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				// true => a service-specific exit code, not a Win32 one (Win32 1
				// = ERROR_INVALID_FUNCTION would be misleading in the Event Log).
				return true, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Generous wait hint: tearing the tunnel down (TLS close, route/
				// DNS cleanup, Wintun) takes a moment, and without it the SCM may
				// kill us mid-cleanup on its default timeout.
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				<-done // let the daemon disconnect and clean up
				return false, 0
			default:
			}
		}
	}
}

// runService runs the daemon under the Service Control Manager.
func runService(name string, run func(context.Context) error) error {
	return svc.Run(name, &daemonService{run: run})
}

// installService registers the helper as an auto-starting Windows service that
// runs the current executable with args. It runs as LocalSystem, which has the
// privileges to create the Wintun adapter and edit the routing table. Requires
// Administrator.
func installService(name, display, desc string, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(name); err == nil {
		existing.Close()
		return fmt.Errorf("service %q is already installed (use -uninstall first)", name)
	}

	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName: display,
		Description: desc,
		StartType:   mgr.StartAutomatic,
		// ServiceStartName empty => LocalSystem.
	}, args...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	return nil
}

// removeService stops (best effort) and deletes the helper's Windows service.
// Requires Administrator.
func removeService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", name, err)
	}
	defer s.Close()

	// Stop it first if it's running; ignore the error (it may be stopped).
	_, _ = s.Control(svc.Stop)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}
