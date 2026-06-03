//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// eventID is the (single, generic) event identifier for our Event Log messages.
const eventID = 1

// isService reports whether the process was started by the Windows Service
// Control Manager (as opposed to a console).
func isService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// daemonService adapts the daemon's run function to svc.Handler. run is given a
// ready callback to invoke once its control endpoint is accepting.
type daemonService struct {
	name string
	run  func(context.Context, func()) error
}

// Execute is called by the SCM. It runs the daemon and maps a Stop/Shutdown
// control to a context cancel, then waits for the daemon to tear the tunnel
// down before reporting Stopped. Key events go to the Windows Event Log — the
// service's stderr is discarded, so this is the operator's only window into a
// start-up failure (Wintun missing, pipe busy, …).
func (s *daemonService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	elog, err := eventlog.Open(s.name)
	if err != nil {
		elog = nil // best effort — never fail the service over logging
	}
	if elog != nil {
		defer elog.Close()
	}
	logInfo := func(msg string) {
		if elog != nil {
			_ = elog.Info(eventID, msg)
		}
	}
	logErr := func(msg string) {
		if elog != nil {
			_ = elog.Error(eventID, msg)
		}
	}

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	var readyOnce sync.Once
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, func() { readyOnce.Do(func() { close(ready) }) }) }()

	// Report Running only once the control endpoint is actually accepting, or
	// fail fast if the daemon errors before that (e.g. the pipe is busy or
	// Wintun is missing) — don't flap through Running on a doomed start-up.
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	select {
	case <-ready:
		status <- svc.Status{State: svc.Running, Accepts: accepted}
		logInfo("vpn-helper service started")
	case err := <-done:
		status <- svc.Status{State: svc.StopPending}
		if err != nil {
			logErr("vpn-helper failed to start: " + err.Error())
			return true, 1
		}
		return false, 0
	}

	for {
		select {
		case err := <-done:
			// The daemon stopped on its own (typically a fatal error).
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				logErr("vpn-helper daemon failed: " + err.Error())
				// true => a service-specific exit code, not a Win32 one (Win32 1
				// = ERROR_INVALID_FUNCTION would be misleading in the Event Log).
				return true, 1
			}
			logInfo("vpn-helper daemon exited")
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
				logInfo("vpn-helper service stopping")
				cancel()
				// Wait for the daemon to disconnect and clean up, and surface a
				// teardown failure to the Event Log (the only operator channel).
				if err := <-done; err != nil {
					logErr("vpn-helper shutdown: " + err.Error())
				}
				return false, 0
			default:
			}
		}
	}
}

// runService runs the daemon under the Service Control Manager.
func runService(name string, run func(context.Context, func()) error) error {
	return svc.Run(name, &daemonService{name: name, run: run})
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

	// Register the Event Log source so the messages Execute writes are formatted
	// properly. Best effort: a missing source only degrades logging, so don't
	// undo a successful service install over it.
	_ = eventlog.InstallAsEventCreate(name, eventlog.Info|eventlog.Warning|eventlog.Error)
	return nil
}

// removeService stops and deletes the helper's Windows service. Requires
// Administrator.
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

	// Stop it and wait until it has actually stopped before deleting. Calling
	// Delete() on a still-running service only marks it "pending deletion",
	// which makes an immediate re-install fail with "marked for deletion".
	// Control returns an error if it is already stopped — then we just delete.
	if st, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(15 * time.Second)
		for st.State != svc.Stopped {
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out waiting for service %q to stop", name)
			}
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return fmt.Errorf("query service status: %w", err)
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	// Drop the Event Log source we registered at install (best effort).
	_ = eventlog.Remove(name)
	return nil
}
