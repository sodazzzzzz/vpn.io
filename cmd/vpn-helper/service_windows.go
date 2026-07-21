//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// eventID is the (single, generic) event identifier for our Event Log messages.
const eventID = 1

// serviceStopTimeout bounds how long we wait for a stop request to reach the
// Stopped state; serviceGoneTimeout bounds how long we wait for the SCM to
// actually forget a deleted service — it lingers in "pending deletion" while any
// handle stays open (an open services.msc / Task Manager is the classic culprit),
// during which a fresh CreateService fails with ERROR_SERVICE_MARKED_FOR_DELETE.
const (
	serviceStopTimeout = 15 * time.Second
	serviceGoneTimeout = 20 * time.Second
)

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

	// Idempotent by design (#112): an in-place upgrade often finds the previous
	// version's service still registered — a -uninstall that was skipped or
	// swallowed, or one that left the service "pending deletion" because a handle
	// was held. Rather than fail the install (the old behaviour, which aborted the
	// installer), remove any leftover and wait for the SCM to actually forget it,
	// then create the new one.
	if err := deleteServiceIfPresent(m, name); err != nil {
		return err
	}

	s, err := createServiceWithRetry(m, name, exe, mgr.Config{
		DisplayName: display,
		Description: desc,
		StartType:   mgr.StartAutomatic,
		// ServiceStartName empty => LocalSystem.
	}, args)
	if err != nil {
		return err
	}
	defer s.Close()

	// Register the Event Log source so the messages Execute writes are formatted
	// properly. Best effort: a missing source only degrades logging, so don't
	// undo a successful service install over it.
	_ = eventlog.InstallAsEventCreate(name, eventlog.Info|eventlog.Warning|eventlog.Error)
	return nil
}

// createServiceWithRetry creates the service, retrying while the SCM still
// reports it "marked for deletion" (1072) — a handle that outlived the delete
// above keeps the name reserved for a moment. Bounded by serviceGoneTimeout.
func createServiceWithRetry(m *mgr.Mgr, name, exe string, cfg mgr.Config, args []string) (*mgr.Service, error) {
	deadline := time.Now().Add(serviceGoneTimeout)
	for {
		s, err := m.CreateService(name, exe, cfg, args...)
		if err == nil {
			return s, nil
		}
		if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("create service: %w", err)
	}
}

// deleteServiceIfPresent stops and deletes name if it is registered, then waits
// until the SCM stops reporting it. A no-op if the service isn't installed.
func deleteServiceIfPresent(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil // not installed — nothing to remove
	}
	if err := stopAndWait(s, name); err != nil {
		s.Close()
		return err
	}
	err = s.Delete()
	s.Close() // the SCM finalises deletion only once every handle is closed
	// "Already marked for deletion" is fine: we only need it gone, and waiting
	// below confirms that. Any other delete error is real.
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete existing service: %w", err)
	}
	return waitServiceGone(m, name)
}

// waitServiceGone blocks until OpenService(name) fails — i.e. the SCM has truly
// dropped the service, not merely marked it for deletion. Returns a pointed
// error on timeout so the operator knows to close whatever holds a handle.
func waitServiceGone(m *mgr.Mgr, name string) error {
	deadline := time.Now().Add(serviceGoneTimeout)
	for {
		s, err := m.OpenService(name)
		if err != nil {
			return nil // gone
		}
		s.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("service %q still pending deletion after %s; close services.msc / Task Manager and retry", name, serviceGoneTimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// stopAndWait requests a stop and blocks until the service reports Stopped (or
// times out). A service that is already stopped (or can't accept the control)
// makes Control return an error, which we treat as "nothing to wait on".
func stopAndWait(s *mgr.Service, name string) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(serviceStopTimeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %q to stop", name)
		}
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return fmt.Errorf("query service status: %w", err)
		}
	}
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

	// Stop it and wait until it has actually stopped before deleting. Calling
	// Delete() on a still-running service only marks it "pending deletion".
	if err := stopAndWait(s, name); err != nil {
		s.Close()
		return err
	}
	err = s.Delete()
	s.Close()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete service: %w", err)
	}
	// Wait for the SCM to truly drop it, so the -install that the installer runs
	// right after (upgrade path) doesn't hit "marked for deletion" (#112).
	if err := waitServiceGone(m, name); err != nil {
		return err
	}
	// Drop the Event Log source we registered at install (best effort).
	_ = eventlog.Remove(name)
	return nil
}
