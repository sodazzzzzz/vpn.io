//go:build !windows

package main

import (
	"context"
	"errors"
)

// On non-Windows platforms the helper runs as an ordinary root process managed
// by systemd (Linux) or launchd (macOS), so the Windows service hooks are
// no-ops or clear errors.

func isService() bool { return false }

func runService(string, func(context.Context) error) error {
	return errors.New("running as a service is supported only on Windows")
}

func installService(string, string, string, []string) error {
	return errors.New("-install is Windows-only (use the systemd unit / launchd plist elsewhere)")
}

func removeService(string) error {
	return errors.New("-uninstall is Windows-only")
}
