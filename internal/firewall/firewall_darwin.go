//go:build darwin

package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/govpn/internal/execx"
)

// On macOS we block IPv6 by turning it off on every active network service
// via `networksetup -setv6off`, rather than installing a pf rule. pf can't
// be extended non-invasively (anchors must be referenced from the main
// ruleset, and reloading that ruleset risks clobbering the user's nat/
// options), whereas networksetup is a supported, reversible per-service
// API — the same tool internal/dns already uses on macOS. With IPv6 off on
// the egress services, dual-stack apps fall back to IPv4 (which the tunnel
// carries) and nothing internet-bound leaks over v6.
//
// The macOS kill-switch (stateful IPv4 filtering via pf) is a follow-up; for
// now Enable ignores the kill-switch fields of cfg and does the v6-only block.
func newRunner(log *slog.Logger) Runner { return &darwinRunner{log: log} }

type darwinRunner struct {
	log *slog.Logger
	// saved[serviceName] = original IPv6 mode ("Automatic", "Off",
	// "Link-local", "Manual") captured before we set it off.
	saved map[string]string
}

func (d *darwinRunner) Enable(_ Config) error {
	svcs, err := d.listEnabledServices()
	if err != nil {
		return err
	}
	if len(svcs) == 0 {
		// No active services means no surface for an IPv6 leak — not an
		// error. (Erroring here would latch the client's leakguardOff flag
		// and skip protection even after an interface is later brought up.)
		return nil
	}
	d.saved = make(map[string]string, len(svcs))
	for _, svc := range svcs {
		mode, err := d.getV6Mode(svc)
		if err != nil {
			return d.restoreOnError(fmt.Errorf("get IPv6 mode for %q: %w", svc, err))
		}
		if mode == "Off" {
			continue // already off; nothing to change or restore
		}
		if mode == "Manual" {
			// We don't capture the static address/prefix/router, so Restore
			// can only return the service to Automatic — surface the loss.
			d.log.Warn("service has a static IPv6 config; leak protection will restore it as Automatic, dropping the manual address", "service", svc)
		}
		if err := d.setV6(svc, "-setv6off"); err != nil {
			return d.restoreOnError(fmt.Errorf("disable IPv6 for %q: %w", svc, err))
		}
		// Record only after a successful change, so Restore touches exactly
		// the services we modified — never one whose setV6 failed and was
		// left on its original config.
		d.saved[svc] = mode
	}
	return nil
}

// restoreOnError rolls back on an Enable failure path and folds any
// restore failure into the returned error, so a partial rollback that
// leaves IPv6 off on some services isn't silently lost.
func (d *darwinRunner) restoreOnError(err error) error {
	if rerr := d.Restore(); rerr != nil {
		return fmt.Errorf("%w (partial restore also failed: %v)", err, rerr)
	}
	return err
}

func (d *darwinRunner) Restore() error {
	if d.saved == nil {
		return nil
	}
	var firstErr error
	failed := make(map[string]string)
	for svc, mode := range d.saved {
		if err := d.setV6(svc, d.v6RestoreFlag(mode)); err != nil {
			// Keep going so the remaining services are restored, but log
			// every failure — only the first is folded into the return.
			d.log.Warn("failed to restore IPv6 for service", "service", svc, "err", err)
			failed[svc] = mode // retain for a later retry
			if firstErr == nil {
				firstErr = fmt.Errorf("restore IPv6 for %q: %w", svc, err)
			}
		}
	}
	// Drop only the services we actually restored. Retaining the failures
	// keeps the Manager's applied-on-error retry meaningful: a subsequent
	// Restore re-attempts exactly the services still left with IPv6 off,
	// instead of short-circuiting on a nil snapshot and falsely succeeding.
	if len(failed) == 0 {
		d.saved = nil
	} else {
		d.saved = failed
	}
	return firstErr
}

// Clear is the stateless escape hatch: with no saved snapshot to restore
// (e.g. recovering after a crash) the best we can do is put IPv6 back to
// Automatic on every active service — the near-universal client default.
func (d *darwinRunner) Clear() error {
	svcs, err := d.listEnabledServices()
	if err != nil {
		return err
	}
	var firstErr error
	for _, svc := range svcs {
		if err := d.setV6(svc, "-setv6automatic"); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("reset IPv6 for %q: %w", svc, err)
		}
	}
	return firstErr
}

// v6RestoreFlag maps a captured mode back to the networksetup flag that
// re-applies it. A "Manual" (static) IPv6 config can't be re-applied
// without its address/router, which we didn't capture; falling back to
// automatic is the safe, near-universal choice for a client.
func (d *darwinRunner) v6RestoreFlag(mode string) string {
	switch mode {
	case "Link-local":
		return "-setv6LinkLocal"
	case "Automatic", "Manual":
		return "-setv6automatic"
	default:
		// An unrecognised mode (e.g. a future macOS addition) can't be
		// reproduced exactly; Automatic is the safe default, but flag it.
		d.log.Warn("unrecognised IPv6 mode on restore; falling back to Automatic", "mode", mode)
		return "-setv6automatic"
	}
}

// listEnabledServices runs `networksetup -listallnetworkservices` and
// returns active services (lines starting with "*" are disabled).
func (d *darwinRunner) listEnabledServices() ([]string, error) {
	out, err := execx.Output("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var svcs []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false // the first line is a banner
			continue
		}
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

// getV6Mode reports a service's IPv6 configuration mode ("Automatic", "Off",
// "Link-local", "Manual") as read from `networksetup -getinfo <svc>`.
//
// -getinfo is the only networksetup verb that reports the mode: the read-side
// counterpart to -setv6off/-setv6automatic simply doesn't exist. Asking for one
// costs an exit status 5 and a usage dump, which aborted Enable on the first
// service and left IPv6 up on every interface while the UI said "connected".
func (d *darwinRunner) getV6Mode(svc string) (string, error) {
	out, err := execx.Output("networksetup", "-getinfo", svc)
	if err != nil {
		return "", err
	}
	mode, err := parseV6Mode(out)
	if err != nil {
		return "", fmt.Errorf("%w for %q", err, svc)
	}
	return mode, nil
}

// parseV6Mode picks the mode out of a -getinfo dump. The dump mixes IPv4 and
// IPv6 lines, several of which start with "IPv6" ("IPv6 IP address:", "IPv6
// Router:"); only the bare "IPv6:" line carries the mode, so the colon is part
// of the prefix we match.
func parseV6Mode(out []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "IPv6:"); ok {
			mode := strings.TrimSpace(v)
			if mode == "" {
				return "", fmt.Errorf("empty IPv6 mode in networksetup -getinfo output")
			}
			return mode, nil
		}
	}
	return "", fmt.Errorf("no IPv6 line in networksetup -getinfo output")
}

func (d *darwinRunner) setV6(svc, flag string) error {
	if err := execx.Run("networksetup", flag, svc); err != nil {
		return err
	}
	return nil
}
