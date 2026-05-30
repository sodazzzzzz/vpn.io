//go:build darwin

package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
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
// The future kill-switch will need stateful IPv4 filtering and will bring
// in pf at that point; this v6-only block is intentionally lighter.
func newRunner(log *slog.Logger) Runner { return &darwinRunner{log: log} }

type darwinRunner struct {
	log *slog.Logger
	// saved[serviceName] = original IPv6 mode ("Automatic", "Off",
	// "Link-local", "Manual") captured before we set it off.
	saved map[string]string
}

func (d *darwinRunner) BlockIPv6() error {
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

// restoreOnError rolls back on a BlockIPv6 failure path and folds any
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
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("listnetworkservices: %w (%s)", err, strings.TrimSpace(string(out)))
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

// getV6Mode parses the "IPv6:" line of `networksetup -getv6settings <svc>`.
// -getv6settings returns only the IPv6 configuration (mode on the first
// line), which is more stable than -getinfo's combined dump.
func (d *darwinRunner) getV6Mode(svc string) (string, error) {
	out, err := exec.Command("networksetup", "-getv6settings", svc).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("getv6settings %q: %w (%s)", svc, err, strings.TrimSpace(string(out)))
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "IPv6:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("no IPv6 line in getv6settings output for %q", svc)
}

func (d *darwinRunner) setV6(svc, flag string) error {
	out, err := exec.Command("networksetup", flag, svc).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s %q: %w (%s)", flag, svc, err, strings.TrimSpace(string(out)))
	}
	return nil
}
