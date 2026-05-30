//go:build darwin

package firewall

import (
	"bufio"
	"bytes"
	"fmt"
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
func newRunner() Runner { return &darwinRunner{} }

type darwinRunner struct {
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
		return fmt.Errorf("no enabled network services found")
	}
	d.saved = make(map[string]string, len(svcs))
	for _, svc := range svcs {
		mode, err := d.getV6Mode(svc)
		if err != nil {
			_ = d.Restore() // undo whatever we changed before this one
			return fmt.Errorf("get IPv6 mode for %q: %w", svc, err)
		}
		if mode == "Off" {
			continue // already off; nothing to change or restore
		}
		if err := d.setV6(svc, "-setv6off"); err != nil {
			_ = d.Restore()
			return fmt.Errorf("disable IPv6 for %q: %w", svc, err)
		}
		// Record only after a successful change, so Restore touches exactly
		// the services we modified — never one whose setV6 failed and was
		// left on its original (possibly Manual) config.
		d.saved[svc] = mode
	}
	return nil
}

func (d *darwinRunner) Restore() error {
	if d.saved == nil {
		return nil
	}
	var firstErr error
	for svc, mode := range d.saved {
		if err := d.setV6(svc, v6RestoreFlag(mode)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore IPv6 for %q: %w", svc, err)
		}
	}
	d.saved = nil
	return firstErr
}

// v6RestoreFlag maps a captured mode back to the networksetup flag that
// re-applies it. A "Manual" (static) IPv6 config can't be re-applied
// without its address/router, which we didn't capture; falling back to
// automatic is the safe, near-universal choice for a client.
func v6RestoreFlag(mode string) string {
	switch mode {
	case "Link-local":
		return "-setv6LinkLocal"
	case "Automatic", "Manual":
		return "-setv6automatic"
	default:
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

// getV6Mode parses the "IPv6:" line of `networksetup -getinfo <svc>`.
func (d *darwinRunner) getV6Mode(svc string) (string, error) {
	out, err := exec.Command("networksetup", "-getinfo", svc).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("getinfo %q: %w (%s)", svc, err, strings.TrimSpace(string(out)))
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "IPv6:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("no IPv6 line in getinfo output for %q", svc)
}

func (d *darwinRunner) setV6(svc, flag string) error {
	out, err := exec.Command("networksetup", flag, svc).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s %q: %w (%s)", flag, svc, err, strings.TrimSpace(string(out)))
	}
	return nil
}
