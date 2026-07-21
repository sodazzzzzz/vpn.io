//go:build darwin

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/govpn/internal/execx"
)

func newRunner() Runner { return &darwinRunner{} }

type darwinRunner struct {
	// saved[serviceName] = original DNS list. Empty slice means "no DNS
	// was set" (networksetup prints "There aren't any..."); we restore by
	// passing the literal "empty" back.
	saved map[string][]string
}

func (d *darwinRunner) Apply(servers []string, _ string) error {
	svcs, err := d.listEnabledServices()
	if err != nil {
		return err
	}
	if len(svcs) == 0 {
		return fmt.Errorf("no enabled network services found")
	}
	d.saved = make(map[string][]string, len(svcs))
	for _, svc := range svcs {
		orig, err := d.getDNS(svc)
		if err != nil {
			// Roll back: undo whatever we changed before this one.
			_ = d.Restore()
			return fmt.Errorf("get DNS for %q: %w", svc, err)
		}
		d.saved[svc] = orig
		if err := d.setDNS(svc, servers); err != nil {
			_ = d.Restore()
			return fmt.Errorf("set DNS for %q: %w", svc, err)
		}
	}
	return nil
}

func (d *darwinRunner) Restore() error {
	if d.saved == nil {
		return nil
	}
	var firstErr error
	for svc, orig := range d.saved {
		var args []string
		if len(orig) == 0 {
			// `networksetup -setdnsservers <svc> empty` clears the list.
			args = []string{"empty"}
		} else {
			args = orig
		}
		if err := d.setDNS(svc, args); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("restore %q: %w", svc, err)
		}
	}
	d.saved = nil
	return firstErr
}

// Clear resets every enabled network service's DNS to automatic (DHCP) without
// a saved snapshot — recovering a host a crashed client left pointing at a dead
// tunnel resolver (vpn-client --clear-dns). It does drop a pre-existing MANUAL
// DNS config, which is acceptable for a recovery command run precisely because
// DNS is already broken.
func (d *darwinRunner) Clear(log *slog.Logger) error {
	svcs, err := d.listEnabledServices()
	if err != nil {
		return err
	}
	var firstErr error
	for _, svc := range svcs {
		if err := d.setDNS(svc, []string{"empty"}); err != nil {
			log.Warn("dns: resetting service to automatic failed", "service", svc, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("clear DNS for %q: %w", svc, err)
			}
		}
	}
	return firstErr
}

// Reconcile is a no-op on macOS: nothing durable records that a prior run set
// DNS, so at startup we can't tell our leftover config from a user's manual one
// and must not touch it. Recovery is manual via --clear-dns for now; a durable
// per-service snapshot for auto-heal is a follow-up.
func (d *darwinRunner) Reconcile(_ *slog.Logger) error { return nil }

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
			// The first line is a banner.
			first = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

// getDNS reads the current DNS list for svc. Returns nil (length 0) when
// networksetup reports no DNS servers are configured.
func (d *darwinRunner) getDNS(svc string) ([]string, error) {
	out, err := execx.Output("networksetup", "-getdnsservers", svc)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(out))
	if strings.HasPrefix(text, "There aren't any") {
		return nil, nil
	}
	return strings.Fields(text), nil
}

func (d *darwinRunner) setDNS(svc string, servers []string) error {
	args := append([]string{"-setdnsservers", svc}, servers...)
	if err := execx.Run("networksetup", args...); err != nil {
		return err
	}
	return nil
}
