//go:build darwin

package dns

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/govpn/internal/execx"
)

// dnsBackupPath is the durable marker that records each network service's DNS
// as it was BEFORE we ran `networksetup -setdnsservers`. It's the macOS analog
// of the Linux resolv.conf backup: written at Apply so a crash (SIGKILL / panic
// / reboot) that loses the in-memory snapshot can still be undone at the next
// helper start. It lives in a root-writable dir that survives a reboot —
// `networksetup` persists the DNS change to the system network config, so the
// marker that reverses it must persist just as long. It's a var so tests can
// point it at a temp file.
var dnsBackupPath = "/Library/Application Support/vpn.io/dns-backup.json"

// darwinBackup is the on-disk form of the pre-Apply DNS snapshot. Services maps
// each network service we touched to its original resolver list; an empty (or
// absent) list means the service had no manual DNS (auto/DHCP), which we put
// back by passing the literal "empty" to networksetup.
type darwinBackup struct {
	Services map[string][]string `json:"services"`
}

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
	// Snapshot every service's current DNS BEFORE mutating any of it, so the
	// durable marker written next is complete: a crash mid-Apply then leaves a
	// marker covering every service we're about to change, and getDNS failing
	// here aborts before we've touched a thing (nothing to roll back).
	saved := make(map[string][]string, len(svcs))
	for _, svc := range svcs {
		orig, err := d.getDNS(svc)
		if err != nil {
			return fmt.Errorf("get DNS for %q: %w", svc, err)
		}
		saved[svc] = orig
	}
	d.saved = saved

	// Persist the snapshot so a crash — which loses d.saved above — can still be
	// undone by Clear/Reconcile. Best-effort: a clean Restore uses the in-memory
	// snapshot, so a failed marker write only costs crash recovery, not
	// correctness; don't fail Apply over it.
	_ = writeDNSBackup(darwinBackup{Services: saved})

	for _, svc := range svcs {
		if err := d.setDNS(svc, servers); err != nil {
			// Undo whatever we already changed (Restore also drops the marker).
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
	// A clean Restore makes the durable marker obsolete — drop it so a later
	// helper start doesn't "recover" DNS we've already put back.
	defer func() { _ = removeDNSBackup() }()
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
	// The forceful reset supersedes any recorded snapshot; drop it so a later
	// Reconcile doesn't try to restore now-stale originals. Best-effort.
	_ = removeDNSBackup()
	return firstErr
}

// Reconcile is the crash-safe recovery run at helper startup. The durable marker
// exists only if a previous run applied DNS and died without a clean Restore, so
// its mere presence proves the mutation was ours: we put every recorded service
// back to its pre-Apply resolvers (or auto/DHCP), then drop the marker. Absent a
// marker it's a no-op, so a host we never configured is never touched — the
// property the previous no-op implementation lacked (#217).
func (d *darwinRunner) Reconcile(log *slog.Logger) error {
	b, ok, err := readDNSBackup()
	if err != nil {
		return err
	}
	if !ok {
		return nil // nothing of ours to undo
	}
	var firstErr error
	for svc, orig := range b.Services {
		// The list crossed disk since we wrote it; re-validate to bare IPs before
		// handing it to networksetup, so a corrupted marker can't inject argv.
		orig = validIPs(orig)
		args := []string{"empty"}
		if len(orig) > 0 {
			args = orig
		}
		if err := d.setDNS(svc, args); err != nil {
			log.Warn("dns: reconciling service from durable marker failed", "service", svc, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("reconcile DNS for %q: %w", svc, err)
			}
		}
	}
	if firstErr != nil {
		// Keep the marker so the next helper start retries the recovery.
		return firstErr
	}
	_ = removeDNSBackup()
	log.Info("dns: reconciled DNS from a prior run's durable marker")
	return nil
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
	return setDNSServers(svc, servers)
}

// setDNSServers is the single seam through which every DNS mutation shells out.
// It's a var so tests can replace it and exercise the Restore/Reconcile logic
// without touching the host's real resolver config.
var setDNSServers = func(svc string, servers []string) error {
	args := append([]string{"-setdnsservers", svc}, servers...)
	return execx.Run("networksetup", args...)
}

// writeDNSBackup persists the pre-Apply snapshot, creating the parent state dir
// if needed. The file is root-only (0600 in a 0700 dir): it names the host's
// network services, and only root should read or rewrite the recovery record.
func writeDNSBackup(b darwinBackup) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dnsBackupPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dnsBackupPath, data, 0o600)
}

// readDNSBackup loads the durable snapshot. ok is false (with a nil error) when
// no marker exists — the common "nothing of ours to undo" case.
func readDNSBackup() (b darwinBackup, ok bool, err error) {
	data, err := os.ReadFile(dnsBackupPath)
	if os.IsNotExist(err) {
		return darwinBackup{}, false, nil
	}
	if err != nil {
		return darwinBackup{}, false, fmt.Errorf("read dns backup: %w", err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return darwinBackup{}, false, fmt.Errorf("parse dns backup: %w", err)
	}
	return b, true, nil
}

func removeDNSBackup() error {
	if err := os.Remove(dnsBackupPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
