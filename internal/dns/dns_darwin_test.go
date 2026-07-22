//go:build darwin

package dns

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// withTempDNSBackup points dnsBackupPath at a fresh temp file and restores the
// package var afterwards.
func withTempDNSBackup(t *testing.T) {
	t.Helper()
	orig := dnsBackupPath
	dnsBackupPath = filepath.Join(t.TempDir(), "dns-backup.json")
	t.Cleanup(func() { dnsBackupPath = orig })
}

// stubSetDNS replaces the shell-out seam with a recorder, so Restore/Reconcile
// can be exercised without mutating the host's real DNS. It returns the map that
// captures the last args each service was set to.
func stubSetDNS(t *testing.T) map[string][]string {
	t.Helper()
	calls := map[string][]string{}
	orig := setDNSServers
	setDNSServers = func(svc string, servers []string) error {
		calls[svc] = append([]string(nil), servers...)
		return nil
	}
	t.Cleanup(func() { setDNSServers = orig })
	return calls
}

// The crash case: a run wrote the durable marker (recording each service's
// pre-Apply DNS) and then died without a clean Restore. A fresh runner's
// Reconcile must put every recorded service back — the manual resolver for one,
// auto/DHCP ("empty") for the other — and then drop the marker so it can't fire
// twice (#217).
func TestReconcile_RecoversFromDurableMarker(t *testing.T) {
	withTempDNSBackup(t)
	calls := stubSetDNS(t)

	// Simulate a crashed Apply: the marker survives, the in-memory runner doesn't.
	if err := writeDNSBackup(darwinBackup{Services: map[string][]string{
		"Wi-Fi":    {"192.168.1.1"}, // had a manual resolver → restore it
		"Ethernet": nil,             // was on auto/DHCP → restore to "empty"
	}}); err != nil {
		t.Fatalf("writeDNSBackup: %v", err)
	}

	if err := (&darwinRunner{}).Reconcile(discard()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	want := map[string][]string{
		"Wi-Fi":    {"192.168.1.1"},
		"Ethernet": {"empty"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Reconcile set DNS to %v, want %v", calls, want)
	}
	if _, ok, _ := readDNSBackup(); ok {
		t.Fatal("marker should be gone after a successful Reconcile")
	}

	// Idempotent: with no marker left, a second Reconcile is a clean no-op.
	calls2 := stubSetDNS(t)
	if err := (&darwinRunner{}).Reconcile(discard()); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(calls2) != 0 {
		t.Fatalf("second Reconcile touched DNS: %v", calls2)
	}
}

// Reconcile must never disturb a host we didn't configure: with no marker on
// disk, it makes no networksetup calls at all.
func TestReconcile_NoMarkerIsNoOp(t *testing.T) {
	withTempDNSBackup(t)
	calls := stubSetDNS(t)
	if err := (&darwinRunner{}).Reconcile(discard()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("Reconcile with no marker touched DNS: %v", calls)
	}
}

// A corrupted marker must not smuggle non-IP tokens into the networksetup argv:
// Reconcile re-validates to bare IPs, dropping junk (an all-junk service falls
// back to "empty").
func TestReconcile_FiltersNonIPFromMarker(t *testing.T) {
	withTempDNSBackup(t)
	calls := stubSetDNS(t)

	if err := writeDNSBackup(darwinBackup{Services: map[string][]string{
		"Wi-Fi": {"1.1.1.1", "1.1.1.1\nsearch attacker.com", "not-an-ip"},
	}}); err != nil {
		t.Fatalf("writeDNSBackup: %v", err)
	}
	if err := (&darwinRunner{}).Reconcile(discard()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := map[string][]string{"Wi-Fi": {"1.1.1.1"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Reconcile set DNS to %v, want only the valid IP %v", calls, want)
	}
}

// A clean Restore must drop the durable marker, so a later helper start doesn't
// "recover" DNS that's already correct.
func TestRestore_DropsDurableMarker(t *testing.T) {
	withTempDNSBackup(t)
	stubSetDNS(t)

	if err := writeDNSBackup(darwinBackup{Services: map[string][]string{
		"Wi-Fi": {"192.168.1.1"},
	}}); err != nil {
		t.Fatalf("writeDNSBackup: %v", err)
	}
	r := &darwinRunner{saved: map[string][]string{"Wi-Fi": {"192.168.1.1"}}}
	if err := r.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, ok, _ := readDNSBackup(); ok {
		t.Fatal("clean Restore should remove the durable marker")
	}
}

// A PARTIAL Restore failure must KEEP the durable marker, so the next helper
// start (Reconcile) can finish reverting the stranded service. Dropping it would
// leave that service on the dead tunnel resolver forever — the "no terminal
// after install" failure this marker exists to prevent.
func TestRestore_KeepsMarkerOnPartialFailure(t *testing.T) {
	withTempDNSBackup(t)
	orig := setDNSServers
	setDNSServers = func(svc string, _ []string) error {
		if svc == "Ethernet" {
			return errors.New("networksetup failed")
		}
		return nil
	}
	t.Cleanup(func() { setDNSServers = orig })

	services := map[string][]string{"Wi-Fi": {"192.168.1.1"}, "Ethernet": {"192.168.1.1"}}
	if err := writeDNSBackup(darwinBackup{Services: services}); err != nil {
		t.Fatalf("writeDNSBackup: %v", err)
	}
	r := &darwinRunner{saved: services}
	if err := r.Restore(); err == nil {
		t.Fatal("Restore should surface the Ethernet failure")
	}
	if _, ok, _ := readDNSBackup(); !ok {
		t.Fatal("a partial Restore failure must keep the durable marker for Reconcile")
	}
}
