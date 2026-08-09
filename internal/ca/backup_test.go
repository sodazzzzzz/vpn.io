package ca

import (
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPassphrase = "correct horse battery staple"

// newPopulatedCA builds a CA with a server cert, two clients and a revocation,
// so a backup of it exercises every file the directory can hold.
func newPopulatedCA(t *testing.T) (dir string, root *CA) {
	t.Helper()
	dir = t.TempDir()
	root, err := Create(dir, "backup test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := root.IssueServer("test server", []string{"vpn.example.com"}, []net.IP{net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := root.IssueClient(name); err != nil {
			t.Fatalf("IssueClient(%s): %v", name, err)
		}
	}
	// Re-issuing alice leaves a superseded serial in the ledger and an entry in
	// the revocation list — both must survive the round trip, or a restored CA
	// silently un-revokes a leaked profile.
	if err := root.IssueClient("alice"); err != nil {
		t.Fatalf("re-IssueClient(alice): %v", err)
	}
	return dir, root
}

// The fire drill from the issue: back the CA up, restore it into an empty
// directory as a fresh machine would, and check the restored CA still issues
// certificates that verify against the original root.
func TestBackupRestoreFireDrill(t *testing.T) {
	dir, root := newPopulatedCA(t)

	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// The container must not carry the key in the clear — the entire point of
	// storing it off-machine.
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read ca.key: %v", err)
	}
	body := strings.TrimSpace(string(keyPEM))
	for _, line := range strings.Split(body, "\n") {
		if len(line) > 20 && strings.Contains(string(container), line) {
			t.Fatal("backup contains raw private key material")
		}
	}

	restored := filepath.Join(t.TempDir(), "restored")
	if err := Restore(container, restored, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	reloaded, err := Load(restored)
	if err != nil {
		t.Fatalf("Load(restored): %v", err)
	}
	if reloaded.Cert.SerialNumber.Cmp(root.Cert.SerialNumber) != 0 {
		t.Error("restored CA has a different certificate")
	}
	if !reloaded.Key.PublicKey.Equal(root.Key.Public()) {
		t.Error("restored CA has a different key")
	}

	// Everything the CA needs to keep operating came back.
	clients, err := reloaded.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 2 {
		t.Errorf("restored clients = %v, want alice and bob", clients)
	}
	serials, err := ClientSerials(restored, "alice")
	if err != nil {
		t.Fatalf("ClientSerials: %v", err)
	}
	if len(serials) != 2 {
		t.Errorf("restored ledger has %d serials for alice, want 2 (the re-issue history)", len(serials))
	}
	if _, err := os.Stat(filepath.Join(restored, "revoked.json")); err != nil {
		t.Errorf("revocation list did not survive the restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restored, "server", "server.key")); err != nil {
		t.Errorf("server key did not survive the restore: %v", err)
	}

	// The real test of a restored CA: it can still sign, and what it signs
	// verifies against the certificate clients already trust.
	if err := reloaded.IssueClient("carol"); err != nil {
		t.Fatalf("IssueClient on restored CA: %v", err)
	}
	carol, err := readCert(filepath.Join(restored, "clients", "carol.crt"))
	if err != nil {
		t.Fatalf("read carol.crt: %v", err)
	}
	assertChain(t, root.Cert, carol, x509.ExtKeyUsageClientAuth)
}

func TestRestorePreservesKeyPermissions(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("file modes are not enforced on Windows")
	}
	dir, _ := newPopulatedCA(t)
	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := Restore(container, restored, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, rel := range []string{"ca.key", filepath.Join("clients", "alice.key")} {
		info, err := os.Stat(filepath.Join(restored, rel))
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s restored with mode %o, want 600", rel, perm)
		}
	}
}

func TestRestoreRejectsWrongPassphrase(t *testing.T) {
	dir, _ := newPopulatedCA(t)
	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	err = Restore(container, filepath.Join(t.TempDir(), "restored"), testPassphrase+"!")
	if err == nil {
		t.Fatal("restored a backup with the wrong passphrase")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error does not mention the passphrase: %v", err)
	}
}

// The header is stored in the clear, so it is the obvious thing to edit. It is
// bound to the ciphertext as additional data precisely so that editing it —
// here, weakening the KDF — cannot produce a container that still opens.
func TestRestoreRejectsTamperedHeader(t *testing.T) {
	dir, _ := newPopulatedCA(t)
	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(container, &hdr); err != nil {
		t.Fatalf("unmarshal container: %v", err)
	}
	hdr["iterations"] = 200_000 // still within the accepted range, so only the tag can catch it
	tampered, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal tampered container: %v", err)
	}
	if err := Restore(tampered, filepath.Join(t.TempDir(), "restored"), testPassphrase); err == nil {
		t.Fatal("restored a backup whose header had been edited")
	}
}

func TestRestoreRefusesToOverwriteExistingCA(t *testing.T) {
	dir, _ := newPopulatedCA(t)
	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	other := t.TempDir()
	if _, err := Create(other, "someone else's CA"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = Restore(container, other, testPassphrase)
	if err == nil {
		t.Fatal("restore overwrote an existing CA")
	}
	// The existing CA must be untouched, not half-replaced.
	if _, err := Load(other); err != nil {
		t.Errorf("existing CA no longer loads after a refused restore: %v", err)
	}
}

func TestBackupRejectsWeakPassphrase(t *testing.T) {
	dir, _ := newPopulatedCA(t)
	if _, err := Backup(dir, "short"); err == nil {
		t.Fatal("accepted a 5-character passphrase for a root-key backup")
	}
}

func TestBackupRejectsNonCADirectory(t *testing.T) {
	if _, err := Backup(t.TempDir(), testPassphrase); err == nil {
		t.Fatal("backed up a directory that holds no CA")
	}
}

// A container is authenticated, but only against whoever knew the passphrase —
// which is not the same as trusted. Path traversal in an entry name must be
// refused rather than allowed to write outside the restore directory.
func TestSafeArchivePathRejectsEscapes(t *testing.T) {
	for _, name := range []string{
		"../escape.key",
		"/etc/passwd",
		`..\escape.key`,
		"clients/../../escape.key",
	} {
		if _, err := safeArchivePath(name); err == nil {
			t.Errorf("safeArchivePath(%q) accepted an escaping path", name)
		}
	}
	for _, name := range []string{"ca.crt", "clients/alice.key", "./server/server.crt"} {
		if _, err := safeArchivePath(name); err != nil {
			t.Errorf("safeArchivePath(%q) rejected a legitimate entry: %v", name, err)
		}
	}
}

func TestBackupInfoReadsHeaderWithoutPassphrase(t *testing.T) {
	dir, _ := newPopulatedCA(t)
	container, err := Backup(dir, testPassphrase)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	createdAt, cn, err := BackupInfo(container)
	if err != nil {
		t.Fatalf("BackupInfo: %v", err)
	}
	if cn != "backup test CA" {
		t.Errorf("BackupInfo CN = %q", cn)
	}
	if createdAt.IsZero() {
		t.Error("BackupInfo returned a zero timestamp")
	}
	if _, _, err := BackupInfo([]byte(`{"format":"something-else"}`)); err == nil {
		t.Error("BackupInfo accepted a non-backup file")
	}
}
