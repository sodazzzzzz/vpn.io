package ca

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/govpn/internal/revoke"
)

func TestCreateLoadAndIssue(t *testing.T) {
	dir := t.TempDir()

	root, err := Create(dir, "test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !root.Cert.IsCA {
		t.Fatal("CA cert is not marked IsCA")
	}
	if root.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA cert missing KeyUsageCertSign")
	}

	if _, err := Create(dir, "again"); err == nil {
		t.Fatal("expected Create to fail when CA already exists")
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Cert.SerialNumber.Cmp(root.Cert.SerialNumber) != 0 {
		t.Fatal("loaded CA has different serial")
	}

	if err := loaded.IssueServer("test server",
		[]string{"vpn.example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	serverCert, err := readCert(filepath.Join(dir, "server", "server.crt"))
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	assertChain(t, loaded.Cert, serverCert, x509.ExtKeyUsageServerAuth)
	if err := serverCert.VerifyHostname("vpn.example.com"); err != nil {
		t.Errorf("VerifyHostname(DNS): %v", err)
	}
	if err := serverCert.VerifyHostname("10.0.0.1"); err != nil {
		t.Errorf("VerifyHostname(IP): %v", err)
	}

	if err := loaded.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	clientCert, err := readCert(filepath.Join(dir, "clients", "alice.crt"))
	if err != nil {
		t.Fatalf("read client cert: %v", err)
	}
	assertChain(t, loaded.Cert, clientCert, x509.ExtKeyUsageClientAuth)
	if clientCert.Subject.CommonName != "alice" {
		t.Errorf("client CN = %q, want alice", clientCert.Subject.CommonName)
	}

	// A client cert must NOT pass server-auth verification, and vice versa.
	if err := verify(loaded.Cert, clientCert, x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("client cert wrongly accepted as server cert")
	}
	if err := verify(loaded.Cert, serverCert, x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("server cert wrongly accepted as client cert")
	}

	names, err := loaded.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(names) != 1 || names[0] != "alice" {
		t.Errorf("ListClients = %v, want [alice]", names)
	}
}

func assertChain(t *testing.T, root, leaf *x509.Certificate, usage x509.ExtKeyUsage) {
	t.Helper()
	if err := verify(root, leaf, usage); err != nil {
		t.Errorf("verify chain (usage=%v): %v", usage, err)
	}
}

func verify(root, leaf *x509.Certificate, usage x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err
}

// The scenario from the issue: alice's profile leaks, the operator re-issues
// to "replace" it, then revokes. Before the ledger the old certificate's serial
// lived only in clients/alice.crt, which the re-issue overwrote — so the leaked
// cert could not be revoked by any tool and stayed valid for up to a year.
func TestReissueLeavesNoUnrevocableCert(t *testing.T) {
	dir := t.TempDir()
	root, err := Create(dir, "test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := root.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	leaked, err := ClientSerial(dir, "alice")
	if err != nil {
		t.Fatalf("ClientSerial: %v", err)
	}

	// The operator re-issues, believing it replaces the leaked profile.
	if err := root.IssueClient("alice"); err != nil {
		t.Fatalf("re-IssueClient: %v", err)
	}
	current, err := ClientSerial(dir, "alice")
	if err != nil {
		t.Fatalf("ClientSerial after re-issue: %v", err)
	}
	if current.Cmp(leaked) == 0 {
		t.Fatal("re-issue reused the serial; test cannot detect the bug")
	}

	// The superseded certificate must already be denied — the operator's intent
	// in re-issuing was to retire it.
	checker := revoke.NewChecker(filepath.Join(dir, "revoked.json"))
	yes, err := checker.IsRevoked(leaked)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !yes {
		t.Error("superseded certificate is still accepted after re-issue")
	}

	// And revoking by name must reach every serial, not just the current one.
	serials, err := ClientSerials(dir, "alice")
	if err != nil {
		t.Fatalf("ClientSerials: %v", err)
	}
	if len(serials) != 2 {
		t.Fatalf("ClientSerials returned %d serials, want 2 (leaked + current)", len(serials))
	}
	found := map[string]bool{}
	for _, s := range serials {
		found[s.Text(16)] = true
	}
	if !found[leaked.Text(16)] || !found[current.Text(16)] {
		t.Errorf("ClientSerials missed a serial: got %v", found)
	}
}

// Corollary from the issue: issuing a previously revoked name used to mint a
// serial absent from the deny-list, silently lifting the revocation. The new
// certificate is legitimately live (the owner asked for it), but the revoked
// one it replaces must stay denied.
func TestReissueDoesNotResurrectRevokedCert(t *testing.T) {
	dir := t.TempDir()
	root, err := Create(dir, "test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := root.IssueClient("bob"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	old, err := ClientSerial(dir, "bob")
	if err != nil {
		t.Fatalf("ClientSerial: %v", err)
	}

	store := revoke.New(filepath.Join(dir, "revoked.json"))
	if _, err := store.Add(old, "bob"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := root.IssueClient("bob"); err != nil {
		t.Fatalf("re-IssueClient: %v", err)
	}

	checker := revoke.NewChecker(filepath.Join(dir, "revoked.json"))
	yes, err := checker.IsRevoked(old)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !yes {
		t.Error("re-issuing the name lifted the revocation on the old certificate")
	}

	// The freshly issued certificate is the live one and must not be denied.
	current, err := ClientSerial(dir, "bob")
	if err != nil {
		t.Fatalf("ClientSerial after re-issue: %v", err)
	}
	yes, err = checker.IsRevoked(current)
	if err != nil {
		t.Fatalf("IsRevoked(current): %v", err)
	}
	if yes {
		t.Error("the newly issued certificate is denied")
	}

	// The re-issue is the owner's deliberate act, so the new cert being live is
	// correct — but it must not happen silently. Both issuances are on record.
	ledger, err := loadLedger(dir)
	if err != nil {
		t.Fatalf("loadLedger: %v", err)
	}
	var forBob []string
	for _, e := range ledger.Issued {
		if e.Name == "bob" {
			forBob = append(forBob, e.Serial)
		}
	}
	if len(forBob) != 2 {
		t.Fatalf("ledger records %d issuances for bob, want 2: %v", len(forBob), forBob)
	}
	if forBob[0] != old.Text(16) || forBob[1] != current.Text(16) {
		t.Errorf("ledger = %v, want [%s %s] in issue order", forBob, old.Text(16), current.Text(16))
	}
}

// A CA created before the ledger existed has no issued.json. Revocation must
// still find the certificate on disk rather than reporting an unknown client.
func TestClientSerialsFallsBackToCertOnDisk(t *testing.T) {
	dir := t.TempDir()
	root, err := Create(dir, "test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := root.IssueClient("carol"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	// Simulate the pre-ledger layout.
	if err := os.Remove(filepath.Join(dir, "issued.json")); err != nil {
		t.Fatalf("remove ledger: %v", err)
	}

	serials, err := ClientSerials(dir, "carol")
	if err != nil {
		t.Fatalf("ClientSerials: %v", err)
	}
	cur, err := ClientSerial(dir, "carol")
	if err != nil {
		t.Fatalf("ClientSerial: %v", err)
	}
	if len(serials) != 1 || serials[0].Cmp(cur) != 0 {
		t.Fatalf("got %v, want just the on-disk serial %s", serials, cur.Text(16))
	}

	if _, err := ClientSerials(dir, "nobody"); err == nil {
		t.Error("ClientSerials succeeded for a name that was never issued")
	}
}

// A client name is turned into a path under clients/, so IssueClient must
// reject anything that escapes that directory — otherwise
// "issue-client -name ../server/server" overwrites the server's cert and key.
func TestIssueClientRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	root, err := Create(dir, "test CA")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := root.IssueServer("test server", []string{"vpn.example.com"},
		[]net.IP{net.ParseIP("10.0.0.1")}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}

	serverKey := filepath.Join(dir, "server", "server.key")
	before, err := os.ReadFile(serverKey)
	if err != nil {
		t.Fatalf("read server key: %v", err)
	}

	for _, name := range []string{
		"../server/server",
		"../../escape",
		"sub/dir",
		"..",
		".",
		"",
	} {
		if err := root.IssueClient(name); err == nil {
			t.Errorf("IssueClient(%q) succeeded, want rejection", name)
		}
		if _, err := ClientSerial(dir, name); err == nil {
			t.Errorf("ClientSerial(%q) succeeded, want rejection", name)
		}
	}

	after, err := os.ReadFile(serverKey)
	if err != nil {
		t.Fatalf("read server key after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("server private key was overwritten by a traversing client name")
	}
}

// Create must not overwrite existing CA material — it checks BOTH ca.crt and
// ca.key, not just the cert. A crash-partial state (or a stray file) must never
// silently clobber a CA private key. Regression for the guard that used to look
// at ca.crt alone.
func TestCreateRefusesWhenEitherCAFileExists(t *testing.T) {
	for _, present := range []string{"ca.crt", "ca.key"} {
		t.Run(present, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, present)
			if err := os.WriteFile(path, []byte("preexisting"), 0o600); err != nil {
				t.Fatalf("seed %s: %v", present, err)
			}
			if _, err := Create(dir, "test CA"); err == nil {
				t.Fatalf("Create succeeded with %s already present; must refuse", present)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s after: %v", present, err)
			}
			if string(got) != "preexisting" {
				t.Errorf("%s was overwritten; Create must not touch existing CA material", present)
			}
		})
	}
}
