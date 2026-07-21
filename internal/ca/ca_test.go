package ca

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
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
