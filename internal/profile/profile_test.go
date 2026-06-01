package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/govpn/internal/ca"
)

const testServer = "vpn.example.com:8443"

// testCA creates a fresh CA in a temp dir, issues the named clients, and
// returns the CA handle plus the directory.
func testCA(t *testing.T, clients ...string) (*ca.CA, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.Create(dir, "test-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	for _, name := range clients {
		if err := c.IssueClient(name); err != nil {
			t.Fatalf("IssueClient(%q): %v", name, err)
		}
	}
	return c, dir
}

func read(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("read %v: %v", parts, err)
	}
	return b
}

func clientPEMs(t *testing.T, dir, name string) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caPEM = read(t, dir, "ca.crt")
	certPEM = read(t, dir, "clients", name+".crt")
	keyPEM = read(t, dir, "clients", name+".key")
	return
}

func TestLoadValid(t *testing.T) {
	_, dir := testCA(t, "alice")

	p, err := Load(Files{
		CACert: filepath.Join(dir, "ca.crt"),
		Cert:   filepath.Join(dir, "clients", "alice.crt"),
		Key:    filepath.Join(dir, "clients", "alice.key"),
		Server: testServer,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.CommonName != "alice" {
		t.Errorf("CommonName = %q, want alice", p.CommonName)
	}
	if p.Server != testServer {
		t.Errorf("Server = %q, want %q", p.Server, testServer)
	}
	if p.ServerName != "vpn.example.com" {
		t.Errorf("ServerName = %q, want vpn.example.com", p.ServerName)
	}
	if !p.NotAfter.After(time.Now()) {
		t.Errorf("NotAfter = %v, expected in the future", p.NotAfter)
	}
	if len(p.CACertPEM) == 0 || len(p.CertPEM) == 0 || len(p.KeyPEM) == 0 {
		t.Error("expected PEM fields to be populated")
	}
}

func TestServerNameOverrideAndDefault(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")

	// Explicit override is kept.
	p, err := LoadPEM(caPEM, certPEM, keyPEM, testServer, "sni.internal")
	if err != nil {
		t.Fatalf("LoadPEM: %v", err)
	}
	if p.ServerName != "sni.internal" {
		t.Errorf("ServerName = %q, want sni.internal", p.ServerName)
	}

	// Default derives from the host part.
	p, err = LoadPEM(caPEM, certPEM, keyPEM, "10.0.0.1:443", "")
	if err != nil {
		t.Fatalf("LoadPEM: %v", err)
	}
	if p.ServerName != "10.0.0.1" {
		t.Errorf("ServerName = %q, want 10.0.0.1", p.ServerName)
	}
}

func TestInvalidServerAddress(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")

	for _, addr := range []string{"", "noport", "host:", ":8443"} {
		if _, err := LoadPEM(caPEM, certPEM, keyPEM, addr, ""); err == nil {
			t.Errorf("address %q: expected error", addr)
		}
	}
}

func TestKeyCertMismatch(t *testing.T) {
	_, dir := testCA(t, "alice", "bob")
	caPEM, aliceCert, _ := clientPEMs(t, dir, "alice")
	_, _, bobKey := clientPEMs(t, dir, "bob")

	if _, err := LoadPEM(caPEM, aliceCert, bobKey, testServer, ""); err == nil {
		t.Fatal("expected mismatched key/cert to fail")
	}
}

func TestWrongCA(t *testing.T) {
	_, dir := testCA(t, "alice")
	_, aliceCert, aliceKey := clientPEMs(t, dir, "alice")

	// A different CA that never signed alice.
	_, otherDir := testCA(t)
	otherCA := read(t, otherDir, "ca.crt")

	if _, err := LoadPEM(otherCA, aliceCert, aliceKey, testServer, ""); err == nil {
		t.Fatal("expected cert signed by a different CA to fail")
	}
}

func TestEmptyCA(t *testing.T) {
	_, dir := testCA(t, "alice")
	_, certPEM, keyPEM := clientPEMs(t, dir, "alice")

	if _, err := LoadPEM([]byte("not a pem"), certPEM, keyPEM, testServer, ""); err == nil {
		t.Fatal("expected empty CA pool to fail")
	}
}

func TestExpiredCert(t *testing.T) {
	c, dir := testCA(t)
	caPEM := read(t, dir, "ca.crt")
	certPEM, keyPEM := mintClient(t, c, "expired", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	if _, err := LoadPEM(caPEM, certPEM, keyPEM, testServer, ""); err == nil {
		t.Fatal("expected expired certificate to fail")
	}
}

func TestNotYetValidCert(t *testing.T) {
	c, dir := testCA(t)
	caPEM := read(t, dir, "ca.crt")
	certPEM, keyPEM := mintClient(t, c, "future", time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	if _, err := LoadPEM(caPEM, certPEM, keyPEM, testServer, ""); err == nil {
		t.Fatal("expected not-yet-valid certificate to fail")
	}
}

// mintClient signs a client certificate with the CA's key over the given
// validity window, returning cert and key PEM. Used to construct certs the
// ca package's fixed-validity issuer can't (expired / not-yet-valid).
func mintClient(t *testing.T, c *ca.CA, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}
