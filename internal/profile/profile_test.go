package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

	for _, addr := range []string{
		"", "noport", "host:", ":8443",
		"host:abc",   // non-numeric port
		"host:0",     // port out of range (low)
		"host:70000", // port out of range (high)
	} {
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
	keyPEM = keyToPEM(t, key)
	return
}

// keyToPEM marshals an EC private key to PKCS#8 PEM.
func keyToPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// mintRootCA creates a self-signed CA that permits an intermediate beneath
// it (the project's own CA is single-level, so this builds an independent
// root to exercise chain building).
func mintRootCA(t *testing.T) (cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, certPEM
}

// TestLoadWithIntermediateChain proves a leaf+intermediate bundle that
// chains to the root (with only the root supplied as the CA) verifies — the
// case the Intermediates pool in LoadPEM exists for. As a control, the leaf
// alone must fail against the root.
func TestLoadWithIntermediateChain(t *testing.T) {
	rootCert, rootKey, rootPEM := mintRootCA(t)

	// Intermediate CA, signed by the root.
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "test-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	// Leaf, signed by the intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := keyToPEM(t, leafKey)

	// Bundle = leaf + intermediate; CA = root only.
	bundle := append(append([]byte{}, leafPEM...), interPEM...)
	if _, err := LoadPEM(rootPEM, bundle, leafKeyPEM, testServer, ""); err != nil {
		t.Fatalf("LoadPEM with intermediate chain: %v", err)
	}

	// Control: leaf alone does not chain to the root.
	if _, err := LoadPEM(rootPEM, leafPEM, leafKeyPEM, testServer, ""); err == nil {
		t.Fatal("expected leaf without its intermediate to fail against the root")
	}
}

// TestProfileStringRedactsKey ensures no PEM material (key or certs) leaks
// through the common fmt verbs, while useful identity still shows.
func TestProfileStringRedactsKey(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")
	p, err := LoadPEM(caPEM, certPEM, keyPEM, testServer, "")
	if err != nil {
		t.Fatal(err)
	}

	// Cover both *Profile and Profile-value formatting: with a value receiver
	// both must go through the redacting Stringer. (A pointer receiver would
	// let the value forms fall back to fmt's default field dump — key bytes
	// rendered as decimals, which "-----BEGIN" alone wouldn't catch, so we
	// also assert the redacted form was produced.)
	renders := map[string]string{
		"String()":  p.String(),
		"%v ptr":    fmt.Sprintf("%v", p),
		"%+v ptr":   fmt.Sprintf("%+v", p),
		"%#v ptr":   fmt.Sprintf("%#v", p),
		"%v value":  fmt.Sprintf("%v", *p),
		"%+v value": fmt.Sprintf("%+v", *p),
		"%#v value": fmt.Sprintf("%#v", *p),
	}
	for name, s := range renders {
		if strings.Contains(s, "-----BEGIN") {
			t.Errorf("%s leaked PEM material: %q", name, s)
		}
		if !strings.Contains(s, "Profile{Server:") {
			t.Errorf("%s did not go through the redacting String(): %q", name, s)
		}
	}
	if !strings.Contains(p.String(), "alice") {
		t.Errorf("String() should include the CN, got %q", p.String())
	}

	// json.Marshal must not carry the credential bytes either (json:"-").
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "-----BEGIN") {
		t.Errorf("json.Marshal leaked PEM material: %s", b)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")

	data, err := MarshalBundle(caPEM, certPEM, keyPEM, testServer, "")
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}

	p, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if p.Server != testServer {
		t.Errorf("Server = %q, want %q", p.Server, testServer)
	}
	if p.CommonName != "alice" {
		t.Errorf("CommonName = %q, want alice", p.CommonName)
	}
	if string(p.CACertPEM) != string(caPEM) ||
		string(p.CertPEM) != string(certPEM) ||
		string(p.KeyPEM) != string(keyPEM) {
		t.Error("PEM bytes did not survive the bundle round-trip")
	}
}

func TestBundleCarriesServerName(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")

	data, err := MarshalBundle(caPEM, certPEM, keyPEM, "10.0.0.5:8443", "vpn.example.com")
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	p, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if p.ServerName != "vpn.example.com" {
		t.Errorf("ServerName = %q, want vpn.example.com", p.ServerName)
	}
}

func TestMarshalBundleRejectsMismatchedKey(t *testing.T) {
	_, dir := testCA(t, "alice", "bob")
	caPEM, certPEM, _ := clientPEMs(t, dir, "alice")
	_, _, bobKey := clientPEMs(t, dir, "bob")

	// alice's cert with bob's key must not produce a bundle.
	if _, err := MarshalBundle(caPEM, certPEM, bobKey, testServer, ""); err == nil {
		t.Fatal("expected error for mismatched cert/key, got nil")
	}
}

func TestParseBundleUnknownVersion(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")
	data, err := MarshalBundle(caPEM, certPEM, keyPEM, testServer, "")
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}

	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	b.Version = BundleVersion + 999
	bumped, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := ParseBundle(bumped); err == nil {
		t.Fatal("expected error for unknown bundle version, got nil")
	}
}

func TestParseBundleMalformedJSON(t *testing.T) {
	if _, err := ParseBundle([]byte("definitely not json")); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestBundleStringRedactsKey(t *testing.T) {
	_, dir := testCA(t, "alice")
	caPEM, certPEM, keyPEM := clientPEMs(t, dir, "alice")
	b := Bundle{
		Version:   BundleVersion,
		Server:    testServer,
		CACertPEM: string(caPEM),
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
	}
	if strings.Contains(b.String(), "-----BEGIN") {
		t.Error("Bundle.String() leaked PEM material")
	}
	// Verb is a variable so staticcheck doesn't fold "%s" into a String() call:
	// the point is to exercise the fmt path the way a stray log line would.
	for _, verb := range []string{"%v", "%s", "%+v", "%#v"} {
		if s := fmt.Sprintf(verb, b); strings.Contains(s, "-----BEGIN") {
			t.Errorf("Bundle %q formatting leaked PEM material: %s", verb, s)
		}
	}
}

// --- endpoint lists (v2) -----------------------------------------------------

// fixture is one valid credential set, reused by the endpoint-list tests.
type fixture struct{ caPEM, certPEM, keyPEM []byte }

func newFixture(t *testing.T) fixture {
	t.Helper()
	_, dir := testCA(t, "alice")
	ca, cert, key := clientPEMs(t, dir, "alice")
	return fixture{caPEM: ca, certPEM: cert, keyPEM: key}
}

// A profile written before endpoint lists existed must keep working untouched.
// This is the compatibility promise the format change was allowed to make.
func TestParseBundleV1StillLoads(t *testing.T) {
	f := newFixture(t)
	data, err := MarshalBundle(f.caPEM, f.certPEM, f.keyPEM, "vpn.example.com:8443", "")
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := raw["version"]; got != float64(BundleVersionSingle) {
		t.Errorf("single-endpoint bundle written as version %v, want %d — older apps would reject it",
			got, BundleVersionSingle)
	}
	if _, ok := raw["endpoints"]; ok {
		t.Error("single-endpoint bundle carries an endpoints list")
	}

	prof, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(prof.Endpoints) != 1 {
		t.Fatalf("v1 bundle yielded %d endpoints, want 1", len(prof.Endpoints))
	}
	if prof.Server != "vpn.example.com:8443" || prof.Endpoints[0].Server != prof.Server {
		t.Errorf("v1 endpoint = %q / %q", prof.Server, prof.Endpoints[0].Server)
	}
	if prof.Endpoints[0].ServerName != "vpn.example.com" {
		t.Errorf("SNI not defaulted from the host: %q", prof.Endpoints[0].ServerName)
	}
}

func TestBundleRoundTripsMultipleEndpoints(t *testing.T) {
	f := newFixture(t)
	eps := []Endpoint{
		{Server: "203.0.113.5:8443", Label: "main"},
		{Server: "vpn2.example.com:8443", ServerName: "vpn.example.com", Label: "backup"},
	}
	data, err := MarshalBundleEndpoints(f.caPEM, f.certPEM, f.keyPEM, eps)
	if err != nil {
		t.Fatalf("MarshalBundleEndpoints: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := raw["version"]; got != float64(BundleVersionList) {
		t.Errorf("multi-endpoint bundle written as version %v, want %d", got, BundleVersionList)
	}

	prof, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(prof.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(prof.Endpoints))
	}
	// The primary fields keep pointing at the first endpoint, so every caller
	// that only knows about one address keeps working.
	if prof.Server != "203.0.113.5:8443" {
		t.Errorf("primary Server = %q, want the first endpoint", prof.Server)
	}
	if prof.Endpoints[0].ServerName != "203.0.113.5" {
		t.Errorf("first endpoint SNI = %q, want the host", prof.Endpoints[0].ServerName)
	}
	if prof.Endpoints[1].ServerName != "vpn.example.com" {
		t.Errorf("explicit SNI not preserved: %q", prof.Endpoints[1].ServerName)
	}
	if prof.Endpoints[1].Label != "backup" {
		t.Errorf("label not preserved: %q", prof.Endpoints[1].Label)
	}
}

func TestParseBundleRejectsBadEndpointLists(t *testing.T) {
	f := newFixture(t)
	body := func(inner string) []byte {
		b, err := json.Marshal(Bundle{
			Version:   BundleVersionList,
			CACertPEM: string(f.caPEM), CertPEM: string(f.certPEM), KeyPEM: string(f.keyPEM),
		})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		var eps any
		if err := json.Unmarshal([]byte(inner), &eps); err != nil {
			t.Fatal(err)
		}
		m["endpoints"] = eps
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := map[string]string{
		"empty list":        `[]`,
		"no port":           `[{"server":"vpn.example.com"}]`,
		"port not numeric":  `[{"server":"vpn.example.com:https"}]`,
		"port out of range": `[{"server":"vpn.example.com:70000"}]`,
		"no host":           `[{"server":":8443"}]`,
		"duplicate":         `[{"server":"a.example.com:8443"},{"server":"a.example.com:8443"}]`,
	}
	for name, inner := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBundle(body(inner)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// A file that claims v1 while carrying a v2 field was written by something
// confused; guessing which half to believe is how a client ends up dialling an
// address nobody intended.
func TestParseBundleRejectsMixedVersions(t *testing.T) {
	f := newFixture(t)
	data, err := json.Marshal(Bundle{
		Version:   BundleVersionSingle,
		Server:    "a.example.com:8443",
		Endpoints: []Endpoint{{Server: "b.example.com:8443"}},
		CACertPEM: string(f.caPEM), CertPEM: string(f.certPEM), KeyPEM: string(f.keyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBundle(data); err == nil {
		t.Fatal("accepted a v1 bundle carrying an endpoint list")
	}

	// v2 may repeat the v1 field for older readers, but not contradict it.
	data, err = json.Marshal(Bundle{
		Version:   BundleVersionList,
		Server:    "a.example.com:8443",
		Endpoints: []Endpoint{{Server: "b.example.com:8443"}},
		CACertPEM: string(f.caPEM), CertPEM: string(f.certPEM), KeyPEM: string(f.keyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBundle(data); err == nil {
		t.Fatal("accepted a v2 bundle whose server disagrees with its first endpoint")
	}
}

func TestParseBundleRejectsFutureVersion(t *testing.T) {
	f := newFixture(t)
	data, err := json.Marshal(Bundle{
		Version:   BundleVersionList + 1,
		Endpoints: []Endpoint{{Server: "a.example.com:8443"}},
		CACertPEM: string(f.caPEM), CertPEM: string(f.certPEM), KeyPEM: string(f.keyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseBundle(data)
	if err == nil {
		t.Fatal("accepted a bundle from the future")
	}
	if !strings.Contains(err.Error(), "update the app") {
		t.Errorf("error does not tell the user what to do: %v", err)
	}
}
