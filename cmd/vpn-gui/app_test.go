package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/profile"
	"github.com/govpn/internal/profilestore"
)

// TestNewAppLoadsSavedProfile checks that a profile persisted by a previous run
// is reloaded into the draft on startup, so the user lands on "Connect" rather
// than "Import a profile". (Runs locally / on macOS; this nested module is not
// part of the root CI.)
func TestNewAppLoadsSavedProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	t.Setenv("VPN_IO_PROFILE", path)

	st := &profilestore.Store{Path: path}
	if err := st.Save(profilestore.Profile{
		Server:    "vpn.example.com:8443",
		CACertPEM: []byte("ca"),
		CertPEM:   []byte("cert"),
		KeyPEM:    []byte("key"),
		CAName:    "ca.pem",
		CertName:  "client.crt",
		KeyName:   "client.key",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	p := NewApp().Profile()
	if !p.HasProfile {
		t.Fatal("expected HasProfile=true after loading a saved profile")
	}
	if p.Server != "vpn.example.com:8443" {
		t.Errorf("Server = %q, want vpn.example.com:8443", p.Server)
	}
	if !p.CA.Loaded || p.CA.FileName != "ca.pem" {
		t.Errorf("CA = %+v, want loaded ca.pem", p.CA)
	}
	if !p.Cert.Loaded || !p.Key.Loaded {
		t.Errorf("cert/key not marked loaded: cert=%+v key=%+v", p.Cert, p.Key)
	}
}

// TestNewAppNoProfile checks that with no saved profile the draft is empty.
func TestNewAppNoProfile(t *testing.T) {
	t.Setenv("VPN_IO_PROFILE", filepath.Join(t.TempDir(), "absent.json"))
	if NewApp().Profile().HasProfile {
		t.Fatal("expected HasProfile=false with no saved profile")
	}
}

// TestConnectInvalidFormKeepsDraft verifies that a Connect whose form fails
// validation (here a portless server address) does not clobber the
// previously-loaded working profile in the draft.
func TestConnectInvalidFormKeepsDraft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	t.Setenv("VPN_IO_PROFILE", path)

	st := &profilestore.Store{Path: path}
	if err := st.Save(profilestore.Profile{
		Server:    "vpn.example.com:8443",
		CACertPEM: []byte("ca"), CertPEM: []byte("cert"), KeyPEM: []byte("key"),
		CAName: "ca.pem", CertName: "client.crt", KeyName: "client.key",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	a := NewApp()
	if _, err := a.Connect(ConnectForm{Server: "vpn.example.com"}); err == nil {
		t.Fatal("expected Connect to fail on a portless address")
	}
	if got := a.Profile().Server; got != "vpn.example.com:8443" {
		t.Errorf("draft server clobbered after a failed Connect: got %q, want vpn.example.com:8443", got)
	}
}

// TestImportBundleStagesProfile verifies that importing a valid .vpnio stages a
// complete, connect-ready draft, and that a malformed bundle is rejected.
func TestImportBundleStagesProfile(t *testing.T) {
	t.Setenv("VPN_IO_PROFILE", filepath.Join(t.TempDir(), "profile.json"))

	// Build a real bundle from a fresh CA.
	caDir := t.TempDir()
	c, err := ca.Create(caDir, "test-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := c.IssueClient("laptop"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	certPEM, _ := os.ReadFile(filepath.Join(caDir, "clients", "laptop.crt"))
	keyPEM, _ := os.ReadFile(filepath.Join(caDir, "clients", "laptop.key"))
	bundle, err := profile.MarshalBundle(caPEM, certPEM, keyPEM, "vpn.example.com:8443", "")
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}

	a := NewApp()
	info, err := a.importBundleData(bundle, "laptop.vpnio")
	if err != nil {
		t.Fatalf("importBundleData: %v", err)
	}
	if !info.HasProfile {
		t.Error("HasProfile = false, want true after import")
	}
	if info.Server != "vpn.example.com:8443" {
		t.Errorf("Server = %q, want vpn.example.com:8443", info.Server)
	}
	if info.CommonName != "laptop" {
		t.Errorf("CommonName = %q, want laptop", info.CommonName)
	}
	if !info.CA.Loaded || !info.Cert.Loaded || !info.Key.Loaded {
		t.Errorf("not all credential slots loaded: %+v", info)
	}
	if info.CA.FileName != "laptop.vpnio" {
		t.Errorf("CA.FileName = %q, want laptop.vpnio", info.CA.FileName)
	}

	// A malformed bundle is rejected.
	if _, err := a.importBundleData([]byte("not a bundle"), "x.vpnio"); err == nil {
		t.Error("expected error for a malformed bundle")
	}
}
