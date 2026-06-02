package main

import (
	"path/filepath"
	"testing"

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
