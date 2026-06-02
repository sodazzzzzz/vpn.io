package profilestore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func sample() Profile {
	return Profile{
		Server:     "vpn.example.com:8443",
		ServerName: "vpn.example.com",
		MTU:        1380,
		TunName:    "utun7",
		CACertPEM:  []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"),
		CertPEM:    []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"),
		KeyPEM:     []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
		CAName:     "ca.pem",
		CertName:   "client.crt",
		KeyName:    "client.key",
	}
}

func tempStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Path: filepath.Join(t.TempDir(), "profile.json")}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := tempStore(t)
	want := sample()
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("Load reported no profile after Save")
	}
	if got.Server != want.Server || got.ServerName != want.ServerName ||
		got.MTU != want.MTU || got.TunName != want.TunName ||
		got.CAName != want.CAName || got.CertName != want.CertName || got.KeyName != want.KeyName {
		t.Errorf("metadata round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if string(got.CACertPEM) != string(want.CACertPEM) ||
		string(got.CertPEM) != string(want.CertPEM) ||
		string(got.KeyPEM) != string(want.KeyPEM) {
		t.Error("PEM bytes did not round-trip")
	}
}

func TestLoadAbsent(t *testing.T) {
	s := tempStore(t)
	_, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load on absent file: unexpected error %v", err)
	}
	if ok {
		t.Fatal("Load reported a profile when none was saved")
	}
}

func TestSavePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions")
	}
	s := tempStore(t)
	if err := s.Save(sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("profile permissions = %o, want 600", perm)
	}
}

func TestDefaultHonoursEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	t.Setenv("VPN_IO_PROFILE", path)
	s, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if s.Path != path {
		t.Errorf("Default path = %q, want override %q", s.Path, path)
	}
}

func TestClear(t *testing.T) {
	s := tempStore(t)
	if err := s.Save(sample()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, ok, _ := s.Load(); ok {
		t.Fatal("profile still present after Clear")
	}
	// Clear on an already-absent file is a no-op.
	if err := s.Clear(); err != nil {
		t.Errorf("Clear on absent file: %v", err)
	}
}
