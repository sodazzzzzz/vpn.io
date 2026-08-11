package profilestore

import (
	"os"
	"path/filepath"

	"github.com/govpn/internal/profile"
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

func TestLoadRejectsOversized(t *testing.T) {
	s := tempStore(t)
	big := make([]byte, (256<<10)+1)
	if err := os.WriteFile(s.Path, big, 0o600); err != nil {
		t.Fatalf("write big file: %v", err)
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatal("expected Load to reject an oversized profile file")
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

// A saved profile must carry its endpoint list and the remembered address, and
// bring both back — that memory is the whole point of storing it locally.
func TestSaveLoadEndpoints(t *testing.T) {
	st := &Store{Path: filepath.Join(t.TempDir(), "profile.json")}
	in := Profile{
		Server: "a.example.com:8443",
		Endpoints: []profile.Endpoint{
			{Server: "a.example.com:8443"},
			{Server: "b.example.com:8443", Label: "backup"},
		},
		LastEndpoint: "b.example.com:8443",
		CACertPEM:    []byte("ca"), CertPEM: []byte("cert"), KeyPEM: []byte("key"),
	}
	if err := st.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := st.Load()
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if len(got.Endpoints) != 2 || got.Endpoints[1].Label != "backup" {
		t.Errorf("endpoints did not round-trip: %+v", got.Endpoints)
	}
	if got.LastEndpoint != "b.example.com:8443" {
		t.Errorf("LastEndpoint = %q", got.LastEndpoint)
	}
}

// A profile written before endpoint lists existed still loads, with no
// endpoints and no memory — the single Server is all it ever had.
func TestLoadProfileWithoutEndpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	old := `{"server":"old.example.com:8443","caCertPem":"Y2E=","certPem":"Y2VydA==","keyPem":"a2V5"}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (&Store{Path: path}).Load()
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.Server != "old.example.com:8443" {
		t.Errorf("Server = %q", got.Server)
	}
	if len(got.Endpoints) != 0 || got.LastEndpoint != "" {
		t.Errorf("old profile gained endpoints out of nowhere: %+v / %q", got.Endpoints, got.LastEndpoint)
	}
}
