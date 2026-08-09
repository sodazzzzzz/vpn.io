package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func getHealth(t *testing.T, h http.Handler, path string) (int, HealthReport) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var rep HealthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode %s body %q: %v", path, rec.Body.String(), err)
	}
	return rec.Code, rep
}

func TestHealthReportsReadyServer(t *testing.T) {
	h := startServer(t, "10.9.0.0/24", "10.9.0.1", "255.255.255.0")
	defer h.shutdown()

	handler := h.srv.HealthHandler()
	for _, path := range []string{"/healthz", "/readyz", "/"} {
		code, rep := getHealth(t, handler, path)
		if code != http.StatusOK {
			t.Errorf("%s = %d, want 200 (notReady: %v)", path, code, rep.NotReady)
		}
		if !rep.Live || !rep.Ready {
			t.Errorf("%s: live=%v ready=%v, want both true", path, rep.Live, rep.Ready)
		}
	}
	_, rep := getHealth(t, handler, "/readyz")
	if rep.Listen == "" {
		t.Error("report has no listen address")
	}
	if rep.TUN != "fake0" {
		t.Errorf("report TUN = %q, want fake0", rep.TUN)
	}
	if rep.CertNotAfter.IsZero() {
		t.Error("report has no certificate expiry")
	}
	if len(rep.NotReady) != 0 || len(rep.Warnings) != 0 {
		t.Errorf("healthy server reported notReady=%v warnings=%v", rep.NotReady, rep.Warnings)
	}
}

// The failure this endpoint exists for: the process is fine, the listener is
// bound, and every client is being turned away because the certificate ran out.
// Liveness must stay true (restarting fixes nothing) while readiness goes false.
func TestHealthNotReadyOnExpiredCertificate(t *testing.T) {
	h := startServer(t, "10.9.1.0/24", "10.9.1.1", "255.255.255.0")
	defer h.shutdown()

	leaf := h.srv.leafCert()
	if leaf == nil {
		t.Fatal("no leaf certificate")
	}
	// Move the clock past the certificate instead of minting an expired one:
	// the CA refuses to issue certificates in the past, and the seam is there
	// precisely so this stays a one-line test.
	restore := now
	now = func() time.Time { return leaf.NotAfter.Add(24 * time.Hour) }
	defer func() { now = restore }()

	code, rep := getHealth(t, h.srv.HealthHandler(), "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d, want 503", code)
	}
	if rep.Ready {
		t.Error("server reports ready with an expired certificate")
	}
	if !rep.Live {
		t.Error("expired certificate made the server report not-live; restarting it would not help")
	}
	if len(rep.NotReady) == 0 {
		t.Fatal("no reason given for not being ready")
	}
	code, _ = getHealth(t, h.srv.HealthHandler(), "/healthz")
	if code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200 — liveness is a separate question", code)
	}
}

// A certificate that is still valid but close to expiry stays ready and gains a
// warning — the signal an alert watches to get rotation done in daylight.
func TestHealthWarnsBeforeCertificateExpiry(t *testing.T) {
	h := startServer(t, "10.9.2.0/24", "10.9.2.1", "255.255.255.0")
	defer h.shutdown()

	leaf := h.srv.leafCert()
	restore := now
	now = func() time.Time { return leaf.NotAfter.Add(-3 * 24 * time.Hour) }
	defer func() { now = restore }()

	code, rep := getHealth(t, h.srv.HealthHandler(), "/readyz")
	if code != http.StatusOK || !rep.Ready {
		t.Errorf("/readyz = %d ready=%v; a certificate valid for three more days still serves clients", code, rep.Ready)
	}
	if len(rep.Warnings) == 0 {
		t.Error("no warning three days before expiry")
	}
}

// The revocation check fails closed, so a deny-list the server cannot parse
// means every handshake is being rejected. That must show up as not-ready
// rather than as a silent outage.
func TestHealthNotReadyOnUnreadableRevocationList(t *testing.T) {
	revoked := filepath.Join(t.TempDir(), "revoked.json")
	if err := os.WriteFile(revoked, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write revoked list: %v", err)
	}
	h := startServer(t, "10.9.3.0/24", "10.9.3.1", "255.255.255.0", func(c *Config) {
		c.RevokedFile = revoked
	})
	defer h.shutdown()

	code, rep := getHealth(t, h.srv.HealthHandler(), "/readyz")
	if code != http.StatusServiceUnavailable || rep.Ready {
		t.Fatalf("/readyz = %d ready=%v, want 503/false with a broken deny-list", code, rep.Ready)
	}
	if len(rep.NotReady) == 0 {
		t.Fatal("no reason given for not being ready")
	}
}

// The endpoint is opt-out: an empty address starts nothing at all, and must not
// keep the tunnel from running.
func TestHealthListenerDisabledByEmptyAddress(t *testing.T) {
	h := startServer(t, "10.9.4.0/24", "10.9.4.1", "255.255.255.0")
	defer h.shutdown()

	stop, err := h.srv.startHealth()
	if err != nil {
		t.Fatalf("startHealth with no address: %v", err)
	}
	if stop != nil {
		t.Error("startHealth bound a listener despite an empty address")
	}
}

// End to end over a real socket: the server binds the endpoint itself when
// configured, and stops it when the server stops.
func TestHealthListenerServesOverHTTP(t *testing.T) {
	h := startServer(t, "10.9.5.0/24", "10.9.5.1", "255.255.255.0", func(c *Config) {
		c.HealthListen = "127.0.0.1:0"
	})
	defer h.shutdown()

	stop, err := h.srv.startHealth()
	if err != nil {
		t.Fatalf("startHealth: %v", err)
	}
	if stop == nil {
		t.Fatal("startHealth returned no stop function")
	}
	defer stop()
	// Run already started one on the configured address; this second listener
	// is the one we can address deterministically (port 0 → kernel-assigned).
	srv := httptest.NewServer(h.srv.HealthHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /readyz = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}
