package vless

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The chain-size rule is the whole reason this check exists: an oversized
// target produces a node where everything looks healthy and no traffic flows.
func TestDestClassify(t *testing.T) {
	tests := []struct {
		name        string
		report      DestReport
		wantOK      bool
		wantWarning bool
	}{
		{"small modern site", DestReport{TLS13: true, ALPN: "h2", ChainBytes: 2000}, true, false},
		{"near the limit", DestReport{TLS13: true, ALPN: "h2", ChainBytes: maxChainBytes - 1}, true, true},
		{"oversized chain", DestReport{TLS13: true, ALPN: "h2", ChainBytes: maxChainBytes + 1}, false, false},
		{"no TLS 1.3", DestReport{TLS13: false, ALPN: "h2", ChainBytes: 2000}, false, false},
		{"no HTTP/2", DestReport{TLS13: true, ALPN: "", ChainBytes: 2000}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.report
			r.classify()
			if got := r.OK(); got != tc.wantOK {
				t.Errorf("OK() = %v, want %v (problems: %v)", got, tc.wantOK, r.Problems)
			}
			if got := len(r.Warnings) > 0; got != tc.wantWarning {
				t.Errorf("warnings = %v, want %v (%v)", got, tc.wantWarning, r.Warnings)
			}
		})
	}
}

// The oversized case must say what the operator will otherwise spend an evening
// discovering: the client connects and nothing flows.
func TestDestProblemExplainsTheSymptom(t *testing.T) {
	r := DestReport{TLS13: true, ALPN: "h2", ChainBytes: maxChainBytes * 2}
	r.classify()
	if len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "no traffic") {
		t.Errorf("problem does not describe the symptom: %v", r.Problems)
	}
}

// Measure a real handshake, against a local server rather than the network: the
// numbers in the report come from the connection, and a mistake there would
// silently turn the check into theatre.
func TestCheckDestMeasuresHandshake(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	prev := destRoots
	destRoots = pool
	t.Cleanup(func() { destRoots = prev })

	// httptest's certificate carries 127.0.0.1 as a SAN, so the address is also
	// a name it serves.
	addr := strings.TrimPrefix(srv.URL, "https://")
	r, err := CheckDest(context.Background(), addr)
	if err != nil {
		t.Fatalf("CheckDest: %v", err)
	}
	if !r.TLS13 {
		t.Error("TLS 1.3 not detected against a TLS 1.3-only server")
	}
	if r.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", r.ALPN)
	}
	if r.ChainBytes == 0 {
		t.Error("chain size was not measured")
	}
	if !r.OK() {
		t.Errorf("a small, modern local server was rejected: %v", r.Problems)
	}
}

func TestCheckDestUnreachable(t *testing.T) {
	// Port 1 on the loopback: nothing listens, and the failure is immediate.
	if _, err := CheckDest(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("CheckDest reported no error for an unreachable target")
	} else if !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("error does not say the target was unreachable: %v", err)
	}
}

func TestCheckDestRejectsMalformedAddress(t *testing.T) {
	if _, err := CheckDest(context.Background(), "www.example.com"); err == nil {
		t.Fatal("CheckDest accepted an address with no port")
	}
}
