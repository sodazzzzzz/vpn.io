package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Health reporting: is this node alive, and is it in a state where a client
// that connects right now will actually get a tunnel?
//
// The two questions are separate on purpose. A server whose certificate expired
// last night is running perfectly and serving nobody — "the process is up" is
// exactly the signal that hides that class of outage. So:
//
//   - /healthz — liveness. The process runs, the TUN device is open, the
//     listener is bound. Answers "should this be restarted?"
//   - /readyz  — readiness. Everything above, plus the things a handshake needs:
//     a server certificate that is valid right now, and a revocation list that
//     can be read (the handshake fails closed on a broken one, so an unreadable
//     deny-list means every client is about to be rejected).
//
// Both are served on a separate, loopback-by-default listener. The status of a
// VPN node — how many people are on it, when its certificate runs out — is
// metadata about its users, and it has no business being reachable from the
// internet. Point a local probe or an SSH tunnel at it (see docs/SERVER.md).

// certExpiryWarning is how long before NotAfter the report starts saying the
// certificate needs attention. It does not affect readiness — a certificate
// valid for one more hour still serves clients — but it is what an alert
// watches so the rotation happens during working hours, not at expiry.
const certExpiryWarning = 21 * 24 * time.Hour

// HealthReport is the JSON body of both endpoints.
type HealthReport struct {
	// Live is false only when the process is up but structurally broken.
	Live bool `json:"live"`
	// Ready reports whether a client connecting now would be admitted.
	Ready bool `json:"ready"`
	// NotReady lists, in plain words, every reason Ready is false. Empty when
	// ready. This is what an operator reads at 3am, so it is prose, not codes.
	NotReady []string `json:"notReady,omitempty"`
	// Warnings are things that are not yet failures but will become one —
	// today's example being a certificate approaching expiry.
	Warnings []string `json:"warnings,omitempty"`

	Listen       string    `json:"listen"`
	TUN          string    `json:"tun"`
	Sessions     int       `json:"sessions"`
	CertNotAfter time.Time `json:"certNotAfter"`
	// CertExpiresInDays is negative once the certificate has expired.
	CertExpiresInDays int `json:"certExpiresInDays"`
}

// Health builds a report from the server's current state.
func (s *Server) Health() HealthReport {
	rep := HealthReport{
		Live:     true,
		Ready:    true,
		TUN:      s.tun.Name(),
		Sessions: len(s.registry.Snapshot()),
	}
	if addr := s.Addr(); addr != nil {
		rep.Listen = addr.String()
	} else {
		// Run has not bound the listener yet (or it went away). Nothing can
		// connect, and a restart is the fix — that is a liveness failure.
		rep.Live = false
		rep.Ready = false
		rep.NotReady = append(rep.NotReady, "listener is not bound")
	}

	if leaf := s.leafCert(); leaf != nil {
		rep.CertNotAfter = leaf.NotAfter
		remaining := leaf.NotAfter.Sub(now())
		rep.CertExpiresInDays = int(remaining / (24 * time.Hour))
		switch {
		case now().After(leaf.NotAfter):
			rep.Ready = false
			rep.NotReady = append(rep.NotReady,
				fmt.Sprintf("server certificate expired on %s — clients cannot verify this node", leaf.NotAfter.Format(time.DateOnly)))
		case now().Before(leaf.NotBefore):
			rep.Ready = false
			rep.NotReady = append(rep.NotReady,
				fmt.Sprintf("server certificate is not valid until %s (check the clock)", leaf.NotBefore.Format(time.DateOnly)))
		case remaining < certExpiryWarning:
			rep.Warnings = append(rep.Warnings,
				fmt.Sprintf("server certificate expires in %d day(s), on %s — re-issue it", rep.CertExpiresInDays, leaf.NotAfter.Format(time.DateOnly)))
		}
	}

	// Probe the deny-list with a serial no certificate has. A read or parse
	// error here is what every real handshake is about to hit, because the
	// revocation check fails closed.
	if s.revoked != nil {
		if _, err := s.revoked.IsRevoked(big.NewInt(0)); err != nil {
			rep.Ready = false
			rep.NotReady = append(rep.NotReady,
				fmt.Sprintf("revocation list cannot be read (%v) — every client is being rejected", err))
		}
	}
	return rep
}

// now is a seam so tests can move the clock without generating certificates
// with contrived validity windows.
var now = time.Now

// leafCert returns the parsed server certificate being presented to clients,
// or nil if it is somehow absent.
func (s *Server) leafCert() *x509.Certificate {
	if len(s.tlsConfig.Certificates) == 0 {
		return nil
	}
	cert := s.tlsConfig.Certificates[0]
	if cert.Leaf != nil {
		return cert.Leaf
	}
	if len(cert.Certificate) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

// HealthHandler serves /healthz and /readyz (and / as an alias for /readyz).
//
// Both return the same body; they differ in which field decides the status
// code, so a probe can use either without parsing JSON: 200 when the answer is
// yes, 503 when it is no.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, s.Health(), func(rep HealthReport) bool { return rep.Live })
	})
	ready := func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, s.Health(), func(rep HealthReport) bool { return rep.Ready })
	}
	mux.HandleFunc("/readyz", ready)
	mux.HandleFunc("/", ready)
	return mux
}

// startHealth binds the health listener, if one is configured, and returns a
// function that shuts it down. It returns (nil, nil) when HealthListen is
// empty — the endpoint is opt-out, not mandatory.
func (s *Server) startHealth() (stop func(), err error) {
	if s.cfg.HealthListen == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", s.cfg.HealthListen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.HealthListen, err)
	}
	srv := &http.Server{
		Handler: s.HealthHandler(),
		// A probe that opens a connection and says nothing must not hold a
		// goroutine open indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("server: health endpoint stopped", "err", err)
		}
	}()
	s.log.Info("server: health endpoint listening", "addr", ln.Addr())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

func writeHealth(w http.ResponseWriter, rep HealthReport, ok func(HealthReport) bool) {
	w.Header().Set("Content-Type", "application/json")
	// Health is a point-in-time answer; a cached one is worse than none.
	w.Header().Set("Cache-Control", "no-store")
	if !ok(rep) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}
