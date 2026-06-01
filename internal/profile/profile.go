// Package profile loads and validates a client's VPN credentials — the CA
// certificate, the client certificate and key, and the server address — and
// turns them into the in-memory form a connection needs (PEM bytes plus a
// parsed server address).
//
// It is the single place that vets credentials before a connect attempt, so
// every front-end (CLI, GUI, or the future one-file profile bundle) reports
// the same clear errors — "key doesn't match certificate", "not signed by
// this CA", "expired" — instead of surfacing them as opaque TLS handshake
// failures later on. The checks here mirror what the server enforces during
// mTLS, caught early and locally.
package profile

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"
)

// Profile is a validated credential set ready to drive a connection. The
// PEM fields are the exact bytes to hand to the tunnel; CommonName and
// NotAfter are non-secret metadata for display (e.g. "as <CN>, expires …").
type Profile struct {
	Server     string // "vpn.example.com:8443"
	ServerName string // SNI / verification host; defaults to Server's host

	CACertPEM []byte
	CertPEM   []byte
	KeyPEM    []byte

	CommonName string    // client certificate CN
	NotAfter   time.Time // client certificate expiry
}

// Files names the on-disk inputs for Load. Server is the literal address
// the user supplies (host:port), not a path; ServerName is optional.
type Files struct {
	CACert     string // path to CA certificate (PEM)
	Cert       string // path to client certificate (PEM)
	Key        string // path to client private key (PEM)
	Server     string // "host:port"
	ServerName string // optional SNI override
}

// Load reads the three credential files and validates them via LoadPEM.
func Load(f Files) (*Profile, error) {
	caPEM, err := os.ReadFile(f.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	certPEM, err := os.ReadFile(f.Cert)
	if err != nil {
		return nil, fmt.Errorf("read client certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(f.Key)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	return LoadPEM(caPEM, certPEM, keyPEM, f.Server, f.ServerName)
}

// LoadPEM validates in-memory credentials and returns a Profile. The
// supplied byte slices are referenced (not copied) by the result; callers
// must not mutate them afterwards.
//
// Validation, in order:
//   - server is a parseable host:port; ServerName defaults to the host
//   - the CA PEM contains at least one certificate
//   - the client cert and key are a matching pair
//   - the client cert is currently within its validity window
//   - the client cert chains to the CA and carries the client-auth EKU
func LoadPEM(caPEM, certPEM, keyPEM []byte, server, serverName string) (*Profile, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", server, err)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("invalid server address %q: host and port are both required", server)
	}
	if serverName == "" {
		serverName = host
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA PEM contains no certificates")
	}

	// X509KeyPair parses both halves and confirms the key matches the cert.
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client certificate and key do not match (or are malformed): %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("client certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("client certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}

	// Confirm the cert chains to the supplied CA and is usable for client
	// authentication — the same trust the server checks at handshake time.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       caPool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: now,
	}); err != nil {
		return nil, fmt.Errorf("client certificate is not signed by the given CA (or lacks client-auth usage): %w", err)
	}

	return &Profile{
		Server:     server,
		ServerName: serverName,
		CACertPEM:  caPEM,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		CommonName: leaf.Subject.CommonName,
		NotAfter:   leaf.NotAfter,
	}, nil
}
