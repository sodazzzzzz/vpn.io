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
	"strconv"
	"time"
)

// Profile is a validated credential set ready to drive a connection. The
// PEM fields are the exact bytes to hand to the tunnel; CommonName and
// NotAfter are non-secret metadata for display (e.g. "as <CN>, expires …").
type Profile struct {
	Server     string // "vpn.example.com:8443"
	ServerName string // SNI / verification host; defaults to Server's host

	// json:"-" keeps the credential bytes (the private key in particular)
	// out of any accidental json.Marshal of a Profile; String/GoString cover
	// the fmt verbs. Profile isn't a wire type — read the fields directly.
	CACertPEM []byte `json:"-"`
	CertPEM   []byte `json:"-"`
	KeyPEM    []byte `json:"-"`

	CommonName string    // client certificate CN
	NotAfter   time.Time // client certificate expiry
}

// String renders a Profile without its credential bytes, so the private key
// can't leak through fmt's %v/%s/%+v or a logger that stringifies values.
// Use the fields directly when you actually need the PEM.
func (p *Profile) String() string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Profile{Server:%s ServerName:%s CN:%s NotAfter:%s}",
		p.Server, p.ServerName, p.CommonName, p.NotAfter.Format(time.RFC3339))
}

// GoString does the same for the %#v verb.
func (p *Profile) GoString() string { return p.String() }

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
	if host == "" {
		return nil, fmt.Errorf("invalid server address %q: host is required", server)
	}
	// SplitHostPort accepts a non-numeric port ("host:abc"); require a real
	// port number so a bad address fails here, not later at dial time.
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid server address %q: port must be a number in 1–65535", server)
	}
	if serverName == "" {
		serverName = host
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA PEM contains no certificates")
	}

	// X509KeyPair parses both halves and confirms the key matches the cert.
	// A bundled certPEM (leaf + intermediates) lands in tlsCert.Certificate:
	// [0] is the leaf, the rest are intermediates.
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client certificate and key do not match (or are malformed): %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	// Feed any intermediates to Verify so a leaf+intermediate bundle chains
	// to the CA — matching what the TLS dialer would accept. Without this a
	// chain the server happily verifies would fail locally with "unknown
	// authority".
	intermediates := x509.NewCertPool()
	for _, der := range tlsCert.Certificate[1:] {
		ic, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(ic)
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
		Roots:         caPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
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
