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
	"encoding/json"
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
	// Server and ServerName describe the PRIMARY endpoint — the first entry of
	// Endpoints. They stay because most of the code has exactly one question
	// ("where do I dial?") and because every profile written before endpoint
	// lists existed had only this. Code that can fall back walks Endpoints.
	Server     string // "vpn.example.com:8443"
	ServerName string // SNI / verification host; defaults to Server's host

	// Endpoints is every address this profile knows for the same node, in the
	// order they should be tried. Always non-empty: a v1 profile yields one.
	Endpoints []Endpoint

	// json:"-" keeps the credential bytes (the private key in particular)
	// out of any accidental json.Marshal of a Profile; String/GoString cover
	// the fmt verbs. Profile isn't a wire type — read the fields directly.
	CACertPEM []byte `json:"-"`
	CertPEM   []byte `json:"-"`
	KeyPEM    []byte `json:"-"`

	CommonName string    // client certificate CN
	NotAfter   time.Time // client certificate expiry
}

// Endpoint is one address a client may connect to. Several of them in a
// profile are not "several servers": they are the same node reachable more than
// one way, so the same client certificate authenticates against all of them.
// That is what makes a moved or re-addressed node survivable without handing
// everyone a new file.
type Endpoint struct {
	Server     string `json:"server"`               // "vpn.example.com:8443"
	ServerName string `json:"serverName,omitempty"` // SNI override; defaults to the host
	// Label is free text shown in the UI ("home", "backup"). It carries no
	// meaning for the connection.
	Label string `json:"label,omitempty"`
}

// String renders an Endpoint for display and logs. No secrets are involved.
func (e Endpoint) String() string {
	if e.Label != "" {
		return fmt.Sprintf("%s (%s)", e.Server, e.Label)
	}
	return e.Server
}

// validateEndpoints checks every address and fills in defaulted SNI, returning
// the cleaned list. The rules are the ones a dial would hit anyway — better to
// fail on import, where the message can be read, than at connect time.
func validateEndpoints(eps []Endpoint) ([]Endpoint, error) {
	if len(eps) == 0 {
		return nil, fmt.Errorf("profile has no server endpoints")
	}
	out := make([]Endpoint, 0, len(eps))
	seen := make(map[string]bool, len(eps))
	for i, ep := range eps {
		host, port, err := net.SplitHostPort(ep.Server)
		if err != nil {
			return nil, fmt.Errorf("endpoint %d: invalid server address %q: %w", i+1, ep.Server, err)
		}
		if host == "" {
			return nil, fmt.Errorf("endpoint %d: invalid server address %q: host is required", i+1, ep.Server)
		}
		// SplitHostPort accepts a non-numeric port ("host:abc"); require a real
		// port number so a bad address fails here, not later at dial time.
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("endpoint %d: invalid server address %q: port must be a number in 1–65535", i+1, ep.Server)
		}
		if ep.ServerName == "" {
			ep.ServerName = host
		}
		// A duplicate is not fatal to a connection, but it means the fallback
		// order silently wastes an attempt on an address that just failed.
		key := ep.Server + "|" + ep.ServerName
		if seen[key] {
			return nil, fmt.Errorf("endpoint %d: %s is listed twice", i+1, ep.Server)
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out, nil
}

// String renders a Profile without its credential bytes, so the private key
// can't leak through fmt's %v/%s/%+v or a logger that stringifies values.
// The receiver is a value (not a pointer) on purpose: a *Profile picks up
// this method too, but a Profile *value* would otherwise format by dumping
// every field — key bytes included. Use the fields directly when you actually
// need the PEM. (fmt prints "<nil>" for a nil *Profile on its own.)
func (p Profile) String() string {
	return fmt.Sprintf("Profile{Server:%s ServerName:%s CN:%s NotAfter:%s}",
		p.Server, p.ServerName, p.CommonName, p.NotAfter.Format(time.RFC3339))
}

// GoString does the same for the %#v verb.
func (p Profile) GoString() string { return p.String() }

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
	return LoadPEMEndpoints(caPEM, certPEM, keyPEM, []Endpoint{{Server: server, ServerName: serverName}})
}

// LoadPEMEndpoints is LoadPEM for a profile that knows more than one address
// for the same node. The credentials are validated once — they are the same for
// every endpoint — and each address is checked for shape.
func LoadPEMEndpoints(caPEM, certPEM, keyPEM []byte, endpoints []Endpoint) (*Profile, error) {
	eps, err := validateEndpoints(endpoints)
	if err != nil {
		return nil, err
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
		Server:     eps[0].Server,
		ServerName: eps[0].ServerName,
		Endpoints:  eps,
		CACertPEM:  caPEM,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		CommonName: leaf.Subject.CommonName,
		NotAfter:   leaf.NotAfter,
	}, nil
}

// Bundle schema versions.
//
// v1 carries exactly one server address. v2 replaces it with a list.
//
// MarshalBundle writes v1 whenever a profile has a single endpoint, and only
// steps up to v2 when it carries something v1 cannot express. That is
// deliberate: every app already installed rejects a version it does not know,
// so emitting v2 unconditionally would break profile delivery for everyone who
// has not updated yet — for a file that would have said the same thing in v1.
const (
	BundleVersionSingle = 1
	BundleVersionList   = 2
	// BundleVersion is the newest version this build understands.
	BundleVersion = BundleVersionList
)

// Bundle is the JSON form of a one-file client profile (".vpnio"): the CA
// certificate, the client certificate and key, and the server address — every
// input LoadPEM needs, packed into a single distributable file. The PEM fields
// hold literal PEM text. A Bundle carries the client private key, so the file
// is a secret (write it 0600).
type Bundle struct {
	Version int `json:"version"`
	// Server/ServerName are the v1 shape, still written for single-endpoint
	// profiles so older apps keep importing them.
	Server     string `json:"server,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	// Endpoints is the v2 shape: every address for the same node, in the order
	// to try them.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	CACertPEM string     `json:"ca"`
	CertPEM   string     `json:"cert"`
	KeyPEM    string     `json:"key"`
}

// String renders a Bundle without its credential bytes so the private key
// can't leak through fmt's %v/%s/%+v or a logger that stringifies values. The
// receiver is a value (not a pointer) on purpose, mirroring Profile: use the
// PEM fields directly when you actually need them. Marshal the Bundle (not
// fmt it) to produce the .vpnio file.
func (b Bundle) String() string {
	return fmt.Sprintf("Bundle{Version:%d Server:%s ServerName:%s Endpoints:%d}",
		b.Version, b.Server, b.ServerName, len(b.Endpoints))
}

// GoString does the same for the %#v verb.
func (b Bundle) GoString() string { return b.String() }

// MarshalBundle validates the credentials (the same checks as LoadPEM, so a
// written bundle is guaranteed importable) and returns the .vpnio JSON.
func MarshalBundle(caPEM, certPEM, keyPEM []byte, server, serverName string) ([]byte, error) {
	return MarshalBundleEndpoints(caPEM, certPEM, keyPEM,
		[]Endpoint{{Server: server, ServerName: serverName}})
}

// MarshalBundleEndpoints writes a bundle for one or more endpoints, choosing
// the oldest schema that can express it (see BundleVersionSingle): one endpoint
// with no label produces a v1 file that every released app can already import.
func MarshalBundleEndpoints(caPEM, certPEM, keyPEM []byte, endpoints []Endpoint) ([]byte, error) {
	prof, err := LoadPEMEndpoints(caPEM, certPEM, keyPEM, endpoints)
	if err != nil {
		return nil, err
	}
	b := Bundle{
		CACertPEM: string(caPEM),
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
	}
	if len(prof.Endpoints) == 1 && prof.Endpoints[0].Label == "" {
		b.Version = BundleVersionSingle
		b.Server = prof.Endpoints[0].Server
		// Write ServerName only when it was set explicitly: v1 defaults it to
		// the host, and writing the default would turn every bundle into one
		// that pins SNI, which is a different thing from leaving it unset.
		if endpoints[0].ServerName != "" {
			b.ServerName = prof.Endpoints[0].ServerName
		}
	} else {
		b.Version = BundleVersionList
		b.Endpoints = prof.Endpoints
	}
	return json.MarshalIndent(b, "", "  ")
}

// ParseBundle parses a .vpnio bundle and validates it into a Profile, applying
// the same checks as Load. An unknown version is rejected up front.
func ParseBundle(data []byte) (*Profile, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse profile bundle: %w", err)
	}
	switch b.Version {
	case BundleVersionSingle:
		// A v1 file is a v2 file with one endpoint. Reading it that way keeps
		// every profile handed out so far working, untouched, forever.
		if len(b.Endpoints) > 0 {
			return nil, fmt.Errorf("profile claims version %d but carries an endpoint list (version %d) — it was written by something that mixed the two",
				BundleVersionSingle, BundleVersionList)
		}
		return LoadPEM([]byte(b.CACertPEM), []byte(b.CertPEM), []byte(b.KeyPEM), b.Server, b.ServerName)
	case BundleVersionList:
		eps := b.Endpoints
		// Tolerate a v2 file that also carries the v1 field, as long as they do
		// not disagree: a writer might include it for older readers.
		if b.Server != "" {
			if len(eps) == 0 {
				eps = []Endpoint{{Server: b.Server, ServerName: b.ServerName}}
			} else if eps[0].Server != b.Server {
				return nil, fmt.Errorf("profile is inconsistent: server %q does not match the first endpoint %q", b.Server, eps[0].Server)
			}
		}
		if len(eps) == 0 {
			return nil, fmt.Errorf("profile has no server endpoints")
		}
		return LoadPEMEndpoints([]byte(b.CACertPEM), []byte(b.CertPEM), []byte(b.KeyPEM), eps)
	default:
		return nil, fmt.Errorf("unsupported profile bundle version %d (this build understands up to %d) — update the app", b.Version, BundleVersion)
	}
}
