package vless

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// destRoots overrides the roots used to verify a target. Only tests set it, so
// they can measure a real handshake against a local server instead of reaching
// across the network.
var destRoots *x509.CertPool

// maxChainBytes is the certificate-chain size above which a target is reported
// as unusable.
//
// REALITY does not present its own certificate: it relays the target's real
// handshake to the client and substitutes only the signature. The relayed
// records go through a fixed buffer, so a target whose certificates do not fit
// produces a handshake that never completes — the client shows "connected" and
// passes nothing.
//
// The number comes from measurement, not from a specification. With
// www.microsoft.com (three certificates, 5.9 KB on the wire) Xray logs
// "Certificate: 8273" against 4050 bytes of remaining buffer and drops the
// connection; www.apple.com (4.5 KB PEM, ~3.2 KB on the wire), dl.google.com
// and www.cloudflare.com all complete. 4 KB sits between the two groups with
// room on either side. A target near the line is reported as a warning rather
// than a refusal — the measurement is a proxy for a limit we do not control,
// and the operator may know better than we do.
const maxChainBytes = 4096

// warnChainBytes is where a target stops being comfortably small.
const warnChainBytes = 3072

// destTimeout bounds the probe. A target that cannot answer this fast is not a
// target worth impersonating.
const destTimeout = 10 * time.Second

// DestReport is what a target looks like to a node about to impersonate it.
type DestReport struct {
	Dest       string
	TLS13      bool
	ALPN       string // negotiated protocol; "h2" is what a modern site answers
	ChainBytes int    // total size of the certificate chain as sent on the wire
	CommonName string
	// Problems are reasons this target cannot be used; Warnings are reasons to
	// think twice. A target with no problems is usable.
	Problems []string
	Warnings []string
}

// OK reports whether the target can be used as-is.
func (r DestReport) OK() bool { return len(r.Problems) == 0 }

// String renders the report the way the CLI prints it.
func (r DestReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Dest)
	fmt.Fprintf(&b, "  certificate  %s\n", r.CommonName)
	fmt.Fprintf(&b, "  TLS 1.3      %v\n", r.TLS13)
	fmt.Fprintf(&b, "  ALPN         %s\n", orNone(r.ALPN))
	fmt.Fprintf(&b, "  chain size   %d bytes\n", r.ChainBytes)
	for _, p := range r.Problems {
		fmt.Fprintf(&b, "  PROBLEM      %s\n", p)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  warning      %s\n", w)
	}
	if r.OK() && len(r.Warnings) == 0 {
		b.WriteString("  usable as a masquerade target\n")
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// CheckDest connects to a candidate masquerade target and reports whether a
// REALITY node can hide behind it.
//
// It exists because the failure it catches is invisible from the node: every
// service is running, the port answers, a scanner sees the real site — and the
// only person who learns that nothing works is the friend holding the link.
// Checking takes one handshake.
func CheckDest(ctx context.Context, dest string) (DestReport, error) {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return DestReport{}, fmt.Errorf("vless: dest %q must be host:port: %w", dest, err)
	}
	r := DestReport{Dest: dest}

	ctx, cancel := context.WithTimeout(ctx, destTimeout)
	defer cancel()

	d := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		RootCAs:    destRoots,
		// Ask for HTTP/2 the way a browser does: a target that does not offer
		// it is not what a browser would have reached, which is the whole
		// premise of hiding behind it.
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return r, fmt.Errorf("vless: cannot reach %s: %w", dest, err)
	}
	defer func() { _ = conn.Close() }()

	state := conn.(*tls.Conn).ConnectionState()
	r.TLS13 = state.Version >= tls.VersionTLS13
	r.ALPN = state.NegotiatedProtocol
	for _, c := range state.PeerCertificates {
		r.ChainBytes += len(c.Raw)
	}
	if len(state.PeerCertificates) > 0 {
		r.CommonName = state.PeerCertificates[0].Subject.CommonName
	}

	r.classify()
	return r, nil
}

// classify turns the measurements into problems and warnings. Split out so the
// judgement can be tested without a target on the network.
func (r *DestReport) classify() {
	if !r.TLS13 {
		r.Problems = append(r.Problems, "does not negotiate TLS 1.3 — REALITY cannot hide behind it")
	}
	switch {
	case r.ChainBytes > maxChainBytes:
		r.Problems = append(r.Problems, fmt.Sprintf(
			"certificate chain is %d bytes; REALITY relays the target's handshake and one this large does not fit — "+
				"clients connect and pass no traffic", r.ChainBytes))
	case r.ChainBytes > warnChainBytes:
		r.Warnings = append(r.Warnings, fmt.Sprintf(
			"certificate chain is %d bytes, close to the %d-byte limit; it may break if the target rotates to a larger chain",
			r.ChainBytes, maxChainBytes))
	}
	if r.ALPN != "h2" {
		r.Warnings = append(r.Warnings, "does not negotiate HTTP/2 — an ordinary browser visit would, so this stands out")
	}
}
