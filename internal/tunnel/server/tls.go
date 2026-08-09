package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/govpn/internal/keyperm"
	"github.com/govpn/internal/revoke"
)

// loadTLSConfig builds a *tls.Config that:
//   - presents serverCert/serverKey to clients
//   - requires clients to present a certificate signed by caCert
//   - pins TLS 1.3 (no downgrade; matches the locked architecture)
//   - verifies the client's ExtKeyUsage includes ClientAuth (the standard
//     verifier already does this; we add an explicit hook for
//     defense-in-depth and to surface clearer errors)
//   - rejects revoked client certificates (deny-list by serial in revokedFile,
//     hot-reloaded; empty path disables the check)
//
// The checks live in VerifyConnection, not VerifyPeerCertificate: the latter
// is not called on resumed TLS sessions, which would let a client that cached
// a session ticket before its cert was revoked keep reconnecting past the
// deny-list for the lifetime of the ticket.
func loadTLSConfig(caCertFile, serverCertFile, serverKeyFile, revokedFile string, log *slog.Logger) (*tls.Config, error) {
	// The server key routinely reaches a node by scp, which leaves it 0644 —
	// world-readable on a machine that may have other accounts. Say so loudly
	// rather than refusing to start: the tunnel is what people depend on, and
	// nobody can fix the mode from a VPN that won't come up (#291).
	if warning := keyperm.Check(serverKeyFile); warning != "" {
		log.Warn("server: " + warning)
	}

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", caCertFile, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q contains no PEM certificates", caCertFile)
	}

	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	revoked := revoke.NewChecker(revokedFile)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// RequireAndVerifyClientCert populates VerifiedChains with at least
			// one fully verified chain (on resumed sessions it is restored from
			// the session state, re-checked against ClientCAs by crypto/tls);
			// we just assert the leaf carries ClientAuth EKU explicitly, in
			// case the CA ever issues a leaf without it.
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				return fmt.Errorf("no verified client chain")
			}
			leaf := cs.VerifiedChains[0][0]
			// Reject revoked clients. Fail closed: a read/parse error on the
			// deny-list rejects the connection rather than admit a possibly
			// revoked client.
			if yes, err := revoked.IsRevoked(leaf.SerialNumber); err != nil {
				return fmt.Errorf("revocation check: %w", err)
			} else if yes {
				return fmt.Errorf("client cert CN=%q (serial %s) is revoked", leaf.Subject.CommonName, leaf.SerialNumber.Text(16))
			}
			for _, eku := range leaf.ExtKeyUsage {
				if eku == x509.ExtKeyUsageClientAuth {
					return nil
				}
			}
			return fmt.Errorf("client cert CN=%q lacks ClientAuth EKU", leaf.Subject.CommonName)
		},
	}
	return cfg, nil
}
