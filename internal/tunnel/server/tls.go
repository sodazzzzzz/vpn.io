package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// loadTLSConfig builds a *tls.Config that:
//   - presents serverCert/serverKey to clients
//   - requires clients to present a certificate signed by caCert
//   - pins TLS 1.3 (no downgrade; matches the locked architecture)
//   - verifies the client's ExtKeyUsage includes ClientAuth (the standard
//     verifier already does this; we add an explicit VerifyPeerCertificate
//     hook for defense-in-depth and to surface clearer errors)
func loadTLSConfig(caCertFile, serverCertFile, serverKeyFile string) (*tls.Config, error) {
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

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// RequireAndVerifyClientCert populates verifiedChains with at least
			// one fully verified chain; we just assert the leaf carries
			// ClientAuth EKU explicitly, in case the CA ever issues a leaf
			// without it.
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("no verified client chain")
			}
			leaf := verifiedChains[0][0]
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
