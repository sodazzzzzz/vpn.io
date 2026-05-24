package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// loadTLSConfig builds the *tls.Config used by the client side of the
// tunnel:
//   - presents clientCert/clientKey to the server (the server's
//     RequireAndVerifyClientCert demands it)
//   - trusts only the named CA when validating the server cert
//   - pins TLS 1.3 to match the locked architecture (no downgrade)
//   - sets ServerName so SNI is sent and the hostname in the server cert
//     is verified
//   - adds an explicit VerifyPeerCertificate hook that asserts the
//     server cert carries the ServerAuth EKU (defense in depth: a CA
//     misconfiguration could in principle issue a cert without it).
func loadTLSConfig(caCertFile, clientCertFile, clientKeyFile, serverName string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", caCertFile, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file %q contains no PEM certificates", caCertFile)
	}

	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("no verified server chain")
			}
			leaf := verifiedChains[0][0]
			for _, eku := range leaf.ExtKeyUsage {
				if eku == x509.ExtKeyUsageServerAuth {
					return nil
				}
			}
			return fmt.Errorf("server cert CN=%q lacks ServerAuth EKU", leaf.Subject.CommonName)
		},
	}
	return cfg, nil
}
