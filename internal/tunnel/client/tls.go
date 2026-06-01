package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// loadTLSConfig reads the CA, client cert and client key from disk and
// builds the client *tls.Config via tlsConfigFromPEM. Used by the CLI,
// which is handed file paths.
func loadTLSConfig(caCertFile, clientCertFile, clientKeyFile, serverName string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", caCertFile, err)
	}
	certPEM, err := os.ReadFile(clientCertFile)
	if err != nil {
		return nil, fmt.Errorf("read client cert %q: %w", clientCertFile, err)
	}
	keyPEM, err := os.ReadFile(clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read client key %q: %w", clientKeyFile, err)
	}
	return tlsConfigFromPEM(caPEM, certPEM, keyPEM, serverName)
}

// tlsConfigFromPEM builds the *tls.Config used by the client side of the
// tunnel from in-memory PEM material:
//   - presents clientCert/clientKey to the server (the server's
//     RequireAndVerifyClientCert demands it)
//   - trusts only the named CA when validating the server cert
//   - pins TLS 1.3 to match the locked architecture (no downgrade)
//   - sets ServerName so SNI is sent and the hostname in the server cert
//     is verified
//   - adds an explicit VerifyPeerCertificate hook that asserts the
//     server cert carries the ServerAuth EKU (defense in depth: a CA
//     misconfiguration could in principle issue a cert without it).
//
// Taking PEM bytes (rather than only file paths) lets a privileged daemon
// receive credentials over IPC and build the config without opening any
// caller-supplied filesystem path as root.
func tlsConfigFromPEM(caPEM, certPEM, keyPEM []byte, serverName string) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA PEM contains no certificates")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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
