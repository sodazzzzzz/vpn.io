// Package ca implements a small X.509 Certificate Authority used by govpn for
// mutual TLS authentication. The CA signs one server certificate and one
// client certificate per VPN peer; both sides require certificates signed by
// the same CA to complete the TLS handshake.
//
// On-disk layout (rooted at the directory passed to Create/Load):
//
//	ca.crt, ca.key                  — root authority (key never leaves this host)
//	server/server.crt, server.key   — single server certificate
//	clients/<name>.crt, <name>.key  — one pair per issued client
//	issued.json                     — append-only ledger of every issued client cert
//	revoked.json                    — deny-list of revoked serials (package revoke)
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/govpn/internal/revoke"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 365 * 24 * time.Hour
	clientValidity = 365 * 24 * time.Hour
)

// CA is a loaded certificate authority bound to its on-disk directory.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Dir  string
}

// Create initialises a fresh CA at dir. Fails if ca.crt already exists there.
func Create(dir, commonName string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("CA already exists at %s", certPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // can sign leaves only, not intermediate CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := writeCert(certPath, der); err != nil {
		return nil, err
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, Dir: dir}, nil
}

// Load reads an existing CA from dir.
func Load(dir string) (*CA, error) {
	cert, err := readCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	key, err := readKey(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	return &CA{Cert: cert, Key: key, Dir: dir}, nil
}

// IssueServer creates a server certificate valid for the given DNS names and
// IP addresses, written to <Dir>/server/server.{crt,key}.
func (c *CA) IssueServer(commonName string, dnsNames []string, ips []net.IP) error {
	tpl, err := baseTemplate(commonName, serverValidity)
	if err != nil {
		return err
	}
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tpl.DNSNames = dnsNames
	tpl.IPAddresses = ips
	return c.issueTo(tpl, filepath.Join(c.Dir, "server"), "server")
}

// IssueClient creates a client certificate identified by name, written to
// <Dir>/clients/<name>.{crt,key}.
//
// Re-issuing an existing name revokes the certificates it supersedes. The
// operator's reason for re-issuing is almost always "that profile leaked" —
// and without this the old certificate stayed valid against the CA for up to a
// year while becoming impossible to revoke, because its serial lived only in
// the file the re-issue just overwrote. One name means one live profile.
func (c *CA) IssueClient(name string) error {
	tpl, err := baseTemplate(name, clientValidity)
	if err != nil {
		return err
	}
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// Revoke the superseded certificates before signing the replacement, so a
	// failure part-way through leaves the old ones denied rather than live.
	if err := c.revokeSuperseded(name); err != nil {
		return err
	}
	// Record the issuance before writing it: a ledger entry whose certificate
	// never made it to disk is harmless, a certificate missing from the ledger
	// is unrevocable.
	if err := appendIssued(c.Dir, name, tpl.SerialNumber); err != nil {
		return err
	}
	return c.issueTo(tpl, filepath.Join(c.Dir, "clients"), name)
}

// revokeSuperseded denies every certificate previously issued to name. A name
// that was never issued has nothing to supersede and is not an error.
func (c *CA) revokeSuperseded(name string) error {
	prior, err := ClientSerials(c.Dir, name)
	if err != nil {
		// No ledger entry and no certificate on disk: a first issuance.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	store := revoke.New(filepath.Join(c.Dir, "revoked.json"))
	for _, serial := range prior {
		if _, err := store.Add(serial, name); err != nil {
			return fmt.Errorf("ca: revoke superseded cert for %q: %w", name, err)
		}
	}
	return nil
}

// ClientSerial returns the serial number of the issued client certificate at
// <dir>/clients/<name>.crt — the identifier used to revoke that exact cert. It
// reads only the public cert, so it needs no CA key (callers that just revoke
// don't have to load the whole CA).
func ClientSerial(dir, name string) (*big.Int, error) {
	// name becomes a path under clients/ — reject anything that could escape it,
	// so an exported caller can't be tricked into reading outside the directory.
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return nil, fmt.Errorf("ca: invalid client name %q", name)
	}
	cert, err := readCert(filepath.Join(dir, "clients", name+".crt"))
	if err != nil {
		return nil, err
	}
	return cert.SerialNumber, nil
}

// ListClients returns the CommonNames of every issued client certificate.
func (c *CA) ListClients() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(c.Dir, "clients"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && filepath.Ext(n) == ".crt" {
			names = append(names, n[:len(n)-len(".crt")])
		}
	}
	return names, nil
}

func (c *CA) issueTo(tpl *x509.Certificate, dir, basename string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}
	if err := writeCert(filepath.Join(dir, basename+".crt"), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, basename+".key"), key)
}

func baseTemplate(commonName string, validity time.Duration) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validity),
		BasicConstraintsValid: true,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writeCert(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// 0600 is honoured on Unix; Windows ignores it, see README for ACL hardening.
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return key, nil
}
