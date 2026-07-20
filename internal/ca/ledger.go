package ca

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// The issuance ledger records every client certificate this CA has ever
// signed, as <Dir>/issued.json.
//
// Without it, a name's serial lives only in the current clients/<name>.crt,
// which re-issuing overwrites — and the overwritten serial becomes impossible
// to revoke with any tool, while the certificate itself stays valid against the
// CA for up to a year. The ledger is append-only for exactly that reason: it is
// the only record that a superseded certificate ever existed.
//
// It holds no secrets (a serial reveals nothing), so it is written 0644, but it
// is written atomically — a half-written ledger would lose revocable history.

// ledgerMaxBytes caps how much the ledger reader will accept, so a corrupt or
// tampered file can't balloon memory. Each entry is ~110 bytes.
const ledgerMaxBytes = 8 << 20

// IssuedCert is one signed client certificate, past or present.
type IssuedCert struct {
	Name     string    `json:"name"`
	Serial   string    `json:"serial"` // lowercase hex, as in the revocation list
	IssuedAt time.Time `json:"issuedAt"`
}

type ledgerFile struct {
	Issued []IssuedCert `json:"issued"`
}

func ledgerPath(dir string) string { return filepath.Join(dir, "issued.json") }

// loadLedger reads the ledger. A missing file is the normal state for a CA
// created before the ledger existed, and reads as empty.
func loadLedger(dir string) (ledgerFile, error) {
	path := ledgerPath(dir)
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return ledgerFile{}, nil
	}
	if err != nil {
		return ledgerFile{}, fmt.Errorf("ca: open ledger %q: %w", path, err)
	}
	defer func() { _ = fh.Close() }()

	data, err := io.ReadAll(io.LimitReader(fh, ledgerMaxBytes+1))
	if err != nil {
		return ledgerFile{}, fmt.Errorf("ca: read ledger %q: %w", path, err)
	}
	if len(data) > ledgerMaxBytes {
		return ledgerFile{}, fmt.Errorf("ca: ledger %q too large (over %d bytes)", path, ledgerMaxBytes)
	}
	if len(data) == 0 {
		return ledgerFile{}, nil
	}
	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return ledgerFile{}, fmt.Errorf("ca: parse ledger %q: %w", path, err)
	}
	return f, nil
}

// appendIssued records a newly signed client certificate. Callers append
// *before* writing the certificate to disk: a ledger entry for a certificate
// that then failed to be written is harmless (revoking a serial that was never
// issued is a no-op), whereas a certificate missing from the ledger is exactly
// the unrevocable-cert bug the ledger exists to prevent.
func appendIssued(dir, name string, serial *big.Int) error {
	f, err := loadLedger(dir)
	if err != nil {
		return err
	}
	f.Issued = append(f.Issued, IssuedCert{
		Name:     name,
		Serial:   serial.Text(16),
		IssuedAt: time.Now(),
	})
	return saveLedger(dir, f)
}

// saveLedger writes f atomically (temp file + fsync + rename).
func saveLedger(dir string, f ledgerFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("ca: encode ledger: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ca: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".issued-*.tmp")
	if err != nil {
		return fmt.Errorf("ca: create temp ledger: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: chmod temp ledger: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: write temp ledger: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ca: sync temp ledger: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ca: close temp ledger: %w", err)
	}
	if err := os.Rename(tmpName, ledgerPath(dir)); err != nil {
		return fmt.Errorf("ca: replace ledger: %w", err)
	}
	// fsync the directory so the rename itself reaches disk — an issuance
	// record shouldn't vanish on a crash right after the rename.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// ClientSerials returns every serial ever issued to name, oldest first — the
// full set that must be revoked to lock that client out.
//
// ClientSerial (singular) reads only the *current* clients/<name>.crt, so it
// misses certificates superseded by a re-issue. Use this for revocation.
//
// For a CA that predates the ledger, the ledger holds nothing for the name; the
// current certificate is then the only serial we can know about, so it is
// returned on its own rather than reporting the client as unknown.
func ClientSerials(dir, name string) ([]*big.Int, error) {
	// Same guard ClientSerial applies: name is used as a path component below
	// (via the pre-ledger fallback), so it must not escape clients/.
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return nil, fmt.Errorf("ca: invalid client name %q", name)
	}
	f, err := loadLedger(dir)
	if err != nil {
		return nil, err
	}
	var serials []*big.Int
	seen := map[string]bool{}
	for _, e := range f.Issued {
		if e.Name != name || seen[e.Serial] {
			continue
		}
		n, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("ca: ledger entry for %q has unparsable serial %q", name, e.Serial)
		}
		seen[e.Serial] = true
		serials = append(serials, n)
	}
	if len(serials) > 0 {
		return serials, nil
	}
	// Pre-ledger CA (or a name that was never issued): fall back to the cert
	// on disk, which is what revocation used before the ledger existed.
	cur, err := ClientSerial(dir, name)
	if err != nil {
		return nil, err
	}
	return []*big.Int{cur}, nil
}
