// Package revoke maintains a deny-list of revoked client-certificate serial
// numbers. The CA tool adds to it (vpn-ca revoke / unrevoke); the server
// enforces it on every connection — rejecting a revoked leaf in its TLS verify
// callback — and hot-reloads the file when it changes, so a revocation takes
// effect without a restart.
//
// The list is keyed by serial, not name: revoking blocks the exact issued
// certificate, and re-issuing the same name (a fresh serial) is not revoked.
// The file isn't secret (a serial reveals nothing), but it is written
// atomically so the server never reads a half-written file.
package revoke

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxFileBytes caps how much load reads, so a corrupt/tampered file can't
// balloon memory. Each entry is ~120 bytes; this holds tens of thousands.
const maxFileBytes = 8 << 20

// Entry is one revoked client certificate.
type Entry struct {
	Serial    string    `json:"serial"` // certificate serial as lowercase hex
	Name      string    `json:"name"`   // client name, for the operator
	RevokedAt time.Time `json:"revokedAt"`
}

type fileFormat struct {
	Revoked []Entry `json:"revoked"`
}

// serialHex renders a certificate serial as the canonical lowercase-hex key
// used both when adding and when checking.
func serialHex(serial *big.Int) string { return serial.Text(16) }

// load reads the deny-list at path. A missing file is reported as os.ErrNotExist
// (via %w) so callers can tell "no file" from "empty file": the Store treats
// missing as empty (loadOrEmpty), while the Checker must keep its last-known set
// if the file vanishes between its stat and this read (TOCTOU / deletion).
func load(path string) (fileFormat, error) {
	fh, err := os.Open(path)
	if err != nil {
		return fileFormat{}, fmt.Errorf("revoke: open %q: %w", path, err)
	}
	defer func() { _ = fh.Close() }()

	data, err := io.ReadAll(io.LimitReader(fh, maxFileBytes+1))
	if err != nil {
		return fileFormat{}, fmt.Errorf("revoke: read %q: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return fileFormat{}, fmt.Errorf("revoke: file %q too large (over %d bytes)", path, maxFileBytes)
	}
	if len(data) == 0 {
		return fileFormat{}, nil
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fileFormat{}, fmt.Errorf("revoke: parse %q: %w", path, err)
	}
	return f, nil
}

// loadOrEmpty is load but treats a missing file as an empty list — the Store's
// view, where "no file yet" is the normal state before the first revocation.
func loadOrEmpty(path string) (fileFormat, error) {
	f, err := load(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileFormat{}, nil
	}
	return f, err
}

// save writes f atomically (temp file + fsync + rename) with 0644 permissions,
// creating the directory if needed.
func save(path string, f fileFormat) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("revoke: encode: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("revoke: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".revoked-*.tmp")
	if err != nil {
		return fmt.Errorf("revoke: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("revoke: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("revoke: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("revoke: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("revoke: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("revoke: replace file: %w", err)
	}
	// fsync the directory so the rename itself (not just the file's data) reaches
	// disk — a revocation shouldn't vanish on a crash right after the rename.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// Store is the file-backed deny-list as used by the CA tool: add, remove, list.
// Safe for concurrent use.
type Store struct {
	Path string
	mu   sync.Mutex
}

// New returns a Store backed by the file at path.
func New(path string) *Store { return &Store{Path: path} }

// Add revokes the certificate with the given serial. It is idempotent: a serial
// already on the list is left as it was (the original revocation time stands).
// Reports whether a new entry was added.
func (s *Store) Add(serial *big.Int, name string) (added bool, err error) {
	key := serialHex(serial)
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := loadOrEmpty(s.Path)
	if err != nil {
		return false, err
	}
	for _, e := range f.Revoked {
		if e.Serial == key {
			return false, nil // already revoked
		}
	}
	f.Revoked = append(f.Revoked, Entry{Serial: key, Name: name, RevokedAt: time.Now()})
	if err := save(s.Path, f); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveSerial un-revokes exactly one certificate and reports whether it was on
// the list.
//
// This is the safe undo for a revocation. Removing by name would also lift the
// revocations a re-issue applied to superseded certificates — which is to say,
// it would hand a leaked profile back its access. Callers that mean "trust this
// client's *current* certificate again" want this, not Remove.
func (s *Store) RemoveSerial(serial *big.Int) (bool, error) {
	key := serialHex(serial)
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := loadOrEmpty(s.Path)
	if err != nil {
		return false, err
	}
	kept := f.Revoked[:0:0]
	for _, e := range f.Revoked {
		if e.Serial != key {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(f.Revoked) {
		return false, nil
	}
	f.Revoked = kept
	if err := save(s.Path, f); err != nil {
		return false, err
	}
	return true, nil
}

// Remove un-revokes every entry with the given client name and reports how many
// were removed.
//
// Prefer RemoveSerial: since a re-issue revokes the certificates it supersedes,
// removing by name also un-revokes those, restoring access to profiles that
// were deliberately retired.
func (s *Store) Remove(name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := loadOrEmpty(s.Path)
	if err != nil {
		return 0, err
	}
	kept := f.Revoked[:0:0]
	for _, e := range f.Revoked {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	removed := len(f.Revoked) - len(kept)
	if removed == 0 {
		return 0, nil
	}
	f.Revoked = kept
	if err := save(s.Path, f); err != nil {
		return 0, err
	}
	return removed, nil
}

// List returns the current revocations.
func (s *Store) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := loadOrEmpty(s.Path)
	if err != nil {
		return nil, err
	}
	return f.Revoked, nil
}

// Checker is the server-side enforcer. It caches the revoked-serial set and
// reloads the file when its modification time changes, so the server applies a
// revocation without a restart and without re-parsing on every connection.
// Safe for concurrent use.
type Checker struct {
	path  string
	mu    sync.Mutex
	mtime time.Time
	size  int64
	set   map[string]struct{}
}

// NewChecker returns a Checker reading path. An empty path means "no deny-list":
// IsRevoked always reports false.
func NewChecker(path string) *Checker { return &Checker{path: path} }

// IsRevoked reports whether serial is on the deny-list, reloading the file first
// if it changed on disk. A parse/read error is returned to the caller, which
// should fail closed (reject the connection) rather than admit a possibly
// revoked client.
func (c *Checker) IsRevoked(serial *big.Int) (bool, error) {
	if c.path == "" {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	fi, err := os.Stat(c.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// The file is gone. Deliberately KEEP the last-known set: if it never
		// held anything c.set is still nil (nothing to enforce), but if it had
		// revocations and then vanished, we keep enforcing them rather than
		// silently un-revoking everyone — a real un-revoke rewrites the file via
		// `vpn-ca unrevoke`, it never deletes it. Reset the stamps so a recreated
		// file reloads.
		c.mtime, c.size = time.Time{}, 0
	case err != nil:
		return false, fmt.Errorf("revoke: stat %q: %w", c.path, err)
	case c.set == nil || !fi.ModTime().Equal(c.mtime) || fi.Size() != c.size:
		// Reload on any mtime or size change (size guards against rapid
		// rewrites that land in the same mtime tick).
		f, err := load(c.path)
		if errors.Is(err, os.ErrNotExist) {
			// TOCTOU: the file vanished between the Stat above and this read.
			// Keep the last-known set (don't un-revoke everyone) and reset the
			// stamps so a recreated file reloads.
			c.mtime, c.size = time.Time{}, 0
			break
		}
		if err != nil {
			return false, err
		}
		set := make(map[string]struct{}, len(f.Revoked))
		for _, e := range f.Revoked {
			set[e.Serial] = struct{}{}
		}
		c.set, c.mtime, c.size = set, fi.ModTime(), fi.Size()
	}

	_, revoked := c.set[serialHex(serial)]
	return revoked, nil
}
