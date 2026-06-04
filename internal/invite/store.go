// Package invite manages one-time invite tokens for the Telegram onboarding
// bot. Redeeming a token issues a client certificate for the token's preset
// name and delivers the .vpnio profile. Tokens are single-use and persisted
// atomically with 0600 permissions: possession of an unused token grants a VPN
// credential, so the file is a secret.
package invite

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotFound is returned by Redeem when no unused token matches the value.
var ErrNotFound = errors.New("invite: token not found or already used")

// maxStoreBytes caps how much loadLocked reads, so a corrupt/tampered file
// can't balloon memory. Each token is ~150 bytes; this holds tens of thousands.
const maxStoreBytes = 4 << 20

// Token is a one-time invite. Redeeming it issues a client certificate for
// ClientName.
type Token struct {
	Value      string    `json:"value"`
	ClientName string    `json:"clientName"`
	Used       bool      `json:"used"`
	UsedBy     string    `json:"usedBy,omitempty"` // Telegram identifier, for audit
	Created    time.Time `json:"created"`
	UsedAt     time.Time `json:"usedAt,omitempty"`
}

// fileFormat is the on-disk JSON envelope (an object, so the schema can grow).
type fileFormat struct {
	Tokens []Token `json:"tokens"`
}

// Store persists the set of invite tokens at Path with atomic, 0600 writes.
// All operations are safe for concurrent use.
type Store struct {
	Path string
	mu   sync.Mutex
}

// New returns a Store backed by the file at path.
func New(path string) *Store { return &Store{Path: path} }

// Generate creates a fresh single-use token for clientName, persists it, and
// returns it.
func (s *Store) Generate(clientName string) (Token, error) {
	if clientName == "" {
		return Token{}, errors.New("invite: client name required")
	}
	value, err := randomToken()
	if err != nil {
		return Token{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return Token{}, err
	}
	tok := Token{Value: value, ClientName: clientName, Created: time.Now()}
	f.Tokens = append(f.Tokens, tok)
	if err := s.saveLocked(f); err != nil {
		return Token{}, err
	}
	return tok, nil
}

// Redeem marks the token with the given value used (recording usedBy for audit)
// and returns the client name to issue. It returns ErrNotFound when no unused
// token matches, so an already-redeemed or unknown value can't issue a second
// credential.
func (s *Store) Redeem(value, usedBy string) (clientName string, err error) {
	if value == "" {
		return "", ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	valueBytes := []byte(value)
	for i := range f.Tokens {
		t := &f.Tokens[i]
		// Constant-time compare so matching a token doesn't leak, via timing,
		// how many leading bytes of the secret were guessed correctly. Unused
		// check first: a spent token can't be redeemed regardless.
		if !t.Used && subtle.ConstantTimeCompare([]byte(t.Value), valueBytes) == 1 {
			t.Used = true
			t.UsedBy = usedBy
			t.UsedAt = time.Now()
			name := t.ClientName
			if err := s.saveLocked(f); err != nil {
				return "", err
			}
			return name, nil
		}
	}
	return "", ErrNotFound
}

func (s *Store) loadLocked() (fileFormat, error) {
	fh, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return fileFormat{}, nil
	}
	if err != nil {
		return fileFormat{}, fmt.Errorf("invite: open store: %w", err)
	}
	defer func() { _ = fh.Close() }()

	data, err := io.ReadAll(io.LimitReader(fh, maxStoreBytes+1))
	if err != nil {
		return fileFormat{}, fmt.Errorf("invite: read store: %w", err)
	}
	if len(data) > maxStoreBytes {
		return fileFormat{}, fmt.Errorf("invite: store file too large (over %d bytes)", maxStoreBytes)
	}
	if len(data) == 0 {
		return fileFormat{}, nil
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fileFormat{}, fmt.Errorf("invite: parse store: %w", err)
	}
	return f, nil
}

// saveLocked writes f atomically (temp file + fsync + rename) with 0600
// permissions, creating the directory (0700) if needed.
func (s *Store) saveLocked(f fileFormat) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("invite: encode store: %w", err)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("invite: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".invite-*.tmp")
	if err != nil {
		return fmt.Errorf("invite: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("invite: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("invite: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("invite: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("invite: close temp: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("invite: replace store: %w", err)
	}
	return nil
}

// randomToken returns a URL-safe 128-bit random token.
func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("invite: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
