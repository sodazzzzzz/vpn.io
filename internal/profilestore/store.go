// Package profilestore persists a single imported VPN profile (credentials +
// server address) to disk, so the desktop app can reconnect after a restart
// without re-importing.
//
// Security posture: the file holds the client private key as PEM, written with
// 0600 permissions in the user's per-user config directory. This matches the
// existing model — the user already has these PEM files on disk (they imported
// from them) — and is no weaker than the CLI, which reads the same PEMs from
// disk. A future hardening could move the key into the OS keychain; until then,
// 0600 + a 0700 directory is the protection.
package profilestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// appDir is the per-user subdirectory under os.UserConfigDir() (e.g.
// ~/Library/Application Support/vpn.io on macOS, ~/.config/vpn.io on Linux).
const appDir = "vpn.io"

// fileName is the stored profile within appDir.
const fileName = "profile.json"

// pathEnv overrides the profile file path. It lets a package point the store at
// a specific location and makes the store easy to exercise in tests.
const pathEnv = "VPN_IO_PROFILE"

// Profile is the persisted credential set: the non-secret form fields, the
// three PEM blobs (base64 in JSON), and the original file names for display.
type Profile struct {
	Server     string `json:"server"`
	ServerName string `json:"serverName,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	TunName    string `json:"tunName,omitempty"`

	CACertPEM []byte `json:"caCertPem"`
	CertPEM   []byte `json:"certPem"`
	KeyPEM    []byte `json:"keyPem"`

	CAName   string `json:"caName,omitempty"`
	CertName string `json:"certName,omitempty"`
	KeyName  string `json:"keyName,omitempty"`
}

// Store reads and writes the profile at Path.
type Store struct {
	Path string
}

// Default returns a Store at the VPN_IO_PROFILE path if set, otherwise the
// per-user config location.
func Default() (*Store, error) {
	if p := os.Getenv(pathEnv); p != "" {
		return &Store{Path: p}, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate config dir: %w", err)
	}
	return &Store{Path: filepath.Join(dir, appDir, fileName)}, nil
}

// Save writes p atomically with 0600 permissions, creating the directory
// (0700) if needed. It writes to a temp file and renames, so a crash mid-write
// can't leave a half-written profile.
func (s *Store) Save(p Profile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode profile: %w", err)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".profile-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("replace profile: %w", err)
	}
	return nil
}

// Load reads the stored profile. The bool is false (with a nil error) when no
// profile has been saved yet.
func (s *Store) Load() (Profile, bool, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Profile{}, false, nil
	}
	if err != nil {
		return Profile{}, false, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, false, fmt.Errorf("parse profile: %w", err)
	}
	return p, true, nil
}

// Clear removes the stored profile. It is a no-op when none exists.
func (s *Store) Clear() error {
	err := os.Remove(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
