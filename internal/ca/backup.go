package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Backup and restore of the whole CA directory as one encrypted file.
//
// The root key exists in exactly one place — the operator's machine — and
// losing it means every client has to be onboarded again from scratch. That
// makes an off-machine copy the single highest-value safety net in the project,
// and it can only be stored off-machine if it is encrypted: a backup of a CA
// key is as sensitive as the key.
//
// The whole directory is captured, not just ca.key: restoring clients/ and
// server/ as well means a restored host can re-export an existing friend's
// profile and keep serving with the same server certificate, instead of
// re-issuing (which revokes the profiles people already have).
//
// Container format (see backupHeader): a single JSON document with a cleartext
// header — format marker, KDF parameters, and enough identification to tell two
// backups apart — plus the base64 of one AES-256-GCM sealed blob. The plaintext
// inside is a gzipped tar of the CA directory. The header is authenticated as
// additional data, so downgrading the iteration count or swapping the salt
// invalidates the tag rather than silently weakening the container.

const (
	backupFormat = "vpnio-ca-backup"
	// backupVersion is the container layout version. Bump it only for a change
	// old vpn-ca builds cannot read; restore refuses anything newer than it
	// knows rather than guessing.
	backupVersion = 1

	// backupKDFIterations is the PBKDF2-HMAC-SHA256 work factor. The passphrase
	// is the only thing between a stolen backup file and the root key, so this
	// is deliberately slow (~0.5s on a laptop). It is recorded in the header:
	// a backup made today still opens after this constant is raised.
	backupKDFIterations = 600_000

	// minPassphraseLen is the shortest passphrase accepted when creating a
	// backup. PBKDF2 slows guessing down; it cannot rescue a six-character
	// passphrase guarding a ten-year root key.
	minPassphraseLen = 12

	// backupMaxPlaintext caps the archive on both sides. A CA directory is a few
	// KiB per client, so this is far above any real one while still bounding how
	// much a malformed or hostile container can make us allocate.
	backupMaxPlaintext = 64 << 20
)

// backupHeader is the cleartext part of the container. It holds no secrets: the
// identification fields exist so an operator staring at three files in cold
// storage can tell which CA and which day each one came from, without having to
// decrypt them first.
type backupHeader struct {
	Format       string    `json:"format"`
	Version      int       `json:"version"`
	CreatedAt    time.Time `json:"createdAt"`
	CACommonName string    `json:"caCommonName"`
	KDF          string    `json:"kdf"`
	Iterations   int       `json:"iterations"`
	Salt         string    `json:"salt"` // base64
	Cipher       string    `json:"cipher"`
	Nonce        string    `json:"nonce"` // base64
	// Payload is the sealed archive, base64. It is excluded from the additional
	// authenticated data (see aad) — everything else in this struct is covered.
	Payload string `json:"payload"`
}

// aad returns the authenticated-but-unencrypted header bytes: the header as
// stored, minus the payload. Binding it to the ciphertext is what stops an
// attacker from editing Iterations down to 1 and handing the file back.
func (h backupHeader) aad() ([]byte, error) {
	h.Payload = ""
	b, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("ca: encode backup header: %w", err)
	}
	return b, nil
}

// Backup packs the CA directory at dir into an encrypted container protected by
// passphrase. The returned bytes are safe to store anywhere the passphrase is
// not — a password manager, another machine, a printed copy.
func Backup(dir, passphrase string) ([]byte, error) {
	if len([]rune(passphrase)) < minPassphraseLen {
		return nil, fmt.Errorf("ca: backup passphrase must be at least %d characters", minPassphraseLen)
	}
	// Load the CA first: it fails loudly on a directory that isn't a CA (or on a
	// key that doesn't match its certificate), so a backup is never taken of
	// something that cannot be restored.
	c, err := Load(dir)
	if err != nil {
		return nil, fmt.Errorf("ca: backup: %w", err)
	}
	if !c.Key.PublicKey.Equal(c.Cert.PublicKey) {
		return nil, fmt.Errorf("ca: backup: %s/ca.key does not match ca.crt — refusing to back up a broken CA", dir)
	}

	archive, err := tarCADir(dir)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ca: generate salt: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ca: generate nonce: %w", err)
	}
	hdr := backupHeader{
		Format:       backupFormat,
		Version:      backupVersion,
		CreatedAt:    time.Now().UTC(),
		CACommonName: c.Cert.Subject.CommonName,
		KDF:          "pbkdf2-hmac-sha256",
		Iterations:   backupKDFIterations,
		Salt:         base64.StdEncoding.EncodeToString(salt),
		Cipher:       "aes-256-gcm",
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
	}
	aead, err := backupAEAD(passphrase, salt, hdr.Iterations)
	if err != nil {
		return nil, err
	}
	aad, err := hdr.aad()
	if err != nil {
		return nil, err
	}
	hdr.Payload = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, archive, aad))

	out, err := json.MarshalIndent(hdr, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("ca: encode backup: %w", err)
	}
	return append(out, '\n'), nil
}

// Restore decrypts a container produced by Backup and writes the CA directory
// it contains to dir. dir must not already hold a CA — overwriting one with a
// backup of another is how an operator ends up unable to revoke the
// certificates they issued yesterday.
func Restore(data []byte, dir, passphrase string) error {
	var hdr backupHeader
	if err := json.Unmarshal(data, &hdr); err != nil {
		return fmt.Errorf("ca: this does not look like a CA backup: %w", err)
	}
	if hdr.Format != backupFormat {
		return fmt.Errorf("ca: not a CA backup (format %q)", hdr.Format)
	}
	if hdr.Version > backupVersion {
		return fmt.Errorf("ca: backup format v%d is newer than this vpn-ca understands (v%d) — update vpn-ca", hdr.Version, backupVersion)
	}
	if hdr.KDF != "pbkdf2-hmac-sha256" || hdr.Cipher != "aes-256-gcm" {
		return fmt.Errorf("ca: unsupported backup kdf/cipher (%q/%q)", hdr.KDF, hdr.Cipher)
	}
	// A hostile file could ask for a billion iterations and hang the restore;
	// an accidental 1 would mean the container was never really protected.
	if hdr.Iterations < 100_000 || hdr.Iterations > 10_000_000 {
		return fmt.Errorf("ca: backup declares an implausible KDF iteration count (%d)", hdr.Iterations)
	}
	salt, err := base64.StdEncoding.DecodeString(hdr.Salt)
	if err != nil {
		return fmt.Errorf("ca: decode backup salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(hdr.Nonce)
	if err != nil {
		return fmt.Errorf("ca: decode backup nonce: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(hdr.Payload)
	if err != nil {
		return fmt.Errorf("ca: decode backup payload: %w", err)
	}
	aead, err := backupAEAD(passphrase, salt, hdr.Iterations)
	if err != nil {
		return err
	}
	if len(nonce) != aead.NonceSize() {
		return fmt.Errorf("ca: backup nonce has wrong length (%d)", len(nonce))
	}
	aad, err := hdr.aad()
	if err != nil {
		return err
	}
	archive, err := aead.Open(nil, nonce, payload, aad)
	if err != nil {
		// GCM cannot tell "wrong passphrase" from "edited file" — both are just a
		// failed tag. Say both, in that order: one is common, the other matters.
		return errors.New("ca: could not open backup — wrong passphrase, or the file has been altered")
	}

	if err := assertNoCA(dir); err != nil {
		return err
	}
	return untarCADir(archive, dir)
}

// BackupInfo reports the cleartext header of a container without decrypting it,
// so an operator can check what a stored backup is before typing a passphrase.
func BackupInfo(data []byte) (createdAt time.Time, commonName string, err error) {
	var hdr backupHeader
	if err := json.Unmarshal(data, &hdr); err != nil {
		return time.Time{}, "", fmt.Errorf("ca: this does not look like a CA backup: %w", err)
	}
	if hdr.Format != backupFormat {
		return time.Time{}, "", fmt.Errorf("ca: not a CA backup (format %q)", hdr.Format)
	}
	return hdr.CreatedAt, hdr.CACommonName, nil
}

func backupAEAD(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
	if err != nil {
		return nil, fmt.Errorf("ca: derive backup key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ca: init cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ca: init GCM: %w", err)
	}
	return aead, nil
}

// assertNoCA refuses a restore into a directory that already holds CA material.
func assertNoCA(dir string) error {
	for _, name := range []string{"ca.crt", "ca.key"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("ca: %s already exists — restore into an empty directory (or move the existing CA aside first)", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("ca: stat %s: %w", p, err)
		}
	}
	return nil
}

// tarCADir packs every regular file under dir into a gzipped tar, with paths
// relative to dir. Half-written temp files from an interrupted issue (see
// writeFileAtomic) are skipped — they are never part of the CA's state.
func tarCADir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		base := filepath.Base(p)
		if strings.HasPrefix(base, ".") && strings.HasSuffix(base, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:    filepath.ToSlash(rel),
			Mode:    int64(info.Mode().Perm()),
			Size:    int64(len(data)),
			ModTime: info.ModTime(),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("ca: pack CA directory: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("ca: pack CA directory: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("ca: pack CA directory: %w", err)
	}
	return buf.Bytes(), nil
}

// untarCADir writes the archive into dir. Entry names are checked rather than
// trusted: the archive is authenticated, but "authenticated" only means it came
// from whoever knew the passphrase — a restore must still not be able to drop a
// file outside the directory the operator named.
func untarCADir(archive []byte, dir string) error {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("ca: read backup archive: %w", err)
	}
	defer func() { _ = zr.Close() }()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ca: create %s: %w", dir, err)
	}
	tr := tar.NewReader(io.LimitReader(zr, backupMaxPlaintext))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("ca: read backup archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, err := safeArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(tr, backupMaxPlaintext))
		if err != nil {
			return fmt.Errorf("ca: read %s from backup: %w", hdr.Name, err)
		}
		// Restore the recorded mode, but never looser than the file deserves:
		// anything that isn't a certificate is treated as key material.
		perm := fs.FileMode(hdr.Mode).Perm()
		if perm == 0 {
			perm = 0o600
		}
		if strings.HasSuffix(rel, ".key") {
			perm = 0o600
		}
		if err := writeFileAtomic(filepath.Join(dir, filepath.FromSlash(rel)), data, perm); err != nil {
			return err
		}
	}
	return nil
}

// safeArchivePath rejects entry names that would escape the restore directory —
// absolute paths, "..", and drive-letter or backslash forms that only Windows
// treats as special.
// It rejects such a name rather than normalising it into something harmless:
// nothing this package writes produces one, so an entry that needs rewriting
// means the container was built by something else, and that is worth failing on.
func safeArchivePath(name string) (string, error) {
	slashed := strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(slashed)
	unsafe := clean == "" || clean == "." ||
		strings.HasPrefix(slashed, "/") || clean == ".." || strings.HasPrefix(clean, "../") ||
		filepath.IsAbs(filepath.FromSlash(clean)) ||
		filepath.VolumeName(filepath.FromSlash(slashed)) != ""
	if unsafe {
		return "", fmt.Errorf("ca: backup contains an unsafe path %q", name)
	}
	return clean, nil
}
