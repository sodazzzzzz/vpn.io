package vless

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DefaultDir is where a node keeps its VLESS state. The directory itself is
// 0700 and owned by the service user (packaging/server/install-xray.sh creates
// it): everything in here is either a key or a credential.
const DefaultDir = "/etc/vpn-xray"

// maxFileBytes caps what the store will read. The files are a few KB; a larger
// one means corruption or something that is not ours, and refusing beats
// allocating whatever is on disk.
const maxFileBytes = 1 << 20

// Store is the on-disk state of one node's VLESS service.
//
// Three files, split by how often they change and by who may read them:
//
//   - node.json    the REALITY identity, including the private key. Written
//     once at init, 0600.
//   - clients.json who has access. Rewritten on every add and revoke, 0600 —
//     a UUID is a credential, not metadata.
//   - config.json  what Xray actually reads, rendered from the two above. 0600
//     as well, since it contains both the private key and every
//     UUID. It is derived state: losing it costs a re-render, not
//     a reissue.
type Store struct {
	Dir string
}

// New returns a Store rooted at dir, defaulting to DefaultDir.
func New(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{Dir: dir}
}

// NodePath, ClientsPath and ConfigPath are the three files described on Store.
func (s *Store) NodePath() string    { return filepath.Join(s.Dir, "node.json") }
func (s *Store) ClientsPath() string { return filepath.Join(s.Dir, "clients.json") }
func (s *Store) ConfigPath() string  { return filepath.Join(s.Dir, "config.json") }

// ErrNoNode is returned when the node has not been initialised yet. Callers
// distinguish it from a read failure: "not set up" has an obvious next step
// ("run vpn-vless init"), a corrupt or unreadable file does not.
var ErrNoNode = errors.New("vless: node is not initialised")

// LoadNode reads and validates node.json.
func (s *Store) LoadNode() (Node, error) {
	data, err := readFile(s.NodePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Node{}, ErrNoNode
		}
		return Node{}, err
	}
	var n Node
	if err := json.Unmarshal(data, &n); err != nil {
		return Node{}, fmt.Errorf("vless: parse %q: %w", s.NodePath(), err)
	}
	if err := n.Validate(); err != nil {
		return Node{}, fmt.Errorf("%w (in %s)", err, s.NodePath())
	}
	return n, nil
}

// SaveNode writes node.json. It refuses to overwrite an existing node: the
// private key in there is what every issued link was derived from, so replacing
// it silently would invalidate everyone's access with no way back. Re-keying is
// a deliberate act — remove the file yourself and run init again, knowing that
// every link must be reissued.
func (s *Store) SaveNode(n Node) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if _, err := os.Stat(s.NodePath()); err == nil {
		return fmt.Errorf("vless: %s already exists — this node already has REALITY keys; "+
			"remove the file to re-key, and reissue every link afterwards", s.NodePath())
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vless: check %q: %w", s.NodePath(), err)
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return fmt.Errorf("vless: encode node: %w", err)
	}
	return s.write(s.NodePath(), append(data, '\n'))
}

// WriteConfig renders the Xray config for the node and clients and writes it to
// config.json.
//
// The render happens before the file is touched, so a client list that would
// produce an invalid config leaves the previous config in place: the service
// keeps running with the state it had rather than failing to restart with the
// state we tried to give it.
func (s *Store) WriteConfig(n Node, clients []Client) error {
	data, err := Config(n, clients)
	if err != nil {
		return err
	}
	return s.write(s.ConfigPath(), data)
}

// write saves data to path atomically (temp file in the same directory, then
// rename) with 0600 permissions, creating the directory 0700 if missing.
//
// Atomicity matters here for the same reason it does in the revocation store:
// Xray may be restarted at any moment by whoever is adding a client, and a
// half-written config.json is a service that does not come back.
func (s *Store) write(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vless: create %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".vless-*.tmp")
	if err != nil {
		return fmt.Errorf("vless: create temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vless: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vless: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("vless: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vless: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("vless: replace %q: %w", path, err)
	}
	// fsync the directory so the rename survives a crash right after it — an
	// added client that vanishes on reboot is worse than one that never landed.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// readFile reads path with a size cap, passing os.ErrNotExist through for
// callers that treat "missing" as a state rather than a failure.
func readFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vless: open %q: %w", path, err)
	}
	defer func() { _ = fh.Close() }()

	data, err := io.ReadAll(io.LimitReader(fh, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("vless: read %q: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("vless: %q is too large (over %d bytes)", path, maxFileBytes)
	}
	return data, nil
}
