package vless

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewNodeDefaults(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if n.Port != DefaultPort {
		t.Errorf("port = %d, want %d", n.Port, DefaultPort)
	}
	if n.Dest != DefaultDest {
		t.Errorf("dest = %q, want %q", n.Dest, DefaultDest)
	}
	// The SNI must name the site we forward unauthenticated handshakes to;
	// announcing something dest does not serve is what makes a node stand out.
	if got, want := n.ServerName(), hostOf(DefaultDest); got != want {
		t.Errorf("server name = %q, want %q", got, want)
	}
	if n.Endpoint() != "203.0.113.10:443" {
		t.Errorf("endpoint = %q", n.Endpoint())
	}
}

func TestNewNodeRequiresAddress(t *testing.T) {
	if _, err := NewNode("  ", "", "", "", "", 0); err == nil {
		t.Fatal("NewNode accepted an empty address")
	}
}

// The public key in every link must be the one derived from the private key we
// keep, or clients negotiate against a key the node cannot use.
func TestKeypairMatches(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(n.PrivateKey)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("private key rejected: %v", err)
	}
	want := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	if n.PublicKey != want {
		t.Errorf("public key = %q, derived = %q", n.PublicKey, want)
	}
	// Stored clamped, so the bytes match what Xray uses byte for byte.
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Errorf("private key is not clamped: %x", priv)
	}
}

func TestNodeValidate(t *testing.T) {
	good, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	tests := []struct {
		name string
		mut  func(*Node)
	}{
		{"no address", func(n *Node) { n.Address = "" }},
		{"bad port", func(n *Node) { n.Port = 70000 }},
		{"no private key", func(n *Node) { n.PrivateKey = "" }},
		{"no server names", func(n *Node) { n.ServerNames = nil }},
		{"dest without port", func(n *Node) { n.Dest = "www.example.com" }},
		{"truncated key", func(n *Node) { n.PublicKey = "abc" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := good
			tc.mut(&n)
			if err := n.Validate(); err == nil {
				t.Error("Validate accepted an invalid node")
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	c, err := NewClient("  anna  ")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Name != "anna" {
		t.Errorf("name = %q, want trimmed", c.Name)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("fresh client does not validate: %v", err)
	}
	other, err := NewClient("anna")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Same name, different credentials: nothing is derived from the name.
	if other.UUID == c.UUID || other.ShortID == c.ShortID {
		t.Error("two clients with the same name share credentials")
	}
}

func TestClientValidate(t *testing.T) {
	good, err := NewClient("anna")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tests := []struct {
		name string
		mut  func(*Client)
	}{
		{"no name", func(c *Client) { c.Name = " " }},
		{"short uuid", func(c *Client) { c.UUID = "1234" }},
		{"uuid without hyphens", func(c *Client) { c.UUID = strings.ReplaceAll(c.UUID, "-", "0") }},
		{"empty shortId", func(c *Client) { c.ShortID = "" }},
		{"odd shortId", func(c *Client) { c.ShortID = "abc" }},
		{"long shortId", func(c *Client) { c.ShortID = strings.Repeat("ab", shortIDBytes+1) }},
		{"uppercase shortId", func(c *Client) { c.ShortID = "ABCDEF01" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate accepted an invalid client")
			}
		})
	}
}

// Config is what Xray reads: check the fields REALITY cannot work without, and
// the two privacy choices we made deliberately.
func TestConfig(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	c, err := NewClient("anna")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	data, err := Config(n, []Client{c})
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	var cfg struct {
		Log struct {
			Access string `json:"access"`
		} `json:"log"`
		Inbounds []struct {
			Port     int `json:"port"`
			Settings struct {
				Clients []struct {
					ID   string `json:"id"`
					Flow string `json:"flow"`
				} `json:"clients"`
				Decryption string `json:"decryption"`
			} `json:"settings"`
			StreamSettings struct {
				Security string `json:"security"`
				Reality  struct {
					Dest        string   `json:"dest"`
					ServerNames []string `json:"serverNames"`
					PrivateKey  string   `json:"privateKey"`
					ShortIDs    []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
			Sniffing struct {
				Enabled bool `json:"enabled"`
			} `json:"sniffing"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(cfg.Inbounds))
	}
	in := cfg.Inbounds[0]
	if in.Port != DefaultPort {
		t.Errorf("port = %d", in.Port)
	}
	if in.StreamSettings.Security != "reality" {
		t.Errorf("security = %q", in.StreamSettings.Security)
	}
	if in.StreamSettings.Reality.PrivateKey != n.PrivateKey {
		t.Error("config does not carry the node's private key")
	}
	if got := in.StreamSettings.Reality.ShortIDs; len(got) != 1 || got[0] != c.ShortID {
		t.Errorf("shortIds = %v, want [%s]", got, c.ShortID)
	}
	if len(in.Settings.Clients) != 1 || in.Settings.Clients[0].ID != c.UUID {
		t.Error("config does not carry the client UUID")
	}
	if in.Settings.Clients[0].Flow != Flow {
		t.Errorf("flow = %q, want %q", in.Settings.Clients[0].Flow, Flow)
	}
	if in.Settings.Decryption != "none" {
		t.Errorf("decryption = %q", in.Settings.Decryption)
	}
	// The node should not learn where its users go, and should not narrate
	// connections into a log.
	if in.Sniffing.Enabled {
		t.Error("sniffing is enabled — the node would learn every destination")
	}
	if cfg.Log.Access != "none" {
		t.Errorf("access log = %q, want none", cfg.Log.Access)
	}
}

func TestConfigRejectsBrokenClient(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if _, err := Config(n, []Client{{Name: "anna", UUID: "nope", ShortID: "abcdef01"}}); err == nil {
		t.Fatal("Config accepted a client with a malformed UUID")
	}
}

func TestStoreNodeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if _, err := s.LoadNode(); err != ErrNoNode {
		t.Fatalf("LoadNode on a fresh dir = %v, want ErrNoNode", err)
	}

	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := s.SaveNode(n); err != nil {
		t.Fatalf("SaveNode: %v", err)
	}
	got, err := s.LoadNode()
	if err != nil {
		t.Fatalf("LoadNode: %v", err)
	}
	if got.PrivateKey != n.PrivateKey || got.PublicKey != n.PublicKey || got.Dest != n.Dest {
		t.Error("node did not survive the round trip")
	}

	// The private key is a credential: owner-only, like every other key this
	// project writes.
	info, err := os.Stat(s.NodePath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("node.json mode = %o, want 600", perm)
	}
}

// Re-keying must be deliberate: every issued link is derived from the stored
// private key, so an accidental second init would cut everyone off.
func TestSaveNodeRefusesOverwrite(t *testing.T) {
	s := New(t.TempDir())
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := s.SaveNode(n); err != nil {
		t.Fatalf("SaveNode: %v", err)
	}
	other, err := NewNode("203.0.113.11", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := s.SaveNode(other); err == nil {
		t.Fatal("SaveNode overwrote an existing node")
	}
	got, err := s.LoadNode()
	if err != nil {
		t.Fatalf("LoadNode: %v", err)
	}
	if got.PrivateKey != n.PrivateKey {
		t.Error("the original key was replaced")
	}
}

func TestWriteConfigPermissionsAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	c, err := NewClient("anna")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := s.WriteConfig(n, []Client{c}); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	info, err := os.Stat(s.ConfigPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config.json mode = %o, want 600 (it holds the private key)", perm)
	}

	// A render that fails must leave the previous config untouched, so the
	// running service keeps the state it had.
	before, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := s.WriteConfig(n, []Client{{Name: "broken"}}); err == nil {
		t.Fatal("WriteConfig accepted a broken client")
	}
	after, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a failed render modified config.json")
	}
	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", filepath.Join(dir, e.Name()))
		}
	}
}
