package vless

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// newTestStore returns a store with an initialised node.
func newTestStore(t *testing.T) (*Store, Node) {
	t.Helper()
	s := New(t.TempDir())
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := s.SaveNode(n); err != nil {
		t.Fatalf("SaveNode: %v", err)
	}
	return s, n
}

func TestAddAndRemove(t *testing.T) {
	s, _ := newTestStore(t)

	clients, err := s.Clients()
	if err != nil {
		t.Fatalf("Clients on a fresh node: %v", err)
	}
	if len(clients) != 0 {
		t.Fatalf("fresh node has %d clients", len(clients))
	}

	anna, err := s.Add("anna")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := s.Add("boris"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	clients, err = s.Clients()
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(clients))
	}

	// Adding the config is not enough — the file Xray reads must carry the new
	// client, or the access exists only on paper.
	cfg, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfg), anna.UUID) {
		t.Error("config.json does not contain the new client's UUID")
	}

	// One person, one credential: a second issue would leave a UUID that
	// revoking by name does not obviously cover.
	if _, err := s.Add("ANNA"); err == nil {
		t.Error("Add issued a second credential for the same person")
	}

	removed, err := s.Remove("Anna")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Error("Remove reported nothing removed")
	}
	cfg, err = os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(cfg), anna.UUID) {
		t.Error("config.json still carries a revoked UUID")
	}
	if strings.Contains(string(cfg), anna.ShortID) {
		t.Error("config.json still carries a revoked shortId")
	}

	// Revoking someone who never had VLESS access is not a failure: they may
	// only ever have had the other service.
	removed, err = s.Remove("nobody")
	if err != nil {
		t.Fatalf("Remove of an unknown name: %v", err)
	}
	if removed {
		t.Error("Remove reported a removal that did not happen")
	}
}

func TestAddWithoutNode(t *testing.T) {
	s := New(t.TempDir())
	if _, err := s.Add("anna"); err != ErrNoNode {
		t.Fatalf("Add on an uninitialised node = %v, want ErrNoNode", err)
	}
}

func TestFind(t *testing.T) {
	s, _ := newTestStore(t)
	if _, ok, err := s.Find("anna"); err != nil || ok {
		t.Fatalf("Find on an empty node: ok=%v err=%v", ok, err)
	}
	added, err := s.Add("anna")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, ok, err := s.Find("ANNA")
	if err != nil || !ok {
		t.Fatalf("Find: ok=%v err=%v", ok, err)
	}
	if got.UUID != added.UUID {
		t.Error("Find returned a different client")
	}
}

func TestRenderRebuildsConfig(t *testing.T) {
	s, _ := newTestStore(t)
	c, err := s.Add("anna")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := os.Remove(s.ConfigPath()); err != nil {
		t.Fatalf("remove config: %v", err)
	}
	if err := s.Render(); err != nil {
		t.Fatalf("Render: %v", err)
	}
	cfg, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfg), c.UUID) {
		t.Error("re-rendered config lost a client")
	}
}

// The link is the whole product for a Happ user: if a parameter is missing or
// misspelled the import silently produces a server that never connects.
func TestLink(t *testing.T) {
	s, n := newTestStore(t)
	c, err := s.Add("anna")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	raw, err := Link(n, c)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("link does not parse: %v", err)
	}
	if u.Scheme != "vless" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	if u.User.Username() != c.UUID {
		t.Errorf("userinfo = %q, want the client UUID", u.User.Username())
	}
	if u.Host != n.Endpoint() {
		t.Errorf("host = %q, want %q", u.Host, n.Endpoint())
	}
	q := u.Query()
	for key, want := range map[string]string{
		"type":       "tcp",
		"security":   "reality",
		"encryption": "none",
		"flow":       Flow,
		"pbk":        n.PublicKey,
		"sni":        n.ServerName(),
		"sid":        c.ShortID,
		"fp":         n.Fingerprint,
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// The private key must never reach a client.
	if strings.Contains(raw, n.PrivateKey) {
		t.Error("the link carries the node's private key")
	}
}

func TestLinkLabelEscaping(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "дом и офис", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	c, err := NewClient("anna")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	raw, err := Link(n, c)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	// A label with spaces and non-ASCII must survive as a fragment a client can
	// parse — unescaped, it would truncate the name or break the link.
	if strings.Contains(raw, "дом и офис") {
		t.Errorf("fragment was not escaped: %s", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("link does not parse: %v", err)
	}
	if u.Fragment != "дом и офис" {
		t.Errorf("fragment = %q, want the label back", u.Fragment)
	}
}

func TestLinkLabelDefaultsToEndpoint(t *testing.T) {
	n, err := NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if got := n.LinkLabel(); got != "203.0.113.10:443" {
		t.Errorf("label = %q, want the endpoint", got)
	}
}
