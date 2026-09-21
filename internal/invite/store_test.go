package invite

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenExpired(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	ttl := time.Hour
	cases := []struct {
		name    string
		created time.Time
		ttl     time.Duration
		want    bool
	}{
		{"fresh", now.Add(-time.Minute), ttl, false},
		{"just past ttl", now.Add(-ttl - time.Second), ttl, true},
		{"exactly at ttl (inclusive)", now.Add(-ttl), ttl, true},
		{"ttl disabled", now.Add(-1000 * time.Hour), 0, false},
		{"zero created is expired", time.Time{}, ttl, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenExpired(tc.created, tc.ttl, now); got != tc.want {
				t.Fatalf("tokenExpired(%v, %v) = %v, want %v", tc.created, tc.ttl, got, tc.want)
			}
		})
	}
}

func TestPruneExpired(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	in := []Token{
		{Value: "fresh", Created: now},
		{Value: "old-unused", Created: old},
		{Value: "old-used", Used: true, Created: old}, // kept: audit trail
	}
	got := pruneExpired(in, time.Hour, now)
	kept := map[string]bool{}
	for _, tk := range got {
		kept[tk.Value] = true
	}
	if !kept["fresh"] || !kept["old-used"] || kept["old-unused"] {
		t.Fatalf("pruneExpired kept the wrong set: %v", kept)
	}
	// ttl <= 0 keeps everything.
	if got := pruneExpired(in, 0, now); len(got) != len(in) {
		t.Fatalf("pruneExpired with ttl=0 dropped tokens: got %d, want %d", len(got), len(in))
	}
}

// An invite past its TTL can't be redeemed — the whole point of #133.
func TestRedeemRejectsExpired(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	s.TTL = time.Nanosecond // anything issued is expired almost immediately
	tok, err := s.Generate("alice", GrantProfile)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := s.Redeem(tok.Value, "tg:1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token Redeem err = %v, want ErrNotFound", err)
	}
}

// Generating a new token sweeps expired, never-redeemed ones from the store.
func TestGeneratePrunesExpiredUnused(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	s.TTL = time.Nanosecond
	old, err := s.Generate("stale", GrantProfile)
	if err != nil {
		t.Fatalf("Generate stale: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	fresh, err := s.Generate("current", GrantProfile)
	if err != nil {
		t.Fatalf("Generate current: %v", err)
	}
	f, err := s.loadLocked()
	if err != nil {
		t.Fatalf("loadLocked: %v", err)
	}
	if len(f.Tokens) != 1 || f.Tokens[0].Value != fresh.Value {
		var names []string
		for _, tk := range f.Tokens {
			names = append(names, tk.ClientName)
		}
		t.Fatalf("expected only the fresh token after prune, got %v (stale=%q)", names, old.ClientName)
	}
}

func TestGenerateAndRedeem(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))

	tok, err := s.Generate("alice", GrantProfile)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if tok.Value == "" || tok.ClientName != "alice" || tok.Used {
		t.Fatalf("unexpected token: %+v", tok)
	}

	redeemed, err := s.Redeem(tok.Value, "tg:123")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if redeemed.ClientName != "alice" {
		t.Errorf("client name = %q, want alice", redeemed.ClientName)
	}
	// The value is spent — handing it back would only put a dead secret in the
	// caller's logs.
	if redeemed.Value != "" {
		t.Error("Redeem returned the token value")
	}

	// A second redemption of the same token must fail (single-use).
	if _, err := s.Redeem(tok.Value, "tg:456"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Redeem err = %v, want ErrNotFound", err)
	}
}

func TestRedeemUnknownAndEmpty(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	if _, err := s.Generate("bob", GrantProfile); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := s.Redeem("nope", "tg:1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token err = %v, want ErrNotFound", err)
	}
	if _, err := s.Redeem("", "tg:1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty token err = %v, want ErrNotFound", err)
	}
}

func TestGenerateRequiresName(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	if _, err := s.Generate("", GrantProfile); err == nil {
		t.Fatal("expected error for empty client name")
	}
}

func TestTokensPersistAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")

	tok, err := New(path).Generate("carol", GrantProfile)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// A fresh Store at the same path must see and redeem the token.
	redeemed, err := New(path).Redeem(tok.Value, "tg:9")
	if err != nil {
		t.Fatalf("Redeem on fresh store: %v", err)
	}
	if redeemed.ClientName != "carol" {
		t.Errorf("client name = %q, want carol", redeemed.ClientName)
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := s.Generate("x", GrantProfile)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[tok.Value] {
			t.Fatalf("duplicate token value: %q", tok.Value)
		}
		seen[tok.Value] = true
	}
}

// List returns every token in issuance order with its redemption state, for the
// owner's /invites (#108).
func TestList(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	a, err := s.Generate("alice", GrantProfile)
	if err != nil {
		t.Fatalf("Generate alice: %v", err)
	}
	if _, err := s.Generate("bob", GrantProfile); err != nil {
		t.Fatalf("Generate bob: %v", err)
	}
	if _, err := s.Redeem(a.Value, "tg:alice"); err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	tokens, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("List len = %d, want 2", len(tokens))
	}
	if tokens[0].ClientName != "alice" || !tokens[0].Used || tokens[0].UsedBy != "tg:alice" {
		t.Errorf("alice entry wrong: %+v", tokens[0])
	}
	if tokens[1].ClientName != "bob" || tokens[1].Used {
		t.Errorf("bob entry wrong: %+v", tokens[1])
	}
}

// List on a store that was never written (fresh bot) is empty, not an error, so
// /invites can answer before any token is issued.
func TestList_FreshStoreIsEmpty(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "nope", "tokens.json"))
	tokens, err := s.List()
	if err != nil {
		t.Fatalf("List on fresh store: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("fresh store List len = %d, want 0", len(tokens))
	}
}

func TestExpired_ExportedWrapper(t *testing.T) {
	now := time.Now()
	fresh := Token{Created: now}
	old := Token{Created: now.Add(-2 * time.Hour)}
	if Expired(fresh, time.Hour, now) {
		t.Error("fresh token reported expired")
	}
	if !Expired(old, time.Hour, now) {
		t.Error("old token not reported expired")
	}
	if Expired(old, 0, now) {
		t.Error("ttl=0 should disable expiry")
	}
}

func TestGrants(t *testing.T) {
	// A token minted before grants existed must keep meaning what it meant when
	// it was handed out: a profile, not nothing and not everything.
	var legacy Token
	if got := legacy.Grants(); got != GrantProfile {
		t.Errorf("legacy token grants %q, want %q", got, GrantProfile)
	}
	if !legacy.Grants().Profile() || legacy.Grants().VLESS() {
		t.Error("legacy token does not grant exactly a profile")
	}

	for _, tc := range []struct {
		in              string
		want            Grant
		profile, vlessB bool
	}{
		{"", GrantProfile, true, false},
		{"profile", GrantProfile, true, false},
		{"VLESS", GrantVLESS, false, true},
		{" both ", GrantBoth, true, true},
	} {
		got, err := ParseGrant(tc.in)
		if err != nil {
			t.Fatalf("ParseGrant(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseGrant(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got.Profile() != tc.profile || got.VLESS() != tc.vlessB {
			t.Errorf("%q covers profile=%v vless=%v", got, got.Profile(), got.VLESS())
		}
	}
	if _, err := ParseGrant("everything"); err == nil {
		t.Error("ParseGrant accepted an unknown grant")
	}
}

func TestGenerateStoresGrant(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	tok, err := s.Generate("anna", GrantVLESS)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	redeemed, err := s.Redeem(tok.Value, "tg:1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if redeemed.Grants() != GrantVLESS {
		t.Errorf("grant = %q, want %q", redeemed.Grants(), GrantVLESS)
	}
}
