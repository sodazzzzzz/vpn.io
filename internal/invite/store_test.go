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
	tok, err := s.Generate("alice")
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
	old, err := s.Generate("stale")
	if err != nil {
		t.Fatalf("Generate stale: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	fresh, err := s.Generate("current")
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

	tok, err := s.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if tok.Value == "" || tok.ClientName != "alice" || tok.Used {
		t.Fatalf("unexpected token: %+v", tok)
	}

	name, err := s.Redeem(tok.Value, "tg:123")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if name != "alice" {
		t.Errorf("client name = %q, want alice", name)
	}

	// A second redemption of the same token must fail (single-use).
	if _, err := s.Redeem(tok.Value, "tg:456"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Redeem err = %v, want ErrNotFound", err)
	}
}

func TestRedeemUnknownAndEmpty(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	if _, err := s.Generate("bob"); err != nil {
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
	if _, err := s.Generate(""); err == nil {
		t.Fatal("expected error for empty client name")
	}
}

func TestTokensPersistAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")

	tok, err := New(path).Generate("carol")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// A fresh Store at the same path must see and redeem the token.
	name, err := New(path).Redeem(tok.Value, "tg:9")
	if err != nil {
		t.Fatalf("Redeem on fresh store: %v", err)
	}
	if name != "carol" {
		t.Errorf("client name = %q, want carol", name)
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "tokens.json"))
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := s.Generate("x")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[tok.Value] {
			t.Fatalf("duplicate token value: %q", tok.Value)
		}
		seen[tok.Value] = true
	}
}
