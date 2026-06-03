package invite

import (
	"errors"
	"path/filepath"
	"testing"
)

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
