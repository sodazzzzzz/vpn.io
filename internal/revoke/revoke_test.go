package revoke

import (
	"math/big"
	"path/filepath"
	"testing"
)

func TestStoreAddCheckRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.json")
	s := New(path)
	c := NewChecker(path)

	s1 := big.NewInt(0x1234)
	s2 := big.NewInt(0xabcd)

	// Missing file -> nothing revoked, no error.
	if yes, err := c.IsRevoked(s1); err != nil || yes {
		t.Fatalf("IsRevoked on missing file = %v, %v; want false, nil", yes, err)
	}

	// Revoke s1.
	if added, err := s.Add(s1, "alice"); err != nil || !added {
		t.Fatalf("Add s1 = %v, %v; want true, nil", added, err)
	}
	// Idempotent: same serial again is a no-op.
	if added, err := s.Add(s1, "alice"); err != nil || added {
		t.Fatalf("Add s1 again = %v, %v; want false, nil", added, err)
	}

	// Checker hot-reloads and sees the revocation.
	if yes, err := c.IsRevoked(s1); err != nil || !yes {
		t.Fatalf("IsRevoked s1 = %v, %v; want true, nil", yes, err)
	}
	if yes, err := c.IsRevoked(s2); err != nil || yes {
		t.Fatalf("IsRevoked s2 = %v, %v; want false, nil", yes, err)
	}

	if l, err := s.List(); err != nil || len(l) != 1 || l[0].Name != "alice" || l[0].Serial != "1234" {
		t.Fatalf("List = %+v, %v; want one alice/1234", l, err)
	}

	// Revoke s2 (bob), then un-revoke alice.
	if _, err := s.Add(s2, "bob"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Remove("alice"); err != nil || n != 1 {
		t.Fatalf("Remove alice = %v, %v; want 1, nil", n, err)
	}
	// Removing an absent name is a no-op.
	if n, err := s.Remove("nobody"); err != nil || n != 0 {
		t.Fatalf("Remove nobody = %v, %v; want 0, nil", n, err)
	}

	// After reload: s1 cleared, s2 still revoked.
	if yes, err := c.IsRevoked(s1); err != nil || yes {
		t.Fatalf("IsRevoked s1 after unrevoke = %v, %v; want false, nil", yes, err)
	}
	if yes, err := c.IsRevoked(s2); err != nil || !yes {
		t.Fatalf("IsRevoked s2 = %v, %v; want true, nil", yes, err)
	}
}

func TestCheckerEmptyPathDisabled(t *testing.T) {
	c := NewChecker("")
	if yes, err := c.IsRevoked(big.NewInt(1)); err != nil || yes {
		t.Fatalf("empty path = %v, %v; want false, nil", yes, err)
	}
}
