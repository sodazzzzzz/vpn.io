package revoke

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A revoke → unrevoke → revoke that rewrites the deny-list to the SAME byte
// count within one coarse mtime tick is invisible to the mtime+size check; while
// the file's mtime is fresh the Checker must re-read anyway and pick up the new
// set (#158). Clock and mtime are pinned so the "recently modified" window is
// deterministic.
func TestChecker_ReloadsRecentSameSizeRewrite(t *testing.T) {
	fixedNow := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	orig := checkerNow
	checkerNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { checkerNow = orig })

	path := filepath.Join(t.TempDir(), "revoked.json")
	mtime := fixedNow.Add(-1 * time.Second) // inside the granularity window
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	write := func(serial string) {
		if err := save(path, fileFormat{Revoked: []Entry{{Serial: serial, Name: "x", RevokedAt: ts}}}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}

	a := big.NewInt(0xaa) // serialHex "aa"
	b := big.NewInt(0xbb) // serialHex "bb" — same on-disk byte count as "aa"

	write("aa")
	fi1, _ := os.Stat(path)
	c := NewChecker(path)
	if yes, err := c.IsRevoked(a); err != nil || !yes {
		t.Fatalf("A after first load = %v, %v; want revoked", yes, err)
	}

	// Same-tick, same-size rewrite: swap A for B under the identical mtime.
	write("bb")
	fi2, _ := os.Stat(path)
	if !fi1.ModTime().Equal(fi2.ModTime()) || fi1.Size() != fi2.Size() {
		t.Fatalf("test setup broken: mtime/size changed (%v/%d vs %v/%d) — can't isolate the same-tick case",
			fi1.ModTime(), fi1.Size(), fi2.ModTime(), fi2.Size())
	}

	// The cheap mtime+size check alone would miss this; recentlyModified forces
	// the reload.
	if yes, err := c.IsRevoked(b); err != nil || !yes {
		t.Fatalf("B after same-tick rewrite = %v, %v; want revoked", yes, err)
	}
	if yes, err := c.IsRevoked(a); err != nil || yes {
		t.Fatalf("A after rewrite = %v, %v; want NOT revoked", yes, err)
	}
}

func TestCheckerKeepsLastKnownOnFileDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.json")
	s := New(path)
	c := NewChecker(path)
	s1 := big.NewInt(0x1234)

	if yes, err := c.IsRevoked(s1); err != nil || yes {
		t.Fatalf("before any file = %v, %v; want false, nil", yes, err)
	}
	if _, err := s.Add(s1, "alice"); err != nil {
		t.Fatal(err)
	}
	if yes, err := c.IsRevoked(s1); err != nil || !yes {
		t.Fatalf("after Add = %v, %v; want true", yes, err)
	}
	// Deleting the file must NOT silently un-revoke everyone: the last-known set
	// stays in force (a real un-revoke rewrites the file, never deletes it).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if yes, err := c.IsRevoked(s1); err != nil || !yes {
		t.Fatalf("after file deletion = %v, %v; want true (last-known kept)", yes, err)
	}
}

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

// Un-revoking must lift exactly one certificate. Removing by name would also
// clear the revocations a re-issue applied to superseded certificates, handing
// a replaced (typically leaked) profile its access back.
func TestRemoveSerialLeavesOtherCertsOfSameNameRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.json")
	s := New(path)

	leaked := big.NewInt(0xaaaa)
	current := big.NewInt(0xbbbb)
	for _, serial := range []*big.Int{leaked, current} {
		if _, err := s.Add(serial, "alice"); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	removed, err := s.RemoveSerial(current)
	if err != nil {
		t.Fatalf("RemoveSerial: %v", err)
	}
	if !removed {
		t.Fatal("RemoveSerial reported nothing removed")
	}

	c := NewChecker(path)
	yes, err := c.IsRevoked(leaked)
	if err != nil {
		t.Fatalf("IsRevoked(leaked): %v", err)
	}
	if !yes {
		t.Error("un-revoking the current cert also lifted the leaked one")
	}
	yes, err = c.IsRevoked(current)
	if err != nil {
		t.Fatalf("IsRevoked(current): %v", err)
	}
	if yes {
		t.Error("current cert is still revoked after RemoveSerial")
	}

	// Removing something that isn't on the list is not an error.
	removed, err = s.RemoveSerial(big.NewInt(0xcccc))
	if err != nil {
		t.Fatalf("RemoveSerial(absent): %v", err)
	}
	if removed {
		t.Error("RemoveSerial reported a removal for an absent serial")
	}
}
