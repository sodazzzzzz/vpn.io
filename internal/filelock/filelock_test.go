package filelock

import (
	"path/filepath"
	"testing"
	"time"
)

// Acquire must block a second caller until the first releases — the property
// that serialises vpn-bot and vpn-ca so neither loses the other's update.
func TestAcquireBlocksUntilUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")

	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire (first): %v", err)
	}

	acquired := make(chan error, 1)
	go func() {
		second, err := Acquire(path)
		acquired <- err
		if err == nil {
			_ = second.Unlock()
		}
	}()

	select {
	case err := <-acquired:
		t.Fatalf("second Acquire returned (err=%v) while the first still held the lock", err)
	case <-time.After(150 * time.Millisecond):
		// Expected: the second caller is blocked.
	}

	if err := first.Unlock(); err != nil {
		t.Fatalf("Unlock (first): %v", err)
	}

	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("second Acquire after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Acquire did not proceed after the first released the lock")
	}
}

// Unlock is safe on a nil lock and idempotent on a real one.
func TestUnlockNilSafeAndIdempotent(t *testing.T) {
	var nilLock *Lock
	if err := nilLock.Unlock(); err != nil {
		t.Errorf("Unlock on nil: %v", err)
	}

	l, err := Acquire(filepath.Join(t.TempDir(), "x"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := l.Unlock(); err != nil {
		t.Errorf("Unlock: %v", err)
	}
	if err := l.Unlock(); err != nil {
		t.Errorf("second Unlock should be a no-op: %v", err)
	}
}
