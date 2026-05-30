package firewall

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

type mockRunner struct {
	blockCalls   int
	restoreCalls int
	blockErr     error
	restoreErr   error
}

func (m *mockRunner) BlockIPv6() error {
	m.blockCalls++
	return m.blockErr
}

func (m *mockRunner) Restore() error {
	m.restoreCalls++
	return m.restoreErr
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBlockIPv6_HappyPath(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.BlockIPv6(); err != nil {
		t.Fatalf("BlockIPv6: %v", err)
	}
	if r.blockCalls != 1 {
		t.Fatalf("BlockIPv6 calls = %d, want 1", r.blockCalls)
	}
	if !m.applied {
		t.Fatal("Manager not marked applied after success")
	}
}

func TestBlockIPv6_DoubleCallFails(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.BlockIPv6(); err != nil {
		t.Fatalf("BlockIPv6: %v", err)
	}
	if err := m.BlockIPv6(); err == nil {
		t.Fatal("expected second BlockIPv6 to fail")
	}
	if r.blockCalls != 1 {
		t.Fatalf("runner BlockIPv6 calls = %d, want 1 (second must be rejected before the runner)", r.blockCalls)
	}
}

func TestBlockIPv6_PropagatesRunnerError(t *testing.T) {
	r := &mockRunner{blockErr: errors.New("boom")}
	m := newWithRunner(discard(), r)
	if err := m.BlockIPv6(); err == nil {
		t.Fatal("expected error")
	}
	// A failed BlockIPv6 must NOT mark the Manager applied — otherwise
	// Remove would call Restore on a block that was never installed.
	if m.applied {
		t.Fatal("Manager marked applied despite runner error")
	}
}

func TestRemove_CallsRestoreOnce(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.BlockIPv6(); err != nil {
		t.Fatalf("BlockIPv6: %v", err)
	}
	m.Remove()
	if r.restoreCalls != 1 {
		t.Fatalf("Restore calls = %d, want 1", r.restoreCalls)
	}
	// Second Remove must be a no-op (applied flag cleared).
	m.Remove()
	if r.restoreCalls != 1 {
		t.Fatalf("Restore calls = %d, want 1 (second Remove must be a no-op)", r.restoreCalls)
	}
}

func TestRemove_BeforeBlockIsNoOp(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	m.Remove()
	if r.restoreCalls != 0 {
		t.Fatalf("Restore called %d times, want 0", r.restoreCalls)
	}
}

func TestRemove_FailedRestoreKeepsApplied(t *testing.T) {
	// If Restore fails, applied stays true rather than being cleared. In
	// the current client lifecycle the Manager is abandoned after Run()
	// exits, so nothing retries — but a later explicit Remove() would try
	// again instead of treating a failed restore as done.
	r := &mockRunner{restoreErr: errors.New("nope")}
	m := newWithRunner(discard(), r)
	if err := m.BlockIPv6(); err != nil {
		t.Fatalf("BlockIPv6: %v", err)
	}
	m.Remove()
	if !m.applied {
		t.Fatal("Manager cleared applied flag despite Restore failure")
	}
}
