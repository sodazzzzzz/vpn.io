package firewall

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

type mockRunner struct {
	enableCalls  int
	restoreCalls int
	clearCalls   int
	lastCfg      Config
	enableErr    error
	restoreErr   error
}

func (m *mockRunner) Enable(cfg Config) error {
	m.enableCalls++
	m.lastCfg = cfg
	return m.enableErr
}

func (m *mockRunner) Restore() error {
	m.restoreCalls++
	return m.restoreErr
}

func (m *mockRunner) Clear() error {
	m.clearCalls++
	return nil
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestEnable_HappyPath(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.Enable(Config{TunIface: "tun0"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if r.enableCalls != 1 {
		t.Fatalf("Enable calls = %d, want 1", r.enableCalls)
	}
	if r.lastCfg.TunIface != "tun0" {
		t.Fatalf("runner got cfg %+v, want TunIface tun0", r.lastCfg)
	}
	if !m.applied {
		t.Fatal("Manager not marked applied after success")
	}
}

func TestEnable_DoubleCallFails(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.Enable(Config{}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := m.Enable(Config{}); err == nil {
		t.Fatal("expected second Enable to fail")
	}
	if r.enableCalls != 1 {
		t.Fatalf("runner Enable calls = %d, want 1 (second must be rejected before the runner)", r.enableCalls)
	}
}

func TestEnable_PropagatesRunnerError(t *testing.T) {
	r := &mockRunner{enableErr: errors.New("boom")}
	m := newWithRunner(discard(), r)
	if err := m.Enable(Config{}); err == nil {
		t.Fatal("expected error")
	}
	// A failed Enable must NOT mark the Manager applied — otherwise Remove
	// would call Restore on protection that was never installed.
	if m.applied {
		t.Fatal("Manager marked applied despite runner error")
	}
}

func TestRemove_CallsRestoreOnce(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), r)
	if err := m.Enable(Config{}); err != nil {
		t.Fatalf("Enable: %v", err)
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

func TestRemove_BeforeEnableIsNoOp(t *testing.T) {
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
	if err := m.Enable(Config{}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	m.Remove()
	if !m.applied {
		t.Fatal("Manager cleared applied flag despite Restore failure")
	}
}
