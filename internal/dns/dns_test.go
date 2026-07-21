package dns

import (
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
)

type applyCall struct {
	servers []string
	iface   string
}

type mockRunner struct {
	applyCalls   []applyCall
	restoreCalls int
	applyErr     error
	restoreErr   error
}

func (m *mockRunner) Apply(servers []string, iface string) error {
	m.applyCalls = append(m.applyCalls, applyCall{
		servers: append([]string(nil), servers...),
		iface:   iface,
	})
	return m.applyErr
}

func (m *mockRunner) Restore() error {
	m.restoreCalls++
	return m.restoreErr
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestApply_HappyPath(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply([]string{"1.1.1.1", "9.9.9.9"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []applyCall{{servers: []string{"1.1.1.1", "9.9.9.9"}, iface: "utun4"}}
	if !reflect.DeepEqual(r.applyCalls, want) {
		t.Fatalf("got %+v, want %+v", r.applyCalls, want)
	}
}

func TestApply_EmptyServersIsNoOp(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil): %v", err)
	}
	if len(r.applyCalls) != 0 {
		t.Fatalf("expected no Apply call, got %+v", r.applyCalls)
	}
}

func TestApply_DoubleCallFails(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply([]string{"1.1.1.1"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Apply([]string{"8.8.8.8"}); err == nil {
		t.Fatal("expected second Apply to fail")
	}
}

func TestApply_PropagatesRunnerError(t *testing.T) {
	r := &mockRunner{applyErr: errors.New("boom")}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply([]string{"1.1.1.1"}); err == nil {
		t.Fatal("expected error")
	}
	// Failed Apply must NOT mark Manager as applied — otherwise Remove
	// would call Restore on a snapshot that was never taken.
	if m.applied {
		t.Fatal("Manager marked applied despite runner error")
	}
}

func TestRemove_CallsRestoreOnce(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	_ = m.Apply([]string{"1.1.1.1"})
	m.Remove()
	if r.restoreCalls != 1 {
		t.Fatalf("Restore calls = %d, want 1", r.restoreCalls)
	}
	// Second Remove should be a no-op (applied flag cleared).
	m.Remove()
	if r.restoreCalls != 1 {
		t.Fatalf("Restore calls = %d, want 1 (second Remove must be a no-op)", r.restoreCalls)
	}
}

func TestRemove_BeforeApplyIsNoOp(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	m.Remove()
	if r.restoreCalls != 0 {
		t.Fatalf("Restore called %d times, want 0", r.restoreCalls)
	}
}

// Apply must filter the semi-trusted pushed list down to bare IPs before any
// platform runner sees it — the fix for macOS/Windows handing raw tokens to
// networksetup/netsh. Cross-platform because it goes through Manager, not a
// per-OS runner.
func TestApply_FiltersInvalidBeforeRunner(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply([]string{
		"1.1.1.1",
		"1.1.1.1\nsearch attacker.com", // newline injection → dropped
		"empty",                        // literal that clears DNS on macOS → dropped
		"  9.9.9.9  ",                  // trimmed → kept
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []applyCall{{servers: []string{"1.1.1.1", "9.9.9.9"}, iface: "utun4"}}
	if !reflect.DeepEqual(r.applyCalls, want) {
		t.Fatalf("runner saw %+v, want only valid IPs %+v", r.applyCalls, want)
	}
}

// A push with entries but no valid IP is an error, and the runner is never
// called — better a failed connect than clearing/garbaging the resolver.
func TestApply_AllInvalidReturnsErrorAndSkipsRunner(t *testing.T) {
	r := &mockRunner{}
	m := newWithRunner(discard(), "utun4", r)
	if err := m.Apply([]string{"not-an-ip", "empty"}); err == nil {
		t.Fatal("expected error for a push with no valid addresses")
	}
	if len(r.applyCalls) != 0 {
		t.Fatalf("runner was called with invalid input: %+v", r.applyCalls)
	}
	if m.applied {
		t.Fatal("Manager marked applied despite no valid servers")
	}
}
