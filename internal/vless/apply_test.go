package vless

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stubUnitState replaces the systemd query for the duration of a test.
func stubUnitState(t *testing.T, states ...string) *int {
	t.Helper()
	prev := unitState
	calls := 0
	unitState = func(context.Context, string) (string, error) {
		s := states[min(calls, len(states)-1)]
		calls++
		if s == "error" {
			return "", errors.New("systemctl not available")
		}
		return s, nil
	}
	t.Cleanup(func() { unitState = prev })
	return &calls
}

func TestWaitAppliedActive(t *testing.T) {
	stubUnitState(t, "active")
	if err := WaitApplied(context.Background(), "vpn-xray"); err != nil {
		t.Fatalf("WaitApplied: %v", err)
	}
}

// A restart takes a moment: the unit is "activating" before it is "active", and
// that must not be mistaken for a failure.
func TestWaitAppliedWaitsThroughRestart(t *testing.T) {
	prevPoll := applyPoll
	applyPoll = time.Millisecond
	t.Cleanup(func() { applyPoll = prevPoll })

	calls := stubUnitState(t, "deactivating", "activating", "active")
	if err := WaitApplied(context.Background(), "vpn-xray"); err != nil {
		t.Fatalf("WaitApplied: %v", err)
	}
	if *calls < 3 {
		t.Errorf("gave up after %d polls", *calls)
	}
}

// A failed restart means someone is holding a link that does nothing. It must
// be reported immediately, not waited out.
func TestWaitAppliedFailedIsImmediate(t *testing.T) {
	prevTimeout := applyTimeout
	applyTimeout = 10 * time.Second
	t.Cleanup(func() { applyTimeout = prevTimeout })

	start := time.Now()
	stubUnitState(t, "failed")
	err := WaitApplied(context.Background(), "vpn-xray")
	if err == nil {
		t.Fatal("WaitApplied accepted a failed unit")
	}
	if !strings.Contains(err.Error(), "failed to restart") {
		t.Errorf("error does not name the problem: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("waited instead of reporting a failed unit right away")
	}
}

func TestWaitAppliedTimesOut(t *testing.T) {
	prevTimeout, prevPoll := applyTimeout, applyPoll
	applyTimeout, applyPoll = 20*time.Millisecond, time.Millisecond
	t.Cleanup(func() { applyTimeout, applyPoll = prevTimeout, prevPoll })

	stubUnitState(t, "activating")
	err := WaitApplied(context.Background(), "vpn-xray")
	if err == nil {
		t.Fatal("WaitApplied returned success for a unit that never came back")
	}
	if !strings.Contains(err.Error(), "activating") {
		t.Errorf("error does not carry the last known state: %v", err)
	}
}

// An unreachable systemd (no systemd at all, or a sandbox that blocks the
// query) must not be reported as success: the caller would tell a user their
// access is live when nothing was verified.
func TestWaitAppliedQueryFailure(t *testing.T) {
	prevTimeout, prevPoll := applyTimeout, applyPoll
	applyTimeout, applyPoll = 20*time.Millisecond, time.Millisecond
	t.Cleanup(func() { applyTimeout, applyPoll = prevTimeout, prevPoll })

	stubUnitState(t, "error")
	if err := WaitApplied(context.Background(), "vpn-xray"); err == nil {
		t.Fatal("WaitApplied reported success without being able to check")
	}
}
