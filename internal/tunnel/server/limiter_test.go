package server

import (
	"net"
	"testing"
	"time"
)

func TestConnLimiter_PerIPCap(t *testing.T) {
	l := newConnLimiter(2, 0, 0)

	r1, ok := l.acquire("1.2.3.4")
	if !ok {
		t.Fatal("first acquire rejected")
	}
	if _, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("second acquire rejected (cap is 2)")
	}
	if _, ok := l.acquire("1.2.3.4"); ok {
		t.Fatal("third acquire allowed past per-IP cap of 2")
	}
	// A different IP is unaffected.
	if _, ok := l.acquire("5.6.7.8"); !ok {
		t.Fatal("other IP rejected by another IP's cap")
	}
	// Freeing a slot lets the same IP back in.
	r1(false)
	if _, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("acquire rejected after a slot was released")
	}
}

func TestConnLimiter_TotalCap(t *testing.T) {
	l := newConnLimiter(0, 2, 0)

	if _, ok := l.acquire("1.1.1.1"); !ok {
		t.Fatal("first acquire rejected")
	}
	if _, ok := l.acquire("2.2.2.2"); !ok {
		t.Fatal("second acquire rejected (cap is 2)")
	}
	if _, ok := l.acquire("3.3.3.3"); ok {
		t.Fatal("third acquire allowed past global cap of 2")
	}
}

func TestConnLimiter_Unlimited(t *testing.T) {
	l := newConnLimiter(0, 0, time.Second)
	for i := 0; i < 100; i++ {
		if _, ok := l.acquire("1.2.3.4"); !ok {
			t.Fatalf("acquire %d rejected with no caps set", i)
		}
	}
}

func TestConnLimiter_FailedHandshakeThrottle(t *testing.T) {
	const penalty = 60 * time.Millisecond
	l := newConnLimiter(1, 4, penalty)

	r, ok := l.acquire("9.9.9.9")
	if !ok {
		t.Fatal("first acquire rejected")
	}
	// Release as a failed handshake: the per-IP slot must stay held for the
	// penalty window, so a retry from the same IP is throttled.
	r(true)
	if _, ok := l.acquire("9.9.9.9"); ok {
		t.Fatal("acquire allowed during the fail-penalty window")
	}

	// After the penalty elapses the slot frees up. Poll to avoid flakiness.
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := l.acquire("9.9.9.9"); ok {
			return // freed as expected
		}
		if time.Now().After(deadline) {
			t.Fatal("slot never freed after the fail-penalty window")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// With no global cap the penalty is skipped (held state would be unbounded),
// so a failed handshake frees its per-IP slot immediately.
func TestConnLimiter_NoPenaltyWithoutGlobalCap(t *testing.T) {
	l := newConnLimiter(1, 0, 50*time.Millisecond)
	r, ok := l.acquire("9.9.9.9")
	if !ok {
		t.Fatal("first acquire rejected")
	}
	r(true)
	if _, ok := l.acquire("9.9.9.9"); !ok {
		t.Fatal("slot not freed immediately when no global cap is set")
	}
}

func TestConnLimiter_ReleaseIdempotent(t *testing.T) {
	l := newConnLimiter(1, 1, 0)
	r, _ := l.acquire("1.2.3.4")
	r(false)
	r(false) // must not double-decrement
	// total should be 0 now; two fresh acquires (per-IP cap 1) prove the
	// counters were not driven negative by the double release.
	if _, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("acquire rejected after release")
	}
	if _, ok := l.acquire("1.2.3.4"); ok {
		t.Fatal("double release corrupted the counter (cap of 1 exceeded)")
	}
}

func TestHost(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5555}, "1.2.3.4"},
		{&net.TCPAddr{IP: net.ParseIP("::1"), Port: 80}, "::1"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := host(c.addr); got != c.want {
			t.Errorf("host(%v) = %q, want %q", c.addr, got, c.want)
		}
	}
}
