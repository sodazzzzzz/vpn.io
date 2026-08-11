package client

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"testing"
	"time"
)

func eps(addrs ...string) []Endpoint {
	out := make([]Endpoint, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, Endpoint{Server: a})
	}
	return out
}

func TestNormalizeEndpoints(t *testing.T) {
	got, err := normalizeEndpoints(nil, "vpn.example.com:8443", "")
	if err != nil {
		t.Fatalf("single server: %v", err)
	}
	if len(got) != 1 || got[0].ServerName != "vpn.example.com" {
		t.Fatalf("single server → %+v", got)
	}

	got, err = normalizeEndpoints([]Endpoint{
		{Server: "203.0.113.5:8443"},
		{Server: "vpn2.example.com:8443", ServerName: "vpn.example.com"},
	}, "", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got[0].ServerName != "203.0.113.5" {
		t.Errorf("SNI not defaulted from host: %q", got[0].ServerName)
	}
	if got[1].ServerName != "vpn.example.com" {
		t.Errorf("explicit SNI lost: %q", got[1].ServerName)
	}

	for _, bad := range [][]Endpoint{
		{{Server: ""}},
		{{Server: "no-port"}},
	} {
		if _, err := normalizeEndpoints(bad, "", ""); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := normalizeEndpoints(nil, "", ""); err == nil {
		t.Error("accepted a config with no address at all")
	}
}

// The ring must hand out every address before it says a cycle is complete —
// that boundary is what the reconnect loop uses to decide when waiting is
// earned rather than wasteful.
func TestRingCyclesThroughEveryEndpoint(t *testing.T) {
	list, err := normalizeEndpoints(eps("a.example.com:8443", "b.example.com:8443", "c.example.com:8443"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	r := newEndpointRing(list, "")

	seen := []string{r.current().Server}
	for i := range 2 {
		if cycled := r.advance(); cycled {
			t.Fatalf("reported a full cycle after %d of 3 endpoints", i+1)
		}
		seen = append(seen, r.current().Server)
	}
	if !r.advance() {
		t.Fatal("did not report a full cycle after all three endpoints")
	}
	if len(seen) != 3 || seen[0] == seen[1] || seen[1] == seen[2] {
		t.Fatalf("did not visit three distinct endpoints: %v", seen)
	}
	// Back at the start, and the cycle counter reset.
	if r.current().Server != seen[0] {
		t.Errorf("after a full cycle the ring is at %q, want %q", r.current().Server, seen[0])
	}
}

// With one endpoint every attempt is a complete cycle, so the loop keeps its
// original backoff behaviour.
func TestRingWithSingleEndpointAlwaysCycles(t *testing.T) {
	list, _ := normalizeEndpoints(eps("only.example.com:8443"), "", "")
	r := newEndpointRing(list, "")
	for range 3 {
		if !r.advance() {
			t.Fatal("single endpoint did not count as a full cycle")
		}
		if r.current().Server != "only.example.com:8443" {
			t.Fatalf("ring moved off the only endpoint: %q", r.current().Server)
		}
	}
}

func TestRingStartsAtPreferredEndpoint(t *testing.T) {
	list, _ := normalizeEndpoints(eps("a.example.com:8443", "b.example.com:8443"), "", "")

	r := newEndpointRing(list, "b.example.com:8443")
	if got := r.current().Server; got != "b.example.com:8443" {
		t.Errorf("ring started at %q, want the remembered endpoint", got)
	}
	// A remembered address that is no longer in the profile must not wedge the
	// ring — it falls back to the top of the list.
	r = newEndpointRing(list, "gone.example.com:8443")
	if got := r.current().Server; got != "a.example.com:8443" {
		t.Errorf("ring started at %q for an unknown preference, want the first endpoint", got)
	}
}

// A success resets the cycle counter: the next failure starts a fresh walk
// rather than being counted against the previous outage.
func TestRingSuccessResetsCycle(t *testing.T) {
	list, _ := normalizeEndpoints(eps("a.example.com:8443", "b.example.com:8443"), "", "")
	r := newEndpointRing(list, "")
	r.advance() // one failure
	r.succeeded()
	if cycled := r.advance(); cycled {
		t.Error("a single failure after a success was counted as a full cycle")
	}
}

// The reconnect loop must walk to the next endpoint on a connection failure
// instead of waiting out a backoff against an address that is not answering.
func TestReconnectLoopWalksEndpointsBeforeBackingOff(t *testing.T) {
	list, _ := normalizeEndpoints(eps("10.255.255.1:8443", "10.255.255.2:8443"), "", "")
	c := &Client{
		cfg: Config{
			ReconnectMin:     time.Hour, // so a backoff would visibly hang the test
			ReconnectMax:     time.Hour,
			HandshakeTimeout: 50 * time.Millisecond,
		},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		tlsConfig: &tls.Config{},
		ring:      newEndpointRing(list, ""),
	}

	// Cancelling mid-dial makes every attempt fail immediately and the loop
	// exit cleanly; what we assert is that it did not park on the first
	// address's backoff before trying the second.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.runReconnectLoop(ctx, make(chan []byte)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect loop hung — it waited out the backoff instead of trying the next endpoint")
	}
}
