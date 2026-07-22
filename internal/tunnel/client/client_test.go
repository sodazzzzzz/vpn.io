package client

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/govpn/internal/tunnel"
)

// After a reconnect where the server assigns a DIFFERENT IP (our lease expired
// and the address was reassigned), the TUN still carries the old address and
// the tunnel is dead. ensureConfigured must return an error so the loop reports
// fatal — not silently keep going and let the caller emit StateConnected on a
// tunnel that carries nothing (#127).
func TestEnsureConfigured_ReassignedIPFailsInsteadOfConnected(t *testing.T) {
	c := &Client{configuredIP: "10.8.0.5", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := c.ensureConfigured(tunnel.AssignIP{IP: "10.8.0.9"}); err == nil {
		t.Fatal("ensureConfigured returned nil for a reassigned IP; want an error so the state is fatal, not Connected")
	}
}

// A reconnect that keeps the same IP is a no-op: no error, no re-Configure.
func TestEnsureConfigured_SameIPIsNoOp(t *testing.T) {
	c := &Client{configuredIP: "10.8.0.5", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := c.ensureConfigured(tunnel.AssignIP{IP: "10.8.0.5"}); err != nil {
		t.Fatalf("ensureConfigured with unchanged IP: %v", err)
	}
}

// Only a smaller, positive pushed MTU narrows the interface; equal, larger, or
// absent leaves the device's own MTU (#146). Widening is refused — read buffers
// are sized for the device's open MTU.
func TestEffectiveMTU_NarrowsButDoesNotWiden(t *testing.T) {
	const dev = 1380
	cases := []struct {
		pushed, want int
	}{
		{0, dev},
		{1200, 1200},
		{1380, dev},
		{1500, dev},
		{-1, dev},
	}
	for _, tc := range cases {
		if got := effectiveMTU(dev, tc.pushed); got != tc.want {
			t.Errorf("effectiveMTU(%d, %d) = %d, want %d", dev, tc.pushed, got, tc.want)
		}
	}
}

// The read-idle deadline follows the SERVER's advertised keepalive, not the
// client's own send interval — so a slow server pulse can't trip the deadline on
// a healthy connection (#179). It falls back to the client interval only when
// the server advertises none (older server), and disables when neither has one.
func TestReadIdleTimeout_FollowsServerKeepalive(t *testing.T) {
	const sec = time.Second
	cases := []struct {
		name         string
		clientKA     time.Duration
		serverKASecs int
		want         time.Duration
	}{
		{"server pulse drives it, not client", 1 * sec, 30, 90 * sec},
		{"fast client interval is ignored", 100 * time.Millisecond, 30, 90 * sec},
		{"old server (no advert) → client fallback", 5 * sec, 0, 15 * sec},
		{"neither runs keepalives → disabled", 0, 0, 0},
	}
	for _, tc := range cases {
		c := &Client{cfg: Config{Keepalive: tc.clientKA}}
		got := c.readIdleTimeout(tunnel.AssignIP{KeepaliveSecs: tc.serverKASecs})
		if got != tc.want {
			t.Errorf("%s: readIdleTimeout = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An IP-literal Server resolves to exactly that IP with no DNS lookup — so we
// pin the address we're about to dial (#126).
func TestResolveServer_IPLiteralNeedsNoDNS(t *testing.T) {
	c := &Client{cfg: Config{Server: "203.0.113.5:8443"}}
	ip, port, err := c.resolveServer(context.Background())
	if err != nil {
		t.Fatalf("resolveServer: %v", err)
	}
	if ip.String() != "203.0.113.5" || port != "8443" {
		t.Fatalf("got %s:%s, want 203.0.113.5:8443", ip, port)
	}
}

// An address with no port is rejected before any lookup.
func TestResolveServer_BadAddressErrors(t *testing.T) {
	c := &Client{cfg: Config{Server: "missing-port"}}
	if _, _, err := c.resolveServer(context.Background()); err == nil {
		t.Fatal("want an error for an address without a port")
	}
}
