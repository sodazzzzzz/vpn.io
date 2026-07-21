package client

import (
	"io"
	"log/slog"
	"testing"

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
