package client

import (
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/govpn/internal/tunnel"
)

// A peer that stops reading eventually fills the send buffer, and an unbounded
// Write parks there forever holding the writer's lock — so the keepalive can't
// run either, nothing ever errors, and the session never ends.
func TestConnWriter_AppliesWriteDeadline(t *testing.T) {
	fc := &deadlineConn{}
	w := newConnWriter(fc, 25*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- w.Control(tunnel.NewKeepalive()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("write to a peer that never drains returned nil, want a timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write never returned — no write deadline was applied")
	}
	if !fc.deadlineSet() {
		t.Error("connWriter did not set a write deadline")
	}
}

// Without a timeout the writer must not touch deadlines at all, so an embedder
// that manages them itself is unaffected.
func TestConnWriter_NoDeadlineWhenDisabled(t *testing.T) {
	fc := &deadlineConn{}
	w := newConnWriter(fc, 0)
	go func() { _ = w.Control(tunnel.NewKeepalive()) }()

	time.Sleep(50 * time.Millisecond)
	if fc.deadlineSet() {
		t.Error("connWriter set a write deadline despite timeout being 0")
	}
}

// deadlineConn is a net.Conn whose Write blocks until the write deadline
// passes, the way a real socket with a full send buffer does. With no deadline
// set it parks forever — exactly the behaviour being fixed.
type deadlineConn struct {
	net.Conn
	mu     sync.Mutex
	dl     time.Time
	wasSet bool
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dl = t
	c.wasSet = true
	return nil
}

func (c *deadlineConn) deadlineSet() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wasSet
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	d := c.dl
	c.mu.Unlock()
	if d.IsZero() {
		select {} // no deadline: park forever
	}
	time.Sleep(time.Until(d))
	return 0, os.ErrDeadlineExceeded
}
