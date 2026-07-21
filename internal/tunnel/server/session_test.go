package server

import (
	"net"
	"testing"
	"time"
)

// recordingConn records the deadline and Close calls close() makes. Only the
// methods close()/newSession touch are implemented; the embedded nil net.Conn
// satisfies the rest of the interface at compile time.
type recordingConn struct {
	net.Conn
	deadlineSet time.Time
	closed      bool
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	c.deadlineSet = t
	return nil
}

func (c *recordingConn) Close() error {
	c.closed = true
	return nil
}

func (c *recordingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 12345}
}

// close must force a past deadline BEFORE Close so a sessionWriter wedged in an
// in-flight Write (dead network, full TCP buffer, no RST) unblocks at once —
// otherwise a same-CN reconnect waiting on Done() hangs for minutes (#138).
func TestSessionClose_ForcesDeadlineBeforeClosing(t *testing.T) {
	c := &recordingConn{}
	s := newSession("alice", net.IPv4(10, 8, 0, 2), c)

	s.close()
	after := time.Now()

	if c.deadlineSet.IsZero() {
		t.Fatal("close did not set a deadline on the conn")
	}
	if c.deadlineSet.After(after) {
		t.Errorf("close set a FUTURE deadline (%v); want past/now to unblock in-flight I/O", c.deadlineSet)
	}
	if !c.closed {
		t.Error("close did not close the conn")
	}
}
