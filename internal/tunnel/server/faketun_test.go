package server

import (
	"io"
	"sync"

	"github.com/govpn/internal/tun"
)

// fakeTUN is an in-memory tun.Device used for integration tests.
//
// inbox holds packets staged by the test (which the server will receive
// via Read, as if they had arrived on the wire-side network). outbox
// holds packets the server has written to the TUN device (which the test
// inspects to verify routing/anti-spoof/isolation).
type fakeTUN struct {
	name   string
	mtu    int
	inbox  chan []byte
	outbox chan []byte

	mu     sync.Mutex
	closed bool
}

var _ tun.Device = (*fakeTUN)(nil)

func newFakeTUN(name string, mtu, buf int) *fakeTUN {
	return &fakeTUN{
		name:   name,
		mtu:    mtu,
		inbox:  make(chan []byte, buf),
		outbox: make(chan []byte, buf),
	}
}

func (f *fakeTUN) Read(p []byte) (int, error) {
	pkt, ok := <-f.inbox
	if !ok {
		return 0, io.EOF
	}
	return copy(p, pkt), nil
}

func (f *fakeTUN) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	out := f.outbox
	f.mu.Unlock()
	out <- cp
	return len(p), nil
}

func (f *fakeTUN) Name() string { return f.name }
func (f *fakeTUN) MTU() int     { return f.mtu }

func (f *fakeTUN) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	close(f.inbox)
	f.mu.Unlock()
	return nil
}

// inject stages a packet for the server to Read from TUN.
func (f *fakeTUN) inject(pkt []byte) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	f.inbox <- cp
}
