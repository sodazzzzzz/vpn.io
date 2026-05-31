package server

import (
	"net"
	"sync"
	"time"
)

// sessionWriteBufferDepth is how many outbound packets a session may queue
// before the router starts dropping. Tunes head-of-line tolerance — too
// large and a slow client gnaws at memory, too small and bursts get
// clipped. 64 ≈ ~90 KiB at MTU 1380, fine for a learning VPN.
const sessionWriteBufferDepth = 64

// Session is one live VPN client.
//
// outbound carries packets queued for delivery; the per-session writer
// goroutine drains it and serializes writes to the TLS connection (a TLS
// conn is not safe for concurrent Writes — interleaved bytes corrupt our
// length-prefix framing).
type Session struct {
	CN       string
	IP       net.IP
	Conn     net.Conn
	Remote   net.Addr  // client's real source address, for audit logging
	Start    time.Time // set at connect (handleConn) — basis for session duration
	outbound chan []byte
	closeCh  chan struct{}
	doneCh   chan struct{} // closed when the session's handler has fully torn down
	closeOne sync.Once
}

func newSession(cn string, ip net.IP, conn net.Conn) *Session {
	return &Session{
		CN:     cn,
		IP:     ip,
		Conn:   conn,
		Remote: conn.RemoteAddr(),
		// Start is set at connect in handleConn (after AssignIP is sent), so
		// session duration reflects tunnel uptime, not admission overhead.
		outbound: make(chan []byte, sessionWriteBufferDepth),
		closeCh:  make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Done returns a channel closed when this session has been fully torn down
// (registry entry removed, IP released, goroutines exited). Used to make
// reconnects from the same CN synchronous: kick the old, wait, then admit.
func (s *Session) Done() <-chan struct{} { return s.doneCh }

// enqueue tries to put pkt in the outbound queue without blocking.
// Returns false if the queue is full (caller logs + drops the packet).
func (s *Session) enqueue(pkt []byte) bool {
	select {
	case s.outbound <- pkt:
		return true
	default:
		return false
	}
}

// close signals the session goroutines to exit. Safe to call multiple times.
func (s *Session) close() {
	s.closeOne.Do(func() {
		close(s.closeCh)
		// Close the connection too so blocked Reads on it return.
		_ = s.Conn.Close()
	})
}

// Registry is a thread-safe set of active sessions, indexed by both CN
// (for kicking previous sessions on reconnect) and IP (for routing
// incoming TUN packets to the right tunnel).
type Registry struct {
	mu     sync.RWMutex
	byCN   map[string]*Session
	byIPv4 map[uint32]*Session
}

func NewRegistry() *Registry {
	return &Registry{
		byCN:   make(map[string]*Session),
		byIPv4: make(map[uint32]*Session),
	}
}

// Add stores s. The caller must guarantee CN and IP are not already
// present (the server's accept path enforces this via the ipalloc Pool).
func (r *Registry) Add(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byCN[s.CN] = s
	r.byIPv4[ipv4ToUint32(s.IP)] = s
}

// Remove drops s from both indexes if it is still the registered session
// for its CN. The "still the same session" check protects against a race
// where a reconnect has already replaced the entry under the same CN.
func (r *Registry) Remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.byCN[s.CN]; ok && current == s {
		delete(r.byCN, s.CN)
		delete(r.byIPv4, ipv4ToUint32(s.IP))
	}
}

// ByCN returns the session bound to cn, or nil.
func (r *Registry) ByCN(cn string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byCN[cn]
}

// ByIPv4 returns the session whose assigned IP equals ip, or nil.
func (r *Registry) ByIPv4(ip net.IP) *Session {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIPv4[ipv4ToUint32(v4)]
}

// Snapshot returns every active session. Used at shutdown for graceful
// close without holding the registry lock while networking happens.
func (r *Registry) Snapshot() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.byCN))
	for _, s := range r.byCN {
		out = append(out, s)
	}
	return out
}

func ipv4ToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
