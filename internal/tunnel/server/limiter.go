package server

import (
	"net"
	"sync"
	"time"
)

// connLimiter bounds how many connections the server keeps in flight, both
// per source IP and in total, to blunt connection-flood / slow-handshake DoS.
//
// A slot is held for the whole lifetime of a connection (handshake + session),
// so the per-IP cap doubles as a cap on concurrent handshakes from one IP.
// Combined with the handshake deadline in handleConn, a single IP can tie up
// at most maxPerIP handshakes for at most one deadline each.
//
// On a failed handshake the per-IP slot is freed only after failPenalty rather
// than immediately. That throttles fast fail-and-retry churn: an attacker who
// keeps tripping the handshake fills their per-IP quota and is then capped at
// roughly maxPerIP/failPenalty new attempts per second, without us tracking any
// unbounded per-IP history — the perIP map never exceeds maxTotal entries.
type connLimiter struct {
	maxPerIP    int           // 0 = no per-IP cap
	maxTotal    int           // 0 = no global cap
	failPenalty time.Duration // delay before freeing a per-IP slot after a failed handshake

	mu    sync.Mutex
	total int
	perIP map[string]int
}

func newConnLimiter(maxPerIP, maxTotal int, failPenalty time.Duration) *connLimiter {
	return &connLimiter{
		maxPerIP:    maxPerIP,
		maxTotal:    maxTotal,
		failPenalty: failPenalty,
		perIP:       make(map[string]int),
	}
}

// host extracts the bare IP from a RemoteAddr, falling back to the raw string
// for addresses without a port (so the limiter still groups them consistently).
func host(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		return h
	}
	return addr.String()
}

// acquire reserves a slot for ip. It returns a release func and true on
// success, or nil and false when a limit is hit (caller should close the
// connection cheaply, before any handshake). Call release exactly once;
// pass penalize=true when the connection failed its handshake, so the per-IP
// slot is held for the throttle window instead of freed immediately.
func (l *connLimiter) acquire(ip string) (release func(penalize bool), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return nil, false
	}
	if l.maxPerIP > 0 && l.perIP[ip] >= l.maxPerIP {
		return nil, false
	}
	l.total++
	l.perIP[ip]++

	var once sync.Once
	return func(penalize bool) {
		once.Do(func() { l.release(ip, penalize) })
	}, true
}

func (l *connLimiter) release(ip string, penalize bool) {
	dec := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.total--
		if n := l.perIP[ip] - 1; n <= 0 {
			delete(l.perIP, ip)
		} else {
			l.perIP[ip] = n
		}
	}
	// Only delay the release when the throttle can actually bite (see
	// throttleActive): the per-IP cap is what it holds slots against, and the
	// global cap keeps the perIP map bounded (sum of its values == total <=
	// maxTotal). Without both, hold nothing — there is no bound to protect and
	// the map could grow unbounded.
	if penalize && l.throttleActive() {
		time.AfterFunc(l.failPenalty, dec)
	} else {
		dec()
	}
}

// throttleActive reports whether the failed-handshake throttle can actually
// slow a flood. It needs a per-IP cap to hold slots against, a global cap to
// keep the perIP map bounded, and a non-zero penalty window; missing any of
// them, a failed handshake is freed immediately and fast fail-retry churn isn't
// slowed at all. This is the single source of truth for that condition — the
// release delay above and the startup warning in New both consult it, so they
// can't drift apart.
func (l *connLimiter) throttleActive() bool {
	return l.maxPerIP > 0 && l.maxTotal > 0 && l.failPenalty > 0
}
