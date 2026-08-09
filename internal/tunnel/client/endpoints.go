package client

import (
	"fmt"
	"net"
	"sync"
)

// Endpoint selection.
//
// A profile can carry several addresses for the SAME node — the node moved, or
// it answers on a second name. The credentials are identical for all of them,
// so a client that cannot reach one should simply try the next instead of
// showing the user an error they cannot act on.
//
// Two rules keep this from becoming a mess:
//
//   - Only a CONNECTION failure moves on. A server that rejected our
//     certificate would reject it at every address; walking the list would turn
//     one clear "your profile is not valid" into N confusing timeouts. That
//     split already exists in the retryable/fatal classification, and this code
//     rides on it rather than inventing a second one.
//   - Backoff counts CYCLES, not attempts. With three addresses, waiting the
//     full backoff between each would turn a 1-second retry into 3 seconds of
//     dead air; the wait belongs after the whole list has been tried.

// Endpoint is one address of the node, with the name its certificate is
// verified against.
type Endpoint struct {
	Server     string // "vpn.example.com:8443"
	ServerName string // SNI / verification host; defaults to Server's host
	Label      string // free text for display ("backup"); no protocol meaning
}

func (e Endpoint) String() string {
	if e.Label != "" {
		return fmt.Sprintf("%s (%s)", e.Server, e.Label)
	}
	return e.Server
}

// normalizeEndpoints builds the list a client will walk, from either the
// endpoint list or the single-server fields, and fills in any missing SNI.
func normalizeEndpoints(eps []Endpoint, server, serverName string) ([]Endpoint, error) {
	if len(eps) == 0 {
		if server == "" {
			return nil, fmt.Errorf("client: empty Server")
		}
		eps = []Endpoint{{Server: server, ServerName: serverName}}
	}
	out := make([]Endpoint, 0, len(eps))
	for _, ep := range eps {
		if ep.Server == "" {
			return nil, fmt.Errorf("client: endpoint with empty address")
		}
		if ep.ServerName == "" {
			host, _, err := net.SplitHostPort(ep.Server)
			if err != nil || host == "" {
				return nil, fmt.Errorf("client: cannot derive ServerName from %q: %w", ep.Server, err)
			}
			ep.ServerName = host
		}
		out = append(out, ep)
	}
	return out, nil
}

// endpointRing walks the endpoint list, remembering which one last worked.
type endpointRing struct {
	mu  sync.Mutex
	eps []Endpoint
	idx int
	// tried counts how many endpoints have been attempted since the last
	// success. It is what tells the reconnect loop when a full cycle is done
	// and the backoff wait has been earned.
	tried int
}

func newEndpointRing(eps []Endpoint, preferred string) *endpointRing {
	r := &endpointRing{eps: eps}
	// Start from the endpoint that worked last time, if it is still in the
	// profile. On a laptop that wakes up where it went to sleep, this is the
	// difference between connecting immediately and timing out on a dead
	// address first.
	for i, ep := range eps {
		if preferred != "" && ep.Server == preferred {
			r.idx = i
			break
		}
	}
	return r
}

// current returns the endpoint to dial now.
func (r *endpointRing) current() Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.eps[r.idx]
}

// advance moves to the next endpoint and reports whether the whole list has
// now been tried since the last success — the point at which waiting is the
// right thing to do rather than hammering the same addresses.
func (r *endpointRing) advance() (cycled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.eps) > 1 {
		r.idx = (r.idx + 1) % len(r.eps)
	}
	r.tried++
	if r.tried >= len(r.eps) {
		r.tried = 0
		return true
	}
	return false
}

// succeeded records that the current endpoint produced a working session, so
// the next reconnect starts here rather than at the top of the list.
func (r *endpointRing) succeeded() Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tried = 0
	return r.eps[r.idx]
}

// all returns a copy of the list, for display.
func (r *endpointRing) all() []Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Endpoint(nil), r.eps...)
}
