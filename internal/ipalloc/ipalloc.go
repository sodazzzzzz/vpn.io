// Package ipalloc hands out IPv4 addresses from a configured subnet to
// VPN clients, identified by a stable client ID (e.g. the certificate CN).
//
// The pool is in-memory: state lives only as long as the server process.
// A restart frees every assignment, which is fine for our model — clients
// reconnect and re-acquire an address.
package ipalloc

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrPoolExhausted is returned by Allocate when no addresses are free.
var ErrPoolExhausted = errors.New("ipalloc: pool exhausted")

// ErrAlreadyAllocated is returned by Allocate when clientID already holds
// an address. The caller must Release the previous assignment first —
// this prevents two concurrent sessions for the same identity from
// colliding on a single tunnel IP.
var ErrAlreadyAllocated = errors.New("ipalloc: client already has an address")

// Pool is a thread-safe IPv4 address allocator over a single CIDR block.
//
// The zero value is not usable; construct with [New].
type Pool struct {
	mu       sync.Mutex
	addrs    []uint32 // candidate addresses in stable iteration order
	free     map[uint32]struct{}
	byClient map[string]uint32
	ipToCN   map[uint32]string
}

// New builds a Pool that allocates from the given IPv4 CIDR (e.g.
// "10.8.0.0/24"). The network address, broadcast address and any IPs
// listed in reserve are excluded from the pool.
func New(cidr string, reserve ...net.IP) (*Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ipalloc: parse cidr %q: %w", cidr, err)
	}
	v4 := network.IP.To4()
	if v4 == nil {
		return nil, fmt.Errorf("ipalloc: cidr %q is not IPv4", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("ipalloc: cidr %q is not IPv4", cidr)
	}
	if ones >= 31 {
		// /31 and /32 have no host range under classical rules, and our
		// callers always want at least a gateway + a few clients.
		return nil, fmt.Errorf("ipalloc: cidr %q has no usable host addresses", cidr)
	}

	base := ipToUint32(v4)
	size := uint32(1) << (32 - ones)
	broadcast := base + size - 1

	reserved := make(map[uint32]struct{}, len(reserve)+2)
	reserved[base] = struct{}{}      // network address
	reserved[broadcast] = struct{}{} // broadcast address
	for _, r := range reserve {
		r4 := r.To4()
		if r4 == nil {
			return nil, fmt.Errorf("ipalloc: reserved address %v is not IPv4", r)
		}
		u := ipToUint32(r4)
		if u < base || u > broadcast {
			return nil, fmt.Errorf("ipalloc: reserved %v outside %s", r, cidr)
		}
		reserved[u] = struct{}{}
	}

	p := &Pool{
		addrs:    make([]uint32, 0, size-2),
		free:     make(map[uint32]struct{}, size-2),
		byClient: make(map[string]uint32),
		ipToCN:   make(map[uint32]string),
	}
	for u := base + 1; u < broadcast; u++ {
		if _, skip := reserved[u]; skip {
			continue
		}
		p.addrs = append(p.addrs, u)
		p.free[u] = struct{}{}
	}
	if len(p.addrs) == 0 {
		return nil, fmt.Errorf("ipalloc: no addresses left after reservations")
	}
	return p, nil
}

// Allocate reserves the next free address for clientID and returns it.
//
// Allocation order is deterministic: the lowest unused address (by
// numeric value) is returned first. This makes logs readable and tests
// repeatable. Returns ErrAlreadyAllocated if clientID is currently
// holding an address.
func (p *Pool) Allocate(clientID string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, held := p.byClient[clientID]; held {
		return nil, ErrAlreadyAllocated
	}
	for _, candidate := range p.addrs {
		if _, isFree := p.free[candidate]; !isFree {
			continue
		}
		delete(p.free, candidate)
		p.byClient[clientID] = candidate
		p.ipToCN[candidate] = clientID
		return uint32ToIP(candidate), nil
	}
	return nil, ErrPoolExhausted
}

// Release returns clientID's address to the pool. It is a no-op if the
// client has no current allocation, so callers may invoke it
// unconditionally on disconnect.
func (p *Pool) Release(clientID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addr, held := p.byClient[clientID]
	if !held {
		return
	}
	delete(p.byClient, clientID)
	delete(p.ipToCN, addr)
	p.free[addr] = struct{}{}
}

// InUse returns the current number of allocated addresses.
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byClient)
}

// Lookup returns the clientID currently holding ip, or ("", false) if ip
// is not allocated. Useful for reverse lookups when an IP packet arrives
// from the TUN interface and the server needs to find the destination
// client's connection.
func (p *Pool) Lookup(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cn, ok := p.ipToCN[ipToUint32(v4)]
	return cn, ok
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
