package ipalloc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
)

func mustNew(t *testing.T, cidr string, reserve ...net.IP) *Pool {
	t.Helper()
	p, err := New(cidr, reserve...)
	if err != nil {
		t.Fatalf("New(%q): %v", cidr, err)
	}
	return p
}

func TestSequentialAllocation(t *testing.T) {
	p := mustNew(t, "10.8.0.0/24", net.IPv4(10, 8, 0, 1))

	want := []string{"10.8.0.2", "10.8.0.3", "10.8.0.4"}
	for i, w := range want {
		got, err := p.Allocate(fmt.Sprintf("client-%d", i))
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
		if got.String() != w {
			t.Fatalf("Allocate %d: got %s, want %s", i, got, w)
		}
	}
	if p.InUse() != 3 {
		t.Fatalf("InUse=%d, want 3", p.InUse())
	}
}

func TestReleaseAndReuse(t *testing.T) {
	p := mustNew(t, "10.8.0.0/24", net.IPv4(10, 8, 0, 1))

	a, _ := p.Allocate("alice")
	b, _ := p.Allocate("bob")
	if a.String() != "10.8.0.2" || b.String() != "10.8.0.3" {
		t.Fatalf("unexpected initial allocation: %s, %s", a, b)
	}
	p.Release("alice")
	if p.InUse() != 1 {
		t.Fatalf("InUse after release = %d, want 1", p.InUse())
	}
	// alice's slot (lowest free) is reused for carol
	c, err := p.Allocate("carol")
	if err != nil {
		t.Fatalf("Allocate carol: %v", err)
	}
	if c.String() != "10.8.0.2" {
		t.Fatalf("got %s, want 10.8.0.2", c)
	}
}

func TestDoubleAllocate(t *testing.T) {
	p := mustNew(t, "10.8.0.0/24", net.IPv4(10, 8, 0, 1))
	if _, err := p.Allocate("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Allocate("alice"); !errors.Is(err, ErrAlreadyAllocated) {
		t.Fatalf("got %v, want ErrAlreadyAllocated", err)
	}
}

func TestReleaseUnknownIsNoop(t *testing.T) {
	p := mustNew(t, "10.8.0.0/24", net.IPv4(10, 8, 0, 1))
	p.Release("nobody") // must not panic
	if p.InUse() != 0 {
		t.Fatalf("InUse=%d, want 0", p.InUse())
	}
}

func TestExhaustion(t *testing.T) {
	// /30 = 4 addrs, minus network + broadcast + 1 reserved gateway = 1 usable.
	p := mustNew(t, "10.8.0.0/30", net.IPv4(10, 8, 0, 1))
	got, err := p.Allocate("alice")
	if err != nil {
		t.Fatalf("Allocate alice: %v", err)
	}
	if got.String() != "10.8.0.2" {
		t.Fatalf("got %s, want 10.8.0.2", got)
	}
	if _, err := p.Allocate("bob"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("got %v, want ErrPoolExhausted", err)
	}
}

func TestConcurrent(t *testing.T) {
	// /22 → 1024 addrs, ~1021 usable (minus net/bcast/gateway).
	p := mustNew(t, "10.8.0.0/22", net.IPv4(10, 8, 0, 1))

	const workers = 50
	const perWorker = 20
	var wg sync.WaitGroup
	seen := make(chan string, workers*perWorker)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("w%d-i%d", w, i)
				ip, err := p.Allocate(id)
				if err != nil {
					t.Errorf("Allocate %s: %v", id, err)
					return
				}
				seen <- ip.String()
			}
		}(w)
	}
	wg.Wait()
	close(seen)

	addrs := make(map[string]struct{})
	for s := range seen {
		if _, dup := addrs[s]; dup {
			t.Fatalf("duplicate IP allocated: %s", s)
		}
		addrs[s] = struct{}{}
	}
	if got := len(addrs); got != workers*perWorker {
		t.Fatalf("got %d unique IPs, want %d", got, workers*perWorker)
	}
	if p.InUse() != workers*perWorker {
		t.Fatalf("InUse=%d, want %d", p.InUse(), workers*perWorker)
	}
}

func TestNewRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name    string
		cidr    string
		reserve []net.IP
	}{
		{"garbage", "not-a-cidr", nil},
		{"ipv6", "fd00::/64", nil},
		{"/31", "10.8.0.0/31", nil},
		{"/32", "10.8.0.0/32", nil},
		{"reserved outside", "10.8.0.0/24", []net.IP{net.IPv4(192, 168, 1, 1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.cidr, c.reserve...); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
