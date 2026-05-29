// Package e2e wires the real server and client packages together over a
// loopback TLS connection and asserts that IP packets round-trip through
// the tunnel in both directions.
//
// Unlike the server-package tests (which drive the server with a raw TLS
// client), this exercises the actual client.Client session loop —
// devicePoller, connWriter framing, connReader, ensureConfigured — against
// a live server. Both ends use an in-memory TUN that implements
// tun.SelfConfigurer, so no privileged OS network calls are made and the
// test runs unprivileged in CI.
package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/client"
	"github.com/govpn/internal/tunnel/server"
)

// memTUN is an in-memory tun.Device + tun.SelfConfigurer.
//
//	inbox  — packets the test stages for the owner to Read (as if arriving
//	         from the kernel/network side of the device)
//	outbox — packets the owner has Written to the device, for the test to
//	         inspect
type memTUN struct {
	name string
	mtu  int

	inbox  chan []byte
	outbox chan []byte

	configured   chan struct{} // closed when ConfigureAddr is first called
	configOnce   sync.Once
	configuredIP string // the IP passed to the first ConfigureAddr; read after <-configured

	mu     sync.Mutex
	closed bool
}

var (
	_ tun.Device         = (*memTUN)(nil)
	_ tun.SelfConfigurer = (*memTUN)(nil)
)

func newMemTUN(name string, mtu, buf int) *memTUN {
	return &memTUN{
		name:       name,
		mtu:        mtu,
		inbox:      make(chan []byte, buf),
		outbox:     make(chan []byte, buf),
		configured: make(chan struct{}),
	}
}

func (m *memTUN) Read(p []byte) (int, error) {
	pkt, ok := <-m.inbox
	if !ok {
		return 0, io.EOF
	}
	return copy(p, pkt), nil
}

func (m *memTUN) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	out := m.outbox
	m.mu.Unlock()
	// Non-blocking: if the test stopped draining outbox (e.g. it already
	// failed a recvWithin), we must not park this goroutine forever. A full
	// buffer means the test isn't reading, which is itself a test bug.
	select {
	case out <- cp:
		return len(p), nil
	default:
		return 0, fmt.Errorf("memTUN %s: outbox full (reader not consuming)", m.name)
	}
}

func (m *memTUN) Name() string { return m.name }
func (m *memTUN) MTU() int     { return m.mtu }

func (m *memTUN) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.inbox)
	m.mu.Unlock()
	return nil
}

// ConfigureAddr satisfies tun.SelfConfigurer: record the assigned IP and
// signal readiness, no OS calls. configuredIP is written exactly once before
// the channel closes, so a reader that waits on <-configured sees it safely.
func (m *memTUN) ConfigureAddr(ip, netmask, gateway string) error {
	m.configOnce.Do(func() {
		m.configuredIP = ip
		close(m.configured)
	})
	return nil
}

// inject stages a packet for the owner to Read. It is non-blocking: a full
// inbox means the owner isn't reading, so we surface that instead of parking
// the test goroutine forever.
func (m *memTUN) inject(t *testing.T, pkt []byte) {
	t.Helper()
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case m.inbox <- cp:
	default:
		t.Fatalf("memTUN %s: inbox full — reader not consuming packets?", m.name)
	}
}

// buildIPv4 constructs a minimal valid IPv4 packet (checksum left zero —
// nothing in this test path validates it).
func buildIPv4(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(payload)))
	pkt[8] = 64   // TTL
	pkt[9] = 0xfd // arbitrary protocol number
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

func waitClosed(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("timeout (%s) waiting for %s", d, what)
	}
}

func recvWithin(t *testing.T, ch <-chan []byte, d time.Duration, what string) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(d):
		t.Fatalf("timeout (%s) waiting for %s", d, what)
		return nil
	}
}

// TestEndToEnd_RoundTrip brings up server + client over loopback and checks
// a packet flows client→server-TUN and server-TUN→client.
func TestEndToEnd_RoundTrip(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- CA + certs on disk -------------------------------------------------
	caDir := filepath.Join(t.TempDir(), "ca")
	authority, err := ca.Create(caDir, "e2e-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := authority.IssueServer("e2e-server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := authority.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	caCert := filepath.Join(caDir, "ca.crt")

	// --- server -------------------------------------------------------------
	srvTUN := newMemTUN("e2e-srv", 1380, 64)
	srv, err := server.New(server.Config{
		Listen:     "127.0.0.1:0",
		CACertFile: caCert,
		CertFile:   filepath.Join(caDir, "server", "server.crt"),
		KeyFile:    filepath.Join(caDir, "server", "server.key"),
		Subnet:     "10.8.0.0/24",
		Gateway:    "10.8.0.1",
		Netmask:    "255.255.255.0",
		MTU:        1380,
		// No PushRoutes/PushDNS → client's ensureRoutes/ensureDNS are no-ops,
		// so the only configuration step is ensureConfigured (handled by the
		// memTUN's SelfConfigurer).
	}, srvTUN, log)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Run(srvCtx) }()
	// Even on an early t.Fatal, tear the server down and wait for Run to
	// return. The server OWNS srvTUN: srvCancel() makes Run call shutdown(),
	// which closes the listener AND the TUN — that closes srvTUN.inbox and
	// unblocks runTUNReader. We must NOT close srvTUN here too (that would be
	// the double close server.New documents as unsafe). Waiting on srvErr
	// keeps the -race detector from attributing late goroutine access to
	// srvTUN after the test "finished".
	t.Cleanup(func() {
		srvCancel()
		select {
		case <-srvErr:
		case <-time.After(5 * time.Second):
			t.Errorf("server goroutine did not exit within 5s after cancel")
		}
	})
	waitClosed(t, srv.Ready(), 2*time.Second, "server ready")

	// --- client -------------------------------------------------------------
	cliTUN := newMemTUN("e2e-cli", 1380, 64)
	cli, err := client.New(client.Config{
		Server:     srv.Addr().String(),
		CACertFile: caCert,
		CertFile:   filepath.Join(caDir, "clients", "alice.crt"),
		KeyFile:    filepath.Join(caDir, "clients", "alice.key"),
		ServerName: "localhost",
	}, cliTUN, log)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Run(cliCtx) }()
	// Same teardown contract as the server: cancel, close cliTUN (unblocks the
	// devicePoller parked in Read), and wait for Run to return.
	t.Cleanup(func() {
		cliCancel()
		_ = cliTUN.Close()
		select {
		case <-cliErr:
		case <-time.After(5 * time.Second):
			t.Errorf("client goroutine did not exit within 5s after cancel")
		}
	})

	// Client configures its TUN right after AssignIP — our signal that the
	// session is live and the devicePoller is draining cliTUN.
	waitClosed(t, cliTUN.configured, 3*time.Second, "client TUN configured")

	// Drive routing with the IP the server actually assigned (captured in
	// ConfigureAddr), not a literal — so the packet assertions below can't
	// silently misroute if allocation order ever changes.
	assignedIP := net.ParseIP(cliTUN.configuredIP)
	if assignedIP == nil {
		t.Fatalf("client configured with unparseable IP %q", cliTUN.configuredIP)
	}
	// This test also intentionally pins the pool's deterministic allocation:
	// the sole client must get the lowest free host in 10.8.0.0/24 after the
	// gateway 10.8.0.1 is reserved. If ipalloc's order ever changes on
	// purpose, update wantIP.
	const wantIP = "10.8.0.2"
	if cliTUN.configuredIP != wantIP {
		t.Fatalf("assigned IP = %q, want %s", cliTUN.configuredIP, wantIP)
	}
	gateway := net.IPv4(10, 8, 0, 1)

	// --- client → server-TUN ------------------------------------------------
	cliTUN.inject(t, buildIPv4(assignedIP, gateway, []byte("ping-up")))
	up := recvWithin(t, srvTUN.outbox, 2*time.Second, "packet on server TUN")
	if got := string(up[20:]); got != "ping-up" {
		t.Fatalf("server TUN payload = %q, want ping-up", got)
	}

	// --- server-TUN → client ------------------------------------------------
	// A packet arriving on the server's TUN destined for the client's IP must
	// be routed down the tunnel and written to the client's TUN.
	srvTUN.inject(t, buildIPv4(net.IPv4(8, 8, 8, 8), assignedIP, []byte("pong-down")))
	down := recvWithin(t, cliTUN.outbox, 2*time.Second, "packet on client TUN")
	if got := string(down[20:]); got != "pong-down" {
		t.Fatalf("client TUN payload = %q, want pong-down", got)
	}

	// Clean shutdown is asserted by the t.Cleanup teardown registered above:
	// it cancels each side, closes its TUN, and fails the test if Run doesn't
	// return within 5s. Cleanups run in LIFO order (client first, then server),
	// which matches a normal disconnect sequence.
}
