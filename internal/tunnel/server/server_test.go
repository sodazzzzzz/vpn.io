package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/tunnel"
)

// --- shared test harness -----------------------------------------------------

type harness struct {
	t      *testing.T
	srv    *Server
	tun    *fakeTUN
	addr   string
	caPool *x509.CertPool
	caDir  string // root of the generated CA on disk
	runErr chan error
	cancel context.CancelFunc
}

// startServer brings up a Server bound to 127.0.0.1:0 with a fresh CA on
// disk and a fake TUN. The caller cancels via h.shutdown().
func startServer(t *testing.T, subnet, gateway, netmask string) *harness {
	t.Helper()

	caDir := filepath.Join(t.TempDir(), "ca")
	authority, err := ca.Create(caDir, "test-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := authority.IssueServer("test-server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}

	caCert := filepath.Join(caDir, "ca.crt")
	serverCert := filepath.Join(caDir, "server", "server.crt")
	serverKey := filepath.Join(caDir, "server", "server.key")

	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	dev := newFakeTUN("fake0", 1380, 64)

	cfg := Config{
		Listen:     "127.0.0.1:0",
		CACertFile: caCert,
		CertFile:   serverCert,
		KeyFile:    serverKey,
		Subnet:     subnet,
		Gateway:    gateway,
		Netmask:    netmask,
		MTU:        1380,
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, dev, log)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	select {
	case <-srv.Ready():
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("server did not become ready within 2s")
	}

	return &harness{
		t: t, srv: srv, tun: dev, addr: srv.Addr().String(),
		caPool: pool, caDir: caDir, runErr: runErr, cancel: cancel,
	}
}

func (h *harness) shutdown() {
	h.cancel()
	select {
	case <-h.runErr:
	case <-time.After(3 * time.Second):
		h.t.Fatal("server did not shut down within 3s")
	}
}

// issueClient signs and loads a client certificate under name; returns a
// tls.Certificate ready to use in a client tls.Config.
func (h *harness) issueClient(name string) tls.Certificate {
	h.t.Helper()
	authority, err := ca.Load(h.caDir)
	if err != nil {
		h.t.Fatalf("ca.Load: %v", err)
	}
	if err := authority.IssueClient(name); err != nil {
		h.t.Fatalf("IssueClient: %v", err)
	}
	crt, err := tls.LoadX509KeyPair(
		filepath.Join(h.caDir, "clients", name+".crt"),
		filepath.Join(h.caDir, "clients", name+".key"),
	)
	if err != nil {
		h.t.Fatalf("LoadX509KeyPair: %v", err)
	}
	return crt
}

// dial opens a TLS connection to the server using the given client cert
// material; pass nil for clientCerts to test the no-cert path.
func (h *harness) dial(clientCerts []tls.Certificate) (*tls.Conn, error) {
	h.t.Helper()
	cfg := &tls.Config{
		RootCAs:      h.caPool,
		Certificates: clientCerts,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", h.addr, cfg)
}

// expectAssignIP reads the first frame from conn and asserts it is an
// AssignIP control message; returns the assigned IP as a string.
func (h *harness) expectAssignIP(conn *tls.Conn) string {
	h.t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	typ, body, err := tunnel.ReadPacket(conn)
	if err != nil {
		h.t.Fatalf("ReadPacket: %v", err)
	}
	if typ != tunnel.FrameControl {
		h.t.Fatalf("got frame type %v, want FrameControl", typ)
	}
	msg, err := tunnel.DecodeControl(body)
	if err != nil {
		h.t.Fatalf("DecodeControl: %v", err)
	}
	if msg.Type != tunnel.CtrlAssignIP {
		h.t.Fatalf("got control type %q, want %q", msg.Type, tunnel.CtrlAssignIP)
	}
	a, err := tunnel.ParseAssignIP(msg)
	if err != nil {
		h.t.Fatalf("ParseAssignIP: %v", err)
	}
	return a.IP
}

// buildIPv4 constructs a minimal valid IPv4 packet with the requested src
// and dst; the IP checksum field is left zero (the server doesn't validate
// it).
func buildIPv4(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(20+len(payload)))
	pkt[8] = 64   // TTL
	pkt[9] = 0xfd // arbitrary protocol number (no kernel processes it here)
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

// drainOutboxFor waits up to d for a packet to appear on the fake TUN's
// outbox. Returns the packet or nil on timeout.
func drainOutboxFor(tun *fakeTUN, d time.Duration) []byte {
	select {
	case pkt := <-tun.outbox:
		return pkt
	case <-time.After(d):
		return nil
	}
}

// --- tests -------------------------------------------------------------------

func TestServer_HappyPath_RoundTrip(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	cert := h.issueClient("alice")
	conn, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	assignedStr := h.expectAssignIP(conn)
	if assignedStr != "10.8.0.2" {
		t.Fatalf("got assigned IP %q, want 10.8.0.2", assignedStr)
	}
	assignedIP := net.ParseIP(assignedStr)

	// Client → server data frame: src=assigned, dst=gateway.
	out := buildIPv4(assignedIP, net.IPv4(10, 8, 0, 1), []byte("hello-from-client"))
	if err := tunnel.WriteData(conn, out); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	got := drainOutboxFor(h.tun, 1*time.Second)
	if got == nil {
		t.Fatal("packet from client never reached TUN outbox")
	}
	if string(got[20:]) != "hello-from-client" {
		t.Fatalf("TUN got payload %q, want hello-from-client", got[20:])
	}

	// Server → client: inject a packet with dst=assigned from outside.
	in := buildIPv4(net.IPv4(8, 8, 8, 8), assignedIP, []byte("hello-from-net"))
	h.tun.inject(in)

	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	typ, body, err := tunnel.ReadPacket(conn)
	if err != nil {
		t.Fatalf("client ReadPacket: %v", err)
	}
	if typ != tunnel.FrameData {
		t.Fatalf("got frame type %v, want FrameData", typ)
	}
	if string(body[20:]) != "hello-from-net" {
		t.Fatalf("client got payload %q, want hello-from-net", body[20:])
	}
}

func TestServer_RejectsClientWithoutCert(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	// In TLS 1.3 the client's Dial may return before the server's
	// post-Finished alert arrives. Surface the rejection by reading.
	conn, err := h.dial(nil)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err = tunnel.ReadPacket(conn)
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("server accepted a connection with no client certificate")
	}
}

func TestServer_RejectsCertFromOtherCA(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	// Build a *different* CA and sign a client under it.
	rogueDir := filepath.Join(t.TempDir(), "rogue-ca")
	rogue, err := ca.Create(rogueDir, "rogue")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := rogue.IssueClient("evil"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	rogueCert, err := tls.LoadX509KeyPair(
		filepath.Join(rogueDir, "clients", "evil.crt"),
		filepath.Join(rogueDir, "clients", "evil.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := h.dial([]tls.Certificate{rogueCert})
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err = tunnel.ReadPacket(conn)
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("server accepted a connection with a cert from an unknown CA")
	}
}

func TestServer_AntiSpoofDropsWrongSrc(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	cert := h.issueClient("alice")
	conn, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assigned := net.ParseIP(h.expectAssignIP(conn))

	// Spoofed: src is someone else's IP.
	spoofed := buildIPv4(net.IPv4(10, 8, 0, 99), net.IPv4(10, 8, 0, 1), []byte("evil"))
	if err := tunnel.WriteData(conn, spoofed); err != nil {
		t.Fatal(err)
	}
	// Server must drop. A valid packet sent right after should reach TUN
	// first — the spoofed one never does.
	valid := buildIPv4(assigned, net.IPv4(10, 8, 0, 1), []byte("good"))
	if err := tunnel.WriteData(conn, valid); err != nil {
		t.Fatal(err)
	}
	got := drainOutboxFor(h.tun, 1*time.Second)
	if got == nil {
		t.Fatal("valid packet never reached TUN")
	}
	if string(got[20:]) != "good" {
		t.Fatalf("first packet through was %q (expected the valid 'good'; the spoofed one slipped through)", got[20:])
	}
	// Drain a bit longer to confirm no second packet (the spoofed one).
	if extra := drainOutboxFor(h.tun, 200*time.Millisecond); extra != nil {
		t.Fatalf("unexpected extra packet on TUN: %q", extra[20:])
	}
}

func TestServer_IsolationDropsInterClient(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	certA := h.issueClient("alice")
	certB := h.issueClient("bob")

	connA, err := h.dial([]tls.Certificate{certA})
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	ipA := net.ParseIP(h.expectAssignIP(connA))

	connB, err := h.dial([]tls.Certificate{certB})
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	ipB := net.ParseIP(h.expectAssignIP(connB))

	// A → B should be dropped (isolation).
	interClient := buildIPv4(ipA, ipB, []byte("hi-bob"))
	if err := tunnel.WriteData(connA, interClient); err != nil {
		t.Fatal(err)
	}
	// Bob must not receive it within a short window.
	_ = connB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := tunnel.ReadPacket(connB); err == nil {
		t.Fatal("bob received an inter-client packet; isolation broken")
	}
	// And no packet should hit the TUN device for that drop.
	if got := drainOutboxFor(h.tun, 200*time.Millisecond); got != nil {
		t.Fatalf("inter-client packet reached TUN outbox: %q", got[20:])
	}
}

func TestServer_KickOnReconnect(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	cert := h.issueClient("alice")

	connA, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	ip1 := h.expectAssignIP(connA)

	// Second connection from the same CN should kick the first.
	connB, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	ip2 := h.expectAssignIP(connB)

	// Same CN → same lowest-free IP (the kick releases ip1, then re-allocates).
	if ip1 != ip2 {
		t.Fatalf("second session got %s, want same as first (%s)", ip2, ip1)
	}
	// The first connection's reader must now return an error (server closed it).
	_ = connA.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, _, err := tunnel.ReadPacket(connA); err == nil {
		t.Fatal("first connection still alive after reconnect; expected to be kicked")
	}
}

func TestServer_PoolExhaustionReportsError(t *testing.T) {
	// /30 with .1 reserved → exactly one usable client slot.
	h := startServer(t, "10.8.0.0/30", "10.8.0.1", "255.255.255.252")
	defer h.shutdown()

	certA := h.issueClient("alice")
	certB := h.issueClient("bob")

	connA, err := h.dial([]tls.Certificate{certA})
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	if got := h.expectAssignIP(connA); got != "10.8.0.2" {
		t.Fatalf("alice got %s, want 10.8.0.2", got)
	}

	connB, err := h.dial([]tls.Certificate{certB})
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()

	// Server should send an Error control message instead of AssignIP.
	_ = connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, body, err := tunnel.ReadPacket(connB)
	if err != nil {
		t.Fatalf("bob ReadPacket: %v", err)
	}
	if typ != tunnel.FrameControl {
		t.Fatalf("bob got frame type %v, want FrameControl", typ)
	}
	msg, err := tunnel.DecodeControl(body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != tunnel.CtrlError {
		t.Fatalf("got %q, want %q", msg.Type, tunnel.CtrlError)
	}
	emsg, err := tunnel.ParseError(msg)
	if err != nil {
		t.Fatal(err)
	}
	if emsg.Code != "no_ip" {
		t.Fatalf("got error code %q, want no_ip", emsg.Code)
	}
}

// Sanity check that the harness shuts down cleanly when no clients ever
// connect — guards against goroutine leaks in the bare lifecycle.
func TestServer_ShutsDownCleanlyIdle(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	h.shutdown()
}
