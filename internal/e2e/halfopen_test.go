package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/tunnel"
	"github.com/govpn/internal/tunnel/client"
)

// wedgedServer is a server that completes the handshake, assigns an IP, sends
// a few keepalives, and then stops sending anything at all while holding the
// TCP connection open — the observable behaviour of a server process that has
// hung (SIGSTOP, deadlock) or a path that silently stopped forwarding while the
// kernel keeps the socket alive.
//
// The real server package can't be made to do this, so this speaks the wire
// protocol directly.
type wedgedServer struct {
	lis       net.Listener
	keepalive time.Duration
	// sent is closed once a client has received enough keepalives for its idle
	// deadline to be armed; after that the server goes quiet.
	sent     chan struct{}
	sentOnce sync.Once

	mu    sync.Mutex
	conns []net.Conn
}

func startWedgedServer(t *testing.T, caDir string, keepalive time.Duration) *wedgedServer {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(caDir, "server", "server.crt"),
		filepath.Join(caDir, "server", "server.key"),
	)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM contained no certificates")
	}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &wedgedServer{lis: lis, keepalive: keepalive, sent: make(chan struct{})}
	go s.acceptLoop()
	t.Cleanup(s.close)
	return s
}

func (s *wedgedServer) addr() string { return s.lis.Addr().String() }

func (s *wedgedServer) acceptLoop() {
	for {
		conn, err := s.lis.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

// serve assigns an IP, emits keepaliveBurst keepalives, then falls silent while
// deliberately keeping the connection open.
func (s *wedgedServer) serve(conn net.Conn) {
	const keepaliveBurst = 2

	assign, err := tunnel.NewAssignIP(tunnel.AssignIP{
		IP:      "10.8.0.2",
		Gateway: "10.8.0.1",
		Netmask: "255.255.255.0",
		MTU:     1380,
	})
	if err != nil {
		return
	}
	if err := tunnel.WriteControl(conn, assign); err != nil {
		return
	}
	for range keepaliveBurst {
		time.Sleep(s.keepalive)
		if err := tunnel.WriteControl(conn, tunnel.NewKeepalive()); err != nil {
			return
		}
	}
	s.sentOnce.Do(func() { close(s.sent) })
	// Now wedge: read nothing, write nothing, hold the connection.
	select {}
}

func (s *wedgedServer) close() {
	_ = s.lis.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
}

// A server that stops sending while its kernel keeps the TCP session open must
// be detected. Before the idle deadline the client parked in ReadPacket
// forever: the session never ended, the reconnect loop never ran, and the user
// kept seeing "Connected" on a tunnel carrying nothing.
func TestHalfOpen_SilentServerEndsSession(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	caDir := filepath.Join(t.TempDir(), "ca")
	authority, err := ca.Create(caDir, "halfopen-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := authority.IssueServer("halfopen-server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := authority.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}

	const keepalive = 100 * time.Millisecond
	srv := startWedgedServer(t, caDir, keepalive)

	// Watch for the client giving up on the dead session. Buffered generously
	// so the client's OnState (which must not block) never waits on us.
	states := make(chan client.State, 64)

	cliTUN := newMemTUN("halfopen-cli", 1380, 64)
	cli, err := client.New(client.Config{
		Server:     srv.addr(),
		CACertFile: filepath.Join(caDir, "ca.crt"),
		CertFile:   filepath.Join(caDir, "clients", "alice.crt"),
		KeyFile:    filepath.Join(caDir, "clients", "alice.key"),
		ServerName: "localhost",
		Keepalive:  keepalive,
		// Keep the backoff short so a detected drop surfaces promptly.
		ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 200 * time.Millisecond,
		OnState:      func(s client.State) { states <- s },
	}, cliTUN, log)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Run(cliCtx) }()
	t.Cleanup(func() {
		cliCancel()
		_ = cliTUN.Close()
		select {
		case <-cliErr:
		case <-time.After(5 * time.Second):
			t.Errorf("client goroutine did not exit within 5s after cancel")
		}
	})

	waitClosed(t, cliTUN.configured, 3*time.Second, "client TUN configured")
	waitClosed(t, srv.sent, 3*time.Second, "server keepalives sent")

	// The idle deadline is 3×Keepalive, so detection is due ~300ms after the
	// last keepalive. Allow generous slack for slow CI, but far below the
	// "never" this used to take.
	deadline := time.After(5 * time.Second)
	sawConnected := false
	for {
		select {
		case st := <-states:
			switch st {
			case client.StateConnected:
				sawConnected = true
			case client.StateReconnecting:
				if !sawConnected {
					// Reconnecting before ever connecting would mean the test
					// is observing a failed dial, not a detected dead session.
					t.Fatal("client reported reconnecting before it ever connected")
				}
				return // detected — this is the fix working
			}
		case <-deadline:
			t.Fatal("client never left Connected on a server that stopped sending")
		}
	}
}
