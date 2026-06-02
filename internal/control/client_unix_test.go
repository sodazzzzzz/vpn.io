//go:build linux || darwin

package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/ipc"
)

// fakeHandler is a programmable ipc.Handler standing in for the daemon's tunnel
// controller. It records the last Connect request and lets each method's
// outcome be set per test.
type fakeHandler struct {
	status        ipc.StatusResponse
	connectErr    error
	disconnectErr error

	lastConnect  ipc.ConnectRequest
	connectCalls int
	disconnectN  int
}

func (h *fakeHandler) Connect(r ipc.ConnectRequest) error {
	h.connectCalls++
	h.lastConnect = r
	return h.connectErr
}
func (h *fakeHandler) Disconnect() error          { h.disconnectN++; return h.disconnectErr }
func (h *fakeHandler) Status() ipc.StatusResponse { return h.status }

// serve starts an ipc.Server with h on a fresh unix socket admitting the
// current uid and returns a Client pointed at it. Serve stops at test end.
func serve(t *testing.T, h ipc.Handler) *Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := ipc.Listen(sock, 0o600, ipc.Policy{AllowUID: []uint32{uint32(os.Getuid())}}, nil)
	if err != nil {
		t.Fatalf("ipc.Listen: %v", err)
	}
	srv := ipc.NewServer(ln, h, nil)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(served) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return New(sock)
}

// testCreds issues a CA + client certificate in a temp dir and returns valid
// Credentials for the given server address.
func testCreds(t *testing.T, server string) Credentials {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.Create(dir, "test-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := c.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	return Credentials{
		Server:    server,
		CACertPEM: readFile(t, filepath.Join(dir, "ca.crt")),
		CertPEM:   readFile(t, filepath.Join(dir, "clients", "alice.crt")),
		KeyPEM:    readFile(t, filepath.Join(dir, "clients", "alice.key")),
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestStatusMapsFields(t *testing.T) {
	h := &fakeHandler{status: ipc.StatusResponse{
		State: "connected", Server: "vpn.example.com:8443", SinceUnix: 1700000000,
	}}
	cl := serve(t, h)

	st, err := cl.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != "connected" || st.Server != "vpn.example.com:8443" || st.SinceUnix != 1700000000 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestStatusSurfacesFailure(t *testing.T) {
	h := &fakeHandler{status: ipc.StatusResponse{State: "failed", LastError: "tls: handshake timeout"}}
	cl := serve(t, h)

	st, err := cl.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != "failed" || st.LastError != "tls: handshake timeout" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestDisconnect(t *testing.T) {
	h := &fakeHandler{}
	cl := serve(t, h)

	if err := cl.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if h.disconnectN != 1 {
		t.Fatalf("Disconnect called %d times, want 1", h.disconnectN)
	}
}

func TestConnectValidCredentials(t *testing.T) {
	const server = "vpn.example.com:8443"
	h := &fakeHandler{}
	cl := serve(t, h)

	info, err := cl.Connect(testCreds(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if info.CommonName != "alice" {
		t.Errorf("CommonName = %q, want alice", info.CommonName)
	}
	if info.NotAfter.IsZero() {
		t.Error("NotAfter not set")
	}
	if h.connectCalls != 1 {
		t.Fatalf("daemon Connect called %d times, want 1", h.connectCalls)
	}
	if h.lastConnect.Server != server {
		t.Errorf("daemon got server %q, want %q", h.lastConnect.Server, server)
	}
	// ServerName defaults to the host of the server address.
	if h.lastConnect.ServerName != "vpn.example.com" {
		t.Errorf("ServerName = %q, want vpn.example.com", h.lastConnect.ServerName)
	}
	if len(h.lastConnect.CACertPEM) == 0 || len(h.lastConnect.CertPEM) == 0 || len(h.lastConnect.KeyPEM) == 0 {
		t.Error("daemon did not receive the credential PEMs")
	}
}

func TestConnectRejectsBadCredentialsLocally(t *testing.T) {
	h := &fakeHandler{}
	cl := serve(t, h)

	_, err := cl.Connect(Credentials{
		Server:    "vpn.example.com:8443",
		CACertPEM: []byte("not a cert"),
		CertPEM:   []byte("not a cert"),
		KeyPEM:    []byte("not a key"),
	})
	if err == nil {
		t.Fatal("expected an invalid-credentials error")
	}
	if h.connectCalls != 0 {
		t.Fatalf("daemon Connect called %d times; local validation should short-circuit", h.connectCalls)
	}
}

func TestConnectRejectsNegativeMTU(t *testing.T) {
	h := &fakeHandler{}
	cl := serve(t, h)

	creds := testCreds(t, "vpn.example.com:8443")
	creds.MTU = -1
	if _, err := cl.Connect(creds); err == nil {
		t.Fatal("expected a negative-MTU rejection")
	}
	if h.connectCalls != 0 {
		t.Fatal("daemon Connect called despite an invalid MTU")
	}
}

func TestSurfacesDaemonError(t *testing.T) {
	h := &fakeHandler{disconnectErr: errors.New("controller busy")}
	cl := serve(t, h)

	err := cl.Disconnect()
	if err == nil || !strings.Contains(err.Error(), "controller busy") {
		t.Fatalf("expected the daemon's error surfaced, got %v", err)
	}
}

func TestFailsWhenDaemonAbsent(t *testing.T) {
	cl := New(filepath.Join(t.TempDir(), "absent.sock"))
	if _, err := cl.Status(); err == nil {
		t.Fatal("expected an error when no daemon is listening")
	}
}
