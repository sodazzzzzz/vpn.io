//go:build linux || darwin

package ipc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// serveTestSocket starts a Server with handler h on a fresh unix socket that
// admits the current uid, and returns the socket path. Serve stops when the
// test ends.
func serveTestSocket(t *testing.T, h Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := Listen(sock, 0600, Policy{AllowUID: []uint32{uint32(os.Getuid())}}, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := NewServer(ln, h, nil)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(served) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return sock
}

func TestDoStatusRoundTrip(t *testing.T) {
	h := &fakeHandler{status: StatusResponse{State: "connected", Server: "vpn:8443"}}
	sock := serveTestSocket(t, h)

	resp, err := Do(sock, Request{Command: CmdStatus})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.OK {
		t.Fatalf("status not ok: %q", resp.Error)
	}
	var st StatusResponse
	if err := json.Unmarshal(resp.Payload, &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.State != "connected" || st.Server != "vpn:8443" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestDoConnectDeliversRequest(t *testing.T) {
	h := &fakeHandler{}
	sock := serveTestSocket(t, h)

	payload, _ := json.Marshal(ConnectRequest{Server: "vpn:8443", CertPEM: []byte("x")})
	resp, err := Do(sock, Request{Command: CmdConnect, Payload: payload})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.OK {
		t.Fatalf("connect not ok: %q", resp.Error)
	}
	if h.lastConnect.Server != "vpn:8443" {
		t.Fatalf("handler did not receive the request: %+v", h.lastConnect)
	}
}

func TestDoFailsWhenNoDaemon(t *testing.T) {
	// A path with no listener: Do should surface a connection error, not hang.
	sock := filepath.Join(t.TempDir(), "absent.sock")
	if _, err := Do(sock, Request{Command: CmdStatus}); err == nil {
		t.Fatal("expected Do to fail when nothing is listening")
	}
}
