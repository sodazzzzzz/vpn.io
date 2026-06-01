package ipc

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// blockingHandler parks in Connect until release is closed, signalling on
// started when it has entered. Used to hold a handler "in flight" while we
// trigger shutdown.
type blockingHandler struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockingHandler) Connect(ConnectRequest) error {
	h.once.Do(func() { close(h.started) })
	<-h.release
	return nil
}
func (h *blockingHandler) Disconnect() error      { return nil }
func (h *blockingHandler) Status() StatusResponse { return StatusResponse{} }

// TestServeWaitsForInflightHandlers verifies Serve doesn't return until an
// in-flight handler finishes, even after ctx is cancelled. A plain TCP
// listener stands in for the transport (peer-cred auth is orthogonal here),
// keeping the test platform-independent.
func TestServeWaitsForInflightHandlers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	h := &blockingHandler{started: make(chan struct{}), release: make(chan struct{})}
	srv := NewServer(ln, h, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload, _ := json.Marshal(ConnectRequest{
		Server: "x:1", CACertPEM: []byte("a"), CertPEM: []byte("b"), KeyPEM: []byte("c"),
	})
	if err := WriteRequest(conn, Request{Command: CmdConnect, Payload: payload}); err != nil {
		t.Fatalf("write request: %v", err)
	}

	<-h.started // handler is now parked inside Connect
	cancel()    // shut the server down while the handler is in flight

	// Serve must not return while the handler is still running.
	select {
	case <-served:
		t.Fatal("Serve returned before the in-flight handler finished")
	case <-time.After(200 * time.Millisecond):
	}

	close(h.release) // let the handler complete

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the handler finished")
	}
}
