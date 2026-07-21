package ipc

import (
	"context"
	"encoding/json"
	"errors"
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

// staticListener drives Serve's accept loop deterministically: Accept returns
// whatever accept yields; Close and Addr are no-ops.
type staticListener struct {
	accept func() (net.Conn, error)
}

func (l staticListener) Accept() (net.Conn, error) {
	return l.accept()
}

func (l staticListener) Close() error {
	return nil
}

func (l staticListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "mock", Net: "unix"}
}

func TestNextAcceptDelay_BacksOffAndCaps(t *testing.T) {
	if d := nextAcceptDelay(0); d != 5*time.Millisecond {
		t.Fatalf("first delay = %v, want 5ms", d)
	}
	d := time.Duration(0)
	for i := 0; i < 20; i++ {
		d = nextAcceptDelay(d)
	}
	if d != time.Second {
		t.Fatalf("saturated delay = %v, want the 1s cap", d)
	}
}

// A persistently broken listener makes Serve give up (return an error) instead
// of hanging or spinning — but only after several retries, not the first failure.
func TestServe_GivesUpAfterPersistentAcceptErrors(t *testing.T) {
	var calls int
	ln := staticListener{accept: func() (net.Conn, error) {
		calls++
		return nil, errors.New("permanent")
	}}
	srv := NewServer(ln, nil, nil)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve returned nil on a broken listener; want an error")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Serve did not give up on a persistently broken listener")
	}
	// calls is safe to read here: the Serve goroutine has returned (channel
	// receive above establishes happens-before).
	if calls < maxAcceptFailures {
		t.Errorf("gave up after %d accepts, want at least %d", calls, maxAcceptFailures)
	}
}

// A transient error must NOT tear the daemon down: Serve retries and keeps
// running (the live tunnel survives). ctx-cancel then ends it cleanly. This is
// the #131 regression — one recoverable Accept error used to kill the daemon.
func TestServe_SurvivesTransientAcceptError(t *testing.T) {
	block := make(chan struct{})
	var n int
	ln := staticListener{accept: func() (net.Conn, error) {
		n++
		if n <= 2 {
			return nil, errors.New("transient")
		}
		<-block // quiet, healthy listener: no more connections
		return nil, net.ErrClosed
	}}
	srv := NewServer(ln, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	select {
	case err := <-done:
		t.Fatalf("Serve exited early (%v) instead of retrying past transient errors", err)
	case <-time.After(300 * time.Millisecond):
		// good: still accepting after the transient errors
	}
	cancel()
	close(block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after cancel returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}
