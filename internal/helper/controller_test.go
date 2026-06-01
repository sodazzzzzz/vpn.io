package helper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/govpn/internal/ipc"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/client"
)

// fakeDev is a no-op TUN device; the fake engine never touches it, but the
// controller opens and closes it around a session.
type fakeDev struct {
	mu     sync.Mutex
	closed bool
}

func (d *fakeDev) Read(p []byte) (int, error)  { return 0, io.EOF }
func (d *fakeDev) Write(p []byte) (int, error) { return len(p), nil }
func (d *fakeDev) Name() string                { return "faketun0" }
func (d *fakeDev) MTU() int                    { return 1380 }
func (d *fakeDev) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}
func (d *fakeDev) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// fakeEngine stands in for *client.Client. Run blocks until ctx is
// cancelled (returning runErr, default nil) unless runErr is set to a
// non-nil error, in which case it returns immediately. onState exposes the
// captured Config.OnState so tests can drive state transitions.
type fakeEngine struct {
	runErr  error
	onState func(client.State)
}

func (e *fakeEngine) Run(ctx context.Context) error {
	if e.runErr != nil {
		return e.runErr
	}
	<-ctx.Done()
	return nil
}

// newTestController wires the controller to a fake TUN and fake engine and
// returns both so tests can drive and observe them.
func newTestController(t *testing.T, eng *fakeEngine) (*Controller, *fakeDev) {
	t.Helper()
	dev := &fakeDev{}
	c := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.openTUN = func(name string, mtu int) (tun.Device, error) { return dev, nil }
	c.newEng = func(cfg client.Config, _ tun.Device, _ *slog.Logger) (engine, error) {
		eng.onState = cfg.OnState
		return eng, nil
	}
	return c, dev
}

func validConnectReq() ipc.ConnectRequest {
	return ipc.ConnectRequest{
		Server:    "vpn.example.com:8443",
		CACertPEM: []byte("ca"),
		CertPEM:   []byte("cert"),
		KeyPEM:    []byte("key"),
	}
}

func waitState(t *testing.T, c *Controller, want State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if State(c.Status().State) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state never reached %q (last=%q)", want, c.Status().State)
}

func TestConnectThenDisconnect(t *testing.T) {
	eng := &fakeEngine{}
	c, dev := newTestController(t, eng)

	if err := c.Connect(validConnectReq()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if got := c.Status().State; got != string(StateConnecting) {
		t.Fatalf("state after Connect = %q, want connecting", got)
	}

	// Drive the engine to "connected".
	eng.onState(client.StateConnected)
	waitState(t, c, StateConnected)
	if c.Status().Server != "vpn.example.com:8443" {
		t.Fatalf("server not reported: %q", c.Status().Server)
	}

	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if got := c.Status().State; got != string(StateDisconnected) {
		t.Fatalf("state after Disconnect = %q, want disconnected", got)
	}
	if !dev.isClosed() {
		t.Fatal("TUN device not closed after Disconnect")
	}
}

func TestConnectRejectedWhenActive(t *testing.T) {
	eng := &fakeEngine{}
	c, _ := newTestController(t, eng)
	if err := c.Connect(validConnectReq()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Disconnect()

	if err := c.Connect(validConnectReq()); err == nil {
		t.Fatal("second Connect should be rejected while active")
	}
}

func TestEngineFatalSetsFailed(t *testing.T) {
	eng := &fakeEngine{runErr: errors.New("bad certificate")}
	c, dev := newTestController(t, eng)

	if err := c.Connect(validConnectReq()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	waitState(t, c, StateFailed)

	st := c.Status()
	if st.LastError == "" {
		t.Fatal("failed state should report LastError")
	}
	if !dev.isClosed() {
		t.Fatal("TUN device not closed after engine exit")
	}
	// After a fatal exit the controller is idle again: a new Connect works.
	eng2 := &fakeEngine{}
	c.newEng = func(cfg client.Config, _ tun.Device, _ *slog.Logger) (engine, error) {
		eng2.onState = cfg.OnState
		return eng2, nil
	}
	if err := c.Connect(validConnectReq()); err != nil {
		t.Fatalf("reconnect after failure: %v", err)
	}
	_ = c.Disconnect()
}

func TestConnectValidation(t *testing.T) {
	eng := &fakeEngine{}
	c, _ := newTestController(t, eng)

	cases := map[string]ipc.ConnectRequest{
		"empty server":  {CACertPEM: []byte("a"), CertPEM: []byte("b"), KeyPEM: []byte("c")},
		"missing creds": {Server: "x:1"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if err := c.Connect(req); err == nil {
				t.Fatal("expected validation error")
			}
			if got := c.Status().State; got != string(StateDisconnected) {
				t.Fatalf("state changed on invalid Connect: %q", got)
			}
		})
	}
}

func TestDisconnectIdempotent(t *testing.T) {
	c, _ := newTestController(t, &fakeEngine{})
	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect on idle: %v", err)
	}
}
