// Package helper implements the privileged VPN helper daemon's tunnel
// controller: the piece that owns the TUN device and the client engine and
// exposes a small, thread-safe Connect/Disconnect/Status surface for the
// IPC layer to drive. It reuses internal/tunnel/client unchanged as the
// connection engine; the daemon adds lifecycle management and status on top.
package helper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/govpn/internal/ipc"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/client"
)

// defaultMTU matches the CLI's default TUN MTU.
const defaultMTU = 1380

// State is the controller's view of the tunnel lifecycle, reported through
// Status. It extends the client's connection states with the two the
// controller itself owns: "disconnected" (no session) and "failed" (a
// session ended with a non-retryable error).
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateFailed       State = "failed"
)

// openFunc and engineFunc are seams for testing; production wires them to
// tun.Open and client.New.
type openFunc func(name string, mtu int) (tun.Device, error)

type engine interface {
	Run(ctx context.Context) error
}

type engineFunc func(cfg client.Config, dev tun.Device, log *slog.Logger) (engine, error)

// Controller manages a single tunnel session at a time. The zero value is
// not usable; construct with New.
type Controller struct {
	log     *slog.Logger
	openTUN openFunc
	newEng  engineFunc

	mu      sync.Mutex
	active  bool               // a session goroutine is running
	cancel  context.CancelFunc // cancels the active session
	done    chan struct{}      // closed when the active session goroutine exits
	state   State
	server  string
	since   time.Time
	lastErr string
}

// New constructs a Controller in the disconnected state.
func New(log *slog.Logger) *Controller {
	if log == nil {
		log = slog.Default()
	}
	return &Controller{
		log:     log,
		openTUN: tun.Open,
		newEng: func(cfg client.Config, dev tun.Device, l *slog.Logger) (engine, error) {
			return client.New(cfg, dev, l)
		},
		state: StateDisconnected,
	}
}

// Connect brings the tunnel up. It is rejected if a session is already
// active — the front-end must Disconnect first. The TUN device is opened
// here (requiring the daemon's privileges) and owned by the session
// goroutine, which closes it on exit.
func (c *Controller) Connect(req ipc.ConnectRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.active {
		return errors.New("already connected; disconnect first")
	}
	if req.Server == "" {
		return errors.New("server address required")
	}
	if len(req.CACertPEM) == 0 || len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return errors.New("ca/cert/key credentials required")
	}

	mtu := req.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	dev, err := c.openTUN(req.TunName, mtu)
	if err != nil {
		return fmt.Errorf("open tun: %w", err)
	}

	cfg := client.Config{
		Server:     req.Server,
		ServerName: req.ServerName,
		CACertPEM:  req.CACertPEM,
		CertPEM:    req.CertPEM,
		KeyPEM:     req.KeyPEM,
		OnState:    c.onEngineState,
	}
	eng, err := c.newEng(cfg, dev, c.log)
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("init client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.active = true
	c.cancel = cancel
	c.done = done
	c.server = req.Server
	c.lastErr = ""
	c.setStateLocked(StateConnecting)

	go c.run(ctx, eng, dev, done)
	return nil
}

// run drives the engine until it returns (ctx cancel or fatal error), then
// closes the TUN device and records the terminal state.
func (c *Controller) run(ctx context.Context, eng engine, dev tun.Device, done chan struct{}) {
	err := eng.Run(ctx)
	_ = dev.Close()

	c.mu.Lock()
	c.active = false
	c.cancel = nil
	c.done = nil
	if err != nil && ctx.Err() == nil {
		c.lastErr = err.Error()
		c.setStateLocked(StateFailed)
	} else {
		c.setStateLocked(StateDisconnected)
	}
	// Close under the lock so clearing c.active and signalling done happen
	// atomically: a concurrent Connect can't observe active==false and start
	// a new session in the gap before done is closed. close is non-blocking
	// and Disconnect waits on the channel (not the mutex), so no deadlock.
	close(done)
	c.mu.Unlock()
}

// Disconnect tears down the active session and waits for it to finish. It
// is idempotent: a no-op when already disconnected.
func (c *Controller) Disconnect() error {
	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	c.mu.Unlock()

	if cancel == nil {
		return nil // nothing running
	}
	cancel()
	<-done // waits on the channel, not the mutex, so run()'s close-under-lock can't deadlock us
	return nil
}

// Status returns a snapshot of the current connection state.
func (c *Controller) Status() ipc.StatusResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp := ipc.StatusResponse{
		State:     string(c.state),
		Server:    c.server,
		LastError: c.lastErr,
	}
	if !c.since.IsZero() {
		resp.SinceUnix = c.since.Unix()
	}
	return resp
}

// onEngineState maps the client engine's transitions onto controller state.
// It is invoked only from the engine's reconnect-loop goroutine.
func (c *Controller) onEngineState(s client.State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Ignore late callbacks from a session we've already torn down.
	if !c.active {
		return
	}
	switch s {
	case client.StateConnecting:
		c.setStateLocked(StateConnecting)
	case client.StateConnected:
		c.setStateLocked(StateConnected)
	case client.StateReconnecting:
		c.setStateLocked(StateReconnecting)
	}
}

// setStateLocked updates state and stamps the transition time. Caller holds mu.
func (c *Controller) setStateLocked(s State) {
	if c.state == s {
		return
	}
	c.state = s
	c.since = time.Now()
	c.log.Info("tunnel state", "state", s, "server", c.server)
}
