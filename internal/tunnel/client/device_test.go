package client

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingTUN reads until its error is armed, then fails every Read — the shape
// of a device the OS has taken away underneath us.
type failingTUN struct {
	mu  sync.Mutex
	err error
}

func (d *failingTUN) arm(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

func (d *failingTUN) Read(p []byte) (int, error) {
	for {
		d.mu.Lock()
		err := d.err
		d.mu.Unlock()
		if err != nil {
			return 0, err
		}
		time.Sleep(time.Millisecond)
	}
}

func (d *failingTUN) Write(p []byte) (int, error) { return len(p), nil }
func (d *failingTUN) Name() string                { return "utunTest" }
func (d *failingTUN) MTU() int                    { return 1380 }
func (d *failingTUN) Close() error                { return nil }

func testClient(t *testing.T, dev *failingTUN) *Client {
	t.Helper()
	eps, err := normalizeEndpoints(nil, "203.0.113.10:8443", "")
	if err != nil {
		t.Fatalf("normalizeEndpoints: %v", err)
	}
	// Built directly rather than through New: this test never dials, so it has
	// no credentials to load, and New insists on them.
	return &Client{
		cfg:     Config{Server: "203.0.113.10:8443", ReconnectMin: time.Millisecond, ReconnectMax: 2 * time.Millisecond},
		dev:     dev,
		log:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1})),
		ring:    newEndpointRing(eps, ""),
		devDead: make(chan error, 1),
	}
}

// TestDevicePollerDeathStopsReconnecting is the regression guard for a silent
// failure: the poller is one goroutine for the whole Run, so when dev.Read dies
// no packet can ever leave the host again — yet the reconnect loop used to keep
// dialing and the UI kept saying "connected". The loop must now refuse to
// reconnect and exit with a fatal error naming the device.
func TestDevicePollerDeathStopsReconnecting(t *testing.T) {
	dev := &failingTUN{}
	c := testClient(t, dev)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devErr := errors.New("read utunTest: input/output error")
	dev.arm(devErr)
	// Run the poller to completion first, so the loop below starts with the
	// device already reported dead — no timing assumptions in the assertion.
	c.runDevicePoller(ctx, make(chan []byte, outboundBufferDepth))

	select {
	case got := <-c.devDead:
		if !errors.Is(got, devErr) {
			t.Fatalf("devDead carried %v, want %v", got, devErr)
		}
		c.devDead <- got // put it back for the loop to find
	default:
		t.Fatal("poller exited without reporting the device as dead")
	}

	done := make(chan error, 1)
	go func() { done <- c.runReconnectLoop(ctx, make(chan []byte, outboundBufferDepth)) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrFatalConfig) {
			t.Fatalf("loop must exit with a fatal error, got %v", err)
		}
		if !strings.Contains(err.Error(), devErr.Error()) {
			t.Fatalf("error must name the device failure, got %v", err)
		}
	case <-ctx.Done():
		t.Fatal("reconnect loop kept running after the TUN device died")
	}
}

// TestDevicePollerSilentOnShutdown keeps the normal path quiet: when the caller
// cancels and closes the device, the poller's read error is the expected way
// out and must not be reported as a dead device.
func TestDevicePollerSilentOnShutdown(t *testing.T) {
	dev := &failingTUN{}
	c := testClient(t, dev)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dev.arm(errors.New("file already closed"))

	c.runDevicePoller(ctx, make(chan []byte, 1))

	select {
	case err := <-c.devDead:
		t.Fatalf("shutdown must not report a dead device, got %v", err)
	default:
	}
}
