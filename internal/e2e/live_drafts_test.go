package e2e

// Live end-to-end checks for the three drafts merged without a live run:
//   #195 — server admission must not hang on a same-CN kick/teardown
//   #188 — the reconnect loop must re-resolve the server hostname each attempt
//
// Both use the real server + client over a loopback TLS listener (memTUN, so no
// privileged OS network calls). This is the genuine concurrency/reconnect path,
// not a protocol stub. #196's shell-out wrapper can't be reached through memTUN
// (SelfConfigurer bypasses route/dns/firewall); it's exercised live against real
// tools in internal/execx and internal/route instead.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/tunnel/client"
	"github.com/govpn/internal/tunnel/server"
)

// liveCA creates a CA on disk with a server cert (localhost / 127.0.0.1 SANs)
// and one client cert "alice", and returns the CA dir.
func liveCA(t *testing.T) string {
	t.Helper()
	caDir := filepath.Join(t.TempDir(), "ca")
	authority, err := ca.Create(caDir, "live-ca")
	if err != nil {
		t.Fatalf("ca.Create: %v", err)
	}
	if err := authority.IssueServer("live-server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := authority.IssueClient("alice"); err != nil {
		t.Fatalf("IssueClient: %v", err)
	}
	return caDir
}

func liveServerConfig(caDir, listen string) server.Config {
	return server.Config{
		Listen:     listen,
		CACertFile: filepath.Join(caDir, "ca.crt"),
		CertFile:   filepath.Join(caDir, "server", "server.crt"),
		KeyFile:    filepath.Join(caDir, "server", "server.key"),
		Subnet:     "10.8.0.0/24",
		Gateway:    "10.8.0.1",
		Netmask:    "255.255.255.0",
		MTU:        1380,
	}
}

// startLiveServer runs a real server and returns it plus a stop func that
// cancels Run and waits for it to return (freeing the listen port).
func startLiveServer(t *testing.T, cfg server.Config, log *slog.Logger) (*server.Server, func()) {
	t.Helper()
	tun := newMemTUN("live-srv", 1380, 64)
	srv, err := server.New(cfg, tun, log)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	stop := func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Errorf("server goroutine did not exit within 5s after cancel")
			_ = tun.Close()
		}
	}
	waitClosed(t, srv.Ready(), 2*time.Second, "server ready")
	return srv, stop
}

// startLiveClient runs a real client (CN=alice) against server addr, delivering
// state transitions to a buffered channel. reconnMin/Max bound its backoff.
func startLiveClient(t *testing.T, caDir, serverAddr, label string, reconnMin, reconnMax time.Duration, log *slog.Logger) chan client.State {
	t.Helper()
	states := make(chan client.State, 64)
	tun := newMemTUN(label, 1380, 64)
	cli, err := client.New(client.Config{
		Server:       serverAddr,
		CACertFile:   filepath.Join(caDir, "ca.crt"),
		CertFile:     filepath.Join(caDir, "clients", "alice.crt"),
		KeyFile:      filepath.Join(caDir, "clients", "alice.key"),
		ServerName:   "localhost",
		Keepalive:    100 * time.Millisecond,
		ReconnectMin: reconnMin,
		ReconnectMax: reconnMax,
		OnState:      func(s client.State) { states <- s },
	}, tun, log)
	if err != nil {
		t.Fatalf("client.New(%s): %v", label, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cli.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = tun.Close()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Errorf("client %s goroutine did not exit within 5s", label)
		}
	})
	return states
}

// awaitState blocks until `want` is observed on states, or fails after d.
func awaitState(t *testing.T, states <-chan client.State, want client.State, d time.Duration, what string) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case st := <-states:
			if st == want {
				return
			}
		case <-deadline:
			t.Fatalf("timeout (%s) waiting for state %q (%s)", d, want, what)
		}
	}
}

// #195: a second client with the same CN must kick the first and be admitted
// PROMPTLY — the admission goroutine must not pin itself waiting on the kicked
// session's teardown. A healthy teardown fires Done() at once, so the newcomer
// should connect far under kickJoinTimeout (5s). If admission hung, this fails.
func TestLive_SameCN_KickAndAdmitDoesNotHang(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	caDir := liveCA(t)
	srv, stop := startLiveServer(t, liveServerConfig(caDir, "127.0.0.1:0"), log)
	t.Cleanup(stop)

	// Client A connects. Give it a long backoff so that, once B kicks it, A does
	// not immediately re-kick B and muddy the observation window.
	statesA := startLiveClient(t, caDir, srv.Addr().String(), "kick-A", 30*time.Second, 30*time.Second, log)
	awaitState(t, statesA, client.StateConnected, 3*time.Second, "A connected")

	// Client B (same CN) must kick A and get admitted promptly.
	start := time.Now()
	statesB := startLiveClient(t, caDir, srv.Addr().String(), "kick-B", 30*time.Second, 30*time.Second, log)
	awaitState(t, statesB, client.StateConnected, 3*time.Second, "B admitted after kicking A")
	if admit := time.Since(start); admit >= 5*time.Second {
		t.Errorf("B took %v to be admitted; admission hung on the kicked session (kickJoinTimeout=5s)", admit)
	}

	// And A must actually lose its session (kicked), not linger as Connected.
	awaitState(t, statesA, client.StateReconnecting, 3*time.Second, "A kicked off its session")
}

// #188: the reconnect loop must re-run resolveServer (by hostname) on every
// attempt, not just the first — so a server that moves is followed. We prove the
// path lives by bouncing the server on the SAME port: the client can only come
// back if its reconnect re-resolved "localhost" and re-dialed. (That the pin is
// re-pointed to a *changed* IP is covered by route.TestPinServer_RepointsOnChangedIP.)
func TestLive_Reconnect_ReResolvesHostnameAndRecovers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	caDir := liveCA(t)

	// First server on an ephemeral port; capture the port so we can rebind it.
	srv1, stop1 := startLiveServer(t, liveServerConfig(caDir, "127.0.0.1:0"), log)
	_, port, err := net.SplitHostPort(srv1.Addr().String())
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}
	fixed := net.JoinHostPort("127.0.0.1", port)

	// Client dials by HOSTNAME so each connect goes through resolveServer's DNS
	// lookup, not a cached IP literal.
	states := startLiveClient(t, caDir, net.JoinHostPort("localhost", port), "reresolve", 100*time.Millisecond, 500*time.Millisecond, log)
	awaitState(t, states, client.StateConnected, 3*time.Second, "initial connect")

	// Drop the server: the client's session ends and it enters the reconnect loop.
	stop1()
	awaitState(t, states, client.StateReconnecting, 3*time.Second, "client noticed server drop")

	// Bring a fresh server up on the SAME port. The client recovers only if its
	// reconnect re-resolved the hostname and re-dialed.
	_, stop2 := startLiveServer(t, liveServerConfig(caDir, fixed), log)
	t.Cleanup(stop2)
	awaitState(t, states, client.StateConnected, 5*time.Second, "reconnect after re-resolving hostname")
}
