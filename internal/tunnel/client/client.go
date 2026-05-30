// Package client implements the VPN client: TLS+mTLS dial to the server,
// receive an IP assignment, configure the local TUN device, and proxy
// IP packets in both directions until the server disconnects or ctx is
// cancelled. Disconnects trigger an exponential-backoff reconnect.
//
// Concurrency model (one connect attempt):
//
//	┌─────────────────┐ outbound chan ┌────────────────┐
//	│ devicePoller    │──────────────▶│ outboundPump   │──▶ TLS conn (data)
//	│ (lives w/ Run)  │               │ (per attempt)  │
//	└─────────────────┘               └────────────────┘
//	                                         ▲
//	                                         │ ctrl (keepalive)
//	                                         │
//	                                  ┌──────────────┐
//	                                  │ keepalive    │
//	                                  │ ticker       │
//	                                  └──────────────┘
//
//	TLS conn (read) → connReader → either dev.Write (data) or process control
//
// The TLS conn is not safe for concurrent Writes, so a connWriter
// mutex-serializes every WriteData / WriteControl. The TUN device is owned
// by the caller (cmd/vpn-client) and lives across reconnects; a single
// long-lived devicePoller drains it into a buffered channel so attempt
// goroutines never race on dev.Read.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/govpn/internal/dns"
	"github.com/govpn/internal/firewall"
	"github.com/govpn/internal/route"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel"
)

// outboundBufferDepth caps how many IP packets we buffer between the TUN
// poller and the (re-)connected TLS writer. When full, the poller drops
// the newest packet — the apps will retransmit.
const outboundBufferDepth = 64

// Config holds every knob the client needs at start-up.
//
// Required: Server, CACertFile, CertFile, KeyFile. Everything else has a
// sane default applied by New if left zero.
type Config struct {
	Server     string // "vpn.example.com:8443"
	CACertFile string // ca.crt
	CertFile   string // client.crt
	KeyFile    string // client.key

	// ServerName is the SNI / hostname-verification target. Defaults to
	// the host part of Server if empty.
	ServerName string

	// Keepalive sends a control-frame ping on this interval. 0 = off.
	Keepalive time.Duration

	// ReconnectMin/Max bound the exponential backoff between attempts.
	// Defaults: 1s / 60s.
	ReconnectMin time.Duration
	ReconnectMax time.Duration

	// HandshakeTimeout caps how long we wait for the server's first
	// control frame (AssignIP or Error) after the TLS handshake.
	// Default: 10s.
	HandshakeTimeout time.Duration
}

// Client is the long-lived VPN client. Construct with New, drive with Run.
type Client struct {
	cfg       Config
	dev       tun.Device
	log       *slog.Logger
	tlsConfig *tls.Config

	mu           sync.Mutex
	configuredIP string            // empty until first AssignIP triggers tun.Configure
	routes       *route.Manager    // non-nil after first successful Install
	resolvers    *dns.Manager      // non-nil after first successful Apply
	leakguard    *firewall.Manager // non-nil after IPv6 leak protection is enabled
}

// New constructs a Client. dev must already be Open()ed; ownership stays
// with the caller, who must Close() it after Run returns.
func New(cfg Config, dev tun.Device, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	if dev == nil {
		return nil, fmt.Errorf("client: nil TUN device")
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("client: empty Server")
	}
	if cfg.CACertFile == "" || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("client: CA/cert/key files all required")
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = 1 * time.Second
	}
	if cfg.ReconnectMax <= 0 {
		cfg.ReconnectMax = 60 * time.Second
	}
	if cfg.ReconnectMin > cfg.ReconnectMax {
		return nil, fmt.Errorf("client: ReconnectMin %v > ReconnectMax %v", cfg.ReconnectMin, cfg.ReconnectMax)
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.Server)
		if err != nil || host == "" {
			return nil, fmt.Errorf("client: cannot derive ServerName from Server=%q: %w", cfg.Server, err)
		}
		cfg.ServerName = host
	}

	tlsCfg, err := loadTLSConfig(cfg.CACertFile, cfg.CertFile, cfg.KeyFile, cfg.ServerName)
	if err != nil {
		return nil, err
	}

	return &Client{cfg: cfg, dev: dev, log: log, tlsConfig: tlsCfg}, nil
}

// Run blocks until ctx is cancelled (returns nil) or a non-retryable
// error fires (returns the error). The TUN device is NOT closed by Run.
//
// The devicePoller goroutine may still be blocked in dev.Read when Run
// returns; the caller's dev.Close() will unblock it. Run does not wait
// on the poller — waiting would deadlock callers that defer dev.Close
// after Run.
//
// Routes installed in the system routing table during the first successful
// AssignIP are torn down on Run exit (success or failure), best effort.
func (c *Client) Run(ctx context.Context) error {
	outbound := make(chan []byte, outboundBufferDepth)

	go c.runDevicePoller(ctx, outbound)

	err := c.runReconnectLoop(ctx, outbound)

	c.mu.Lock()
	rm := c.routes
	dm := c.resolvers
	fm := c.leakguard
	c.routes = nil
	c.resolvers = nil
	c.leakguard = nil
	c.mu.Unlock()
	if dm != nil {
		dm.Remove()
	}
	if fm != nil {
		fm.Remove()
	}
	if rm != nil {
		rm.Remove()
	}
	return err
}

// runDevicePoller drains dev.Read into outbound. Exits when dev.Read
// returns an error (typically because the caller closed the device after
// Run returned).
func (c *Client) runDevicePoller(ctx context.Context, outbound chan<- []byte) {
	buf := make([]byte, c.dev.MTU()+64) // +64 for any overhead/safety

	for {
		n, err := c.dev.Read(buf)
		if err != nil {
			c.log.Debug("device poller exiting", "err", err)
			return
		}
		if n == 0 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case outbound <- pkt:
		default:
			// Queue full (we're disconnected or the writer is slow);
			// drop the newest packet. The TCP/UDP layer above will
			// retransmit if it cares.
			c.log.Debug("outbound queue full; packet dropped")
		}

		// Cheap ctx check between reads — won't preempt a blocked Read
		// but lets us exit promptly between bursts.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// connectOnce performs a single connect attempt: TLS dial, expect an
// AssignIP (or Error) on the first frame, configure TUN (first time
// only), then run the bidirectional packet loop until the session ends.
//
// Returns nil if ctx caused a clean exit. Returns a fatal error
// (wrapping one of the sentinels) if the failure shouldn't be retried.
// Otherwise returns a retryable error.
func (c *Client) connectOnce(ctx context.Context, outbound <-chan []byte) error {
	dialer := &tls.Dialer{Config: c.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return classifyConnectError(err)
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("client: dial returned non-TLS conn (%T)", conn)
	}
	// Make sure conn is closed on every error path below.
	closeConn := true
	defer func() {
		if closeConn {
			_ = tlsConn.Close()
		}
	}()

	// First frame must be a Control message: AssignIP or Error. TLS 1.3
	// "bad certificate" alerts surface here, not in DialContext.
	_ = tlsConn.SetReadDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	typ, body, err := tunnel.ReadPacket(tlsConn)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return classifyConnectError(err)
	}
	if typ != tunnel.FrameControl {
		return fmt.Errorf("client: expected control frame, got type 0x%02x", typ)
	}
	msg, err := tunnel.DecodeControl(body)
	if err != nil {
		return fmt.Errorf("client: decode first control: %w", err)
	}

	switch msg.Type {
	case tunnel.CtrlError:
		emsg, perr := tunnel.ParseError(msg)
		if perr != nil {
			return fmt.Errorf("client: %w", perr)
		}
		return fmt.Errorf("%w: %s: %s", ErrFatalServer, emsg.Code, emsg.Message)
	case tunnel.CtrlAssignIP:
		// proceed below
	default:
		return fmt.Errorf("client: unexpected first control type %q", msg.Type)
	}

	assign, err := tunnel.ParseAssignIP(msg)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	c.log.Info("connected",
		"server", c.cfg.Server,
		"assigned", assign.IP,
		"gateway", assign.Gateway,
		"mtu", assign.MTU,
	)

	if err := c.ensureConfigured(assign); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	if err := c.ensureRoutes(assign, tlsConn.RemoteAddr()); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	c.ensureLeakProtection(assign)

	if err := c.ensureDNS(assign); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	// Hand the live conn to runSession; it owns the connection from here
	// on (and will Close it on its own way out).
	closeConn = false
	return c.runSession(ctx, tlsConn, outbound)
}

// ensureRoutes installs the pushed routes on the first successful AssignIP.
// On subsequent reconnects it's a no-op — we don't try to update the
// routing table mid-flight (the original default gateway may have changed,
// and a fresh install would need an OS-aware "is current pin-hole still
// valid?" check that's out of scope here).
//
// If AssignIP carries no routes, this is a no-op too — server is asking
// for a private-LAN-only setup.
func (c *Client) ensureRoutes(a tunnel.AssignIP, remote net.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.routes != nil {
		return nil
	}
	if len(a.Routes) == 0 {
		return nil
	}

	tunGW, err := netip.ParseAddr(a.Gateway)
	if err != nil {
		return fmt.Errorf("parse tunnel gateway %q: %w", a.Gateway, err)
	}

	tcp, ok := remote.(*net.TCPAddr)
	if !ok || tcp == nil {
		return fmt.Errorf("remote addr is not TCPAddr (%T)", remote)
	}
	serverIP, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return fmt.Errorf("invalid server IP %v", tcp.IP)
	}
	serverIP = serverIP.Unmap() // 4-in-6 → 4

	mgr := route.New(c.log, c.dev.Name(), tunGW, serverIP)
	if err := mgr.Install(a.Routes); err != nil {
		return err
	}
	c.routes = mgr
	c.log.Info("system routes installed", "count", len(a.Routes), "via", tunGW, "server-pinhole", serverIP)
	return nil
}

// ensureLeakProtection blocks routable IPv6 egress on the first AssignIP
// that makes this a full-tunnel client. The data plane is IPv4-only, so a
// redirected IPv4 default leaves the host's untouched IPv6 default free to
// carry traffic straight out the open network — a real address leak.
// Blocking global-unicast IPv6 makes dual-stack apps fall back to IPv4,
// which the tunnel carries. On reconnects (or split-tunnel) it's a no-op.
//
// Failure is deliberately NON-fatal: a host without nft / an OS firewall
// shouldn't be unable to connect at all. We log loudly and carry on — no
// worse than the prior behaviour, which never blocked IPv6. Hardening to
// fail-closed is tracked as follow-up.
func (c *Client) ensureLeakProtection(a tunnel.AssignIP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.leakguard != nil {
		return
	}
	if !isFullTunnel(a.Routes) {
		return
	}

	mgr := firewall.New(c.log)
	if err := mgr.BlockIPv6(); err != nil {
		c.log.Warn("IPv6 leak protection failed; IPv6 traffic may bypass the tunnel — block it manually or run with privileges", "err", err)
		return
	}
	c.leakguard = mgr
}

// isFullTunnel reports whether any pushed route is a default route (/0),
// i.e. the client is redirecting all traffic through the tunnel. Invalid
// CIDRs are ignored: ensureRoutes runs first and is the authority on route
// validity — it has already failed the connection before we get here.
func isFullTunnel(routes []string) bool {
	for _, raw := range routes {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Bits() == 0 {
			return true
		}
	}
	return false
}

// ensureDNS pushes the resolvers from AssignIP into the OS resolver
// config on the first successful reception. On subsequent reconnects it's
// a no-op — see ensureRoutes for the rationale.
func (c *Client) ensureDNS(a tunnel.AssignIP) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.resolvers != nil {
		return nil
	}
	if len(a.DNS) == 0 {
		return nil
	}

	mgr := dns.New(c.log, c.dev.Name())
	if err := mgr.Apply(a.DNS); err != nil {
		return err
	}
	c.resolvers = mgr
	return nil
}

// ensureConfigured calls tun.Configure on the FIRST successful AssignIP.
// Subsequent reconnects with the same IP are no-ops (Linux `ip addr add`
// errors on an already-present address). If the server hands out a
// different IP after reconnect, we log a warning and keep the old config —
// changing IPs mid-flight would require an adapter teardown that's out of
// block-6 scope.
func (c *Client) ensureConfigured(a tunnel.AssignIP) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.configuredIP == "" {
		if err := tun.Configure(c.dev, a.IP, a.Netmask, a.Gateway); err != nil {
			return fmt.Errorf("configure TUN: %w", err)
		}
		c.configuredIP = a.IP
		c.log.Info("TUN configured", "iface", c.dev.Name(), "ip", a.IP, "gw", a.Gateway, "mask", a.Netmask)
		return nil
	}
	if c.configuredIP != a.IP {
		c.log.Warn("server reassigned IP after reconnect; keeping old TUN config",
			"had", c.configuredIP, "now", a.IP)
	}
	return nil
}

// runSession runs the three (or two) goroutines that drive a live
// connection: conn-reader (server → TUN), outbound-pump (TUN → server)
// and an optional keepalive ticker. It returns when the first one errors
// or ctx is cancelled.
func (c *Client) runSession(ctx context.Context, conn *tls.Conn, outbound <-chan []byte) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = conn.Close() }()

	w := newConnWriter(conn)
	errCh := make(chan error, 3) // bounded by # of goroutines below

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- c.connReader(sessionCtx, conn)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- c.outboundPump(sessionCtx, w, outbound)
	}()

	if c.cfg.Keepalive > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- c.keepalive(sessionCtx, w)
		}()
	}

	// Wait for the first event: either a goroutine returns an error, or
	// the parent ctx is cancelled (clean shutdown).
	var firstErr error
	select {
	case firstErr = <-errCh:
	case <-ctx.Done():
		firstErr = nil
	}

	cancel()
	_ = conn.Close() // unblock connReader if it's still in Read

	// Drain remaining errors so wg.Wait completes. We've already picked
	// firstErr; the rest are noise (typically nil from ctx-cancel exits).
	go func() {
		for range errCh {
		}
	}()
	wg.Wait()
	close(errCh)

	return firstErr
}

// connReader pulls frames from the server and dispatches them.
// Data frames go straight to the TUN device (no anti-spoof needed —
// these are packets the server is delivering to us). Control frames are
// inspected; an explicit Error message ends the session as fatal.
func (c *Client) connReader(ctx context.Context, conn *tls.Conn) error {
	for {
		typ, body, err := tunnel.ReadPacket(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("client: read packet: %w", err)
		}
		switch typ {
		case tunnel.FrameData:
			if _, err := c.dev.Write(body); err != nil {
				return fmt.Errorf("client: write to TUN: %w", err)
			}
		case tunnel.FrameControl:
			msg, derr := tunnel.DecodeControl(body)
			if derr != nil {
				c.log.Debug("bad control frame from server", "err", derr)
				continue
			}
			switch msg.Type {
			case tunnel.CtrlKeepalive:
				// rx is proof of life — nothing to do.
			case tunnel.CtrlError:
				emsg, _ := tunnel.ParseError(msg)
				return fmt.Errorf("%w: %s: %s", ErrFatalServer, emsg.Code, emsg.Message)
			default:
				c.log.Debug("ignoring unexpected control type", "type", msg.Type)
			}
		}
	}
}

// outboundPump drains the TUN→conn channel and writes each packet to the
// server. Exits on ctx-cancel (nil) or write error.
func (c *Client) outboundPump(ctx context.Context, w *connWriter, outbound <-chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-outbound:
			if err := w.Data(pkt); err != nil {
				return fmt.Errorf("client: write data: %w", err)
			}
		}
	}
}

// keepalive sends a Control(Keepalive) every cfg.Keepalive. The server
// doesn't reply explicitly — receiving any frame from it during normal
// traffic counts as keepalive too, but we send these to keep the
// TCP/TLS path warm (NAT timeouts, dead-peer detection on routers).
func (c *Client) keepalive(ctx context.Context, w *connWriter) error {
	t := time.NewTicker(c.cfg.Keepalive)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := w.Control(tunnel.NewKeepalive()); err != nil {
				return fmt.Errorf("client: keepalive: %w", err)
			}
		}
	}
}

// connWriter serializes Writes to the TLS connection. Both
// tunnel.WriteData and tunnel.WriteControl emit a length-prefix header
// followed by a payload as two separate Write calls — concurrent
// invocations on the same conn would interleave those, corrupting the
// frame stream. Every producer must go through this writer.
type connWriter struct {
	conn net.Conn
	mu   sync.Mutex
}

func newConnWriter(conn net.Conn) *connWriter {
	return &connWriter{conn: conn}
}

func (w *connWriter) Data(pkt []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return tunnel.WriteData(w.conn, pkt)
}

func (w *connWriter) Control(msg tunnel.ControlMessage) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return tunnel.WriteControl(w.conn, msg)
}
