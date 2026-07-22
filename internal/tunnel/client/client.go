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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
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

// writeTimeout bounds a single frame write to the server. Frames are at most
// one MTU, so any healthy path finishes one in milliseconds; this is set far
// above that because the only thing it needs to distinguish is "slow" from
// "the peer stopped reading and never will".
const writeTimeout = 30 * time.Second

// Config holds every knob the client needs at start-up.
//
// Required: Server, CACertFile, CertFile, KeyFile. Everything else has a
// sane default applied by New if left zero.
type Config struct {
	Server     string // "vpn.example.com:8443"
	CACertFile string // ca.crt
	CertFile   string // client.crt
	KeyFile    string // client.key

	// In-memory credentials. When all three are non-empty they are used
	// instead of the *File paths above (the file fields are then ignored).
	// This lets a privileged daemon receive credentials over IPC and build
	// the TLS config without opening any caller-supplied path as root.
	// Supplying some but not all of the three is a configuration error.
	CACertPEM []byte
	CertPEM   []byte
	KeyPEM    []byte

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

	// AllowInsecureLeak keeps a full-tunnel session up even when leak
	// protection (the IPv6 block on macOS/Windows, the kill-switch on Linux)
	// can't be enabled. The default (false) is fail-closed: rather than come up
	// "protected" while IPv6 leaks past the tunnel, the connection is refused.
	// Set it only on a host that can't run the firewall and knowingly accepts
	// the exposure (vpn-client's --allow-insecure-leak).
	AllowInsecureLeak bool

	// OnState, if non-nil, is invoked on connection-state transitions so an
	// embedding daemon can report status. It is called only from Run's
	// reconnect-loop goroutine (never concurrently) and must not block.
	OnState func(State)
}

// State is a coarse connection state reported through Config.OnState.
type State string

const (
	// StateConnecting is emitted at the start of each connect attempt.
	StateConnecting State = "connecting"
	// StateConnected is emitted once the server has assigned an IP and the
	// TUN device is configured (the tunnel is up).
	StateConnected State = "connected"
	// StateReconnecting is emitted while waiting out the backoff before a
	// retry after a dropped or failed attempt.
	StateReconnecting State = "reconnecting"
)

// Client is the long-lived VPN client. Construct with New, drive with Run.
type Client struct {
	cfg       Config
	dev       tun.Device
	log       *slog.Logger
	tlsConfig *tls.Config

	mu             sync.Mutex
	configuredIP   string            // empty until first AssignIP triggers tun.Configure
	routes         *route.Manager    // non-nil after first successful Install
	resolvers      *dns.Manager      // non-nil after first successful Apply
	leakguard      *firewall.Manager // non-nil after IPv6 leak protection is enabled
	leakguardOff   bool              // a block attempt failed; don't retry/re-warn each reconnect
	pinnedServerIP netip.Addr        // server IP the pin-hole/kill-switch currently allow
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
	// Credentials come either fully in-memory (PEM) or fully from files.
	nPEM := btoi(len(cfg.CACertPEM) > 0) + btoi(len(cfg.CertPEM) > 0) + btoi(len(cfg.KeyPEM) > 0)
	inlineCreds := nPEM > 0
	if inlineCreds && nPEM != 3 {
		return nil, fmt.Errorf("client: CACertPEM/CertPEM/KeyPEM must all be set together")
	}
	if !inlineCreds && (cfg.CACertFile == "" || cfg.CertFile == "" || cfg.KeyFile == "") {
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

	var (
		tlsCfg *tls.Config
		err    error
	)
	if inlineCreds {
		tlsCfg, err = tlsConfigFromPEM(cfg.CACertPEM, cfg.CertPEM, cfg.KeyPEM, cfg.ServerName)
	} else {
		tlsCfg, err = loadTLSConfig(cfg.CACertFile, cfg.CertFile, cfg.KeyFile, cfg.ServerName)
	}
	if err != nil {
		return nil, err
	}

	// The raw credential PEM is no longer needed once tlsCfg holds the parsed
	// key and certs. Drop the references so the private key in particular
	// doesn't linger in the Client (and its memory/core dumps) for the whole
	// session. Best-effort: the GC reclaims the backing arrays once no other
	// reference remains; this just stops Client from being one such reference.
	cfg.CACertPEM, cfg.CertPEM, cfg.KeyPEM = nil, nil, nil

	return &Client{cfg: cfg, dev: dev, log: log, tlsConfig: tlsCfg}, nil
}

// btoi returns 1 for true and 0 for false.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// emitState forwards a state transition to Config.OnState if set.
func (c *Client) emitState(s State) {
	if c.cfg.OnState != nil {
		c.cfg.OnState(s)
	}
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
	// Tear down in reverse of install (leak-block → routes → DNS): drop DNS,
	// then the routes, and unblock IPv6 LAST. That preserves the invariant
	// "IPv6 stays blocked while the IPv4 default still points into the
	// tunnel" — important once a kill-switch is layered on here.
	if dm != nil {
		dm.Remove()
	}
	if rm != nil {
		rm.Remove()
	}
	if fm != nil {
		fm.Remove()
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
	// Resolve the server ourselves so we can pin the exact address we dial. A
	// server behind DNS (DDNS / failover / round-robin) can move between
	// reconnects; letting the dialer resolve would connect to the new IP while
	// the pin-hole and kill-switch still allow only the old one, black-holing
	// the dial (#126).
	serverIP, port, err := c.resolveServer(ctx)
	if err != nil {
		return err // retryable: DNS may recover
	}
	// Before dialing, re-point the pin-hole (and kill-switch) at serverIP — both
	// to follow a moved server and to re-assert the route across a local network
	// change (Wi-Fi drop/rejoin) that may have flushed the pin-hole.
	c.preparePath(serverIP)

	dialer := &tls.Dialer{Config: c.tlsConfig}
	// Dial the resolved IP, not the hostname: tlsConfig.ServerName still carries
	// the hostname, so SNI and certificate verification are unchanged.
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(serverIP.String(), port))
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

	// Version negotiation (#143). Reject a server too old for this build with a
	// clear message rather than an opaque mid-session failure, then announce our
	// own version so a newer server can reject us the same way. A pre-versioning
	// server advertises 0 and is accepted (PeerCompatible); the Hello is additive
	// — older servers ignore the unknown control type.
	if !tunnel.PeerCompatible(assign.ProtoVersion) {
		return fmt.Errorf("%w: server speaks protocol v%d, this app needs at least v%d — update the server",
			ErrFatalServer, assign.ProtoVersion, tunnel.MinPeerVersion)
	}
	if hello, herr := tunnel.NewHello(tunnel.ProtocolVersion); herr == nil {
		if werr := tunnel.WriteControl(tlsConn, hello); werr != nil {
			return classifyConnectError(werr)
		}
	}

	c.log.Info("connected",
		"server", c.cfg.Server,
		"assigned", assign.IP,
		"gateway", assign.Gateway,
		"mtu", assign.MTU,
		"server_proto", assign.ProtoVersion,
	)

	if err := c.ensureConfigured(assign); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	// Enable leak protection BEFORE flipping the IPv4 default into the
	// tunnel, so there's no window where v4 is already tunnelled but
	// traffic still leaks out the open interface. Fail-closed: if it can't be
	// established (and the user hasn't opted into --allow-insecure-leak), abort
	// rather than come up leaking.
	if err := c.ensureLeakProtection(assign, tlsConn.RemoteAddr()); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	if err := c.ensureRoutes(assign, tlsConn.RemoteAddr()); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	if err := c.ensureDNS(assign); err != nil {
		return fmt.Errorf("%w: %v", ErrFatalConfig, err)
	}

	// The tunnel is now fully up (IP assigned, TUN/routes/DNS configured).
	c.emitState(StateConnected)

	// Hand the live conn to runSession; it owns the connection from here
	// on (and will Close it on its own way out). The read-idle deadline is
	// derived from the server's advertised keepalive (see readIdleTimeout).
	closeConn = false
	return c.runSession(ctx, tlsConn, outbound, c.readIdleTimeout(assign))
}

// readIdleTimeout is how long connReader waits for ANY frame before declaring
// the connection dead. The pulse that keeps a healthy idle tunnel alive is the
// SERVER's keepalive, so the timeout is a multiple of the SERVER's interval
// (advertised in AssignIP) — not the client's own send interval. Otherwise a
// server pinging slower than 3× the client's interval would trip the deadline on
// a perfectly healthy connection (#179). Falls back to the client's interval for
// older servers that don't advertise one, and is 0 (disabled) when neither side
// runs keepalives.
func (c *Client) readIdleTimeout(a tunnel.AssignIP) time.Duration {
	if a.KeepaliveSecs > 0 {
		// Clamp the server-advertised interval before scaling: an absurd value
		// (corrupt/hostile/typo'd server config) could otherwise overflow
		// time.Duration and wrap to a negative or never-firing deadline, silently
		// disabling the dead-link detection this exists for.
		secs := min(a.KeepaliveSecs, maxAdvertisedKeepaliveSecs)
		return 3 * time.Duration(secs) * time.Second
	}
	if c.cfg.Keepalive > 0 {
		return 3 * c.cfg.Keepalive
	}
	return 0
}

// maxAdvertisedKeepaliveSecs caps a server-advertised keepalive interval. An
// hour is already far beyond any sane keepalive; the cap only exists to keep the
// 3× read-idle deadline from overflowing on a garbage value.
const maxAdvertisedKeepaliveSecs = 3600

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

	serverIP, err := serverIPFromRemote(remote)
	if err != nil {
		return err
	}

	mgr := route.New(c.log, c.dev.Name(), tunGW, serverIP)
	if err := mgr.Install(a.Routes); err != nil {
		return err
	}
	c.routes = mgr
	c.log.Info("system routes installed", "count", len(a.Routes), "via", tunGW, "server-pinhole", serverIP)
	return nil
}

// resolveServer resolves the configured Server (host:port) into a concrete IP
// and port string. A hostname goes through the system resolver; an IP literal
// is returned as-is. We resolve here — rather than let the dialer do it — so the
// address we pin is exactly the address we dial (#126). IPv4 is preferred: the
// data plane is IPv4-only.
func (c *Client) resolveServer(ctx context.Context) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(c.cfg.Server)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("client: bad server address %q: %w", c.cfg.Server, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), port, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("client: resolve %q: %w", host, err)
	}
	var fallback netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, port, nil
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	if fallback.IsValid() {
		return fallback, port, nil
	}
	return netip.Addr{}, "", fmt.Errorf("client: no addresses for %q", host)
}

// preparePath re-points the server pin-hole and, on Linux, the kill-switch at
// serverIP before a (re)connect dial. It's a no-op on the first connect — the
// managers aren't built yet, and ensureRoutes/ensureLeakProtection will pin the
// IP we dial. Re-pointing the pin-hole also re-asserts it across a local network
// change (Wi-Fi drop/rejoin) that may have flushed it (the "eternal reconnect"
// case). Best-effort: a failure is logged and the dial proceeds (and then
// fails/retries), so this never makes reconnect worse.
func (c *Client) preparePath(serverIP netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.routes != nil {
		if err := c.routes.PinServer(serverIP); err != nil {
			c.log.Debug("server pin-hole prepare skipped", "err", err)
		}
	}

	// If the server moved, the kill-switch still allows only the old IP and
	// would block the dial to the new one — re-point it. Brief window where leak
	// protection is down, but we're already disconnected here, and this only
	// runs when the resolved IP actually changed.
	if c.leakguard != nil && c.pinnedServerIP.IsValid() && serverIP != c.pinnedServerIP {
		c.leakguard.Remove()
		cfg := firewall.Config{ServerIP: serverIP, TunIface: c.dev.Name(), AllowLAN: true}
		if err := c.leakguard.Enable(cfg); err != nil {
			c.log.Warn("re-pointing leak protection failed; run 'vpn-client --clear-firewall' if the network is stuck", "err", err)
			c.leakguardOff = true
			c.leakguard = nil
		}
	}

	if serverIP.IsValid() {
		c.pinnedServerIP = serverIP
	}
}

// ensureLeakProtection enables leak protection on the first AssignIP that
// makes this a full-tunnel client. On Linux that's a kill-switch (egress is
// default-deny except the tunnel, the server pin-hole, loopback, DHCP and
// local networks), so a dropped tunnel can't leak; on macOS/Windows it's an
// IPv6-only block (the data plane is IPv4-only, so a redirected IPv4 default
// would otherwise leak all IPv6 out the open interface). On reconnects (or
// split-tunnel) it's a no-op.
//
// Failure is fail-closed: if protection can't be established the connection is
// refused (returns an error), so a full-tunnel session never comes up
// "protected" while traffic leaks past it. The failure causes (tool missing,
// no privileges) are static, so wrapping in ErrFatalConfig stops the reconnect
// loop rather than looping forever. Config.AllowInsecureLeak (vpn-client
// --allow-insecure-leak) opts back into the old warn-and-continue for a host
// that can't run the firewall and knowingly accepts the exposure — see
// leakProtectionUnavailable.
func (c *Client) ensureLeakProtection(a tunnel.AssignIP, remote net.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.leakguard != nil || c.leakguardOff {
		return nil
	}
	if !isFullTunnel(a.Routes) {
		return nil
	}

	serverIP, err := serverIPFromRemote(remote)
	if err != nil {
		return c.leakProtectionUnavailable("cannot determine server IP for leak protection", err)
	}

	mgr := firewall.New(c.log)
	cfg := firewall.Config{
		ServerIP: serverIP,
		TunIface: c.dev.Name(),
		AllowLAN: true, // local networks stay reachable (LAN devices, DHCP)
	}
	if err := mgr.Enable(cfg); err != nil {
		return c.leakProtectionUnavailable("could not enable leak protection", err)
	}
	c.leakguard = mgr
	return nil
}

// leakProtectionUnavailable decides what happens when full-tunnel leak
// protection can't be established. Full-tunnel redirects the IPv4 default into
// the tunnel; without the leak guard (an IPv6 block on macOS/Windows, a
// kill-switch on Linux) IPv6 — and, on a tunnel drop, everything — would escape
// the open interface while the UI still says "protected". So the default is
// fail-closed: return an error and let the caller abort the connection, rather
// than come up leaking. Config.AllowInsecureLeak restores the old
// warn-and-continue for a host that can't run the firewall and knowingly
// accepts the exposure. The caller holds c.mu.
func (c *Client) leakProtectionUnavailable(what string, cause error) error {
	if c.cfg.AllowInsecureLeak {
		c.log.Warn("leak protection unavailable; continuing anyway (--allow-insecure-leak): traffic may bypass the tunnel — check privileges, or run 'vpn-client --clear-firewall' to unstick the network",
			"what", what, "err", cause)
		c.leakguardOff = true
		return nil
	}
	return fmt.Errorf("%s: %w — refusing to connect so traffic can't leak past the tunnel; fix privileges/tooling, or pass --allow-insecure-leak to connect without it", what, cause)
}

// serverIPFromRemote extracts the VPN server's IP from the TLS connection's
// remote address (used for both the route pin-hole and the kill-switch
// allow rule).
func serverIPFromRemote(remote net.Addr) (netip.Addr, error) {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok || tcp == nil {
		return netip.Addr{}, fmt.Errorf("remote addr is not TCPAddr (%T)", remote)
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid server IP %v", tcp.IP)
	}
	return ip.Unmap(), nil // 4-in-6 → 4
}

// isFullTunnel reports whether any pushed route is a default route (/0),
// i.e. the client is redirecting all traffic through the tunnel. Invalid
// CIDRs are ignored here: ensureRoutes is the authority on route validity
// and aborts the connection on a bad CIDR. (We may briefly block IPv6 for
// an attempt that then fails; teardown undoes it.)
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
// errors on an already-present address).
//
// If the server hands out a DIFFERENT IP after reconnect (our lease expired and
// the address was reassigned), the tunnel is effectively dead: the TUN still
// carries the old IP, the server now delivers traffic to the new one, and
// anti-spoof drops our packets sent from the old source. Re-addressing the
// adapter mid-flight would need a teardown that's out of scope here, so we fail
// loudly. The caller turns this into a fatal error, which is honest — far better
// than reporting Connected on a tunnel that carries nothing.
func (c *Client) ensureConfigured(a tunnel.AssignIP) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.configuredIP == "" {
		// Apply the server-pushed MTU (only when it narrows the interface): if
		// the server routes over a smaller MTU, locally-generated packets sized
		// to our default would be dropped or fragmented server-side — a PMTU
		// black hole invisible to ping. Widening is refused: the read buffers are
		// sized for the device's open MTU (#146).
		mtu := effectiveMTU(c.dev.MTU(), a.MTU)
		if err := tun.Configure(c.dev, a.IP, a.Netmask, a.Gateway, mtu); err != nil {
			return fmt.Errorf("configure TUN: %w", err)
		}
		c.configuredIP = a.IP
		c.log.Info("TUN configured", "iface", c.dev.Name(), "ip", a.IP, "gw", a.Gateway, "mask", a.Netmask, "mtu", mtu)
		return nil
	}
	if c.configuredIP != a.IP {
		return fmt.Errorf("server reassigned IP after reconnect (had %s, now %s); restart to reconnect",
			c.configuredIP, a.IP)
	}
	return nil
}

// effectiveMTU returns the MTU to program on the interface: the server-pushed
// value when it is a valid narrowing of the device's own MTU, else the device's
// MTU. Only narrowing is honoured — a larger pushed MTU could exceed the read
// buffers the device was opened with, and isn't the PMTU-blackhole case anyway.
func effectiveMTU(deviceMTU, pushed int) int {
	if pushed > 0 && pushed < deviceMTU {
		return pushed
	}
	return deviceMTU
}

// runSession runs the three (or two) goroutines that drive a live
// connection: conn-reader (server → TUN), outbound-pump (TUN → server)
// and an optional keepalive ticker. It returns when the first one errors
// or ctx is cancelled.
func (c *Client) runSession(ctx context.Context, conn *tls.Conn, outbound <-chan []byte, readIdle time.Duration) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = conn.Close() }()

	w := newConnWriter(conn, writeTimeout)
	errCh := make(chan error, 3) // bounded by # of goroutines below

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- c.connReader(sessionCtx, conn, readIdle)
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
	// Unblock the session goroutines WITHOUT a second Close: the deferred
	// Close is the single owner of closing conn (a double Close risks a
	// use-after-close fd-reuse race). A past deadline on BOTH directions makes
	// a parked Read (connReader) and a parked Write (outboundPump/keepalive,
	// when the server has stopped reading) return promptly. The one spot it
	// can't cover is connReader sitting in dev.Write (the TUN, not the conn);
	// that unblocks only when the write completes, which it does promptly on a
	// healthy device. Each goroutine then maps its error to a clean exit
	// because sessionCtx is already cancelled.
	_ = conn.SetDeadline(time.Now())

	// errCh is buffered to one slot per goroutine, so every goroutine can send
	// its single result and exit without a reader — wg.Wait can't deadlock on a
	// blocked send, and no drain goroutine is needed. (It still assumes the
	// goroutines actually return; see the deadline note above plus the
	// cancelled sessionCtx they all observe.)
	wg.Wait()
	close(errCh)

	return firstErr
}

// connReader pulls frames from the server and dispatches them.
// Data frames go straight to the TUN device (no anti-spoof needed —
// these are packets the server is delivering to us). Control frames are
// inspected; an explicit Error message ends the session as fatal.
func (c *Client) connReader(ctx context.Context, conn *tls.Conn, idle time.Duration) error {
	// Read-idle detection. A server whose process has wedged while its kernel
	// keeps the TCP session open sends nothing, and without a deadline this
	// Read parks forever: the session never ends, the reconnect loop never
	// runs, and the user keeps seeing "Connected" on a tunnel carrying nothing.
	//
	// idle is derived from the server's advertised keepalive (see
	// readIdleTimeout); 0 disables the check. The deadline is armed only after
	// the first server-sent keepalive, which is what makes it safe to ship
	// against an already-deployed server: older servers never send them, so the
	// deadline is never armed and those connections behave exactly as before.
	// Once a server has proved it sends keepalives, silence for several intervals
	// means the path is dead.
	armed := false

	for {
		if armed {
			if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
				return fmt.Errorf("client: set read deadline: %w", err)
			}
		}
		typ, body, err := tunnel.ReadPacket(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if armed && errors.Is(err, os.ErrDeadlineExceeded) {
				return fmt.Errorf("client: no frame from server for %s — connection is dead", idle)
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
				// rx is proof of life. It also tells us this server sends
				// keepalives on a schedule, so from here on their absence is
				// meaningful and the idle deadline can be enforced.
				if idle > 0 {
					armed = true
				}
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
	// timeout bounds each write. A peer whose kernel still holds the TCP
	// session but whose process has stopped reading eventually fills the send
	// buffer, and an unbounded Write parks there forever — taking the writer's
	// mutex with it, so the keepalive can't run either and nothing ever errors.
	// The session then never ends and the user keeps seeing "Connected".
	// 0 disables the bound.
	timeout time.Duration
}

func newConnWriter(conn net.Conn, timeout time.Duration) *connWriter {
	return &connWriter{conn: conn, timeout: timeout}
}

// write runs fn under the writer's lock with a fresh write deadline applied.
//
// The deadline is deliberately not cleared afterwards. Every write sets its
// own, so a leftover one can never shorten a later write; and clearing it would
// wipe the past deadline runSession's teardown sets to unpark writers that are
// parked on a peer which stopped reading.
func (w *connWriter) write(fn func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timeout > 0 {
		if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
			return err
		}
	}
	return fn()
}

func (w *connWriter) Data(pkt []byte) error {
	return w.write(func() error { return tunnel.WriteData(w.conn, pkt) })
}

func (w *connWriter) Control(msg tunnel.ControlMessage) error {
	return w.write(func() error { return tunnel.WriteControl(w.conn, msg) })
}
