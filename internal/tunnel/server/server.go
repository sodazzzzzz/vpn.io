// Package server implements the VPN server: TLS listener with mTLS,
// per-client TUN routing, and lifecycle management.
//
// Concurrency model:
//
//	┌────────────┐  one goroutine per connection
//	│ acceptLoop │──┐
//	└────────────┘  │
//	                ▼
//	         ┌──────────────┐    pkt copy → outbound chan
//	         │ sessionReader│────────────────────────────┐
//	         └──────────────┘                            │
//	                                                     ▼
//	┌────────────┐                              ┌───────────────┐
//	│tun.Reader  │────dst lookup───────────────▶│sessionWriter  │
//	│(1 routine) │  registry.ByIPv4             │(per session)  │
//	└────────────┘                              └───────────────┘
//
// The TUN device is shared (Read by router, Write by every sessionReader);
// wireguard/tun is documented to allow concurrent Read+Write.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/govpn/internal/ipalloc"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel"
)

// Config carries every knob the server needs at start-up.
type Config struct {
	Listen     string // ":8443"
	CACertFile string
	CertFile   string
	KeyFile    string
	Subnet     string        // "10.8.0.0/24" — pool source
	Gateway    string        // "10.8.0.1"    — server's TUN IP
	Netmask    string        // "255.255.255.0" — for AssignIP and TUN config
	MTU        int           // 1380
	TUNName    string        // "" → driver picks
	Keepalive  time.Duration // 0 → off

	// PushRoutes are CIDRs the server tells every client to install via
	// the tunnel. Empty = server doesn't push routes (client keeps its
	// existing routing table). Typical full-tunnel value: []string{"0.0.0.0/0"}.
	PushRoutes []string

	// PushDNS are resolver IPs the server tells every client to configure
	// while the tunnel is up. Empty = no DNS push.
	PushDNS []string
}

// Server holds the listener, TUN device, IP pool and session registry.
type Server struct {
	cfg       Config
	log       *slog.Logger
	tlsConfig *tls.Config

	tun      tun.Device
	pool     *ipalloc.Pool
	registry *Registry

	mu       sync.Mutex
	listener net.Listener
	readyCh  chan struct{}

	wg       sync.WaitGroup
	closeCh  chan struct{}
	closeOne sync.Once
}

// New constructs a Server around an already-opened TUN device.
//
// Ownership of dev transfers to the Server: Run closes it on exit (via
// shutdown) so the TUN-reader goroutine can unblock. Callers must NOT also
// defer dev.Close() — a double close on a real wireguard/tun device is not
// guaranteed safe. The seam still lets tests inject a fake in-memory TUN.
func New(cfg Config, dev tun.Device, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if dev == nil {
		return nil, fmt.Errorf("server: nil TUN device")
	}

	tlsCfg, err := loadTLSConfig(cfg.CACertFile, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	gwIP := net.ParseIP(cfg.Gateway)
	if gwIP == nil || gwIP.To4() == nil {
		return nil, fmt.Errorf("server: invalid gateway %q", cfg.Gateway)
	}
	pool, err := ipalloc.New(cfg.Subnet, gwIP)
	if err != nil {
		return nil, fmt.Errorf("server: build ip pool: %w", err)
	}

	return &Server{
		cfg:       cfg,
		log:       log,
		tlsConfig: tlsCfg,
		tun:       dev,
		pool:      pool,
		registry:  NewRegistry(),
		readyCh:   make(chan struct{}),
		closeCh:   make(chan struct{}),
	}, nil
}

// Ready returns a channel closed when the listener is bound and accepting.
// Useful for tests that need to know the assigned port via Addr().
func (s *Server) Ready() <-chan struct{} { return s.readyCh }

// Addr returns the bound listen address, or nil if Run has not yet bound it.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Run starts the listener and blocks until ctx is cancelled or the
// listener fails. The TUN device is Close()d on exit so the TUN-reader
// goroutine can unblock; do not reuse the device after Run returns.
func (s *Server) Run(ctx context.Context) error {
	lis, err := tls.Listen("tcp", s.cfg.Listen, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", s.cfg.Listen, err)
	}
	s.mu.Lock()
	s.listener = lis
	s.mu.Unlock()
	close(s.readyCh)
	s.log.Info("server listening", "addr", lis.Addr(), "tun", s.tun.Name(), "gw", s.cfg.Gateway)

	s.wg.Add(1)
	go s.runTUNReader()

	stopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-stopCtx.Done()
		s.shutdown()
	}()

	acceptErr := s.acceptLoop()
	s.shutdown()
	s.wg.Wait()

	if errors.Is(acceptErr, net.ErrClosed) {
		return nil
	}
	return acceptErr
}

func (s *Server) acceptLoop() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// shutdown is idempotent: it closes the listener, the TUN device (so the
// reader can unblock), and every active session. Goroutine exit is awaited
// by Run via s.wg.
func (s *Server) shutdown() {
	s.closeOne.Do(func() {
		close(s.closeCh)
		s.mu.Lock()
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.mu.Unlock()
		_ = s.tun.Close()
		for _, sess := range s.registry.Snapshot() {
			sess.close()
		}
	})
}

// handleConn processes one client from TLS handshake through to disconnect.
//
// On exit it always: removes the session from the registry, releases its
// IP, and closes the session's done channel so a same-CN reconnect can
// proceed deterministically.
func (s *Server) handleConn(rawConn net.Conn) {
	defer s.wg.Done()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		s.log.Error("non-TLS conn slipped past tls.Listen")
		return
	}

	// Force the handshake so we have peer certs available.
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		s.log.Info("tls handshake failed", "remote", rawConn.RemoteAddr(), "err", err)
		_ = tlsConn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.log.Warn("client presented no certificate", "remote", rawConn.RemoteAddr())
		_ = tlsConn.Close()
		return
	}
	cn := strings.TrimSpace(state.PeerCertificates[0].Subject.CommonName)
	if cn == "" {
		s.log.Warn("client cert has empty CN", "remote", rawConn.RemoteAddr())
		_ = tlsConn.Close()
		return
	}

	// Kick any prior session for this CN. Done() lets us await its full
	// teardown before allocating a fresh IP under the same identity.
	if prev := s.registry.ByCN(cn); prev != nil {
		s.log.Info("kicking previous session", "cn", cn)
		prev.close()
		<-prev.Done()
	}

	ip, err := s.pool.Allocate(cn)
	if err != nil {
		s.log.Warn("ip allocation failed", "cn", cn, "err", err)
		if msg, mErr := tunnel.NewError("no_ip", err.Error()); mErr == nil {
			_ = tunnel.WriteControl(tlsConn, msg)
		}
		_ = tlsConn.Close()
		return
	}

	sess := newSession(cn, ip, tlsConn)
	s.registry.Add(sess)
	defer func() {
		s.registry.Remove(sess)
		s.pool.Release(cn)
		close(sess.doneCh)
	}()

	// Send the AssignIP control message before any data flows.
	assign, err := tunnel.NewAssignIP(tunnel.AssignIP{
		IP:      ip.String(),
		Gateway: s.cfg.Gateway,
		Netmask: s.cfg.Netmask,
		MTU:     s.cfg.MTU,
		Routes:  s.cfg.PushRoutes,
		DNS:     s.cfg.PushDNS,
	})
	if err != nil {
		s.log.Error("build assign_ip", "err", err)
		_ = tlsConn.Close()
		return
	}
	if err := tunnel.WriteControl(tlsConn, assign); err != nil {
		s.log.Info("assign_ip write failed", "cn", cn, "err", err)
		_ = tlsConn.Close()
		return
	}
	s.log.Info("client connected", "cn", cn, "ip", ip)

	// Writer goroutine drains sess.outbound; reader returns when the
	// connection ends, which closes sess (closing the conn) and unblocks
	// the writer.
	var sessWG sync.WaitGroup
	sessWG.Add(1)
	go func() {
		defer sessWG.Done()
		s.sessionWriter(sess)
	}()

	s.sessionReader(sess)

	sess.close()
	sessWG.Wait()
	s.log.Info("client disconnected", "cn", cn, "ip", ip)
}

// sessionReader pulls frames from the client connection and either
// dispatches control messages or writes data frames to the TUN device.
//
// The two security checks (anti-spoof on src, isolation on dst) live here
// so that no client packet reaches the TUN without them.
func (s *Server) sessionReader(sess *Session) {
	for {
		typ, body, err := tunnel.ReadPacket(sess.Conn)
		if err != nil {
			return
		}
		switch typ {
		case tunnel.FrameControl:
			msg, err := tunnel.DecodeControl(body)
			if err != nil {
				s.log.Debug("bad control frame", "cn", sess.CN, "err", err)
				continue
			}
			switch msg.Type {
			case tunnel.CtrlKeepalive:
				// rx is proof of life — nothing else to do.
			default:
				s.log.Debug("ignoring unexpected control from client",
					"cn", sess.CN, "type", msg.Type)
			}

		case tunnel.FrameData:
			src, dst, err := parseIPv4SrcDst(body)
			if err != nil {
				continue // drop non-IPv4 / short
			}
			if !src.Equal(sess.IP) {
				s.log.Debug("anti-spoof drop", "cn", sess.CN, "src", src, "expected", sess.IP)
				continue
			}
			if other := s.registry.ByIPv4(dst); other != nil && other != sess {
				// Hub-and-spoke isolation: client A may not address client B.
				s.log.Debug("isolation drop", "cn", sess.CN, "dst", dst)
				continue
			}
			if _, err := s.tun.Write(body); err != nil {
				s.log.Warn("tun write", "err", err)
				return
			}
		}
	}
}

// sessionWriter serializes outbound writes to one client. It exits when
// the session's closeCh fires (e.g. peer disconnect, server shutdown,
// reconnect kick).
func (s *Server) sessionWriter(sess *Session) {
	for {
		select {
		case <-sess.closeCh:
			return
		case pkt := <-sess.outbound:
			if err := tunnel.WriteData(sess.Conn, pkt); err != nil {
				sess.close()
				return
			}
		}
	}
}

// isClosedErr returns true for the network-poll errors that mean "the
// thing you were reading from is closed" rather than a real I/O problem.
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "file already closed")
}
