// Command vpn-server runs the govpn TLS+mTLS VPN server.
//
// Required privileges:
//   - Linux/macOS: root (TUN creation and `ip`/`ifconfig` invocations)
//   - Windows:     Administrator (wintun + netsh)
//
// On Windows, wintun.dll must sit next to the executable or on PATH.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/server"
)

func main() {
	var (
		listen    = flag.String("listen", ":8443", "listen address")
		caFile    = flag.String("ca", "ca-data/ca.crt", "CA certificate (clients must be signed by this)")
		certFile  = flag.String("cert", "ca-data/server/server.crt", "server certificate")
		keyFile   = flag.String("key", "ca-data/server/server.key", "server private key")
		subnet    = flag.String("subnet", "10.8.0.0/24", "tunnel subnet")
		gateway   = flag.String("gateway", "10.8.0.1", "server's tunnel IP (gateway for clients)")
		netmask   = flag.String("netmask", "255.255.255.0", "tunnel netmask")
		mtu       = flag.Int("mtu", 1380, "TUN MTU")
		tunName   = flag.String("tun-name", "", "TUN interface name (empty = driver picks)")
		keepalive = flag.Duration("keepalive", 30*time.Second, "keepalive interval (0 = off)")
		hsTimeout = flag.Duration("handshake-timeout", 10*time.Second, "max TLS handshake duration (0 = default)")
		maxPerIP  = flag.Int("max-conns-per-ip", 16, "max concurrent connections per source IP (0 = unlimited)")
		maxConns  = flag.Int("max-conns", 256, "max concurrent connections across all IPs (0 = unlimited; 0 also disables the per-IP failed-handshake throttle, which needs a global cap to stay bounded)")
		logLevel  = flag.String("log-level", "info", "debug|info|warn|error")
		routesRaw = flag.String("push-routes", "", "comma-separated CIDRs to push to clients (e.g. 0.0.0.0/0 for full-tunnel)")
		dnsRaw    = flag.String("push-dns", "", "comma-separated DNS resolver IPs to push to clients (e.g. 1.1.1.1,9.9.9.9)")
	)
	flag.Parse()

	level := parseLevel(*logLevel)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	warnIfForwardingDisabled(log)

	cfg := server.Config{
		Listen:           *listen,
		CACertFile:       *caFile,
		CertFile:         *certFile,
		KeyFile:          *keyFile,
		Subnet:           *subnet,
		Gateway:          *gateway,
		Netmask:          *netmask,
		MTU:              *mtu,
		TUNName:          *tunName,
		Keepalive:        *keepalive,
		HandshakeTimeout: *hsTimeout,
		MaxConnsPerIP:    *maxPerIP,
		MaxConns:         *maxConns,
		PushRoutes:       splitCSV(*routesRaw),
		PushDNS:          splitCSV(*dnsRaw),
	}

	dev, err := tun.Open(cfg.TUNName, cfg.MTU)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-server: open tun:", err)
		os.Exit(1)
	}
	if err := tun.Configure(dev, cfg.Gateway, cfg.Netmask, cfg.Gateway); err != nil {
		_ = dev.Close()
		fmt.Fprintln(os.Stderr, "vpn-server: configure tun:", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, dev, log)
	if err != nil {
		_ = dev.Close()
		fmt.Fprintln(os.Stderr, "vpn-server:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-server:", err)
		os.Exit(1)
	}
	log.Info("vpn-server: exited cleanly")
}

// splitCSV trims and drops empties so `-push-routes ""` yields nil rather
// than [""]. The empty slice is what the server treats as "no push".
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
