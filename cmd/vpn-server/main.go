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
	"syscall"
	"time"

	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/server"
)

func main() {
	var (
		listen    = flag.String("listen", ":8443", "listen address")
		caFile    = flag.String("ca", "ca-data/ca.crt", "CA certificate (clients must be signed by this)")
		certFile  = flag.String("cert", "ca-data/server.crt", "server certificate")
		keyFile   = flag.String("key", "ca-data/server.key", "server private key")
		subnet    = flag.String("subnet", "10.8.0.0/24", "tunnel subnet")
		gateway   = flag.String("gateway", "10.8.0.1", "server's tunnel IP (gateway for clients)")
		netmask   = flag.String("netmask", "255.255.255.0", "tunnel netmask")
		mtu       = flag.Int("mtu", 1380, "TUN MTU")
		tunName   = flag.String("tun-name", "", "TUN interface name (empty = driver picks)")
		keepalive = flag.Duration("keepalive", 30*time.Second, "keepalive interval (0 = off)")
		logLevel  = flag.String("log-level", "info", "debug|info|warn|error")
	)
	flag.Parse()

	level := parseLevel(*logLevel)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg := server.Config{
		Listen:     *listen,
		CACertFile: *caFile,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		Subnet:     *subnet,
		Gateway:    *gateway,
		Netmask:    *netmask,
		MTU:        *mtu,
		TUNName:    *tunName,
		Keepalive:  *keepalive,
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
