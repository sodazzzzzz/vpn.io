// Command vpn-client connects to a govpn server over TLS+mTLS.
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

	"github.com/govpn/internal/firewall"
	"github.com/govpn/internal/tun"
	"github.com/govpn/internal/tunnel/client"
)

func main() {
	var (
		server     = flag.String("server", "", "server host:port, e.g. vpn.example.com:8443")
		caFile     = flag.String("ca", "ca-data/ca.crt", "CA certificate (server must be signed by this)")
		certFile   = flag.String("cert", "", "client certificate (PEM)")
		keyFile    = flag.String("key", "", "client private key (PEM)")
		serverName = flag.String("server-name", "", "TLS SNI / verification hostname (default = host part of -server)")
		mtu        = flag.Int("mtu", 1380, "TUN MTU")
		tunName    = flag.String("tun-name", "", "TUN interface name (empty = driver picks)")
		keepalive  = flag.Duration("keepalive", 30*time.Second, "keepalive interval (0 = off)")
		recMin     = flag.Duration("reconnect-min", 1*time.Second, "min reconnect backoff")
		recMax     = flag.Duration("reconnect-max", 60*time.Second, "max reconnect backoff")
		logLevel   = flag.String("log-level", "info", "debug|info|warn|error")
		clearFW    = flag.Bool("clear-firewall", false, "remove any leftover leak-protection/kill-switch firewall rules and exit (best-effort; recovers a network locked after a crash)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	// Escape hatch: clear stale rules and exit. Runs without a tunnel and
	// without the connection flags below.
	if *clearFW {
		if err := firewall.Clear(log); err != nil {
			log.Warn("clear-firewall reported an error (this often just means there was nothing to remove)", "err", err)
		} else {
			log.Info("vpn-client: leak-protection rules cleared")
		}
		return
	}

	if *server == "" || *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "vpn-client: -server, -cert, -key are required")
		flag.Usage()
		os.Exit(2)
	}

	dev, err := tun.Open(*tunName, *mtu)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-client: open tun:", err)
		os.Exit(1)
	}
	defer func() { _ = dev.Close() }()

	cfg := client.Config{
		Server:       *server,
		CACertFile:   *caFile,
		CertFile:     *certFile,
		KeyFile:      *keyFile,
		ServerName:   *serverName,
		Keepalive:    *keepalive,
		ReconnectMin: *recMin,
		ReconnectMax: *recMax,
	}

	cli, err := client.New(cfg, dev, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-client:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Once the first signal cancels ctx, restore the default signal disposition
	// so a SECOND Ctrl-C / SIGTERM force-kills the process even if Run's teardown
	// wedges on a hung external command (networksetup / ip / nft). Otherwise
	// NotifyContext keeps swallowing signals until Run returns, and only SIGKILL
	// works — which then leaves DNS/routes applied.
	context.AfterFunc(ctx, stop)

	if err := cli.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-client:", err)
		os.Exit(1)
	}
	log.Info("vpn-client: exited cleanly")
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
