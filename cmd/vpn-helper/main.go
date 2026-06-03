// Command vpn-helper is the privileged VPN helper daemon. It owns the
// tunnel (TUN device, routes, DNS, leak protection) and exposes a small
// local control API — Connect/Disconnect/Status — over an authenticated
// IPC transport so an unprivileged front-end (CLI or GUI) can drive it
// without sudo on every action.
//
// Required privileges:
//   - Linux/macOS: root (TUN creation, routing, firewall)
//   - Windows:     Administrator (not yet supported; see internal/ipc)
//
// The control socket admits only root and any uid/gid named with
// -allow-uid / -allow-gid (verified from the peer's kernel credentials).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/govpn/internal/helper"
	"github.com/govpn/internal/ipc"
)

func main() {
	var (
		socket   = flag.String("socket", ipc.DefaultControlPath(), "control socket path (named pipe on Windows)")
		modeStr  = flag.String("socket-mode", "0660", "control socket file mode (octal)")
		allowUID = flag.String("allow-uid", "", "comma-separated uids allowed to connect (root always allowed)")
		allowGID = flag.String("allow-gid", "", "comma-separated gids allowed to connect")
		logLevel = flag.String("log-level", "info", "debug|info|warn|error")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	mode, err := parseMode(*modeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper:", err)
		os.Exit(2)
	}
	uids, err := parseIDs(*allowUID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper: -allow-uid:", err)
		os.Exit(2)
	}
	gids, err := parseIDs(*allowGID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper: -allow-gid:", err)
		os.Exit(2)
	}
	policy := ipc.Policy{AllowUID: uids, AllowGID: gids}

	ln, err := ipc.Listen(*socket, mode, policy, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper:", err)
		os.Exit(1)
	}
	log.Info("vpn-helper listening", "socket", *socket, "mode", *modeStr, "allow_uid", uids, "allow_gid", gids)

	ctrl := helper.New(log)
	srv := ipc.NewServer(ln, ctrl, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := srv.Serve(ctx)

	// Shutting down: tear the tunnel down and clean up the socket file.
	if err := ctrl.Disconnect(); err != nil {
		log.Warn("vpn-helper: disconnect on shutdown", "err", err)
	}
	_ = os.Remove(*socket)

	if serveErr != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper:", serveErr)
		os.Exit(1)
	}
	log.Info("vpn-helper: exited cleanly")
}

// parseMode parses an octal file-mode string like "0660".
func parseMode(s string) (os.FileMode, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid socket mode %q (want octal, e.g. 0660)", s)
	}
	return os.FileMode(v), nil
}

// parseIDs parses a comma-separated list of unsigned IDs. Empty -> nil.
func parseIDs(s string) ([]uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var ids []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid id %q", part)
		}
		ids = append(ids, uint32(v))
	}
	return ids, nil
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
