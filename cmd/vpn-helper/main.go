// Command vpn-helper is the privileged VPN helper daemon. It owns the
// tunnel (TUN device, routes, DNS, leak protection) and exposes a small
// local control API — Connect/Disconnect/Status — over an authenticated
// IPC transport so an unprivileged front-end (CLI or GUI) can drive it
// without sudo on every action.
//
// Required privileges:
//   - Linux/macOS: root (TUN creation, routing, firewall)
//   - Windows:     LocalSystem / Administrator (Wintun, routing). Install it as
//     a service with `vpn-helper -install` (run elevated); remove with
//     `-uninstall`. When the Service Control Manager starts it, it runs as a
//     service automatically.
//
// On unix the control socket admits only root and any uid/gid named with
// -allow-uid / -allow-gid (verified from the peer's kernel credentials); on
// Windows the named pipe's security descriptor is the gate (those flags are
// ignored there).
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

// serviceName is the Windows service identifier (and the display/description).
const (
	serviceName    = "vpn-io-helper"
	serviceDisplay = "vpn.io Helper"
	serviceDesc    = "Privileged helper for the vpn.io VPN client (owns the TUN device and routes)."
)

func main() {
	var (
		socket    = flag.String("socket", ipc.DefaultControlPath(), "control socket path (named pipe on Windows)")
		modeStr   = flag.String("socket-mode", "0660", "control socket file mode (octal)")
		allowUID  = flag.String("allow-uid", "", "comma-separated uids allowed to connect (root always allowed)")
		allowGID  = flag.String("allow-gid", "", "comma-separated gids allowed to connect")
		logLevel  = flag.String("log-level", "info", "debug|info|warn|error")
		install   = flag.Bool("install", false, "(Windows) install the helper as a service and exit")
		uninstall = flag.Bool("uninstall", false, "(Windows) remove the helper service and exit")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	// Service management (Windows): register/remove and exit before any daemon
	// setup. On other platforms these return a clear "Windows-only" error.
	if *uninstall {
		exitOnErr(removeService(serviceName))
		return
	}
	if *install {
		args := []string{"-log-level", *logLevel}
		if *socket != ipc.DefaultControlPath() {
			args = append(args, "-socket", *socket)
		}
		exitOnErr(installService(serviceName, serviceDisplay, serviceDesc, args))
		return
	}

	mode, err := parseMode(*modeStr)
	if err != nil {
		exitOnErr(err)
	}
	uids, err := parseIDs(*allowUID)
	if err != nil {
		exitOnErr(fmt.Errorf("-allow-uid: %w", err))
	}
	gids, err := parseIDs(*allowGID)
	if err != nil {
		exitOnErr(fmt.Errorf("-allow-gid: %w", err))
	}
	policy := ipc.Policy{AllowUID: uids, AllowGID: gids}

	run := func(ctx context.Context) error {
		return runDaemon(ctx, *socket, mode, policy, log)
	}

	// When started by the Windows Service Control Manager, run under it so it can
	// stop us cleanly; otherwise run as a normal console process.
	if isService() {
		exitOnErr(runService(serviceName, run))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitOnErr(run(ctx))
}

// runDaemon brings up the control endpoint and serves Connect/Disconnect/Status
// until ctx is cancelled, then tears the tunnel down. Shared by the console and
// Windows-service entry points.
func runDaemon(ctx context.Context, socket string, mode os.FileMode, policy ipc.Policy, log *slog.Logger) error {
	ln, err := ipc.Listen(socket, mode, policy, log)
	if err != nil {
		return err
	}
	log.Info("vpn-helper listening", "socket", socket, "mode", fmt.Sprintf("%#o", mode),
		"allow_uid", policy.AllowUID, "allow_gid", policy.AllowGID)

	ctrl := helper.New(log)
	srv := ipc.NewServer(ln, ctrl, log)

	serveErr := srv.Serve(ctx)

	// Shutting down: tear the tunnel down and clean up.
	if err := ctrl.Disconnect(); err != nil {
		log.Warn("vpn-helper: disconnect on shutdown", "err", err)
	}
	// Remove the leftover unix socket file. On Windows socket is a named pipe
	// (\\.\pipe\...): os.Remove returns an error we ignore — the pipe is
	// released by the listener's Close, so this is a harmless no-op there.
	_ = os.Remove(socket)

	if serveErr != nil {
		return serveErr
	}
	log.Info("vpn-helper: exited cleanly")
	return nil
}

// exitOnErr prints err to stderr and exits non-zero; a nil err is a no-op so a
// service manager sees a real failure code rather than a healthy-looking exit 0.
func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-helper:", err)
		os.Exit(1)
	}
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
