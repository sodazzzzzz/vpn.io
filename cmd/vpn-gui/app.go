package main

import (
	"context"
	"os"

	"github.com/govpn/internal/control"
)

// defaultSocket matches cmd/vpn-helper's default control socket. A packaged
// macOS launchd job will set its own path; wire that through when packaging
// lands (the systemd unit already uses /run/vpn-io/helper.sock on Linux).
const defaultSocket = "/var/run/vpn-io-helper.sock"

// socketEnv overrides the control-socket path. It lets a launchd/systemd
// package point the GUI at the path its daemon actually listens on, and lets a
// developer aim the app at a throwaway socket without root.
const socketEnv = "VPN_IO_HELPER_SOCKET"

// helperSocket resolves the control-socket path: the override env var if set,
// otherwise the daemon's default.
func helperSocket() string {
	if s := os.Getenv(socketEnv); s != "" {
		return s
	}
	return defaultSocket
}

// App is the Wails-bound backend — a thin adapter over control.Client. Every
// bound method forwards to the privileged daemon over its control socket, so
// the web front-end never speaks the IPC wire format itself. Methods return
// JSON-serializable values (or an error) that Wails marshals to the webview.
type App struct {
	ctx context.Context
	cl  *control.Client
}

// NewApp constructs the backend targeting the daemon's control socket.
func NewApp() *App {
	return &App{cl: control.New(helperSocket())}
}

// startup captures the Wails runtime context (used by later window calls).
func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// Status reports the daemon's current connection state. The front-end polls
// this; a transport error (typically "daemon not running") comes back as-is
// for the UI to surface.
func (a *App) Status() (control.Status, error) { return a.cl.Status() }

// Connect validates the supplied credentials locally, then asks the daemon to
// bring the tunnel up, returning who the certificate authenticates as on
// success. (The credential-import screen that fills this in is a follow-up.)
func (a *App) Connect(creds control.Credentials) (control.Connected, error) {
	return a.cl.Connect(creds)
}

// Disconnect tears the tunnel down (idempotent: a no-op when disconnected).
func (a *App) Disconnect() error { return a.cl.Disconnect() }
