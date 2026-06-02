# vpn-gui

Desktop front-end for the `vpn-helper` daemon — a small [Wails](https://wails.io)
(Go + web) tray-style window that shows the tunnel state and drives the daemon's
Connect / Disconnect / Status over its local control socket. It holds no
privileges of its own; the daemon does.

This is the main screen of the "Quiet Signal" design (`docs/DESIGN.md`).
Credential import and a native menu-bar tray item are follow-ups; today the
window reflects the daemon's state and can Disconnect/Cancel a live session.

## Layout

- `main.go` — Wails window options (frameless 360px, OS theme).
- `app.go` — the bound backend: a thin adapter over `internal/control`, which
  speaks the IPC protocol (`internal/ipc`) and validates credentials
  (`internal/profile`).
- `frontend/` — the web UI (vanilla JS + Vite). `src/main.js` polls `Status()`
  and renders the tray; `src/style.css` is ported from `docs/ui/mockup.html`.
- `frontend/wailsjs/` — generated Go↔JS bindings (committed).

## Nested module

This directory is its own Go module so the Wails/CGO desktop dependency tree
stays out of the repo root: the root's `go build ./...`, `go vet ./...` and
`go test ./...` (run on headless Linux CI without GTK/WebKit) never descend
here. It imports the root module's `internal/...` packages via the `replace`
directive in `go.mod`.

## Develop / build (macOS first)

Requires the Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`),
Node and npm.

```bash
cd cmd/vpn-gui
wails dev      # live-reloading dev window
wails build    # production .app bundle in build/bin/
```

`wails build`/`wails dev` generate the JS bindings and build the frontend
(`frontend/dist`) before compiling Go. A bare `go build`/`go vet` in this
directory needs one of those to have run first, so `//go:embed all:frontend/dist`
resolves.

Point the app at a non-default control socket with the `VPN_IO_HELPER_SOCKET`
environment variable (handy for testing against a daemon you ran as your own
user on a throwaway socket).
