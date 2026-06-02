package main

import (
	_ "embed"
	"sync"
	"time"

	"github.com/energye/systray"
	"github.com/govpn/internal/control"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Menu-bar template icons (black-on-transparent; macOS recolours them for the
// light/dark bar). One per visual state.
//
//go:embed trayicons/disconnected.png
var iconDisconnected []byte

//go:embed trayicons/connected.png
var iconConnected []byte

//go:embed trayicons/working.png
var iconWorking []byte

//go:embed trayicons/failed.png
var iconFailed []byte

// trayPollInterval is how often the tray re-reads the daemon state. The window
// polls on its own; this keeps the menu-bar icon honest even while the window
// is hidden.
const trayPollInterval = 2 * time.Second

// tray is the menu-bar presence: a status icon that mirrors the tunnel state
// plus a small menu (Connect / Disconnect / Show Window / Quit). Left-click
// toggles the window; right-click opens the menu. It drives the window and the
// daemon through the App it points back to.
type tray struct {
	app *App

	mu         sync.Mutex
	winVisible bool   // best-effort track of the window's visibility
	state      string // last state applied to the icon, to skip no-op updates

	mStatus     *systray.MenuItem
	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
}

func newTray(a *App) *tray { return &tray{app: a, winVisible: true} }

// start hooks the systray into the host (Wails) run loop. RunWithExternalLoop
// registers the callbacks and returns a start func that actually creates the
// status item; that func touches NSStatusBar, so it must run on the Cocoa main
// thread. Wails calls OnStartup on a goroutine, so we hand the start func to
// the main thread (runOnMainThread). onReady then fires once the item exists.
func (t *tray) start() {
	startTray, _ := systray.RunWithExternalLoop(t.onReady, func() {})
	runOnMainThread(startTray)
}

func (t *tray) onReady() {
	systray.SetTemplateIcon(iconDisconnected, iconDisconnected)
	systray.SetTooltip("vpn.io")

	t.mStatus = systray.AddMenuItem("Not connected", "")
	t.mStatus.Disable()
	systray.AddSeparator()
	t.mConnect = systray.AddMenuItem("Connect", "Bring the tunnel up")
	t.mDisconnect = systray.AddMenuItem("Disconnect", "Take the tunnel down")
	systray.AddSeparator()
	mShow := systray.AddMenuItem("Show Window", "")
	mQuit := systray.AddMenuItem("Quit vpn.io", "")

	t.mConnect.Click(func() {
		// Connecting needs a staged profile; without one, just open the window
		// so the user can import. IPC calls run off the menu thread.
		if t.app.Profile().HasProfile {
			go func() { _, _ = t.app.Reconnect() }()
		} else {
			t.showWindow()
		}
	})
	t.mDisconnect.Click(func() { go func() { _ = t.app.Disconnect() }() })
	mShow.Click(t.showWindow)
	mQuit.Click(func() { wruntime.Quit(t.app.ctx) })

	systray.SetOnClick(func(systray.IMenu) { t.toggleWindow() })
	systray.SetOnRClick(func(menu systray.IMenu) { _ = menu.ShowMenu() })

	setTrayHighlighted(true) // window starts visible
	go t.refreshLoop()
}

func (t *tray) refreshLoop() {
	tick := time.NewTicker(trayPollInterval)
	defer tick.Stop()
	t.refresh()
	for range tick.C {
		t.refresh()
	}
}

// refresh re-reads the daemon state and updates the icon, status line and the
// enabled state of the Connect/Disconnect items.
func (t *tray) refresh() {
	state := "disconnected"
	label := "Background helper not running"
	if st, err := t.app.Status(); err == nil {
		state = st.State
		label = trayStatusLabel(st)
	}

	t.mu.Lock()
	changed := state != t.state
	t.state = state
	t.mu.Unlock()
	if changed {
		icon := trayIconFor(state)
		systray.SetTemplateIcon(icon, icon)
	}

	t.mStatus.SetTitle(label)

	active := state == "connecting" || state == "connected" || state == "reconnecting"
	setEnabled(t.mDisconnect, active)
	setEnabled(t.mConnect, !active && t.app.Profile().HasProfile)
}

func (t *tray) showWindow() { t.setWindow(true) }

func (t *tray) toggleWindow() { t.setWindow(!t.visible()) }

// onBeforeClose hides the window instead of quitting, so the app keeps running
// in the menu bar. Returning true tells Wails to cancel the actual close.
func (t *tray) onBeforeClose() bool {
	t.setWindow(false)
	return true
}

// setWindow shows or hides the window, keeping the tracked visibility and the
// tray icon's highlighted (selected) look in sync — the icon stays highlighted
// while the window is open, as click feedback.
func (t *tray) setWindow(show bool) {
	if show {
		wruntime.WindowShow(t.app.ctx)
	} else {
		wruntime.WindowHide(t.app.ctx)
	}
	t.setVisible(show)
	setTrayHighlighted(show)
}

func (t *tray) visible() bool     { t.mu.Lock(); defer t.mu.Unlock(); return t.winVisible }
func (t *tray) setVisible(v bool) { t.mu.Lock(); t.winVisible = v; t.mu.Unlock() }

func setEnabled(item *systray.MenuItem, enabled bool) {
	if enabled {
		item.Enable()
	} else {
		item.Disable()
	}
}

func trayIconFor(state string) []byte {
	switch state {
	case "connected":
		return iconConnected
	case "connecting", "reconnecting":
		return iconWorking
	case "failed":
		return iconFailed
	default:
		return iconDisconnected
	}
}

func trayStatusLabel(st control.Status) string {
	switch st.State {
	case "connected":
		if st.Server != "" {
			return "Connected — " + st.Server
		}
		return "Connected"
	case "connecting":
		return "Connecting…"
	case "reconnecting":
		return "Reconnecting…"
	case "failed":
		return "Connection failed"
	default:
		return "Not connected"
	}
}
