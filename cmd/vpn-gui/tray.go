package main

import (
	_ "embed"
	"sync"
	"sync/atomic"
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

// appIcon is the full-colour app logo. It's the second ("regular") argument to
// SetTemplateIcon: macOS uses the black template above and recolours it, but on
// Windows/Linux a black-on-transparent template is invisible on the taskbar, so
// those platforms get this visible colour icon instead.
//
//go:embed build/appicon.png
var appIcon []byte

// trayPollInterval is how often the tray re-reads the daemon state. This is the
// single state watcher for the whole app: it updates the menu-bar icon AND emits
// a "daemon-changed" event so the window refreshes in lockstep, instead of the
// window running its own competing poll (which drifted up to ~2s out of sync,
// #154).
const trayPollInterval = 1 * time.Second

// tray is the menu-bar presence: a status icon that mirrors the tunnel state
// plus a menu (Connect / Disconnect / Open / Settings / Quit). Clicking the icon
// opens the menu (OpenVPN-style); the window is reached through the menu. It
// drives the window and the daemon through the App it points back to.
type tray struct {
	app *App

	// quitting marks that a shutdown is under way, so onBeforeClose knows to
	// let it through instead of cancelling it. Atomic rather than guarded by
	// mu: it is read from inside onBeforeClose, which Wails may invoke on the
	// main thread while a tray callback is still on the way out.
	quitting atomic.Bool

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
	systray.SetTemplateIcon(iconDisconnected, appIcon)
	systray.SetTooltip("vpn.io")

	t.mStatus = systray.AddMenuItem("Not connected", "")
	t.mStatus.Disable()
	systray.AddSeparator()
	t.mConnect = systray.AddMenuItem("Connect", "Bring the tunnel up")
	t.mDisconnect = systray.AddMenuItem("Disconnect", "Take the tunnel down")
	systray.AddSeparator()
	mOpen := systray.AddMenuItem("Open vpn.io…", "Show the main window")
	mSettings := systray.AddMenuItem("Settings…", "Open the profile & settings screen")
	mQuit := systray.AddMenuItem("Quit vpn.io", "")

	t.mConnect.Click(func() {
		// Connecting needs a staged profile; without one, just open the window
		// so the user can import. IPC calls run off the menu thread.
		if t.app.Profile().HasProfile {
			go func() {
				if _, err := t.app.Reconnect(); err != nil {
					t.app.reportTrayError("Connect failed", err)
				}
			}()
		} else {
			t.showWindow()
		}
	})
	t.mDisconnect.Click(func() {
		go func() {
			if err := t.app.Disconnect(); err != nil {
				t.app.reportTrayError("Disconnect failed", err)
			}
		}()
	})
	mOpen.Click(t.showWindow)
	mSettings.Click(t.showSettings)
	mQuit.Click(func() { t.requestQuit() })

	// Clicking the tray icon opens the menu (both buttons), OpenVPN-style; the
	// window is reached through "Open vpn.io…"/"Settings…". This also sidesteps
	// the stale-winVisible desync of the old toggle-on-click (#154).
	showMenu := func(menu systray.IMenu) { _ = menu.ShowMenu() }
	systray.SetOnClick(showMenu)
	systray.SetOnRClick(showMenu)

	// The app lives in the Dock; let a Dock-icon click reopen the window even
	// though systray owns the NSApplication delegate (#154).
	installDockReopen(t.showWindow)

	setTrayHighlighted(true) // window starts visible
	go t.refreshLoop()
}

func (t *tray) refreshLoop() {
	// Runs for the whole life of the app — the tray mirrors the daemon until the
	// process exits, so the ticker is intentionally never stopped (a defer Stop
	// here would be dead code: the range below never returns).
	tick := time.NewTicker(trayPollInterval)
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
		systray.SetTemplateIcon(icon, appIcon)
	}

	t.mStatus.SetTitle(label)

	active := state == "connecting" || state == "connected" || state == "reconnecting"
	setEnabled(t.mDisconnect, active)
	setEnabled(t.mConnect, !active && t.app.Profile().HasProfile)

	// Drive the window from this same watcher: nudge the frontend to re-read the
	// daemon so its view and the tray icon move together (#154). Cheap, and the
	// frontend coalesces overlapping refreshes.
	if t.app.ctx != nil {
		wruntime.EventsEmit(t.app.ctx, "daemon-changed")
	}
}

func (t *tray) showWindow() { t.setWindow(true) }

// showSettings opens the window and asks the frontend to jump straight to the
// profile & settings screen.
func (t *tray) showSettings() {
	t.showWindow()
	if t.app.ctx != nil {
		wruntime.EventsEmit(t.app.ctx, "open-settings")
	}
}

// requestQuit starts a graceful shutdown. Used by the tray's "Quit" item — on
// macOS the only way out, since the window's close button just hides.
//
// The flag must be set *before* calling Quit: runtime.Quit invokes
// OnBeforeClose and aborts if it returns true, so without it the tray's Quit
// merely hid the window and the process had to be killed from Activity Monitor.
// Swap also makes a second Quit a no-op while one is already running.
func (t *tray) requestQuit() {
	if t.quitting.Swap(true) {
		return
	}
	wruntime.Quit(t.app.ctx)
}

// onBeforeClose decides what the window's close button does, and is also the
// gate every quit passes through — Wails calls it from runtime.Quit as well.
// Returning true cancels the close; false lets it proceed.
func (t *tray) onBeforeClose() bool {
	cancel := cancelClose(t.quitting.Load(), quitOnWindowClose())
	if !cancel {
		// Whether this came from the tray's Quit or the X on Windows/Linux, the
		// app is going down — remember it so a second pass through here (Wails
		// calls this once per Quit) doesn't fall into the hide branch.
		t.quitting.Store(true)
		return false
	}
	t.setWindow(false)
	return true
}

// cancelClose reports whether a close request should be cancelled, given
// whether a quit is already under way and whether this platform treats the
// window's close button as "quit".
//
// The subtlety is that Wails routes *both* meanings through OnBeforeClose, and
// cancelling is the default-looking answer that happens to be wrong for a quit:
//
//   - quitting: runtime.Quit calls OnBeforeClose and aborts if it returns true.
//     The tray's "Quit" used to return true here, so on macOS — where it is the
//     only way out — it just hid the window and the process survived.
//
//   - quitOnWindowClose (Windows/Linux): the close handler *already* called
//     Quit, which is what called us. Answering "cancel, and by the way please
//     Quit" re-entered that sequence: on Windows synchronously, until the stack
//     overflowed and killed the process before WebView2 teardown and
//     profile-save could run; on Linux by spawning a goroutine per round.
//
//   - otherwise (macOS): the app lives in the menu bar, so closing the window
//     genuinely means "hide" and cancelling is correct.
func cancelClose(quitting, quitOnWindowClose bool) bool {
	return !quitting && !quitOnWindowClose
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
