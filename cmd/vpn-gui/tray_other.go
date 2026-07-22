//go:build !darwin

package main

// runOnMainThread runs fn immediately on non-macOS platforms. The macOS
// NSStatusBar main-thread constraint doesn't apply the same way for the
// systray backends there; the real cross-platform tray is a later step.
func runOnMainThread(fn func()) { fn() }

// setTrayHighlighted is a no-op off macOS (the menu-bar "selected" look is a
// macOS NSStatusBar feature).
func setTrayHighlighted(bool) {}

// quitOnWindowClose reports that the window's X button should quit the app.
// Windows/Linux users expect close to exit; macOS keeps it in the menu bar.
func quitOnWindowClose() bool { return true }

// installDockReopen is a no-op off macOS: the "click the Dock icon to reopen the
// window" behaviour is a macOS concept, and on Windows/Linux the window's own
// controls (and taskbar) manage it.
func installDockReopen(func()) {}
