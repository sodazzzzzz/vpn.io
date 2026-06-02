//go:build !darwin

package main

// runOnMainThread runs fn immediately on non-macOS platforms. The macOS
// NSStatusBar main-thread constraint doesn't apply the same way for the
// systray backends there; the real cross-platform tray is a later step.
func runOnMainThread(fn func()) { fn() }

// setTrayHighlighted is a no-op off macOS (the menu-bar "selected" look is a
// macOS NSStatusBar feature).
func setTrayHighlighted(bool) {}
