package main

import "testing"

// Wails routes both "the user closed the window" and "the app is quitting"
// through OnBeforeClose, and returning true (cancel) is wrong for a quit. That
// mistake made the tray's Quit a no-op on macOS — the only way out there — and
// recursed the X button into a crash on Windows.
func TestCancelClose(t *testing.T) {
	tests := []struct {
		name              string
		quitting          bool
		quitOnWindowClose bool
		want              bool
	}{
		{
			name:              "macOS window close hides the app",
			quitting:          false,
			quitOnWindowClose: false,
			want:              true,
		},
		{
			name:              "macOS tray Quit must actually quit",
			quitting:          true,
			quitOnWindowClose: false,
			want:              false,
		},
		{
			name:              "Windows/Linux X quits without re-entering Quit",
			quitting:          false,
			quitOnWindowClose: true,
			want:              false,
		},
		{
			name:              "Windows/Linux tray Quit quits",
			quitting:          true,
			quitOnWindowClose: true,
			want:              false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cancelClose(tt.quitting, tt.quitOnWindowClose); got != tt.want {
				t.Errorf("cancelClose(quitting=%v, quitOnWindowClose=%v) = %v, want %v",
					tt.quitting, tt.quitOnWindowClose, got, tt.want)
			}
		})
	}
}

// requestQuit must call runtime.Quit at most once: on Windows Quit invokes
// OnBeforeClose synchronously, so a second one would re-enter the sequence.
func TestQuittingFlagLatches(t *testing.T) {
	var tr tray
	if tr.quitting.Swap(true) {
		t.Fatal("first Swap reported a quit already in progress")
	}
	if !tr.quitting.Swap(true) {
		t.Error("second Swap did not report the in-progress quit — Quit would run twice")
	}
}
