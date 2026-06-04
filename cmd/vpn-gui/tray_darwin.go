//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>
#include <stdint.h>

extern void trayMainThreadCallback(void *ctx);

// owner is energye/systray's status-item delegate (file-scope symbol, external
// linkage). We reach its private statusItem via KVC to toggle the menu-bar
// button's "selected" look — the standard feedback that a menu-bar app's window
// is open.
extern id owner;

// dispatchToMain runs trayMainThreadCallback on the Cocoa main queue, which the
// Wails main loop ([NSApp run]) drains — so the work runs on the main thread, as
// NSStatusBar requires. The Go callback travels as a cgo.Handle in the context
// pointer (one per call, freed in the callback), so there is no shared state to
// race on.
static void dispatchToMain(uintptr_t handle) {
    dispatch_async_f(dispatch_get_main_queue(), (void *)handle, trayMainThreadCallback);
}

static void setTrayHighlightedNow(bool on) {
    if (owner == nil) { return; }
    @try {
        id statusItem = [owner valueForKey:@"statusItem"];
        if (statusItem != nil) {
            [[statusItem button] setHighlighted:(BOOL)on];
        }
    } @catch (NSException *e) {
        // KVC reaches a private ivar; tolerate it ever changing.
    }
}

static void highlightMainCallback(void *ctx) {
    setTrayHighlightedNow(ctx != NULL);
}

// dispatchHighlightToMain toggles the highlight on the main thread; the bool
// rides in the context pointer so no Go callback is needed.
static void dispatchHighlightToMain(bool on) {
    dispatch_async_f(dispatch_get_main_queue(), (void *)(intptr_t)(on ? 1 : 0), highlightMainCallback);
}
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

//export trayMainThreadCallback
func trayMainThreadCallback(ctx unsafe.Pointer) {
	h := cgo.Handle(uintptr(ctx))
	fn := h.Value().(func())
	h.Delete()
	fn()
}

// runOnMainThread schedules fn to run on the Cocoa main thread. The menu-bar
// status item must be created there; Wails runs OnStartup on a goroutine, so we
// bounce through the main dispatch queue. fn travels as a cgo.Handle, so
// concurrent or repeated calls don't clobber one another.
//
// Note: the systray's start takes over the NSApplication delegate (to create
// the status item), which is what wires up its click handling — so we leave it
// in place. The trade-off is that clicking the app's *dock* icon won't reopen
// the window; the title-bar buttons and the tray icon manage the window.
func runOnMainThread(fn func()) {
	C.dispatchToMain(C.uintptr_t(cgo.NewHandle(fn)))
}

// setTrayHighlighted gives the menu-bar icon the selected (highlighted) look
// while the window is open, as visual feedback for the click. Safe to call from
// any goroutine — it dispatches to the main thread.
func setTrayHighlighted(on bool) {
	C.dispatchHighlightToMain(C.bool(on))
}

// quitOnWindowClose is false on macOS: closing the window hides it to the menu
// bar (the standard menu-bar-app behaviour) rather than quitting.
func quitOnWindowClose() bool { return false }
