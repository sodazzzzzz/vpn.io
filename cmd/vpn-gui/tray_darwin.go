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

// dispatchToMain queues trayMainThreadCallback onto the Cocoa main queue, which
// the Wails main loop ([NSApp run]) drains — so the work runs on the main
// thread, as NSStatusBar requires.
static void dispatchToMain(void) {
    dispatch_async_f(dispatch_get_main_queue(), 0, trayMainThreadCallback);
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

import "unsafe"

// pendingMainFn holds the function to run on the main thread. It is set once at
// startup and consumed by the dispatched callback, so a plain global is enough.
var pendingMainFn func()

//export trayMainThreadCallback
func trayMainThreadCallback(_ unsafe.Pointer) {
	if pendingMainFn != nil {
		fn := pendingMainFn
		pendingMainFn = nil
		fn()
	}
}

// runOnMainThread schedules fn to run on the Cocoa main thread. The menu-bar
// status item must be created there; Wails runs OnStartup on a goroutine, so we
// bounce through the main dispatch queue.
//
// Note: the systray's start takes over the NSApplication delegate (to create
// the status item), which is what wires up its click handling — so we leave it
// in place. The trade-off is that clicking the app's *dock* icon won't reopen
// the window; the title-bar buttons and the tray icon manage the window.
func runOnMainThread(fn func()) {
	pendingMainFn = fn
	C.dispatchToMain()
}

// setTrayHighlighted gives the menu-bar icon the selected (highlighted) look
// while the window is open, as visual feedback for the click. Safe to call from
// any goroutine — it dispatches to the main thread.
func setTrayHighlighted(on bool) {
	C.dispatchHighlightToMain(C.bool(on))
}
