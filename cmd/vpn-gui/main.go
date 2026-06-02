// Command vpn-gui is the desktop front-end for the vpn-helper daemon: a small
// Wails (Go + web) tray-style window that shows the tunnel state and drives the
// daemon's Connect/Disconnect/Status over its local control socket.
//
// It needs no privileges of its own — the daemon holds them. The window is the
// "Quiet Signal" main screen from docs/DESIGN.md; credential import and a
// native tray item are follow-ups.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:         "vpn.io",
		Width:         360,
		Height:        420,
		DisableResize: true,
		Frameless:     true,
		AssetServer:   &assetserver.Options{Assets: assets},
		// Opaque fallback matching --c-window (light). A native menu-bar
		// material can sit behind this later; the opaque value is what the
		// design's contrast numbers assume. The webview repaints per theme.
		BackgroundColour: &options.RGBA{R: 0xf5, G: 0xf5, B: 0xf7, A: 0xff},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
		Mac: &mac.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
