//go:build windows

// Окно xdiag: одна кнопка «Диагностировать» над тем же ядром, что у CLI (docs/architecture.md
// §3.3). Wails v2 + WebView2 (есть в Windows 11). Сборка без CLI Wails:
//
//	go build -tags desktop,production -ldflags "-H windowsgui" ./cmd/xdiag-ui
package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"github.com/grokki91/xray_client/internal/capture"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	// Тот же exe — вспомогательный процесс захвата с правами администратора (UAC).
	if len(os.Args) >= 3 && os.Args[1] == "capture-helper" {
		if err := capture.RunJob(os.Args[2]); err != nil {
			os.Exit(1)
		}
		return
	}
	perMonitorDPI()
	app := NewApp()
	err := wails.Run(&options.App{
		Title:     "xdiag — диагностика подключения",
		Width:     1180,
		Height:    820,
		MinWidth:  760,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 243, G: 246, B: 251, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "xdiag-6f1d2c84-diagnostics",
		},
		Windows: &windows.Options{
			Theme:                windows.SystemDefault,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdiag-ui:", err)
		os.Exit(1)
	}
}
