//go:build windows

package main

import "golang.org/x/sys/windows"

// perMonitorDPI — чёткое окно на экранах с масштабом > 100 % без манифеста (ресурсы с
// манифестом добавляет сборка через go-winres, но и без них окно не размыто). До создания окна.
func perMonitorDPI() {
	p := windows.NewLazySystemDLL("user32.dll").NewProc("SetProcessDpiAwarenessContext")
	if p.Find() == nil {
		const perMonitorV2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
		_, _, _ = p.Call(perMonitorV2)
	}
}
