//go:build windows

package main

import "golang.org/x/sys/windows"

// consoleUTF8 — вывод по-русски в старой консоли (conhost с кодовой страницей 866).
func consoleUTF8() {
	_ = windows.SetConsoleOutputCP(65001)
	_ = windows.SetConsoleCP(65001)
}
