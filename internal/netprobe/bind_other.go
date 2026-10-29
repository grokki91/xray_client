//go:build !windows

package netprobe

import "syscall"

// bindInterface вне Windows не нужна: приложение диагностирует Windows-клиенты, а на Linux
// работают только тесты на петле.
func bindInterface(string, syscall.RawConn, int) error { return nil }
