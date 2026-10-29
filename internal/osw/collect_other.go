//go:build !windows

package osw

import (
	"context"
	"os/exec"
	"time"
)

func collect(context.Context, []string) Facts {
	return Facts{Err: "не Windows: факты ОС не собираются"}
}

// FileVersion вне Windows не определяется.
func FileVersion(string) string { return "" }

// BestInterface вне Windows не нужен.
func BestInterface(string) int { return 0 }

// RunHidden — запуск программы (вне Windows окно не появляется).
func RunHidden(ctx context.Context, exe string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, exe, args...).CombinedOutput()
}

// IsAdmin вне Windows не проверяется.
func IsAdmin() bool { return false }
