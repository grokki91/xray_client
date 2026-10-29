//go:build !windows

package capture

import (
	"context"
	"errors"
	"time"
)

func pktmonCapture(Job, string, time.Duration) Result {
	return Result{Err: "pktmon есть только в Windows"}
}

// RunElevated вне Windows недоступен.
func RunElevated(context.Context, string, string) error {
	return errors.New("захват pktmon есть только в Windows")
}

// Available — pktmon есть только в Windows.
func Available() bool { return false }
