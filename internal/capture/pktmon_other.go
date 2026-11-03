//go:build !windows

package capture

import (
	"context"
	"errors"
)

func pktmon(...string) error { return errors.New("pktmon есть только в Windows") }

// RunElevated вне Windows недоступен.
func RunElevated(context.Context, string, string) error {
	return errors.New("захват pktmon есть только в Windows")
}

// Available — pktmon есть только в Windows.
func Available() bool { return false }
