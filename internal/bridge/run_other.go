//go:build !windows

package bridge

import (
	"bytes"
	"context"
	"os/exec"
)

func runProcess(ctx context.Context, exe string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	var out, serr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &serr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	return out.Bytes(), serr.Bytes(), err
}
