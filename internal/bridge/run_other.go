//go:build !windows

package bridge

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

func runProcess(ctx context.Context, exe string, args []string, stdin []byte, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var out, serr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &serr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	return out.Bytes(), serr.Bytes(), err
}
