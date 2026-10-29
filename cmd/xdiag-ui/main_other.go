//go:build !windows

// Окно xdiag — только для Windows; вне Windows есть CLI `xdiag`.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "xdiag-ui работает только в Windows; в терминале — xdiag run")
	os.Exit(1)
}
