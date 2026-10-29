//go:build windows

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

func pretty(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return b.String()
}

func baseName(p string) string { return filepath.Base(p) }
