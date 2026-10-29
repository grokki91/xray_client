// Package repocheck — проверка репозитория на данные установки (AGENTS.md): IP вне
// документационных сетей (RFC 5737), петли, частных сетей и публичных резолверов, UUID кроме
// заглушек 00000000-0000-…, URI vless:// с адресом — провал. Те же правила, что tests/check.sh
// в grokki91/xray.
package repocheck

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	reIP   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reUUID = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reURI  = regexp.MustCompile(`(?i)vless://[0-9a-f-]{36}@([^:/?#\s"'\x60]+)`)
)

var resolvers = map[string]bool{"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true, "9.9.9.9": true,
	"149.112.112.112": true, "77.88.8.8": true, "77.88.8.1": true, "94.140.14.14": true, "94.140.15.15": true,
	"208.67.222.222": true, "208.67.220.220": true,
	"128.0.0.0": true} // половина пространства в маршрутах TUN (0.0.0.0/1, 128.0.0.0/1)

// IPOK — адрес допустим в репозитории.
func IPOK(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return true // не адрес (номер версии и т. п.)
	}
	if resolvers[s] || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10", "255.0.0.0/8"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return true
		}
	}
	return false
}

func root(t *testing.T) string {
	d, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			t.Fatal("нет go.mod")
		}
		d = p
	}
}

func files(t *testing.T, dir string) []string {
	out, err := exec.Command("git", "-C", dir, "ls-files", "-co", "--exclude-standard").Output()
	if err != nil {
		t.Skip("нет git")
	}
	var fs []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f != "" && !strings.HasSuffix(f, "go.sum") {
			fs = append(fs, f)
		}
	}
	return fs
}

func TestNoInstallationData(t *testing.T) {
	dir := root(t)
	for _, f := range files(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil || bytes.IndexByte(b, 0) >= 0 {
			continue // удалён или бинарный
		}
		s := string(b)
		for _, ip := range reIP.FindAllString(s, -1) {
			if !IPOK(ip) {
				t.Errorf("%s: адрес %s — не документационный, не частный, не резолвер", f, ip)
			}
		}
		for _, u := range reUUID.FindAllString(s, -1) {
			if !strings.HasPrefix(u, "00000000-0000-") {
				t.Errorf("%s: UUID %s (данные установки — никогда; в тестах — 00000000-0000-…)", f, u)
			}
		}
		for _, m := range reURI.FindAllStringSubmatch(s, -1) {
			h := m[1]
			if !IPOK(h) && !strings.HasSuffix(h, "example.com") && !strings.HasSuffix(h, "example.net") {
				t.Errorf("%s: vless:// с адресом %s", f, h)
			}
		}
	}
}

func TestIPOK(t *testing.T) {
	// Негативные примеры собираются из частей: сам тест тоже проходит проверку.
	bad1, bad2 := "26.10."+"21.1", "45.10."+"20.30"
	for ip, ok := range map[string]bool{"192.0.2.1": true, "127.0.0.1": true, "10.1.2.3": true, "1.1.1.1": true, bad1: false,
		"203.0.113.9": true, bad2: false, "999.1.1.1": true} {
		if IPOK(ip) != ok {
			t.Errorf("%s: %v", ip, !ok)
		}
	}
}
