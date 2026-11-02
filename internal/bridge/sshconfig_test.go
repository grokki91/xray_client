package bridge

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeCfg(t *testing.T, dir, name, text string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Алиас сервера находится по HostName = адрес профиля, порт — первый из подходящих блоков (как
// у ssh), маски и отрицания алиасами не считаются, Match и параметры до первого Host не
// путают блоки, Include (с маской) читается, строки после Include — снова свой блок.
func TestSSHConfigFind(t *testing.T) {
	dir := t.TempDir()
	writeCfg(t, dir, "config.d/work", "Host work\n  HostName 198.51.100.20\n")
	p := writeCfg(t, dir, "config", `# комментарий
Host xm-ui vps
    HostName 203.0.113.7
    Port 40022
    IdentityFile ~/.ssh/id_ed25519
Host *.example.com !skip.example.com
    Port 2222
Host old
    HostName=203.0.113.8
Match host other
    HostName 203.0.113.9
    Port 1
Host "quoted"
    Include config.d/*
    HostName 192.0.2.10
Host plain.example.com
Host *
    Port 2022
`)
	c := ReadSSHConfig(p)
	if got := c.Aliases(); !slices.Equal(got, []string{"xm-ui", "vps", "old", "quoted", "work", "plain.example.com"}) {
		t.Fatalf("алиасы: %v", got)
	}
	for _, x := range []struct {
		addrs []string
		alias string
		port  int
	}{
		{[]string{"203.0.113.7"}, "xm-ui", 40022},
		{[]string{"[203.0.113.8]"}, "old", 2022},  // свой Port не задан — из «Host *»
		{[]string{"198.51.100.20"}, "work", 2022}, // из включённого файла
		{[]string{"192.0.2.10"}, "quoted", 2022},  // HostName после Include — в своём блоке
		{[]string{"PLAIN.example.com."}, "plain.example.com", 2222},
		{[]string{"x.example.net", "203.0.113.7"}, "xm-ui", 40022},
	} {
		alias, port, ok := c.Find(x.addrs...)
		if !ok || alias != x.alias || port != x.port {
			t.Errorf("%v: %q %d %v, ожидалось %q %d", x.addrs, alias, port, ok, x.alias, x.port)
		}
	}
	if _, _, ok := c.Find("203.0.113.9"); ok {
		t.Error("HostName из блока Match не должен находиться")
	}
	if _, _, ok := c.Find(""); ok {
		t.Error("пустой адрес")
	}
	if h, port := c.Resolve("skip.example.com"); h != "skip.example.com" || port != 2022 {
		t.Errorf("отрицание: %s %d", h, port)
	}
	// Параметр до первого Host — для всех хостов и первый: у ssh он побеждает свой Port блока.
	g := ReadSSHConfig(writeCfg(t, dir, "global", "Port 2200\nHost xm-ui\n  HostName 203.0.113.7\n  Port 40022\n"))
	if _, port, ok := g.Find("203.0.113.7"); !ok || port != 2200 {
		t.Errorf("глобальный Port: %d %v", port, ok)
	}
	// Нет файла — пустой конфиг, не ошибка.
	if _, _, ok := ReadSSHConfig(filepath.Join(dir, "нет")).Find("203.0.113.7"); ok {
		t.Error("нет файла")
	}
}

func TestSSHLine(t *testing.T) {
	for _, x := range []struct {
		in   string
		key  string
		args []string
	}{
		{"  HostName  203.0.113.7  ", "hostname", []string{"203.0.113.7"}},
		{"Port=40022", "port", []string{"40022"}},
		{"Port = 40022 # свой порт", "port", []string{"40022"}},
		{`Host "a b" c`, "host", []string{"a b", "c"}},
		{"# Host x", "", nil},
	} {
		k, a := sshLine(x.in)
		if k != x.key || !slices.Equal(a, x.args) {
			t.Errorf("%q: %q %q", x.in, k, a)
		}
	}
}
