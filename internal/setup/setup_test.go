package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/clients"
)

// Тестовые значения: адреса — RFC 5737, домены — example.com, ключ сгенерирован для теста.
const (
	tUUID = "00000000-0000-4000-8000-000000000001"
	tPBK  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
	tURI  = "vless://" + tUUID + "@192.0.2.10:443?encryption=none&security=reality&sni=www.example.com" +
		"&fp=chrome&pbk=" + tPBK + "&sid=0123abcd&type=xhttp&path=%2Fxh-test&mode=auto#test"
)

func TestProfile(t *testing.T) {
	for _, c := range []struct {
		uri, state, want string
	}{
		{"", Off, "профиль из клиента"},
		{"vless://%zz", Bad, "целиком"},
		{"vless://испорчен", Warn, "нет UUID"},
		{tURI, OK, "VLESS · REALITY · XHTTP · порт 443"},
		{strings.Replace(tURI, "&fp=chrome", "", 1), Warn, "Не задан отпечаток (fp)"},
		{strings.Replace(tURI, ":443?", ":8443?", 1), OK, "нестандартный порт"},
		{tURI + "\n" + tURI, OK, "профилей в тексте: 2"},
	} {
		it := Profile(c.uri)
		if it.State != c.state || !strings.Contains(it.Note, c.want) {
			t.Errorf("%.40q → %+v", c.uri, it)
		}
		// Ни адреса, ни ключа, ни UUID, ни пути, ни нестандартного порта — в окне только описание.
		for _, secret := range []string{"192.0.2.10", tUUID, tPBK, "xh-test", "example.com", "8443", "0123abcd"} {
			if strings.Contains(it.Text+it.Note, secret) {
				t.Errorf("в описании профиля %q", secret)
			}
		}
	}
}

func TestBridgeOffline(t *testing.T) {
	noSSH := func() error { return errors.New("not found") }
	haveSSH := func() error { return nil }
	for _, c := range []struct {
		alias string
		look  func() error
		state string
	}{
		{"", noSSH, Off},
		{"-oProxyCommand=calc", haveSSH, Bad},
		{"xm-ui", noSSH, Bad},
		{"xm-ui", haveSSH, Idle},
	} {
		if it := BridgeOffline(c.alias, c.look); it.State != c.state {
			t.Errorf("%q → %+v", c.alias, it)
		}
	}
}

type fakeBridge struct {
	salt  string
	facts *bridge.Facts
	err   error
}

func (f *fakeBridge) Facts(_ context.Context, salt string) (*bridge.Facts, error) {
	f.salt = salt
	return f.facts, f.err
}

func TestBridge(t *testing.T) {
	ok := &bridge.Facts{}
	ok.Xray.Version = "26.10.21"
	fb := &fakeBridge{facts: ok}
	it := Bridge(context.Background(), " xm-ui ", func(alias string) (Facter, error) {
		if alias != "xm-ui" {
			t.Errorf("алиас %q", alias)
		}
		return fb, nil
	})
	if it.State != OK || !strings.Contains(it.Note, "Xray 26.10.21") {
		t.Fatalf("%+v", it)
	}
	if len(fb.salt) != 32 || strings.Trim(fb.salt, "0123456789abcdef") != "" {
		t.Fatalf("соль %q — не 32 hex", fb.salt)
	}

	// Без алиаса и с плохим алиасом ssh не запускается.
	for _, alias := range []string{"", "xm ui"} {
		Bridge(context.Background(), alias, func(string) (Facter, error) { t.Fatalf("ssh для %q", alias); return nil, nil })
	}

	// Звено, на котором остановилось: SSH работает, но на сервере нет моста — это не «не работает».
	for err, want := range map[error]Item{
		bridge.ErrNoBridge:                  {State: Warn, Text: "SSH работает, моста на сервере нет"},
		bridge.ErrSudo:                      {State: Warn, Text: "SSH работает, нет правила sudo"},
		bridge.ErrAuth:                      {State: Bad, Text: "Ключ не принят"},
		bridge.ErrResolve:                   {State: Bad, Text: "Алиас не найден"},
		bridge.ErrUnreachable:               {State: Bad, Text: "Сервер недоступен по SSH"},
		bridge.ErrOlderContract:             {State: Warn, Text: "Сервер старее приложения"},
		context.DeadlineExceeded:            {State: Bad, Text: "Нет ответа"},
		errors.New("мост: exit status 255"): {State: Bad, Text: "Не работает"},
	} {
		got := Bridge(context.Background(), "xm-ui", func(string) (Facter, error) { return &fakeBridge{err: err}, nil })
		if got.State != want.State || got.Text != want.Text {
			t.Errorf("%v → %+v", err, got)
		}
	}
	got := Bridge(context.Background(), "xm-ui", func(string) (Facter, error) { return nil, bridge.ErrNoSSH })
	if got.State != Bad || got.Text != "Нет ssh.exe" {
		t.Errorf("нет ssh.exe → %+v", got)
	}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testEnv(t *testing.T) *clients.Env {
	root := t.TempDir()
	return &clients.Env{AppData: filepath.Join(root, "Roaming"), LocalAppData: filepath.Join(root, "Local"), ProgramFiles: filepath.Join(root, "PF"),
		UserProfile: filepath.Join(root, "user"), TempDir: t.TempDir(), Now: time.Now,
		FileVersion: func(p string) string {
			switch filepath.Base(p) {
			case "Hiddify.exe":
				return "4.1.2"
			case "v2rayN.exe":
				return "7.25.6"
			}
			return ""
		},
	}
}

func byName(t *testing.T, l []Client, name string) Client {
	t.Helper()
	for _, c := range l {
		if c.Client == name {
			return c
		}
	}
	t.Fatalf("нет %s в %+v", name, l)
	return Client{}
}

func TestClients(t *testing.T) {
	env := testEnv(t)
	write(t, filepath.Join(env.ProgramFiles, "Hiddify", "Hiddify.exe"), "MZ")
	hid := filepath.Join(env.AppData, "Hiddify", "hiddify")
	write(t, filepath.Join(hid, "shared_preferences.json"), `{}`)
	v2 := filepath.Join(t.TempDir(), "portable", "v2rayN-windows-64")
	write(t, filepath.Join(v2, "v2rayN.exe"), "MZ")
	ctx := context.Background()

	// Ничего не указано: Hiddify найден сам, портативный v2rayN в своей папке — нет.
	l := Clients(ctx, env, Input{})
	if h := byName(t, l, "hiddify"); h.State != OK || h.Manual || h.Dir != hid || h.Version != "4.1.2" {
		t.Fatalf("hiddify: %+v", h)
	}
	if v := byName(t, l, "v2rayn"); v.State != Off {
		t.Fatalf("v2rayn: %+v", v)
	}

	// Указаны: Hiddify — та же папка, что находится сама; v2rayN — портативный каталог.
	l = Clients(ctx, env, Input{HiddifyDir: hid, V2rayNDir: v2})
	if h := byName(t, l, "hiddify"); h.State != OK || !h.Manual || !strings.Contains(h.Note, "указывать не обязательно") {
		t.Fatalf("hiddify вручную: %+v", h)
	}
	if v := byName(t, l, "v2rayn"); v.State != OK || !v.Manual || v.Dir != v2 || v.Version != "7.25.6" {
		t.Fatalf("v2rayn вручную: %+v", v)
	}

	// Указана папка уровнем выше и несуществующая: «не подходит», с подсказкой, что найдено само.
	l = Clients(ctx, env, Input{HiddifyDir: filepath.Dir(hid), V2rayNDir: filepath.Join(v2, "нет")})
	if h := byName(t, l, "hiddify"); h.State != Bad || !strings.Contains(h.Note, "уровнем выше") || !strings.Contains(h.Note, "Найден сам: "+hid) {
		t.Fatalf("hiddify уровнем выше: %+v", h)
	}
	if v := byName(t, l, "v2rayn"); v.State != Bad || !strings.Contains(v.Note, "Папка не найдена") {
		t.Fatalf("v2rayn нет папки: %+v", v)
	}

	// Папка программы v2rayN уровнем выше каталога с exe.
	if v := byName(t, Clients(ctx, env, Input{V2rayNDir: filepath.Dir(v2)}), "v2rayn"); v.State != Bad || !strings.Contains(v.Note, "v2rayN-windows-64") {
		t.Fatalf("v2rayn уровнем выше: %+v", v)
	}
}
