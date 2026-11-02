package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/sim"
)

// closedPort — порт на петле, который никто не слушает (соединение — отказ, RST).
func closedPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// sshCfg — ~/.ssh/config во временном каталоге.
func sshCfg(t *testing.T, text string) func() *bridge.SSHConfig {
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return func() *bridge.SSHConfig { return bridge.ReadSSHConfig(p) }
}

// Порт сервера открыт, эталон не прошёл: SSH того же адреса проверяется с портом из
// ~/.ssh/config (Host с адресом сервера) — алиас в настройках не нужен; алиас настроек от другого
// сервера не используется; порт неизвестен — пробы нет, а в «для точного ответа» — почему.
func TestSSHWhenServerAnswers(t *testing.T) {
	closed := closedPort(t)
	prof := &profile.Profile{Address: "127.0.0.1", Port: 1}
	for _, c := range []struct {
		name, alias, cfg string
		want             string // source P6: "" — пробы нет
	}{
		{"Host с адресом сервера", "", fmt.Sprintf("Host srv\n  HostName 127.0.0.1\n  Port %d\n", closed), "config"},
		{"алиас настроек — от другого сервера", "other", fmt.Sprintf("Host other\n  HostName 203.0.113.50\n  Port 2222\nHost srv\n  HostName 127.0.0.1\n  Port %d\n", closed), "config"},
		{"алиас настроек", "srv", fmt.Sprintf("Host srv\n  HostName 127.0.0.1\n  Port %d\n", closed), "settings"},
		{"порт неизвестен", "", "Host other\n  HostName 203.0.113.50\n", ""},
	} {
		r := probeRun(t, Options{SSHAlias: c.alias}, prof)
		r.e.SSHConfig = sshCfg(t, c.cfg)
		r.put(evidence.Evidence{ID: "P1", Facts: map[string]any{"outcome": "ok"}})
		r.sshPort(context.Background(), net.ParseIP("127.0.0.1"), true)
		p6 := r.set.Get("P6")
		if c.want == "" {
			if p6 != nil || r.budget.Usage().TotalTCP != 0 || strings.Join(r.need, ",") != "ssh_port" {
				t.Fatalf("%s: P6 %+v, need %v", c.name, p6, r.need)
			}
			continue
		}
		if p6 == nil || p6.Str("outcome") != "refused" || !p6.Bool("known") || p6.Str("source") != c.want {
			t.Fatalf("%s: P6 %+v", c.name, p6)
		}
		if !strings.Contains(p6.Summary, "SSH на этом порту не слушает") || strings.Contains(p6.Summary, fmt.Sprint(closed)) ||
			strings.Contains(p6.Summary, "srv") || len(r.need) != 0 {
			t.Fatalf("%s: текст P6 %q, need %v", c.name, p6.Summary, r.need)
		}
	}
}

// Скрин 7 на стенде: профиль с ключом REALITY от другого сервера. TCP есть, эталон и обычный TLS
// получают сертификат не той маски, SSH того же адреса (порт из ~/.ssh/config) отказывает — мост и
// окно сервера не советуются (вместо них веб-консоль), к серверу — 4 TCP и 2 TLS.
func TestStaleProfileSSHClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	uri := strings.Replace(s.URI("chrome"), "pbk="+s.PublicKey, "pbk="+other, 1)
	e := testEngine(t, s, t.TempDir())
	e.SSHConfig = sshCfg(t, fmt.Sprintf("Host srv\n  HostName 127.0.0.1\n  Port %d\n", closedPort(t)))
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), ProfileURI: uri, SkipRepeat: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	f := func(id string) map[string]any { return evFacts(t, sess, id) }
	if f("P1")["outcome"] != "ok" || f("P3")["outcome"] != "real_cert" || f("P2")["outcome"] != "other_cert" ||
		f("P6")["outcome"] != "refused" || f("P6")["source"] != "config" {
		t.Fatalf("P1 %v, P3 %v, P2 %v, P6 %v", f("P1"), f("P3"), f("P2"), f("P6"))
	}
	v := sess.Verdict
	var next, find, poss []string
	for _, c := range v.NextChecks {
		next = append(next, c.ID)
	}
	for _, x := range v.Findings {
		find = append(find, x.Code)
	}
	for _, x := range v.Possible {
		poss = append(poss, x.Code)
	}
	// Маска по своему адресу на стенде не проверяется (нет DNS): «профиль не от этого сервера» —
	// «возможно», с ней — «вероятно» (сценарий в internal/rules).
	if strings.Join(next, ",") != "K1" || !strings.Contains(strings.Join(find, ","), "server.ssh.silent") ||
		!strings.Contains(strings.Join(poss, ","), "profile.stale") {
		t.Fatalf("вердикт %s: проверки %v, находки %v, возможные %v", v.Main.Code, next, find, poss)
	}
	if sess.Budget.TotalTCP != 4 || sess.Budget.TotalTLS != 2 || len(sess.Need) != 0 {
		t.Fatalf("бюджет %+v, need %v", sess.Budget, sess.Need)
	}
}

// Клиент запущен и не работает, эталон не прошёл, SSH-порт неизвестен — «для точного ответа»
// называет, чего не хватило (логи клиента — тоже), а при работающем клиенте не говорит ничего.
func TestNeedTexts(t *testing.T) {
	r := probeRun(t, Options{}, &profile.Profile{Address: "127.0.0.1", Port: 1})
	r.put(evidence.Evidence{ID: "N1", Facts: map[string]any{"ok": true}})
	r.put(evidence.Evidence{ID: "C10", Facts: map[string]any{"outcome": "fail", "listening": true}})
	r.put(evidence.Evidence{ID: "C6", Facts: map[string]any{"found": false}})
	r.missing("ssh_port")
	r.missing("ssh_port")
	r.finish()
	if len(r.sess.Need) != 2 || !strings.Contains(r.sess.Need[0], "SSH-порт") || !strings.Contains(r.sess.Need[1], "Логи клиента") {
		t.Fatalf("need: %q", r.sess.Need)
	}
	r = probeRun(t, Options{}, &profile.Profile{Address: "127.0.0.1", Port: 1})
	r.put(evidence.Evidence{ID: "C10", Facts: map[string]any{"outcome": "ok", "listening": true}})
	r.missing("ssh_port")
	r.finish()
	if len(r.sess.Need) != 0 {
		t.Fatalf("клиент работает, а need: %q", r.sess.Need)
	}
}
