package engine

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/sim"
)

// doctorAt — вывод `xm doctor --live 60 --json` сервера с адресом ip: за окно — только сканеры
// портов (SYN → SYN-ACK → RST), попыток с ключом нет: net.nosyn.
func doctorAt(ip string) []byte {
	return []byte(`{"server":{"self":{"r":"ok","ms":106},"xver":"26.10.21","port":443,"ufw":"open","ssh_peer":false,"server_ip":"` + ip + `"},
	"timeline":{"windows":2016},"profile":{},"live":{"seconds":60,"old":2,"drops":0},
	"groups":[{"label":"A","ssh":false,"own":false,"attempts":[{"t":1,"syn":1,"c":0,"s":0,"acked":0,"st":"scan"}]}],
	"verdict":{"code":"net.nosyn","title":"До сервера не доходит ни одной попытки клиента","evidence":[],"actions":[]}}`)
}

// Живой случай 2026-11-03: окно `xm doctor` снято на другом сервере владельца (адрес в выводе —
// не адрес профиля). «До сервера ничего не доходит» с чужого сервера — не про этот профиль: окно
// не учитывается, сеанс об этом говорит. С сервера профиля — учитывается как раньше.
func TestDoctorFromOtherServer(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	root := t.TempDir()
	hiddifyDir(t, s, root)
	e := testEngine(t, s, root)
	run := func(ip string) *SessionData {
		sess, err := e.Run(context.Background(), Options{Offline: true, Imports: []Import{{Name: "doctor.json", Data: doctorAt(ip)}}}, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	sess := run("198.51.100.20")
	for _, x := range sess.Evidence {
		if x.ID == "S3" {
			t.Fatalf("окно с другого сервера учтено: %+v", x.Facts)
		}
	}
	// Имя профиля стенда — «сервер», редактор прячет его и внутри слов: в заметке ищется остальное.
	if !strings.Contains(strings.Join(sess.Need, " "), "снято на другом сервере") || !strings.Contains(strings.Join(sess.Notes, " "), "окно не учтено") {
		t.Fatalf("не сказано про чужой сервер: need %v, notes %v", sess.Need, sess.Notes)
	}
	warned := false
	for _, st := range sess.Steps {
		warned = warned || (st.ID == "S3" && st.Status == "warn")
	}
	if !warned {
		t.Fatalf("шаг S3: %+v", sess.Steps)
	}
	if c := evFacts(t, run("127.0.0.1"), "S3"); c["code"] != "net.nosyn" {
		t.Fatalf("окно с сервера профиля: %v", c)
	}
}

// Мост: алиас в «Настройках» ведёт на другой сервер — его факты сверили бы хэши профиля с чужим
// сервером («ключ не совпал» — подтверждено, хотя профиль ни при чём). Мост пропускается.
func TestBridgeAliasOtherServer(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	root := t.TempDir()
	hiddifyDir(t, s, root)
	e := testEngine(t, s, root)
	cfg := filepath.Join(root, "ssh_config")
	write(t, cfg, "Host other\n  HostName 198.51.100.20\n  Port 2222\nHost here\n  HostName 127.0.0.1\n")
	e.SSHConfig = func() *bridge.SSHConfig { return bridge.ReadSSHConfig(cfg) }
	p, _ := profile.ParseURI(s.URI("chrome"))
	called := false
	e.NewSSH = func(string) (SSHBridge, error) {
		called = true
		return &fakeBridge{prof: p, doctor: string(doctorAt("127.0.0.1"))}, nil
	}
	sess, err := e.Run(context.Background(), Options{Offline: true, Bridge: "ssh", SSHAlias: "other"}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if called || !strings.Contains(strings.Join(sess.Need, " "), "от другого сервера") {
		t.Fatalf("мост к чужому серверу: вызван %v, need %v", called, sess.Need)
	}
	sess, _ = e.Run(context.Background(), Options{Offline: true, Bridge: "ssh", SSHAlias: "here"}, Hooks{})
	if !called || sess.Bridge != "ssh" {
		t.Fatalf("мост к серверу профиля не вызван: %v %q", called, sess.Bridge)
	}
}
