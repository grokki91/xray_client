package engine

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/osw"
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

// Мост — под сервер профиля. Алиас «Настроек» ведёт на другой сервер: его факты сверили бы хэши
// профиля с чужим сервером («ключ не совпал» — подтверждено, хотя профиль ни при чём). Есть Host с
// адресом профиля в ~/.ssh/config — мост идёт через него; нет — сеанс не начинается, окно ведёт в
// «Настройки».
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
	var dialed []string
	e.NewSSH = func(alias, _ string) (SSHBridge, error) {
		dialed = append(dialed, alias)
		return &fakeBridge{prof: p, doctor: string(doctorAt("127.0.0.1"))}, nil
	}
	sess, err := e.Run(context.Background(), Options{Offline: true, Bridge: "ssh", SSHAlias: "other"}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dialed, ",") != "here" || sess.Bridge != "ssh" || evFacts(t, sess, "S1")["match_pbk"] != true {
		t.Fatalf("мост к серверу профиля по Host из ~/.ssh/config: %v %q", dialed, sess.Bridge)
	}
	dialed = nil
	sess, _ = e.Run(context.Background(), Options{Offline: true, Bridge: "ssh", SSHAlias: "here"}, Hooks{})
	if strings.Join(dialed, ",") != "here" || sess.Bridge != "ssh" {
		t.Fatalf("алиас настроек сервера профиля: %v %q", dialed, sess.Bridge)
	}
	// Своего Host у сервера профиля нет: мост не к кому — в «Настройки», к серверу ни одного SSH.
	write(t, cfg, "Host other\n  HostName 198.51.100.20\n")
	dialed = nil
	_, err = e.Run(context.Background(), Options{Offline: true, Bridge: "ssh", SSHAlias: "other"}, Hooks{})
	var be *BridgeError
	if !errors.As(err, &be) || be.Code != "other_server" || be.Alias != "other" || !errors.Is(err, bridge.ErrOtherServer) || len(dialed) > 0 {
		t.Fatalf("алиас другого сервера без своего Host: %v, мост %v", err, dialed)
	}
	// Алиаса нет и Host сервера нет: SSH не задан — сеанс без моста, как раньше.
	sess, err = e.Run(context.Background(), Options{Offline: true, Bridge: "ssh"}, Hooks{})
	if err != nil || sess.Bridge != "" || len(dialed) > 0 {
		t.Fatalf("без SSH: %v %q %v", err, sess.Bridge, dialed)
	}
}

// Вход по SSH не удался по причине на ПК (ключ, пароль ключа, known_hosts) — сеанс
// останавливается до первой пробы сети: это чинится за минуту в «Настройках». SSH не дошёл — улика, сеанс идёт; под TUN клиента — и не улика: ssh.exe
// шёл через тоннель.
func TestBridgeNotReady(t *testing.T) {
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
	write(t, cfg, "Host nl\n  HostName 127.0.0.1\n")
	e.SSHConfig = func() *bridge.SSHConfig { return bridge.ReadSSHConfig(cfg) }
	p, _ := profile.ParseURI(s.URI("chrome"))
	fail := bridge.ErrPassphrase
	e.NewSSH = func(string, string) (SSHBridge, error) { return &fakeBridge{prof: p, err: fail}, nil }
	var phases []int
	hooks := Hooks{Progress: func(st Step) { phases = append(phases, st.Phase) }}
	o := Options{Reference: true, Hosts: testHosts(s), Bridge: "ssh", SkipRepeat: true}
	for _, f := range []error{bridge.ErrPassphrase, bridge.ErrBadPassphrase, bridge.ErrAuth, bridge.ErrHostKey} {
		fail, phases = f, nil
		_, err = e.Run(context.Background(), o, hooks)
		var be *BridgeError
		if !errors.As(err, &be) || be.Alias != "nl" || !errors.Is(err, f) {
			t.Fatalf("%v: сеанс не остановлен: %v", f, err)
		}
		for _, ph := range phases {
			if ph == 1 || ph == 2 {
				t.Fatalf("%v: пробы сети до готового моста: фазы %v", f, phases)
			}
		}
	}
	// Скрин 10: вход по SSH есть, а `sudo -n xm bridge` нет (в xm сервера команды bridge пока нет) —
	// не повод стоять: вход — улика «соединение с сервером есть», сеанс идёт без фактов сервера.
	for _, f := range []error{bridge.ErrSudo, bridge.ErrNoBridge} {
		fail = f
		sess, err := e.Run(context.Background(), Options{Offline: true, Bridge: "ssh"}, Hooks{})
		if err != nil || evFacts(t, sess, "S0")["ssh"] != "ok" {
			t.Fatalf("%v: вход есть — сеанс должен идти с S0.ssh=ok: %v", f, err)
		}
	}
	// SSH не дошёл — это улика (адрес режется целиком), сеанс идёт без моста.
	fail = bridge.ErrUnreachable
	sess, err := e.Run(context.Background(), Options{Offline: true, Bridge: "ssh"}, Hooks{})
	if err != nil || evFacts(t, sess, "S0")["ssh"] != "unreachable" {
		t.Fatalf("SSH недоступен: %v", err)
	}
	// Под TUN ssh.exe шёл через тоннель клиента: таймаут — не про SSH сервера.
	e.CollectOS = func(context.Context, []string) osw.Facts {
		return osw.Facts{Collected: true, Services: map[string]string{}, DefaultViaTUN: true}
	}
	sess, err = e.Run(context.Background(), Options{Offline: true, Bridge: "ssh"}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := evFacts(t, sess, "S0")["ssh"]; ok || !strings.Contains(strings.Join(sess.Need, " "), "через тоннель клиента") {
		t.Fatalf("TUN: S0 %v, need %v", evFacts(t, sess, "S0"), sess.Need)
	}
}
