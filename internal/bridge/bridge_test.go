package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/grokki91/xray_client/internal/redact"
)

// Вывод `xm doctor --json` в формате ui/doctor.py (адреса — RFC 5737).
const doctorJSON = `{"server":{"self":{"r":"ok","ms":180},"xver":"26.10.21","port":443,"ufw":"open","ssh_peer":true,"server_ip":"203.0.113.50","traffic":{}},
"timeline":{"windows":120,"last_traffic":1761500000,"after":[{"t":1761560000,"e":"ver_xray:26.10.21","text":"версия Xray 26.10.21"}],"self_last":"ok"},
"profile":{"backups":3,"same_since":1761000000},
"groups":[{"label":"A","ssh":true,"own":true,"attempts":[{"t":1761650000,"syn":1,"c":1800,"s":5000,"acked":4000,"retx":0,"st":"hello",
"rd":{"sni":"www.example.com","mlkem":false,"shares":["X25519"],"own":true,"mlkem_rule":true,"idx":0,"ver":[1,8,1],"core":"sing-box: Hiddify 4.x, NekoBox, Karing, SFA/SFI","dt":0,"sid_ok":true,"r":"mlkem"},"after":"closed"}]}],
"live":{"seconds":60,"old":0,"drops":0},
"verdict":{"code":"client.core","title":"Клиент: ядро не шлёт X25519MLKEM768","evidence":["сеть A (та же, что у SSH): попыток с ключом этого сервера — 1"],
"actions":["Windows: Test-NetConnection 203.0.113.50 -Port 443"],"ruled_out":["сервер: Xray слушает"]}}`

func TestParseDoctorAndPick(t *testing.T) {
	d, err := ParseDoctor([]byte(doctorJSON))
	if err != nil {
		t.Fatal(err)
	}
	a, ssh, own, n := d.Pick()
	if a == nil || !ssh || !own || n != 1 || a.RD.R != "mlkem" || !d.Window() {
		t.Fatalf("%+v %v %v %d", a, ssh, own, n)
	}
	r := redact.New(nil)
	d.Register(r)
	if out := r.String(strings.Join(d.Verdict.Actions, " ")); strings.Contains(out, "203.0.113.50") {
		t.Fatalf("адрес сервера остался: %s", out)
	}
	if Detect([]byte(doctorJSON)) != "doctor" || Detect([]byte(`{}`)) != "health" {
		t.Fatal("Detect")
	}
}

func TestContractVersions(t *testing.T) {
	if _, err := ParseDoctor([]byte(`{"schema":{"name":"doctor","major":2},"server":{},"verdict":{"code":"ok"}}`)); !errors.Is(err, ErrNewerContract) {
		t.Fatalf("major 2: %v", err)
	}
	if _, err := ParseDoctor([]byte(`{"server":{},"verdict":{}}`)); err == nil {
		t.Fatal("пустой verdict — не doctor")
	}
	if _, err := ParseFacts([]byte(`{"xray":{"version":"26.10.21"}}`)); err == nil {
		t.Fatal("facts без schema")
	}
	f, err := ParseFacts([]byte(`{"schema":{"name":"bridge-facts","major":1,"minor":3},"xray":{"version":"26.10.21","mlkem_rule":true},
	"profile":{"salted":true,"clients":{"pc":"aaa","phone":"bbb"},"pbk":"ccc","short_ids":["ddd",""],"path":"eee","sni":["fff"],"port":"ggg"}}`))
	if err != nil {
		t.Fatal(err)
	}
	m := f.Match(map[string]string{"uuid": "bbb", "pbk": "xxx", "sid": "ddd", "path": "eee", "sni": "fff", "port": "ggg"})
	if !m["uuid"] || m["pbk"] || !m["sid"] || !m["path"] || !m["sni"] || !m["port"] {
		t.Fatalf("%v", m)
	}
}

func TestHealth(t *testing.T) {
	h, err := ParseHealth([]byte(`{"now":1761650000,"d7":{"windows":10},"incidents":[{"from":1,"to":2,"why":"заморозка","vd":"freeze","n":2}],
	"events":[{"t":5,"e":"ver_xray:26.9.30"},{"t":9,"e":"ver_xray:26.10.21"},{"t":7,"e":"xray"}],"last":{"t":1761650000,"vd":"nodata"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if v, ts := h.LastXrayVersion(); v != "26.10.21" || ts != 9 || h.Count("freeze") != 2 || h.Empty() {
		t.Fatalf("%s %d", v, ts)
	}
	e, _ := ParseHealth([]byte(`{}`))
	if !e.Empty() {
		t.Fatal("пустой журнал")
	}
}

func TestArgsAllowlist(t *testing.T) {
	a, err := Args("xm-ui", "doctor", 60)
	if err != nil || strings.Join(a[len(a)-9:], " ") != "-- xm-ui sudo -n xm bridge doctor --live 60" {
		t.Fatalf("%v %v", a, err)
	}
	for _, bad := range []struct {
		alias, cmd string
		live       int
	}{{"-oProxyCommand=calc", "facts", 0}, {"xm ui", "facts", 0}, {"xm-ui", "restart", 0}, {"xm-ui", "doctor", 500}, {"xm-ui;rm", "facts", 0}} {
		if _, err := Args(bad.alias, bad.cmd, bad.live); err == nil {
			t.Errorf("пропущено: %+v", bad)
		}
	}
}

func TestSSHErrors(t *testing.T) {
	cases := map[string]error{
		"Host key verification failed.":                        ErrHostKey,
		"user@host: Permission denied (publickey).":            ErrAuth,
		"sudo: a password is required":                         ErrSudo,
		"ssh: connect to host x port 22: Connection timed out": ErrUnreachable,
		"ssh: Could not resolve hostname xm-ui":                ErrResolve,
	}
	for serr, want := range cases {
		s := &SSH{Alias: "xm-ui", Exe: "ssh", Run: func(context.Context, string, []string, []byte) ([]byte, []byte, error) {
			return nil, []byte(serr), errors.New("exit status 255")
		}}
		if _, err := s.Facts(context.Background(), "00"); !errors.Is(err, want) {
			t.Errorf("%q → %v", serr, err)
		}
	}
	// xm без bridge печатает справку — это не JSON.
	s := &SSH{Alias: "xm-ui", Exe: "ssh", Run: func(context.Context, string, []string, []byte) ([]byte, []byte, error) {
		return []byte("xm — менеджер Xray   sudo xm <команда>"), nil, nil
	}}
	if _, err := s.Health(context.Background()); !errors.Is(err, ErrNoBridge) {
		t.Fatalf("%v", err)
	}
	var gotStdin string
	s = &SSH{Alias: "xm-ui", Exe: "ssh", Run: func(_ context.Context, _ string, _ []string, in []byte) ([]byte, []byte, error) {
		gotStdin = string(in)
		return []byte(`{"schema":{"name":"bridge-facts","major":1},"xray":{"version":"26.10.21"}}`), nil, nil
	}}
	if _, err := s.Facts(context.Background(), "0123456789abcdef0123456789abcdef"); err != nil || gotStdin != "0123456789abcdef0123456789abcdef\n" {
		t.Fatalf("%v %q", err, gotStdin)
	}
}
