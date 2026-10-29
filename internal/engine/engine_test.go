package engine

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/redact"
	"github.com/grokki91/xray_client/internal/refcore"
	"github.com/grokki91/xray_client/internal/rules"
	"github.com/grokki91/xray_client/internal/sim"
	"github.com/grokki91/xray_client/internal/store"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hiddifyDir — каталог данных Hiddify 4.1.2 с профилем на стенд (как его пишет приложение).
func hiddifyDir(t *testing.T, s *sim.Sim, root string) {
	dir := filepath.Join(root, "Roaming", "Hiddify", "hiddify")
	write(t, filepath.Join(root, "PF", "Hiddify", "Hiddify.exe"), "MZ")
	write(t, filepath.Join(dir, "shared_preferences.json"), `{"flutter.service-mode":"system-proxy","flutter.connection-test-url":"`+s.URL("/generate_204")+`"}`)
	write(t, filepath.Join(dir, "configs", "p1.json"), fmt.Sprintf(`{"outbounds":[{"type":"vless","tag":"sim","server":"127.0.0.1","server_port":%d,
	"uuid":"%s","tls":{"enabled":true,"server_name":"%s","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,
	"public_key":"%s","short_id":"%s"}},"transport":{"type":"xhttp","path":"%s","mode":"auto"}}]}`, s.Port, sim.UUID, sim.SNI, s.PublicKey, sim.ShortID, sim.Path))
	db, err := sql.Open("sqlite", filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{`CREATE TABLE profile_entries (id TEXT, type TEXT, active INTEGER, name TEXT, url TEXT)`,
		`INSERT INTO profile_entries VALUES ('p1','remote',1,'сервер','https://sub.example.com/token/abcdef')`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

type fakeBridge struct {
	prof   *profile.Profile
	doctor string
	err    error
}

func (f *fakeBridge) Facts(_ context.Context, saltHex string) (*bridge.Facts, error) {
	if f.err != nil {
		return nil, f.err
	}
	salt := []byte{}
	fmt.Sscanf(saltHex, "%x", &salt)
	h := f.prof.Hashes(salt)
	b := fmt.Sprintf(`{"schema":{"name":"bridge-facts","major":1,"minor":0},"time":%d,"xray":{"version":"26.10.21","active":true,"mlkem_rule":true},
	"public":{"port":%d,"transport":"xhttp","sni":"%s"},"firewall":{"ufw":"open"},"self":{"r":"ok","ms":120},"ru_block":true,
	"profile":{"salted":true,"clients":{"pc":"%s"},"pbk":"%s","short_ids":["%s"],"path":"%s","sni":["%s"],"port":"%s"}}`,
		time.Now().Unix(), f.prof.Port, sim.SNI, h["uuid"], h["pbk"], h["sid"], h["path"], h["sni"], h["port"])
	return bridge.ParseFacts([]byte(b))
}

func (f *fakeBridge) Doctor(context.Context, int) (*bridge.Doctor, []byte, error) {
	d, err := bridge.ParseDoctor([]byte(f.doctor))
	return d, []byte(f.doctor), err
}

func (f *fakeBridge) Health(context.Context) (*bridge.Health, error) {
	return bridge.ParseHealth([]byte(`{"now":1,"d7":{"windows":5},"events":[{"t":1761560000,"e":"ver_xray:26.10.21"}],"incidents":[]}`))
}

func testEngine(t *testing.T, s *sim.Sim, root string) *Engine {
	re, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(root, "xdiag"))
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Rules: re, Store: st, Budget: netprobe.NewBudget(), Adapters: clients.All(), RunRef: refcore.Run,
		CollectOS: func(context.Context, []string) osw.Facts {
			return osw.Facts{Collected: true, Services: map[string]string{}}
		},
		// DNS в тестах нет: имя маски не резолвится (N4 — «нет»), сервер задан IP.
		Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("нет DNS") }}}
	e.NewEnv = func(f *osw.Facts) *clients.Env {
		return &clients.Env{AppData: filepath.Join(root, "Roaming"), LocalAppData: filepath.Join(root, "Local"), ProgramFiles: filepath.Join(root, "PF"),
			UserProfile: filepath.Join(root, "user"), TempDir: t.TempDir(), OS: f, Compat: re.Compat, Now: time.Now,
			FileVersion: func(p string) string {
				if strings.HasSuffix(p, "Hiddify.exe") {
					return "4.1.2"
				}
				return ""
			}}
	}
	return e
}

func testHosts(s *sim.Sim) *rules.Hosts {
	h := &rules.Hosts{}
	h.Internet = append(h.Internet, struct {
		Name            string `yaml:"name" json:"name"`
		URL             string `yaml:"url" json:"url"`
		ExpectBody      string `yaml:"expect_body" json:"expect_body,omitempty"`
		ExpectStatus    int    `yaml:"expect_status" json:"expect_status,omitempty"`
		ExpectStatusMax int    `yaml:"expect_status_max" json:"expect_status_max,omitempty"`
		Region          string `yaml:"region" json:"region"`
	}{Name: "local 204", URL: s.URL("/generate_204"), ExpectStatus: 204, Region: "foreign"})
	h.Tunnel.Probe204 = s.URL("/generate_204")
	h.Tunnel.Download = s.URL("/down?bytes=65536")
	h.Tunnel.DownloadBytes = 65536
	return h
}

// Первый кейс MVP (§0): Hiddify 4.1.x не проходит REALITY сервера на Xray ≥ v26.9.9.
func TestHiddifyAgainstMlkemServer(t *testing.T) {
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
	p, _ := profile.ParseURI(s.URI("chrome"))
	doctor := `{"server":{"self":{"r":"ok","ms":100},"xver":"26.10.21","port":443,"ufw":"open","ssh_peer":true,"server_ip":"127.0.0.1"},
	"timeline":{},"profile":{},"live":{"seconds":60},
	"groups":[{"label":"A","ssh":true,"own":true,"attempts":[{"t":1,"st":"hello","rd":{"own":true,"r":"mlkem","core":"sing-box: Hiddify 4.x","mlkem_rule":true},"after":"closed"}]}],
	"verdict":{"code":"client.core","title":"Клиент: ядро не шлёт X25519MLKEM768","evidence":["Test-NetConnection 127.0.0.1"],"actions":[]}}`
	e.NewSSH = func(string) (SSHBridge, error) { return &fakeBridge{prof: p, doctor: doctor}, nil }

	var steps []Step
	var windows int
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), Bridge: "ssh", SSHAlias: "xm-test", LiveSeconds: 10,
		SkipRepeat: true}, Hooks{Progress: func(st Step) { steps = append(steps, st) },
		Window: func(context.Context, string, int) { windows++ }})
	if err != nil {
		t.Fatal(err)
	}
	v := sess.Verdict
	if v.Main.Code != "client.core.mlkem" || v.Main.Level != rules.Confirmed {
		b, _ := json.MarshalIndent(sess.Evidence, "", " ")
		t.Fatalf("вердикт %s/%s\n%s", v.Main.Code, v.Main.Level, b)
	}
	get := func(id string) map[string]any {
		for _, x := range sess.Evidence {
			if x.ID == id {
				return x.Facts
			}
		}
		t.Fatalf("нет улики %s", id)
		return nil
	}
	if get("P3")["outcome"] != "ok" || get("P3m")["outcome"] != "real_cert" || get("CX")["core_mlkem"] != false {
		t.Fatalf("P3/P3m/CX: %v %v %v", get("P3"), get("P3m"), get("CX"))
	}
	if get("S1")["match_pbk"] != true || get("S1")["match_uuid"] != true || get("S1")["match_sid"] != true {
		t.Fatalf("сверка хэшей: %v", get("S1"))
	}
	if get("B3")["tunnel_ok"] != true || get("S3")["rd_r"] != "mlkem" {
		t.Fatalf("B3/S3: %v %v", get("B3"), get("S3"))
	}
	// Бюджет: P2 + P3 + P3m = 3 TLS за минуту, не больше.
	if sess.Budget.TotalTLS != 3 || sess.Budget.Refused != 0 {
		t.Fatalf("бюджет: %+v", sess.Budget)
	}
	// Ни одного секрета вне Secret.
	sess.Secret = nil
	js, _ := json.Marshal(sess)
	for _, secret := range []string{sim.UUID, s.PublicKey, sim.ShortID, "xh-test", "sub.example.com", "abcdef", sim.SNI, fmt.Sprint(s.Port)} {
		if strings.Contains(string(js), secret) {
			t.Errorf("в сеансе секрет %q", secret)
		}
	}
	if l := redact.Leaks(string(js)); len(l) > 0 {
		t.Errorf("утечки: %v", l)
	}
	if windows != 1 {
		t.Errorf("окно doctor: %d", windows)
	}
	if err := e.Save(sess); err != nil {
		t.Fatal(err)
	}
	if l := e.Store.Sessions(); len(l) != 1 || l[0].Code != "client.core.mlkem" {
		t.Fatalf("история: %+v", l)
	}
}

// Профиль из настроек, клиентов нет, сервер пускает — «работает».
func TestProfileOnlyOK(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	root := t.TempDir()
	e := testEngine(t, s, root)
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), ProfileURI: s.URI("chrome"), SkipRepeat: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Verdict.Main.Code != "ok" || sess.Budget.TotalTLS != 2 {
		t.Fatalf("%s/%s, бюджет %+v", sess.Verdict.Main.Code, sess.Verdict.Main.Level, sess.Budget)
	}
}

// Без сети и без профиля — быстро и без падения (§12.2 п. 1: вердикт за ≤ 15 с).
func TestOfflineNoProfile(t *testing.T) {
	root := t.TempDir()
	e := testEngine(t, nil, root)
	t0 := time.Now()
	sess, err := e.Run(context.Background(), Options{Offline: true}, Hooks{})
	if err != nil || time.Since(t0) > 15*time.Second {
		t.Fatal(err)
	}
	if sess.Verdict.Main.Code != "unknown.need_window" && sess.Verdict.Main.Code != "profile.missing" {
		t.Fatalf("%s", sess.Verdict.Main.Code)
	}
}

// Нет интернета: эталоны недоступны — lan.noinet, а не «блокировка».
func TestNoInternet(t *testing.T) {
	root := t.TempDir()
	e := testEngine(t, nil, root)
	h := &rules.Hosts{}
	h.Internet = append(h.Internet, struct {
		Name            string `yaml:"name" json:"name"`
		URL             string `yaml:"url" json:"url"`
		ExpectBody      string `yaml:"expect_body" json:"expect_body,omitempty"`
		ExpectStatus    int    `yaml:"expect_status" json:"expect_status,omitempty"`
		ExpectStatusMax int    `yaml:"expect_status_max" json:"expect_status_max,omitempty"`
		Region          string `yaml:"region" json:"region"`
	}{Name: "closed", URL: "http://127.0.0.1:9/", ExpectStatus: 204, Region: "foreign"})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	uri := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=xhttp&path=%s", sim.UUID, port, sim.SNI, sim.PublicKey(), sim.ShortID, sim.Path)
	sess, err := e.Run(context.Background(), Options{Hosts: h, ProfileURI: uri, SkipRepeat: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Verdict.Main.Code != "lan.noinet" {
		t.Fatalf("%s", sess.Verdict.Main.Code)
	}
}
