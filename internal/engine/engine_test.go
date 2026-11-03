package engine

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/evidence"
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
func hiddifyDir(t *testing.T, s *sim.Sim, root string) { hiddifyDirPort(t, s, root, 0) }

// hiddifyDirPort — то же с портом локального прокси (mixed-port) Hiddify.
func hiddifyDirPort(t *testing.T, s *sim.Sim, root string, mixed int) {
	dir := filepath.Join(root, "Roaming", "Hiddify", "hiddify")
	write(t, filepath.Join(root, "PF", "Hiddify", "Hiddify.exe"), "MZ")
	mp := ""
	if mixed > 0 {
		mp = fmt.Sprintf(`,"flutter.mixed-port":%d`, mixed)
	}
	write(t, filepath.Join(dir, "shared_preferences.json"), `{"flutter.service-mode":"system-proxy","flutter.connection-test-url":"`+s.URL("/generate_204")+`"`+mp+`}`)
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
	e := &Engine{Rules: re, Store: st, Adapters: clients.All(), RunRef: refcore.Run,
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
	h.Tunnel.UDPDNS = s.DNS
	h.Tunnel.UDPName = "www.example.com"
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
	// Window движок зовёт в горутине (окно идёт параллельно xm doctor), а фальшивый мост отвечает
	// сразу: Run может вернуться раньше хука, поэтому вызов ждём на канале, а не считаем счётчиком.
	windows := make(chan struct{}, 4)
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), Bridge: "ssh", SSHAlias: "xm-test", LiveSeconds: 10,
		SkipRepeat: true}, Hooks{Progress: func(st Step) { steps = append(steps, st) },
		Window: func(context.Context, string, int) { windows <- struct{}{} }})
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
	// Бюджет: P3 + P3m = 2 TLS (обычный TLS P2 не нужен, когда эталон прошёл) и P1 — 3 TCP.
	if sess.Budget.TotalTLS != 2 || sess.Budget.TotalTCP != 3 || sess.Budget.Refused != 0 {
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
	select {
	case <-windows:
	case <-time.After(5 * time.Second):
		t.Errorf("окно doctor: хук не вызван")
	}
	select {
	case <-windows:
		t.Errorf("окно doctor: хук вызван больше одного раза")
	case <-time.After(100 * time.Millisecond):
	}
	if err := e.Save(sess); err != nil {
		t.Fatal(err)
	}
	if l := e.Store.Sessions(); len(l) != 1 || l[0].Code != "client.core.mlkem" {
		t.Fatalf("история: %+v", l)
	}
	// Повтор на тех же правилах: улики после JSON и DPAPI дают тот же вердикт.
	if l := e.ReplayHistory(); len(l) != 1 || l[0].Changed || l[0].Err != "" || l[0].Now.Code != "client.core.mlkem" {
		t.Fatalf("повтор: %+v", l)
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
	if sess.Verdict.Main.Code != "ok" || sess.Budget.TotalTLS != 1 {
		t.Fatalf("%s/%s, бюджет %+v", sess.Verdict.Main.Code, sess.Verdict.Main.Level, sess.Budget)
	}
}

// Issue #17: сервер режет UDP из тоннеля — итог «работает», находка beyond.udp, B4 без
// лишнего TLS к серверу. С открытым UDP — B4.udp_ok=true и находки нет.
func TestUDPThroughTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	for _, block := range []bool{true, false} {
		s, err := sim.StartWith(sim.Options{BlockUDP: block})
		if err != nil {
			t.Fatal(err)
		}
		e := testEngine(t, s, t.TempDir())
		sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), ProfileURI: s.URI("chrome"), SkipRepeat: true}, Hooks{})
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		var b4 map[string]any
		for _, x := range sess.Evidence {
			if x.ID == "B4" {
				b4 = x.Facts
			}
		}
		found := false
		for _, f := range sess.Verdict.Findings {
			found = found || f.Code == "beyond.udp"
		}
		if sess.Verdict.Main.Code != "ok" || b4 == nil || b4["udp_ok"] != !block || found != block || sess.Budget.TotalTLS != 1 {
			t.Fatalf("block=%v: %s, B4 %v, находка %v, бюджет %+v", block, sess.Verdict.Main.Code, b4, found, sess.Budget)
		}
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

// VLESS + TLS из настроек: профиль цел, но не REALITY — «не поддерживается», а не
// «испорчен при импорте» (issue #15).
func TestSettingsProfileNotReality(t *testing.T) {
	root := t.TempDir()
	e := testEngine(t, nil, root)
	uri := "vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=%2Fx#t"
	sess, err := e.Run(context.Background(), Options{Offline: true, ProfileURI: uri}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	m := sess.Verdict.Main
	if m.Code != "profile.unsupported" || !strings.Contains(m.Title, "VLESS + TLS") {
		t.Fatalf("%s/%s: %s", m.Code, m.Level, m.Title)
	}
	for _, r := range append(append(sess.Verdict.Also, sess.Verdict.Possible...), m) {
		if r.Code == "profile.import" {
			t.Fatalf("profile.import при целом профиле: %+v", r)
		}
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

func evFacts(t *testing.T, sess *SessionData, id string) map[string]any {
	t.Helper()
	for _, x := range sess.Evidence {
		if x.ID == id {
			return x.Facts
		}
	}
	t.Fatalf("нет улики %s", id)
	return nil
}

// clientEngine — Hiddify с локальным прокси на стенде: works — клиент подключён и трафик идёт,
// иначе прокси принимает соединение и молчит («Подключение…» / «Тайм-аут»).
func clientEngine(t *testing.T, s *sim.Sim, works bool) (*Engine, func()) {
	px, err := sim.StartProxy(works)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	hiddifyDirPort(t, s, root, px.Port)
	e := testEngine(t, s, root)
	e.LocalOpen = func(port int) bool { return port == px.Port }
	e.ProbeClient = func(ctx context.Context, port int, u204, down string, n int, test string) netprobe.ClientResult {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return netprobe.ProbeViaClient(c, port, u204, down, n, test)
	}
	return e, px.Close
}

// Скрин 1: клиент подключён и трафик через него идёт — «всё работает» (подтверждено), а не
// «проверяется, почему клиент пишет таймаут».
func TestClientConnectedWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e, done := clientEngine(t, s, true)
	defer done()
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), SkipRepeat: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Verdict.Main.Code != "ok.client" || sess.Verdict.Main.Level != rules.Confirmed {
		t.Fatalf("вердикт %s/%s", sess.Verdict.Main.Code, sess.Verdict.Main.Level)
	}
	// URL проверки Hiddify (connection-test-url) через его прокси открылся — на кнопке «Подключено».
	if c := evFacts(t, sess, "C10"); c["outcome"] != "ok" || c["bytes"].(float64) < 65536 || c["test_url_ok"] != true || c["shows"] != "connected" {
		t.Fatalf("C10: %v", c)
	}
	if sess.Secret == nil || sess.Secret.Name != "сервер" {
		t.Fatalf("имя профиля для окна: %+v", sess.Secret)
	}
}

// Скрин 3: Hiddify «Подключение…» на сервере с правилом X25519MLKEM768 — подтверждено, и
// проверка через сам клиент — в уликах.
func TestClientConnectingFails(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e, done := clientEngine(t, s, false)
	defer done()
	var steps []Step
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), SkipRepeat: true},
		Hooks{Progress: func(st Step) { steps = append(steps, st) }})
	if err != nil {
		t.Fatal(err)
	}
	v := sess.Verdict.Main
	if v.Code != "client.core.mlkem" || v.Level != rules.Confirmed || !strings.Contains(strings.Join(v.Evidence, ","), "C10") {
		t.Fatalf("вердикт %s/%s %v", v.Code, v.Level, v.Evidence)
	}
	if c := evFacts(t, sess, "C10"); c["outcome"] != "fail" || c["error"] != "timeout" || c["shows"] != "connecting" {
		t.Fatalf("C10: %v", c)
	}
	if c8 := sess.Evidence[slices.IndexFunc(sess.Evidence, func(e evidence.Evidence) bool { return e.ID == "C8" })]; !strings.Contains(c8.Summary, "ядро запущено") {
		t.Fatalf("C8 при «Подключение…»: %q", c8.Summary)
	}
	// P3m нашёл причину — шаг помечен как найденная проблема, а не «!».
	for _, st := range steps {
		if st.ID == "P3m" && st.Status != "run" && st.Status != "fail" {
			t.Fatalf("P3m: %+v", st)
		}
	}
}

// Пробы к одному серверу не расходуют лимит другого, а лимит переживает перезапуск без удвоения
// (было: второй сеанс подряд — все пробы «пропущено: бюджет»).
func TestBudgetPerServer(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	a, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	root := t.TempDir()
	e := testEngine(t, a, root)
	run := func(s *sim.Sim) *SessionData {
		sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), ProfileURI: s.URI("chrome"), SkipRepeat: true}, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	sa := run(a)
	pb, _ := profile.ParseURI(b.URI("chrome"))
	if u := e.Budget(pb.ServerKey()).Usage(); u.TLS != 0 || u.TCP != 0 {
		t.Fatalf("сервер B получил расход сервера A: %+v", u)
	}
	sb := run(b)
	for _, sess := range []*SessionData{sa, sb} {
		if sess.Verdict.Main.Code != "ok" || sess.Budget.TotalTLS != 1 || sess.Budget.TotalTCP != 2 || sess.Budget.Refused != 0 {
			t.Fatalf("%s, бюджет за сеанс %+v", sess.Verdict.Main.Code, sess.Budget)
		}
	}
	pa, _ := profile.ParseURI(a.URI("chrome"))
	e2 := testEngine(t, a, root) // новый процесс (CLI) с тем же каталогом данных
	for i := 0; i < 2; i++ {
		if u := e2.Budget(pa.ServerKey()).Usage(); u.TCP != 2 || u.TLS != 1 {
			t.Fatalf("восстановлено %d: %+v", i, u)
		}
	}
}

// probeRun — сеанс без фаз: для проверки отдельных проб на петле.
func probeRun(t *testing.T, o Options, prof *profile.Profile) *run {
	e := testEngine(t, nil, t.TempDir())
	return &run{e: e, o: o, set: evidence.NewSet(), red: redact.New(nil), now: time.Now, dial: &netprobe.Dialer{Timeout: 2 * time.Second},
		res: e.Resolver, sess: &SessionData{}, prof: prof, budget: netprobe.NewBudget()}
}

// listen — сервер на петле: на каждое соединение пишет greet (пусто — молчит) и держит его hold.
func listen(t *testing.T, greet string, hold time.Duration) *net.TCPAddr {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if greet != "" {
				_, _ = c.Write([]byte(greet))
			}
			go func() { time.Sleep(hold); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// Скрин 5: порт сервера молчит, SSH того же адреса открыт. Порт SSH — из алиаса (`ssh -G`), в
// улики и текст он не попадает; проба — одно TCP в бюджете сервера.
func TestSSHPortProbe(t *testing.T) {
	ssh := listen(t, "SSH-2.0-OpenSSH_9.6\r\n", time.Second)
	r := probeRun(t, Options{SSHAlias: "xm-test"}, &profile.Profile{Address: "127.0.0.1", Port: 1})
	var alias string
	r.e.SSHPort = func(_ context.Context, a string) int { alias = a; return ssh.Port }
	r.sshPort(context.Background(), ssh.IP, false)
	p6 := r.set.Get("P6")
	if p6 == nil || !p6.Bool("reach") || !p6.Bool("banner") || !p6.Bool("known") || alias != "xm-test" {
		t.Fatalf("P6: %+v, алиас %q", p6, alias)
	}
	if strings.Contains(p6.Summary, fmt.Sprint(ssh.Port)) || !strings.Contains(p6.Summary, "молчит только порт") {
		t.Fatalf("текст P6: %q", p6.Summary)
	}
	if u := r.budget.Usage(); u.TotalTCP != 1 {
		t.Fatalf("бюджет: %+v", u)
	}
	// SSH на том же порту, что сервер, — сравнивать не с чем: пробы нет.
	r = probeRun(t, Options{SSHAlias: "xm-test"}, &profile.Profile{Address: "127.0.0.1", Port: ssh.Port})
	r.e.SSHPort = func(context.Context, string) int { return ssh.Port }
	r.sshPort(context.Background(), ssh.IP, false)
	if r.set.Has("P6") || r.budget.Usage().TotalTCP != 0 {
		t.Fatal("P6 на порт сервера")
	}
}

// N5: маска по своему адресу молчит — тот же SNI на адрес эталона. Эталон отвечает TLS — SNI не
// режется; молчит — режут по SNI.
func TestSNIElsewhere(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	silent := listen(t, "", 300*time.Millisecond) // молчит после ClientHello и закрывает
	for _, c := range []struct {
		url    string
		passed bool
	}{{tlsSrv.URL, true}, {"https://" + silent.String() + "/", false}} {
		r := probeRun(t, Options{}, &profile.Profile{SNI: "www.example.com"})
		h := &rules.Hosts{}
		h.Internet = slices.Grow(h.Internet, 1)[:1]
		h.Internet[0].URL = c.url
		r.sniElsewhere(context.Background(), h, []netprobe.HTTPResult{{OK: true, Region: "foreign"}})
		n5 := r.set.Get("N5")
		if n5 == nil || n5.Bool("passed") != c.passed {
			t.Fatalf("%s: N5 %+v", c.url, n5)
		}
	}
}

// Скрин 6: «Я в другой сети» без галочки. Сеанс узнаёт другую сеть по шлюзу и сравнивает пробы с
// последним сеансом к тому же серверу оттуда; та же сеть, другой сервер или давний сеанс — не
// сравниваются, а улики этого сеанса не подменяются прошлыми.
func TestOtherNetworkAuto(t *testing.T) {
	prof := &profile.Profile{Address: "203.0.113.7", Port: 8443}
	netA := osw.Facts{Collected: true, GatewayMAC: "02005e000001"}
	netB := osw.Facts{Collected: true, GatewayMAC: "02005e000002"}
	start := time.Now()
	cases := []struct {
		name  string
		prev  osw.Facts
		age   time.Duration
		addr  string
		wantP bool
	}{
		{"другая сеть", netA, 2 * time.Minute, prof.Address, true},
		{"та же сеть", netB, 2 * time.Minute, prof.Address, false},
		{"другой сервер", netA, 2 * time.Minute, "203.0.113.8", false},
		{"слишком давно", netA, otherNetworkWindow + time.Minute, prof.Address, false},
	}
	for _, c := range cases {
		r := probeRun(t, Options{}, prof)
		r.facts, r.sess.Started = netB, start
		prev := &SessionData{ID: store.NewID(start.Add(-c.age), 1), Started: start.Add(-c.age),
			Secret: &Secret{Server: c.addr, Port: prof.Port, Network: networkKey(&c.prev)},
			Evidence: []evidence.Evidence{
				{ID: "N1", Facts: map[string]any{"ok": true}},
				{ID: "P1", Facts: map[string]any{"outcome": "timeout"}, At: start.Add(-c.age)},
				{ID: "P6", Facts: map[string]any{"reach": false, "known": true}},
			}}
		if err := r.e.Save(prev); err != nil {
			t.Fatal(err)
		}
		r.put(evidence.Evidence{ID: "N1", Facts: map[string]any{"ok": true, "hosts_ok": 3}})
		r.put(evidence.Evidence{ID: "P1", Facts: map[string]any{"outcome": "timeout"}})
		r.otherNetwork()
		p5 := r.set.Get("P5")
		if (p5 != nil) != c.wantP {
			t.Fatalf("%s: P5 %+v", c.name, p5)
		}
		if p5 == nil {
			continue
		}
		if p5.Str("p1") != "timeout" || p5.Str("p6") != "silent" || !strings.Contains(p5.Summary, "2 мин назад") ||
			!strings.Contains(p5.Summary, "так же, как из этой сети") || !r.sess.OtherNetwork {
			t.Fatalf("%s: P5 %+v", c.name, p5)
		}
		// Свои улики остались своими: N1 этого сеанса, а не прошлого.
		if n, _ := r.set.Get("N1").Num("hosts_ok"); n != 3 {
			t.Fatalf("%s: N1 подменён прошлым сеансом", c.name)
		}
		if v := r.e.Rules.Decide(r.set); v.Main.Code != "server.unreachable" {
			t.Fatalf("%s: вердикт %s", c.name, v.Main.Code)
		}
	}
	// Без отпечатка сети (факты Windows не собраны) сравнивать не с чем.
	if networkKey(&osw.Facts{}) != "" || networkKey(&netA) == networkKey(&netB) {
		t.Fatal("отпечаток сети")
	}
}

// Что на кнопке Hiddify 4.x: ядро запущено, а тест задержки не проходит — «Подключение…»; ответ
// не 204 — тест задержки Hiddify его принимает, по C10 не определить.
func TestHiddifyShows(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		r    netprobe.ClientResult
		want string
	}{
		{netprobe.ClientResult{Outcome: "fail", Error: "eof"}, "connecting"},
		{netprobe.ClientResult{Outcome: "fail", Error: "status"}, ""},
		{netprobe.ClientResult{Outcome: "ok", TestOK: &no}, "connecting"},
		{netprobe.ClientResult{Outcome: "ok", TestOK: &yes}, "connected"},
		{netprobe.ClientResult{Outcome: "ok"}, ""},
	} {
		if got := hiddifyShows(c.r); got != c.want {
			t.Errorf("%+v: %q, ожидалось %q", c.r, got, c.want)
		}
	}
}

// «После диагностики VPN уходит в таймаут»: по отчётам смена отпечатка к серверу во время
// заморозки продлевает её до 10 минут. Все TLS к серверу — отпечатком клиента; эталон другим
// отпечатком (у клиента пресет без X25519MLKEM768) — только если TLS отпечатком клиента получил
// ответ. Пресет клиента с X25519MLKEM768 (firefox) — эталон им же, без лишнего TLS перед ним.
func TestProbesKeepClientFingerprint(t *testing.T) {
	silent := listen(t, "", 300*time.Millisecond) // TCP есть, после ClientHello — тишина и закрытие
	tlsSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	tlsSrv.Config.ErrorLog = log.New(io.Discard, "", 0) // P1 закрывает TCP без TLS
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	answers := tlsSrv.Listener.Addr().(*net.TCPAddr)
	for _, c := range []struct {
		name, fp string
		srv      *net.TCPAddr
		refFP    string // "" — эталон не запускается
		p2First  bool
	}{
		{"edge, заморозка", "edge", silent, "", true},
		{"edge, сервер отвечает", "edge", answers, "chrome", true},
		{"firefox", "firefox", answers, "firefox", false},
		{"chrome", "chrome", silent, "chrome", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := probeRun(t, Options{Reference: true, SkipRepeat: true}, &profile.Profile{Protocol: "vless", Security: "reality",
				Address: "127.0.0.1", Port: c.srv.Port, SNI: "www.example.com", Fingerprint: c.fp})
			var refFP string
			var p2Before bool
			r.e.RunRef = func(_ context.Context, o refcore.Options) refcore.Result {
				refFP, p2Before = o.Fingerprint, r.set.Has("P2")
				return refcore.Result{Outcome: "handshake_timeout"}
			}
			r.phase2(context.Background())
			if refFP != c.refFP || (c.refFP != "" && p2Before != c.p2First) {
				t.Fatalf("эталон: fp %q (ждали %q), P2 до эталона — %v", refFP, c.refFP, p2Before)
			}
			if p2 := r.set.Get("P2"); p2 == nil || p2.Str("fp") != c.fp {
				t.Fatalf("P2: %+v", p2)
			}
			if c.refFP == "" {
				var skip bool
				for _, s := range r.sess.Steps {
					skip = skip || (s.ID == "P3" && s.Status == "skip" && strings.Contains(s.Note, "до 10 минут"))
				}
				if !skip {
					t.Fatalf("шаг P3: %+v", r.sess.Steps)
				}
			}
		})
	}
}
