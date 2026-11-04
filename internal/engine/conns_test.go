package engine

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/rules"
	"github.com/grokki91/xray_client/internal/sim"
)

// fakeConns — таблица TCP для тестов: строки меняет сам тест (как их увидел бы опрос Windows).
type fakeConns struct {
	mu   sync.Mutex
	rows []osw.Conn
}

func (f *fakeConns) set(rows ...osw.Conn) {
	f.mu.Lock()
	f.rows = rows
	f.mu.Unlock()
}

func (f *fakeConns) table() ([]osw.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]osw.Conn(nil), f.rows...), nil
}

func conn(local, remote string, st osw.TCPState, pid int) osw.Conn {
	return osw.Conn{Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: st, PID: pid}
}

// Опрос таблицы: попытки клиента к серверу — по состояниям; свои соединения xdiag и закрытые
// сокеты без владельца (TIME_WAIT прошлого сеанса) — не попытки клиента; новый хендшейк — в бюджет.
func TestConnWatch(t *testing.T) {
	const srv = "203.0.113.7:443"
	self := os.Getpid()
	f := &fakeConns{}
	f.set(
		conn("192.0.2.10:50001", srv, osw.TCPEstablished, 4242), // клиент уже держал соединение
		conn("192.0.2.10:50002", srv, osw.TCPTimeWait, 0),       // проба прошлого сеанса
		conn("192.0.2.10:50003", srv, osw.TCPSynSent, self),     // своя проба
		conn("127.0.0.1:12334", "0.0.0.0:0", osw.TCPListen, 4242),
	)
	now := time.Unix(5_000_000, 0)
	w, err := newConnWatch(f.table, []netip.AddrPort{netip.MustParseAddrPort(srv)}, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:443")},
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var tls []time.Time
	w.onTLS = func(at time.Time) { tls = append(tls, at) }
	rows := func(r ...osw.Conn) {
		f.set(r...)
		rr, _ := f.table()
		w.scan(rr, false)
		now = now.Add(500 * time.Millisecond)
	}
	rows(conn("192.0.2.10:50004", srv, osw.TCPSynSent, 4242), conn("192.0.2.10:50005", srv, osw.TCPSynSent, 4242))
	rows(conn("192.0.2.10:50004", srv, osw.TCPSynSent, 4242), conn("192.0.2.10:50005", srv, osw.TCPEstablished, 4242),
		conn("192.0.2.10:50006", "198.51.100.9:443", osw.TCPSynSent, 4242), conn("192.0.2.10:50002", srv, osw.TCPTimeWait, 0))
	rows(conn("192.0.2.10:50004", srv, osw.TCPSynSent, 4242), conn("192.0.2.10:50005", srv, osw.TCPTimeWait, 0))
	s := w.stats()
	want := connStats{Before: 1, New: 2, Established: 2, SynOnly: 1, SynMs: 1000, TLS: 1, Other: 1}
	if s != want {
		t.Fatalf("итог %+v, ожидалось %+v", s, want)
	}
	if s.outcome() != "established" || len(tls) != 1 {
		t.Fatalf("исход %s, хендшейков в бюджет %d", s.outcome(), len(tls))
	}
	if (connStats{SynOnly: 1}).outcome() != "syn" || (connStats{Other: 3}).outcome() != "none" {
		t.Fatal("исходы syn и none")
	}
}

// Сеанс с наблюдением соединений: клиент «Подключение…» (прокси молчит), а таблица TCP —
// такая, какой её задаёт during на время запроса через клиент.
func connsSession(t *testing.T, during func(srv string) []osw.Conn, prep ...func(e *Engine)) (*SessionData, *fakeConns) {
	t.Helper()
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	e, done := clientEngine(t, s, false)
	t.Cleanup(done)
	for _, p := range prep {
		p(e)
	}
	f := &fakeConns{}
	e.Conns = f.table
	srv := fmt.Sprintf("127.0.0.1:%d", s.Port)
	probe := e.ProbeClient
	e.ProbeClient = func(ctx context.Context, port int, u204, down string, n int, test string) netprobe.ClientResult {
		if during != nil {
			f.set(during(srv)...)
		}
		defer f.set()
		return probe(ctx, port, u204, down, n, test)
	}
	sess, err := e.Run(context.Background(), Options{Reference: true, Hosts: testHosts(s), SkipRepeat: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return sess, f
}

// Живой случай 2026-11-03: «когда Hiddify пишет „Подключение…“, к серверу ничего не уходит?» —
// это видно на ПК, до окна сервера. Клиент не открыл к серверу ни одного соединения, а эталон с
// тем же профилем подключился: сбой в клиенте — подтверждено, и это — первое по стеку.
func TestClientSendsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	sess, _ := connsSession(t, nil)
	v := sess.Verdict
	if v.Main.Code != "client.nosend" || v.Main.Level != rules.Confirmed || !strings.Contains(strings.Join(v.Main.Evidence, ","), "C11") {
		t.Fatalf("вердикт %s/%s %v", v.Main.Code, v.Main.Level, v.Main.Evidence)
	}
	if c := evFacts(t, sess, "C11"); c["outcome"] != "none" || c["new"] != float64(0) {
		t.Fatalf("C11: %v", c)
	}
	var also []string
	for _, r := range v.Also {
		also = append(also, r.Code)
	}
	// Ядро без X25519MLKEM768 — тоже правда (всплывёт, когда клиент начнёт слать), а «трафик не
	// идёт» без уточнения не дублирует «не шлёт».
	if a := strings.Join(also, ","); !strings.Contains(a, "client.core.mlkem") || strings.Contains(a, "client.tunnel") {
		t.Fatalf("также найдено: %v", also)
	}
}

// Hiddify ведёт VLESS «поверх WARP»: TCP до сервера идёт внутри WireGuard и в таблице не виден —
// «не шлёт» по пустой таблице было бы ложью. Наблюдение не учитывается, вывод — как без него.
func TestClientViaWARPNotJudged(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	sess, _ := connsSession(t, nil, func(e *Engine) {
		p := filepath.Join(e.NewEnv(&osw.Facts{}).AppData, "Hiddify", "hiddify", "shared_preferences.json")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		write(t, p, strings.Replace(string(b), "{", `{"flutter.enable-warp":true,"flutter.warp-detour-mode":"proxyOverWarp",`, 1))
	})
	if v := sess.Verdict.Main; v.Code != "client.core.mlkem" || v.Level != rules.Confirmed {
		t.Fatalf("вердикт %s/%s", v.Code, v.Level)
	}
	skipped := false
	for _, x := range sess.Evidence {
		skipped = skipped || (x.ID == "C11" && strings.Contains(x.Skipped, "WARP"))
	}
	if !skipped {
		t.Fatal("C11 при WARP должна быть пропущена с причиной")
	}
}

// Клиент шлёт SYN, ответа нет: «не шлёт» исключено, вывод — как без наблюдения.
func TestClientSendsSYN(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	sess, _ := connsSession(t, func(srv string) []osw.Conn { return []osw.Conn{conn("127.0.0.1:50001", srv, osw.TCPSynSent, 4242)} })
	v := sess.Verdict
	if v.Main.Code != "client.core.mlkem" || v.Main.Level != rules.Confirmed {
		t.Fatalf("вердикт %s/%s", v.Main.Code, v.Main.Level)
	}
	if c := evFacts(t, sess, "C11"); c["outcome"] != "syn" || c["syn_only"] != float64(1) {
		t.Fatalf("C11: %v", c)
	}
	excluded := false
	for _, r := range v.RuledOut {
		excluded = excluded || r.Code == "client.nosend"
	}
	if !excluded {
		t.Fatal("«клиент не шлёт» должно быть исключено наблюдением")
	}
}

// Хендшейк самого клиента к серверу во время запроса — в бюджете TLS того же сервера и в отчёте.
func TestClientHandshakeInBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	sess, _ := connsSession(t, func(srv string) []osw.Conn { return []osw.Conn{conn("127.0.0.1:50002", srv, osw.TCPEstablished, 4242)} })
	if c := evFacts(t, sess, "C11"); c["outcome"] != "established" || c["tls"] != float64(1) {
		t.Fatalf("C11: %v", c)
	}
	// Клиент — 1, эталон P3 и P3m — 2: вместе 3, в пределах лимита, ждать не пришлось.
	if b := sess.Budget; b.TotalClient != 1 || b.TotalTLS != 2 || b.Refused != 0 {
		t.Fatalf("бюджет: %+v", b)
	}
}

// Выбор профиля: Hiddify сейчас соединён со вторым сервером подписки — проверяется он, а не
// первый VLESS + REALITY активного профиля.
func TestProfileByClientConnections(t *testing.T) {
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
	// Первый сервер подписки — другой адрес (RFC 5737), второй — стенд.
	cfg := filepath.Join(root, "Roaming", "Hiddify", "hiddify", "configs", "p1.json")
	b, _ := os.ReadFile(cfg)
	other := strings.Replace(strings.Replace(string(b), `"tag":"sim","server":"127.0.0.1"`, `"tag":"first","server":"198.51.100.20"`, 1),
		fmt.Sprintf(`"server_port":%d`, s.Port), `"server_port":443`, 1)
	first := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(other), `{"outbounds":[`), `]}`)
	second := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(string(b)), `{"outbounds":[`), `]}`)
	write(t, cfg, `{"outbounds":[`+first+","+second+`]}`)
	e := testEngine(t, s, root)
	f := &fakeConns{}
	f.set(conn("192.0.2.10:50001", fmt.Sprintf("127.0.0.1:%d", s.Port), osw.TCPEstablished, 4242))
	e.Conns = f.table
	sess, err := e.Run(context.Background(), Options{Offline: true}, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Secret == nil || sess.Secret.Server != "127.0.0.1" || sess.Secret.Port != s.Port {
		t.Fatalf("проверяется %+v, а клиент соединён со стендом", sess.Secret)
	}
	if !strings.Contains(strings.Join(sess.Notes, " "), "с которым клиент сейчас соединён") {
		t.Fatalf("заметки: %v", sess.Notes)
	}
	// Соединений нет — как раньше: первый VLESS + REALITY активного профиля.
	f.set()
	sess, _ = e.Run(context.Background(), Options{Offline: true}, Hooks{})
	if sess.Secret == nil || sess.Secret.Server != "198.51.100.20" {
		t.Fatalf("без соединений: %+v", sess.Secret)
	}
}
