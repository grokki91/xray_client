// Package clients — адаптеры клиентских приложений Windows (L0): Hiddify и v2rayN.
//
// Адаптер — пять методов (docs/architecture.md §3.3): Detect — установлен ли, версия приложения
// и ядра, режим, каталог данных; Profiles — профили в нормализованной модели; Logs — сводка
// журналов; State — запущен ли, слушает ли локальный прокси; Hints — особенности версии.
// Новый клиент — новый файл, остальное не меняется. Файлы клиента только читаются; базы SQLite —
// через копию, чтобы не мешать работающему приложению.
package clients

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/rules"
)

// Env — окружение адаптера: пути, факты ОС, таблица совместимости. В тестах — подставное.
type Env struct {
	AppData      string
	LocalAppData string
	ProgramFiles string
	UserProfile  string
	TempDir      string

	HiddifyDir string // переопределение каталога данных Hiddify (настройки)
	V2rayNDir  string // переопределение каталога v2rayN (портативный)

	OS     *osw.Facts
	Compat *rules.Compat
	Now    func() time.Time

	FileVersion func(path string) string
	RunVersion  func(ctx context.Context, exe string, args ...string) ([]byte, error)
}

// DefaultEnv — из переменных окружения Windows.
func DefaultEnv(facts *osw.Facts, compat *rules.Compat) *Env {
	return &Env{
		AppData: os.Getenv("APPDATA"), LocalAppData: os.Getenv("LOCALAPPDATA"), ProgramFiles: os.Getenv("ProgramFiles"),
		UserProfile: os.Getenv("USERPROFILE"), TempDir: os.TempDir(), OS: facts, Compat: compat, Now: time.Now,
		FileVersion: osw.FileVersion, RunVersion: osw.RunHidden,
	}
}

// Detection — что известно о клиенте без сети.
type Detection struct {
	Client      string `json:"client"` // hiddify | v2rayn
	Installed   bool   `json:"installed"`
	Version     string `json:"version"`
	Portable    bool   `json:"portable"`
	ExePath     string `json:"-"`
	DataDir     string `json:"-"`
	Core        string `json:"core"`        // имя ядра, которое делает REALITY
	CoreFamily  string `json:"core_family"` // xray | sing-box | mihomo
	CoreVersion string `json:"core_version"`
	CoreMlkem   *bool  `json:"core_mlkem"` // nil — неизвестно
	Note        string `json:"note,omitempty"`
	Mode        string `json:"mode"` // vpn | system-proxy | proxy
	TUN         bool   `json:"tun"`
	ProxyPort   int    `json:"proxy_port"`
	LAN         bool   `json:"lan"`
	TestURL     string `json:"-"` // URL теста задержки клиента
	RUDirect    *bool  `json:"ru_direct"`
	// Detour — соединение с сервером клиент ведёт внутри другого тоннеля (Hiddify: WARP в режиме
	// «прокси поверх WARP»): TCP до сервера в таблице соединений ПК не видно.
	Detour  bool   `json:"detour,omitempty"`
	Support string `json:"support"` // full | partial
}

// LogSummary — сводка журналов клиента.
type LogSummary struct {
	Found  bool           `json:"found"`
	Files  int            `json:"files"`
	Counts map[string]int `json:"counts"`
	AgeMin int            `json:"age_min"` // давность последней записи
	Lines  []string       `json:"-"`       // характерные строки — наружу только через redact
	Pasted bool           `json:"pasted"`

	direct []string // строки прямого выхода: в Lines — после остальных (mergeLines)
	marks  []mark   // строки со временем — хронология (timeline.go)
}

// Сколько характерных строк хранить: строки о соединениях через сервер важнее — прямые проверки
// клиента (DNS, URL-тест мимо сервера) идут потоком и не должны их вытеснять.
const (
	maxLines       = 14
	maxDirectLines = 6
)

// State — состояние клиента сейчас.
type State struct {
	Running       bool   `json:"running"`
	CoreListening bool   `json:"core_listening"`
	TunAdapter    bool   `json:"tun_adapter"`
	Service       string `json:"service,omitempty"`
	Exposed       []int  `json:"exposed,omitempty"` // порты локального прокси на 0.0.0.0/::
}

// Adapter — клиентское приложение.
type Adapter interface {
	Name() string
	Title() string
	Detect(ctx context.Context, env *Env) Detection
	Profiles(ctx context.Context, env *Env, d Detection) ([]*profile.Profile, error)
	Logs(env *Env, d Detection, since time.Time) LogSummary
	State(env *Env, d Detection) State
	Hints(d Detection) []string
}

// All — известные адаптеры.
func All() []Adapter { return []Adapter{&Hiddify{}, &V2rayN{}} }

// ─── Журналы ─────────────────────────────────────────────────────────────────

// Шаблоны строк журналов ядер (Xray, sing-box) и приложений.
var logPatterns = []struct {
	key string
	re  *regexp.Regexp
}{
	{"reality_failed", regexp.MustCompile(`(?i)reality verification failed`)},
	{"real_cert", regexp.MustCompile(`(?i)received real certificate`)},
	{"invalid_conn", regexp.MustCompile(`(?i)processed invalid connection`)},
	{"x509", regexp.MustCompile(`(?i)\bx509:`)},
	{"eof", regexp.MustCompile(`\bEOF\b`)},
	// RST от сервера или посредника: «forcibly closed by the remote host» (WSAECONNRESET).
	{"reset", regexp.MustCompile(`(?i)connection reset|forcibly closed`)},
	// «An established connection was aborted by the software in your host machine»
	// (WSAECONNABORTED) — не RST: соединение закрыл сам Windows, когда отправленное не
	// подтверждалось (тишина, заморозка по пути), реже — локальный сетевой фильтр.
	{"aborted", regexp.MustCompile(`(?i)connection was aborted|software caused connection abort`)},
	{"refused", regexp.MustCompile(`(?i)connection refused|actively refused`)},
	{"timeout", regexp.MustCompile(`(?i)i/o timeout|context deadline exceeded|handshake timeout|timed out|did not properly respond`)},
	{"tun_error", regexp.MustCompile(`(?i)(configure|create|open|start)[^\n]{0,40}tun[^\n]{0,60}(error|fail)|wintun[^\n]{0,60}(error|fail)|tun device`)},
	{"port_busy", regexp.MustCompile(`(?i)address already in use|only one usage of each socket address|bind: an attempt was made`)},
	{"core_failed", regexp.MustCompile(`(?i)failed to (start|run) (the )?core|start service[^\n]{0,30}(error|fail)|core (process )?(exited|crashed)|panic:|createService - null`)},
	{"empty_fp", regexp.MustCompile(`(?i)empty fingerprint`)},
	{"dns_error", regexp.MustCompile(`(?i)(dns|lookup)[^\n]{0,60}(no such host|server misbehaving|refused|failed)`)},
}

// AppError — ключи ошибок самого приложения клиента (ядро, порт, TUN, профиль), а не соединений.
var AppError = map[string]bool{"core_failed": true, "port_busy": true, "tun_error": true, "empty_fp": true}

// reDirect — строка о прямом выходе клиента, мимо сервера: «using outbound/direct[…]», монитор
// Hiddify «outbound direct-fragment … URL test failed», DNS прямых соединений. Её таймауты и
// ошибки DNS — не про сервер и считаются отдельно (direct_failed): иначе сотни таймаутов
// прямого DNS читаются как «таймаут ×372» к серверу.
var reDirect = regexp.MustCompile(`(?i)outbound[/ ]direct|dns[-/]direct`)

// reLoopback — соединение приложения с локальным прокси клиента (127.0.0.1:порт → 127.0.0.1:порт):
// его обрыв закрыл браузер или xdiag, а не сервер — в сбои через сервер не идёт.
var reLoopback = regexp.MustCompile(`(?:127\.\d+\.\d+\.\d+|\[::1\]):\d+->(?:127\.\d+\.\d+\.\d+|\[::1\]):\d+`)

// reFail — в строке прямого выхода есть сбой.
var reFail = regexp.MustCompile(`(?i)\b(error|errors|fail|failed|failure|timeout|refused|reset|eof|unreachable)\b|deadline exceeded|timed out`)

// ScanLogs читает хвосты файлов (до 512 КБ каждый) и считает характерные строки.
func ScanLogs(files []string, now time.Time) LogSummary {
	s := LogSummary{Counts: map[string]int{}}
	var newest time.Time
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil || st.IsDir() {
			continue
		}
		s.Found = true
		s.Files++
		if st.ModTime().After(newest) {
			newest = st.ModTime()
		}
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		if st.Size() > 512<<10 {
			_, _ = fh.Seek(-512<<10, io.SeekEnd)
		}
		scanText(fh, &s)
		fh.Close()
	}
	if !newest.IsZero() {
		s.AgeMin = int(now.Sub(newest).Minutes())
	}
	s.mergeLines()
	return s
}

// ScanText — то же для вставленного пользователем текста (экспорт логов Hiddify).
func ScanText(text string) LogSummary {
	s := LogSummary{Counts: map[string]int{}, Found: strings.TrimSpace(text) != "", Pasted: true}
	scanText(strings.NewReader(text), &s)
	s.mergeLines()
	return s
}

func scanText(r io.Reader, s *LogSummary) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	keep := func(l []string, line string, max int) []string {
		if len(line) > 300 {
			line = line[:300] + "…"
		}
		l = append(l, line)
		if len(l) > max {
			l = l[1:]
		}
		return l
	}
	for sc.Scan() {
		line := sc.Text()
		if reDirect.MatchString(line) {
			if reFail.MatchString(line) {
				s.Counts["direct_failed"]++
				s.direct = keep(s.direct, line, maxDirectLines)
			}
			continue // прямой выход — не про тоннель: в хронологию не идёт
		}
		if reLoopback.MatchString(line) {
			continue
		}
		hit, fail, app := false, false, false
		for _, p := range logPatterns {
			if p.re.MatchString(line) {
				s.Counts[p.key]++
				hit = true
				fail = fail || connFail[p.key]
				app = app || AppError[p.key]
			}
		}
		if hit {
			s.Lines = keep(s.Lines, line, maxLines)
		}
		// Ошибка самого приложения (ядро, TUN, порт) — не сбой через сервер и не «работал».
		if t, ok := stamp(line); ok && (fail || !app) {
			s.marks = append(s.marks, mark{t: t, fail: fail})
		}
	}
}

// mergeLines — строки прямого выхода в конец Lines.
func (s *LogSummary) mergeLines() {
	s.Lines = append(s.Lines, s.direct...)
	s.direct = nil
}

// ─── Папка из настроек ───────────────────────────────────────────────────────

// CheckDir — подходит ли папка, указанная вручную (настройки): "" — да, иначе причина
// по-русски. Признаки — те же файлы, по которым адаптер её читает.
func CheckDir(client, dir string) string {
	if !dirExists(dir) {
		return "папка не найдена"
	}
	switch client {
	case "hiddify":
		looks := func(d string) bool {
			return exists(filepath.Join(d, "db.sqlite")) || exists(filepath.Join(d, "shared_preferences.json"))
		}
		switch {
		case looks(dir):
			return ""
		case looks(filepath.Join(dir, "hiddify")):
			return "это папка уровнем выше — нужна вложенная …\\hiddify"
		case looks(filepath.Join(dir, "hiddify_portable_data")):
			return "здесь программа — нужна папка данных …\\hiddify_portable_data рядом с ней"
		case exists(filepath.Join(dir, "Hiddify.exe")):
			return "здесь программа, а нужна папка данных (обычно %APPDATA%\\Hiddify\\hiddify)"
		}
		return "в папке нет файлов Hiddify (db.sqlite, shared_preferences.json)"
	case "v2rayn":
		looks := func(d string) bool {
			return exists(filepath.Join(d, "guiConfigs", "guiNConfig.json")) || exists(filepath.Join(d, "v2rayN.exe"))
		}
		if looks(dir) {
			return ""
		}
		if m, _ := filepath.Glob(filepath.Join(dir, "v2rayN*")); len(m) > 0 && looks(m[0]) {
			return "это папка уровнем выше — нужна " + filepath.Base(m[0])
		}
		return "в папке нет v2rayN.exe и guiConfigs\\guiNConfig.json"
	}
	return "неизвестный клиент"
}

// ─── Общее ───────────────────────────────────────────────────────────────────

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// newest — до n самых свежих файлов по маске.
func newest(pattern string, n int) []string {
	files, _ := filepath.Glob(pattern)
	sort.Slice(files, func(i, j int) bool {
		a, _ := os.Stat(files[i])
		b, _ := os.Stat(files[j])
		if a == nil || b == nil {
			return false
		}
		return a.ModTime().After(b.ModTime())
	})
	if len(files) > n {
		files = files[:n]
	}
	return files
}

// copyToTemp — копия файла (и -wal/-shm рядом) во временный каталог: работающее приложение
// держит базу открытой, читать её на месте небезопасно.
func copyToTemp(src, tmp string) (string, func(), error) {
	dir, err := os.MkdirTemp(tmp, "xdiag-db-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, filepath.Base(src))
	for _, suf := range []string{"", "-wal", "-shm"} {
		in, err := os.Open(src + suf)
		if err != nil {
			if suf == "" {
				cleanup()
				return "", func() {}, err
			}
			continue
		}
		out, err := os.Create(dst + suf)
		if err == nil {
			_, _ = io.Copy(out, in)
			out.Close()
		}
		in.Close()
	}
	return dst, cleanup, nil
}

// listeningState — слушает ли кто-то порт и открыт ли он наружу.
func listeningState(f *osw.Facts, port int) (listening bool, exposed bool) {
	if f == nil || port == 0 {
		return false, false
	}
	for _, l := range f.ListeningOn(port) {
		listening = true
		if l.Addr == "0.0.0.0" || l.Addr == "::" || l.Addr == "[::]" {
			exposed = true
		}
	}
	return
}

func boolp(b bool) *bool { return &b }
