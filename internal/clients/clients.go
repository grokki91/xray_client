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
	Support     string `json:"support"` // full | partial
}

// LogSummary — сводка журналов клиента.
type LogSummary struct {
	Found  bool           `json:"found"`
	Files  int            `json:"files"`
	Counts map[string]int `json:"counts"`
	AgeMin int            `json:"age_min"` // давность последней записи
	Lines  []string       `json:"-"`       // характерные строки — наружу только через redact
	Pasted bool           `json:"pasted"`
}

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
	{"timeout", regexp.MustCompile(`(?i)i/o timeout|context deadline exceeded|handshake timeout|timed out`)},
	// Hiddify сам проверяет прямой выход (outbound direct/direct-fragment): это не сервер.
	{"direct_failed", regexp.MustCompile(`(?i)outbound direct\S*\s[^\n]{0,40}(test failed|timeout|error)`)},
	{"tun_error", regexp.MustCompile(`(?i)(configure|create|open|start)[^\n]{0,40}tun[^\n]{0,60}(error|fail)|wintun[^\n]{0,60}(error|fail)|tun device`)},
	{"port_busy", regexp.MustCompile(`(?i)address already in use|only one usage of each socket address|bind: an attempt was made`)},
	{"core_failed", regexp.MustCompile(`(?i)failed to (start|run) (the )?core|start service[^\n]{0,30}(error|fail)|core (process )?(exited|crashed)|panic:|createService - null`)},
	{"empty_fp", regexp.MustCompile(`(?i)empty fingerprint`)},
	{"dns_error", regexp.MustCompile(`(?i)(dns|lookup)[^\n]{0,60}(no such host|server misbehaving|refused|failed)`)},
}

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
	return s
}

// ScanText — то же для вставленного пользователем текста (экспорт логов Hiddify).
func ScanText(text string) LogSummary {
	s := LogSummary{Counts: map[string]int{}, Found: strings.TrimSpace(text) != "", Pasted: true}
	scanText(strings.NewReader(text), &s)
	return s
}

func scanText(r io.Reader, s *LogSummary) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		hit := false
		for _, p := range logPatterns {
			if p.re.MatchString(line) {
				s.Counts[p.key]++
				hit = true
			}
		}
		if hit {
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			s.Lines = append(s.Lines, line)
			if len(s.Lines) > 20 {
				s.Lines = s.Lines[1:]
			}
		}
	}
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
