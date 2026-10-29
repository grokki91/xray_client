package clients

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/grokki91/xray_client/internal/profile"
)

// Hiddify — Hiddify (hiddify-app, Flutter) для Windows.
//
// Пути — по исходнику тега v4.1.2: данные — getApplicationSupportDirectory() =
// %APPDATA%\Hiddify\hiddify (CompanyName\ProductName из Runner.rc) или hiddify_portable_data
// рядом с exe; там db.sqlite (drift, таблица profile_entries), configs\<id>.json (профиль,
// приведённый ядром к конфигу sing-box), shared_preferences.json, box.log и app.log
// (с PR hiddify-app#2333 — ещё data\box.log). Установщик — {autopf64}\Hiddify, служба TUN —
// HiddifyTunnelService. Сборка Microsoft Store хранит данные в песочнице пакета — частичная
// поддержка.
type Hiddify struct{}

func (*Hiddify) Name() string  { return "hiddify" }
func (*Hiddify) Title() string { return "Hiddify" }

// prefs — нужные настройки из shared_preferences.json (ключи «flutter.<имя>», в портативной
// сборке — с префиксом «portable.»).
type hiddifyPrefs struct {
	ServiceMode string
	MixedPort   int
	LAN         bool
	TestURL     string
	Region      string
}

func (h *Hiddify) exeCandidates(env *Env) []string {
	var out []string
	if env.OS != nil {
		for _, p := range env.OS.ProcessByName("hiddify") {
			if p.Path != "" {
				out = append(out, p.Path)
			}
		}
	}
	if env.ProgramFiles != "" {
		out = append(out, filepath.Join(env.ProgramFiles, "Hiddify", "Hiddify.exe"))
	}
	if env.LocalAppData != "" {
		out = append(out, filepath.Join(env.LocalAppData, "Programs", "Hiddify", "Hiddify.exe"))
	}
	return out
}

func (h *Hiddify) Detect(ctx context.Context, env *Env) Detection {
	d := Detection{Client: "hiddify", Core: "hiddify-sing-box", CoreFamily: "sing-box", Support: "full"}
	for _, exe := range h.exeCandidates(env) {
		if exists(exe) {
			d.ExePath, d.Installed = exe, true
			break
		}
	}
	// Каталог данных: настройка → portable рядом с exe → %APPDATA%.
	switch {
	case env.HiddifyDir != "" && dirExists(env.HiddifyDir):
		d.DataDir = env.HiddifyDir
	case d.ExePath != "" && dirExists(filepath.Join(filepath.Dir(d.ExePath), "hiddify_portable_data")):
		d.DataDir, d.Portable = filepath.Join(filepath.Dir(d.ExePath), "hiddify_portable_data"), true
	case env.AppData != "" && dirExists(filepath.Join(env.AppData, "Hiddify", "hiddify")):
		d.DataDir = filepath.Join(env.AppData, "Hiddify", "hiddify")
	}
	if d.DataDir != "" {
		d.Installed = true
	}
	if !d.Installed {
		return d
	}
	if d.ExePath != "" && env.FileVersion != nil {
		d.Version = env.FileVersion(d.ExePath)
	}
	if d.Version == "" && env.OS != nil {
		for _, p := range env.OS.ProcessByName("hiddify") {
			if p.Version != "" {
				d.Version = p.Version
			}
		}
	}
	if env.Compat != nil {
		if row, ok := env.Compat.Hiddify(d.Version); ok {
			d.Core, d.CoreFamily, d.CoreMlkem, d.Note = row.Core, row.CoreFamily, row.Mlkem, row.Note
			if row.Mlkem == nil {
				d.Support = "partial"
			}
		} else {
			// Версия не определилась: все вышедшие релизы — на ядре sing-box без X25519MLKEM768,
			// но без версии это только «возможно».
			d.Note = "версия Hiddify не определена; все релизы 4.x — ядро sing-box без X25519MLKEM768"
			d.Support = "partial"
		}
	}
	pr := h.prefs(d.DataDir)
	d.Mode = pr.ServiceMode
	if d.Mode == "" {
		d.Mode = "system-proxy" // умолчание десктопа (ServiceMode.defaultMode)
	}
	d.TUN = d.Mode == "vpn" || d.Mode == "tun"
	d.ProxyPort = pr.MixedPort
	if d.ProxyPort == 0 {
		d.ProxyPort = 12334
	}
	d.LAN = pr.LAN
	d.TestURL = pr.TestURL
	if d.TestURL == "" {
		d.TestURL = "http://captive.apple.com/hotspot-detect.html"
	}
	if pr.Region != "" {
		d.RUDirect = boolp(pr.Region == "ru")
	}
	return d
}

func (h *Hiddify) prefs(dir string) hiddifyPrefs {
	var p hiddifyPrefs
	if dir == "" {
		return p
	}
	b, err := os.ReadFile(filepath.Join(dir, "shared_preferences.json"))
	if err != nil {
		return p
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return p
	}
	get := func(k string) any {
		for _, pre := range []string{"flutter.", "portable.flutter.", "portable."} {
			if v, ok := m[pre+k]; ok {
				return v
			}
		}
		return nil
	}
	if v, ok := get("service-mode").(string); ok {
		p.ServiceMode = v
	}
	if v, ok := get("mixed-port").(float64); ok {
		p.MixedPort = int(v)
	}
	if v, ok := get("allow-connection-from-lan").(bool); ok {
		p.LAN = v
	}
	if v, ok := get("connection-test-url").(string); ok {
		p.TestURL = v
	}
	if v, ok := get("region").(string); ok {
		p.Region = v
	}
	return p
}

type hiddifyEntry struct {
	ID, Name, URL string
	Active        bool
}

// entries — профили из db.sqlite (через копию).
func (h *Hiddify) entries(env *Env, dir string) ([]hiddifyEntry, error) {
	src := filepath.Join(dir, "db.sqlite")
	if !exists(src) {
		return nil, os.ErrNotExist
	}
	tmp, cleanup, err := copyToTemp(src, env.TempDir)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	// Копия — своя: открывается простым путём (URI file: ломается на пробелах в профиле Windows).
	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, name, COALESCE(url, ''), active FROM profile_entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hiddifyEntry
	for rows.Next() {
		var e hiddifyEntry
		var active any
		if rows.Scan(&e.ID, &e.Name, &e.URL, &active) == nil {
			e.Active = fmt.Sprint(active) == "1" || fmt.Sprint(active) == "true"
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

func (h *Hiddify) Profiles(ctx context.Context, env *Env, d Detection) ([]*profile.Profile, error) {
	if d.DataDir == "" {
		return nil, nil
	}
	entries, dbErr := h.entries(env, d.DataDir)
	byID := map[string]hiddifyEntry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	files, _ := filepath.Glob(filepath.Join(d.DataDir, "configs", "*.json"))
	var out []*profile.Profile
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		if strings.HasSuffix(id, ".tmp") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 8<<20 {
			continue
		}
		e := byID[id]
		for _, p := range profile.ParseAny(b) {
			p.Source = "hiddify"
			p.ID = id
			p.Origin = "Hiddify: configs\\" + filepath.Base(f)
			if e.Name != "" {
				p.Name = e.Name
			}
			p.SubURL = e.URL
			p.Active = e.Active
			out = append(out, p)
		}
	}
	if len(out) == 0 && dbErr != nil && len(files) == 0 {
		return nil, fmt.Errorf("профили Hiddify не прочитаны: %w", dbErr)
	}
	return out, nil
}

func (h *Hiddify) Logs(env *Env, d Detection, since time.Time) LogSummary {
	if d.DataDir == "" {
		return LogSummary{Counts: map[string]int{}}
	}
	var files []string
	for _, f := range []string{"box.log", "app.log", filepath.Join("data", "box.log")} {
		files = append(files, filepath.Join(d.DataDir, f))
	}
	return ScanLogs(files, env.Now())
}

func (h *Hiddify) State(env *Env, d Detection) State {
	var s State
	if env.OS == nil {
		return s
	}
	s.Running = len(env.OS.ProcessByName("hiddify", "hiddifycli", "hiddify-core")) > 0
	listening, exposed := listeningState(env.OS, d.ProxyPort)
	s.CoreListening = listening
	if exposed {
		s.Exposed = []int{d.ProxyPort}
	}
	for _, a := range env.OS.Adapters {
		if a.Up && strings.Contains(strings.ToLower(a.Name+" "+a.Desc), "hiddify") {
			s.TunAdapter = true
		}
	}
	if v, ok := env.OS.Services["HiddifyTunnelService"]; ok {
		s.Service = v
	}
	return s
}

func (h *Hiddify) Hints(d Detection) []string {
	var out []string
	if d.CoreMlkem != nil && !*d.CoreMlkem {
		out = append(out, "Hiddify "+d.Version+": ядро sing-box вырезает X25519MLKEM768 — к серверу с Xray ≥ v26.9.9 не подключится")
	}
	out = append(out, "В Hiddify 4.1.x файл box.log на диске может быть пустым: логи — «Логи» → «Скопировать» и вставить в xdiag")
	return out
}
