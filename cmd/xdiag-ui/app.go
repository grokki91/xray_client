//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/report"
	"github.com/grokki91/xray_client/internal/store"
)

// App — методы, доступные окну (window.go.main.App.*). Секреты наружу не отдаются: в окно
// идут только представления сеансов без адресов, ключей и URL; расшифровка локальных данных —
// только по явной кнопке «Показать сохранённые данные».
type App struct {
	ctx context.Context
	st  *store.Store
	e   *engine.Engine
	err error

	mu       sync.Mutex
	cancel   context.CancelFunc
	pending  map[string]chan bool
	seq      atomic.Int64
	imports  []engine.Import
	logs     string
	lastView *report.View
}

func NewApp() *App { return &App{pending: map[string]chan bool{}} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.st, a.err = store.Open("")
	if a.err == nil {
		a.e, a.err = engine.New(a.st)
	}
	if a.err == nil {
		a.st.Prune(a.st.LoadSettings().RetentionDays, time.Now())
	}
}

func (a *App) shutdown(context.Context) {
	a.Cancel()
}

// Info — версия и состояние для заголовка окна.
type Info struct {
	Version   string `json:"version"`
	Error     string `json:"error,omitempty"`
	DataDir   string `json:"data_dir"`
	Protected bool   `json:"protected"`
}

func (a *App) Info() Info {
	i := Info{Version: engine.Version}
	if a.err != nil {
		i.Error = a.err.Error()
	}
	if a.st != nil {
		i.DataDir, i.Protected = a.st.Dir, a.st.Protected
	}
	return i
}

// SettingsForm — настройки для формы: секреты — только «задан / не задан».
type SettingsForm struct {
	store.Settings
	HasAlias   bool   `json:"has_alias"`
	Alias      string `json:"alias"` // алиас из ~/.ssh/config — не секрет установки, показывается
	HasURI     bool   `json:"has_uri"`
	HiddifyDir string `json:"hiddify_dir"`
	V2rayNDir  string `json:"v2rayn_dir"`
	// Для сохранения: пустая строка — не менять; "-" — удалить.
	NewURI string `json:"new_uri"`
}

func (a *App) Settings() (SettingsForm, error) {
	if a.err != nil {
		return SettingsForm{}, a.err
	}
	v, err := a.st.LoadVault()
	f := SettingsForm{Settings: a.st.LoadSettings(), HasAlias: v.SSHAlias != "", Alias: v.SSHAlias, HasURI: v.ProfileURI != "",
		HiddifyDir: v.HiddifyDir, V2rayNDir: v.V2rayNDir}
	return f, err
}

func (a *App) SaveSettings(f SettingsForm) error {
	if a.err != nil {
		return a.err
	}
	v, err := a.st.LoadVault()
	if err != nil {
		return err
	}
	if f.Alias != "" {
		if _, err := bridge.Args(f.Alias, "facts", 0); err != nil {
			return err
		}
	}
	v.SSHAlias, v.HiddifyDir, v.V2rayNDir = strings.TrimSpace(f.Alias), strings.TrimSpace(f.HiddifyDir), strings.TrimSpace(f.V2rayNDir)
	switch strings.TrimSpace(f.NewURI) {
	case "":
	case "-":
		v.ProfileURI = ""
	default:
		u := strings.TrimSpace(f.NewURI)
		if !strings.HasPrefix(strings.ToLower(u), "vless://") {
			return errors.New("профиль должен начинаться с vless://")
		}
		v.ProfileURI = u
	}
	if err := a.st.SaveVault(v); err != nil {
		return err
	}
	s := f.Settings
	if s.RetentionDays < 0 || s.RetentionDays > 365 {
		return errors.New("срок хранения — 0–365 дней")
	}
	if s.LiveSeconds < 10 || s.LiveSeconds > 120 {
		s.LiveSeconds = 60
	}
	s.Theme = a.st.LoadSettings().Theme // тема — переключателем (SetTheme), форма её не меняет
	return a.st.SaveSettings(s)
}

// SetTheme — тема окна (переключатель на боковой панели): dark | light | "" — как в Windows.
func (a *App) SetTheme(t string) error {
	if a.err != nil {
		return a.err
	}
	switch t {
	case "", "dark", "light":
	default:
		return errors.New("тема: dark, light или пусто")
	}
	s := a.st.LoadSettings()
	s.Theme = t
	return a.st.SaveSettings(s)
}

// RunRequest — параметры запуска из окна.
type RunRequest struct {
	Client       string `json:"client"`
	Bridge       bool   `json:"bridge"`
	Capture      bool   `json:"capture"`
	OtherNetwork bool   `json:"other_network"`
	Offline      bool   `json:"offline"`
}

// Run — сеанс диагностики. Ход — событиями progress/budget/consent/window.
func (a *App) Run(req RunRequest) (*report.View, error) {
	if a.err != nil {
		return nil, a.err
	}
	set := a.st.LoadSettings()
	v, err := a.st.LoadVault()
	if err != nil {
		return nil, err
	}
	o := engine.Options{Client: set.Client, ProfileURI: v.ProfileURI, HiddifyDir: v.HiddifyDir, V2rayNDir: v.V2rayNDir,
		Reference: set.Reference, LiveSeconds: set.LiveSeconds, Capture: req.Capture, CaptureSecs: 60, Offline: req.Offline}
	if req.Client != "" {
		o.Client = req.Client
	}
	if req.Bridge {
		if v.SSHAlias == "" {
			return nil, errors.New("для моста укажите SSH-алиас в «Настройках»")
		}
		o.Bridge, o.SSHAlias = "ssh", v.SSHAlias
	}
	if exe, err := os.Executable(); err == nil {
		o.SelfExe = exe
	}
	a.mu.Lock()
	o.Imports, a.imports = a.imports, nil
	o.PastedLogs, a.logs = a.logs, ""
	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel
	a.mu.Unlock()
	defer cancel()
	if req.OtherNetwork {
		l := a.st.Sessions()
		if len(l) == 0 {
			return nil, errors.New("нет прошлого сеанса для сравнения: сначала обычная диагностика в своей сети")
		}
		prev, err := a.e.Load(l[0].ID)
		if err != nil {
			return nil, err
		}
		o.OtherNetwork, o.Prev = true, prev
	}
	hooks := engine.Hooks{
		Progress: func(s engine.Step) { runtime.EventsEmit(a.ctx, "progress", s) },
		Budget:   func(u netprobe.Usage) { runtime.EventsEmit(a.ctx, "budget", u) },
		Confirm:  a.confirm,
		Window: func(ctx context.Context, what string, secs int) {
			runtime.EventsEmit(a.ctx, "window", map[string]any{"text": what, "seconds": secs})
		},
	}
	sess, err := a.e.Run(ctx, o, hooks)
	if err != nil {
		return nil, err
	}
	if err := a.e.Save(sess); err != nil {
		runtime.EventsEmit(a.ctx, "progress", engine.Step{ID: "save", Title: "История", Status: "warn", Note: err.Error()})
	}
	vw := report.Build(sess)
	a.lastView = &vw
	return &vw, nil
}

func (a *App) confirm(ctx context.Context, c engine.Consent) bool {
	id := fmt.Sprint(a.seq.Add(1))
	ch := make(chan bool, 1)
	a.mu.Lock()
	a.pending[id] = ch
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.pending, id); a.mu.Unlock() }()
	runtime.EventsEmit(a.ctx, "consent", map[string]string{"id": id, "kind": c.Kind, "text": c.Text})
	select {
	case ok := <-ch:
		return ok
	case <-ctx.Done():
		return false
	}
}

// Answer — ответ окна на запрос согласия.
func (a *App) Answer(id string, ok bool) {
	a.mu.Lock()
	ch := a.pending[id]
	a.mu.Unlock()
	if ch != nil {
		select {
		case ch <- ok:
		default:
		}
	}
}

// Cancel — прервать сеанс.
func (a *App) Cancel() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
}

// ImportFiles — выбрать doctor.json / health.json с сервера.
func (a *App) ImportFiles() ([]string, error) {
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{Title: "Файлы xm с сервера (doctor.json, health.json)",
		Filters: []runtime.FileFilter{{DisplayName: "JSON", Pattern: "*.json"}}})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		kind := bridge.Detect(b)
		if kind == "" {
			return nil, fmt.Errorf("%s: не вывод xm doctor/health", baseName(p))
		}
		a.mu.Lock()
		a.imports = append(a.imports, engine.Import{Name: baseName(p), Data: b})
		a.mu.Unlock()
		names = append(names, baseName(p)+" ("+kind+")")
	}
	return names, nil
}

// PasteLogs — экспорт логов клиента (Hiddify: «Логи» → «Скопировать»).
func (a *App) PasteLogs(text string) int {
	a.mu.Lock()
	a.logs = text
	a.mu.Unlock()
	return len(strings.Split(strings.TrimSpace(text), "\n"))
}

// ManualCommands — команды для ручного режима.
func (a *App) ManualCommands() []string {
	return bridge.ManualCommands(a.st.LoadSettings().LiveSeconds)
}

// History — список сеансов.
func (a *App) History() []store.IndexEntry {
	if a.err != nil {
		return nil
	}
	return a.st.Sessions()
}

// Session — сеанс из истории.
func (a *App) Session(id string) (*report.View, error) {
	s, err := a.e.Load(id)
	if err != nil {
		return nil, err
	}
	v := report.Build(s)
	return &v, nil
}

func (a *App) DeleteSession(id string) error { return a.st.DeleteSession(id) }

func (a *App) ClearHistory() error { return a.st.ClearHistory() }

// CopyReport — текст отчёта без секретов в буфер обмена.
func (a *App) CopyReport(id string) error {
	s, err := a.e.Load(id)
	if err != nil {
		return err
	}
	return runtime.ClipboardSetText(a.ctx, report.ExportText(s))
}

// ExportSession — сохранить экспорт (JSON) в файл; адрес — только по галочке.
func (a *App) ExportSession(id string, includeAddress bool) (string, error) {
	s, err := a.e.Load(id)
	if err != nil {
		return "", err
	}
	b, err := report.Export(s, includeAddress)
	if err != nil {
		return "", err
	}
	p, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "Экспорт сеанса", DefaultFilename: "xdiag-" + id + ".json",
		Filters: []runtime.FileFilter{{DisplayName: "JSON", Pattern: "*.json"}}})
	if err != nil || p == "" {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o600)
}

// RevealData — расшифрованные локальные данные (по явной кнопке).
func (a *App) RevealData(sessionID string) (string, error) {
	if a.err != nil {
		return "", a.err
	}
	if sessionID != "" {
		var raw map[string]any
		if err := a.st.LoadSession(sessionID, &raw); err != nil {
			return "", err
		}
		return pretty(raw), nil
	}
	v, err := a.st.LoadVault()
	if err != nil {
		return "", err
	}
	return "Каталог: " + a.st.Dir + "\n\nНастройки (settings.json):\n" + pretty(a.st.LoadSettings()) +
		"\nСекреты (vault.dpapi):\n" + pretty(v), nil
}

// OpenDataDir — открыть каталог данных в Проводнике.
func (a *App) OpenDataDir() error {
	return exec.Command("explorer.exe", a.st.Dir).Start()
}
