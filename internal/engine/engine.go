// Package engine — оркестратор диагностики (docs/architecture.md §4.1): фазы, бюджет проб,
// согласия пользователя, сбор улик и вердикт.
//
//	Фаза 0  факты без сети: клиенты (версии, профили, логи, состояние) и Windows
//	Фаза 1  локальная сеть и эталонные хосты; к серверу — ничего
//	Фаза 2  сервер снаружи: TCP, TLS с SNI маски, эталонное ядро (бюджет: ≤ 3 TLS за 60 с)
//	Фаза 3  мост к xm (SSH) или импорт файлов xm
//	Фаза 4  вердикт и запись сеанса
//
// Каждая фаза прерываема и оставляет улики, даже если следующая не состоялась.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/redact"
	"github.com/grokki91/xray_client/internal/refcore"
	"github.com/grokki91/xray_client/internal/rules"
	"github.com/grokki91/xray_client/internal/store"
)

// Version — версия приложения (подставляется при сборке -ldflags).
var Version = "dev"

// Options — что делать в сеансе.
type Options struct {
	Client     string // auto | hiddify | v2rayn
	ProfileURI string // профиль из настроек (секрет; хранится в vault)
	HiddifyDir string
	V2rayNDir  string

	Offline   bool // только фаза 0
	Reference bool // эталонная проба P3/P3m

	OtherNetwork bool         // повтор «из другой сети» (P5) — сравнение с Prev
	Prev         *SessionData // предыдущий сеанс для P5
	Bridge       string       // "" | "ssh"
	SSHAlias     string       // алиас из ~/.ssh/config: мост (Bridge=ssh) и порт SSH для P6
	LiveSeconds  int          // окно xm doctor
	Imports      []Import     // файлы xm (ручной мост)
	PastedLogs   string       // экспорт логов клиента
	Capture      bool         // C7: pktmon (UAC)
	CaptureSecs  int          // окно захвата
	SelfExe      string       // путь к xdiag.exe для capture-helper
	SkipRepeat   bool         // не ждать 30 с ради P4 (тесты)
	Hosts        *rules.Hosts // переопределение эталонов (тесты)
	PreferIPv4   bool
	Now          func() time.Time // тесты
}

// Import — содержимое файла xm (doctor.json / health.json / facts.json).
type Import struct {
	Name string
	Data []byte
}

// Step — ход сеанса для интерфейса.
type Step struct {
	Phase  int    `json:"phase"`
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"` // run | ok | warn | fail | skip
	Note   string `json:"note,omitempty"`
	Wait   int    `json:"wait,omitempty"` // шаг ждёт столько секунд (пауза бюджета, повтор) — окно ведёт отсчёт
}

// Consent — запрос согласия пользователя.
type Consent struct {
	Kind string `json:"kind"` // bridge | window | uac | wait
	Text string `json:"text"`
}

// Hooks — связь с интерфейсом (CLI или окно). Любой может быть nil.
type Hooks struct {
	Progress func(Step)
	Confirm  func(ctx context.Context, c Consent) bool
	// Window — началось окно, в которое пользователь один раз жмёт «Подключить» в клиенте.
	Window func(ctx context.Context, what string, seconds int)
	Budget func(netprobe.Usage)
}

// Engine — зависимости; поля можно подменить в тестах.
type Engine struct {
	Rules    *rules.Engine
	Store    *store.Store
	Adapters []clients.Adapter

	CollectOS func(ctx context.Context, exe []string) osw.Facts
	NewEnv    func(f *osw.Facts) *clients.Env
	NewSSH    func(alias string) (SSHBridge, error)
	RunRef    func(ctx context.Context, o refcore.Options) refcore.Result
	Capture   func(ctx context.Context, job string, selfExe string) error
	Resolver  *net.Resolver // nil — системный (тесты подставляют свой)
	// LocalOpen — слушает ли 127.0.0.1:port (локальный прокси клиента); nil — не проверять.
	LocalOpen func(port int) bool
	// ProbeClient — C10: запрос через локальный прокси клиента (port 0 — по системному маршруту).
	ProbeClient func(ctx context.Context, port int, probe204, download string, limit int) netprobe.ClientResult
	// SSHPort — порт SSH алиаса (`ssh -G`, без подключения); 0 — не узнать, P6 берёт 22.
	SSHPort func(ctx context.Context, alias string) int

	mu      sync.Mutex
	running bool

	budgetMu sync.Mutex
	budgets  map[string]*netprobe.Budget // ключ — Profile.ServerKey(): у каждого сервера свой лимит
}

// Budget — бюджет проб к серверу key (хэш адреса и порта). Создаётся при первом обращении и
// подхватывает отметки прошлых запусков из store (CLI запускается заново на каждый сеанс).
func (e *Engine) Budget(key string) *netprobe.Budget {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	if b := e.budgets[key]; b != nil {
		return b
	}
	b := netprobe.NewBudget()
	if e.Store != nil {
		m := e.Store.LoadBudget().For(key)
		b.Restore(netprobe.Snapshot{TLS: m.TLS, TCP: m.TCP})
	}
	if e.budgets == nil {
		e.budgets = map[string]*netprobe.Budget{}
	}
	e.budgets[key] = b
	return b
}

// SSHBridge — мост (интерфейс ради тестов).
type SSHBridge interface {
	Facts(ctx context.Context, saltHex string) (*bridge.Facts, error)
	Doctor(ctx context.Context, live int) (*bridge.Doctor, []byte, error)
	Health(ctx context.Context) (*bridge.Health, error)
}

// New — движок с настоящими зависимостями.
func New(st *store.Store) (*Engine, error) {
	re, err := rules.Load()
	if err != nil {
		return nil, err
	}
	e := &Engine{Rules: re, Store: st, Adapters: clients.All(), CollectOS: osw.Collect, RunRef: refcore.Run,
		LocalOpen: netprobe.LocalListening, ProbeClient: netprobe.ProbeViaClient}
	e.NewEnv = func(f *osw.Facts) *clients.Env { return clients.DefaultEnv(f, re.Compat) }
	e.NewSSH = func(alias string) (SSHBridge, error) { return bridge.NewSSH(alias) }
	e.SSHPort = func(ctx context.Context, alias string) int {
		s, err := bridge.NewSSH(alias)
		if err != nil {
			return 0
		}
		return s.Port(ctx)
	}
	return e, nil
}

// SessionData — сеанс целиком (сохраняется под DPAPI; в экспорт — без Secret).
type SessionData struct {
	ID           string              `json:"id"`
	App          string              `json:"app"`
	Started      time.Time           `json:"started"`
	Finished     time.Time           `json:"finished"`
	Client       string              `json:"client"`
	ClientName   string              `json:"client_name"`
	Clients      []ClientInfo        `json:"clients"`
	Profile      *profile.Summary    `json:"profile,omitempty"`
	Profiles     int                 `json:"profiles"`
	Evidence     []evidence.Evidence `json:"evidence"`
	Verdict      rules.Verdict       `json:"verdict"`
	Steps        []Step              `json:"steps"`
	Notes        []string            `json:"notes,omitempty"`
	Logs         []string            `json:"logs,omitempty"` // характерные строки (уже без секретов)
	Budget       netprobe.Usage      `json:"budget"`
	Bridge       string              `json:"bridge"`
	OtherNetwork bool                `json:"other_network,omitempty"`
	Cancelled    bool                `json:"cancelled,omitempty"` // остановлен до конца проверок
	Secret       *Secret             `json:"secret,omitempty"`
}

// Secret — то, что идентифицирует установку: только в DPAPI-файле сеанса, не в экспорте и не в
// окне (§8.1: адрес, порт и SNI — как есть под DPAPI).
type Secret struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
	SNI    string `json:"sni"`
	Name   string `json:"name,omitempty"` // имя профиля у пользователя: окно показывает, что проверялось
}

// ClientInfo — клиент без путей.
type ClientInfo struct {
	Client      string `json:"client"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version"`
	Core        string `json:"core"`
	CoreFamily  string `json:"core_family"`
	CoreMlkem   *bool  `json:"core_mlkem"`
	Mode        string `json:"mode"`
	Running     bool   `json:"running"`
	Profiles    int    `json:"profiles"`
	Support     string `json:"support"`
	Portable    bool   `json:"portable"`
	ProfilesErr string `json:"profiles_err,omitempty"`
}

// run — состояние одного сеанса.
type run struct {
	e     *Engine
	o     Options
	h     Hooks
	set   *evidence.Set
	red   *redact.Redactor
	sess  *SessionData
	now   func() time.Time
	dial  *netprobe.Dialer
	res   *net.Resolver
	facts osw.Facts

	prof     *profile.Profile // профиль, который проверяется
	uriProf  *profile.Profile // профиль из настроек
	active   *clientRun
	all      []*clientRun
	serverIP []net.IP
	mu       sync.Mutex

	budget      *netprobe.Budget // бюджет сервера профиля (фаза 2)
	budgetStart netprobe.Usage   // расход на начало сеанса — в отчёт идёт разница
}

type clientRun struct {
	a     clients.Adapter
	d     clients.Detection
	ps    []*profile.Profile
	perr  error
	logs  clients.LogSummary
	state clients.State
}

// Run — один сеанс диагностики.
func (e *Engine) Run(ctx context.Context, o Options, h Hooks) (*SessionData, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, ErrBusy
	}
	e.running = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.running = false; e.mu.Unlock() }()

	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.LiveSeconds == 0 {
		o.LiveSeconds = 60
	}
	if o.CaptureSecs == 0 {
		o.CaptureSecs = 60
	}
	r := &run{e: e, o: o, h: h, set: evidence.NewSet(), red: redact.New(nil), now: now, dial: &netprobe.Dialer{}, res: net.DefaultResolver}
	if e.Resolver != nil {
		r.res = e.Resolver
	}
	var rnd [2]byte
	_, _ = rand.Read(rnd[:])
	r.sess = &SessionData{ID: store.NewID(now(), binary.BigEndian.Uint16(rnd[:])), App: Version, Started: now(), OtherNetwork: o.OtherNetwork}
	for _, hst := range r.hosts().PublicHosts() {
		r.red.Keep(hst)
	}
	defer func() {
		if r.budget != nil {
			r.budget.OnChange(nil)
		}
	}()

	r.phase0(ctx)
	if !o.Offline && ctx.Err() == nil {
		r.phase1(ctx)
		if ctx.Err() == nil {
			r.phase2(ctx)
		}
	}
	if ctx.Err() == nil {
		r.phase3(ctx)
	}
	if o.Capture && ctx.Err() == nil {
		r.phaseCapture(ctx)
	}
	if o.OtherNetwork && o.Prev != nil {
		r.mergeOtherNetwork()
	}
	r.finish()
	if ctx.Err() != nil {
		r.sess.Cancelled = true
		r.note("Сеанс прерван: вердикт — по собранным уликам")
	}
	return r.sess, nil
}

func (r *run) hosts() *rules.Hosts {
	if r.o.Hosts != nil {
		return r.o.Hosts
	}
	return r.e.Rules.Hosts
}

func (r *run) step(phase int, id, title, status, note string) {
	s := Step{Phase: phase, ID: id, Title: title, Status: status, Note: r.red.String(note)}
	r.mu.Lock()
	if status != "run" {
		r.sess.Steps = append(r.sess.Steps, s)
	}
	r.mu.Unlock()
	if r.h.Progress != nil {
		r.h.Progress(s)
	}
}

// stepWait — шаг ждёт secs секунд (окно показывает обратный отсчёт).
func (r *run) stepWait(phase int, id, title string, secs int, note string) {
	if r.h.Progress != nil {
		r.h.Progress(Step{Phase: phase, ID: id, Title: title, Status: "run", Note: note, Wait: secs})
	}
}

func (r *run) note(s string) {
	r.mu.Lock()
	r.sess.Notes = append(r.sess.Notes, r.red.String(s))
	r.mu.Unlock()
}

func (r *run) put(e evidence.Evidence) {
	if e.Title == "" {
		e.Title = Titles[e.ID]
	}
	if e.At.IsZero() {
		e.At = r.now()
	}
	for k, v := range e.Facts {
		e.Facts[k] = r.red.Any(v)
	}
	e.Summary = r.red.String(e.Summary)
	r.set.Put(e)
}

func (r *run) confirm(ctx context.Context, c Consent) bool {
	if r.h.Confirm == nil {
		return true
	}
	return r.h.Confirm(ctx, c)
}

// finish — вердикт, редактирование и запись.
func (r *run) finish() {
	v := r.e.Rules.Decide(r.set)
	r.sess.Verdict = v
	r.sess.Evidence = r.set.All()
	r.sess.Finished = r.now()
	if r.budget != nil {
		r.sess.Budget = r.budget.Usage().Since(r.budgetStart)
	} else {
		r.sess.Budget = netprobe.NewBudget().Usage()
	}
	if r.prof != nil {
		s := r.prof.Summary()
		r.sess.Profile = &s
		r.sess.Secret = &Secret{Server: r.prof.Address, Port: r.prof.Port, SNI: r.prof.SNI, Name: strings.TrimSpace(r.prof.Name)}
	}
	if r.e.Store != nil && r.prof != nil && r.budget != nil {
		key := r.prof.ServerKey()
		bf := r.e.Store.LoadBudget()
		m := bf.For(key)
		snap := r.budget.Snapshot()
		m.TLS, m.TCP = snap.TLS, snap.TCP
		if strings.HasPrefix(v.Main.Code, "path.") {
			m.LastPath = r.now()
		}
		bf.Set(key, m, r.now())
		_ = r.e.Store.SaveBudget(bf)
	}
}

// Save — сеанс в историю (DPAPI) и строка индекса; заодно чистка старше срока хранения.
func (e *Engine) Save(s *SessionData) error {
	if e.Store == nil {
		return nil
	}
	st := e.Store.LoadSettings()
	if st.RetentionDays == 0 {
		return nil // история выключена
	}
	ie := store.IndexEntry{ID: s.ID, At: s.Started, Code: s.Verdict.Main.Code, Level: string(s.Verdict.Main.Level),
		Short: s.Verdict.Main.Short, Client: s.Client, Other: s.OtherNetwork}
	if err := e.Store.SaveSession(ie, s); err != nil {
		return err
	}
	e.Store.Prune(st.RetentionDays, time.Now())
	return nil
}

// Load — сеанс из истории.
func (e *Engine) Load(id string) (*SessionData, error) {
	var s SessionData
	if err := e.Store.LoadSession(id, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ErrBusy — сеанс уже идёт.
var ErrBusy = errBusy{}

type errBusy struct{}

func (errBusy) Error() string { return "диагностика уже идёт" }
