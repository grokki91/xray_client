// Package rules — движок гипотез: читает rules/*.yaml, сопоставляет с уликами сессии и выдаёт
// вердикт — одну причину с уровнем уверенности, уликами, исключённым и следующими проверками.
package rules

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/grokki91/xray_client/internal/evidence"
	data "github.com/grokki91/xray_client/rules"
)

// Level — уровень уверенности (ординальный, без процентов).
type Level string

const (
	None      Level = ""
	Possible  Level = "possible"
	Likely    Level = "likely"
	Confirmed Level = "confirmed"
	Excluded  Level = "excluded"
)

// Rank — для сравнения уровней.
func (l Level) Rank() int {
	switch l {
	case Confirmed:
		return 3
	case Likely:
		return 2
	case Possible:
		return 1
	}
	return 0
}

// Text — по-русски.
func (l Level) Text() string {
	switch l {
	case Confirmed:
		return "подтверждено"
	case Likely:
		return "вероятно"
	case Possible:
		return "возможно"
	case Excluded:
		return "исключено"
	}
	return "не проверялось"
}

// Hypothesis — одна гипотеза из YAML.
type Hypothesis struct {
	Code        string     `yaml:"code"`
	Kind        string     `yaml:"kind"` // cause (по умолчанию) | finding | ok
	Gate        []string   `yaml:"gate"`
	Confirmed   [][]string `yaml:"confirmed"`
	Likely      [][]string `yaml:"likely"`
	Possible    [][]string `yaml:"possible"`
	Excluded    []string   `yaml:"excluded"`
	NextChecks  []string   `yaml:"next_checks"`
	Title       string     `yaml:"title"`
	Why         string     `yaml:"why"`
	Alternative string     `yaml:"alternative"`
	Actions     []string   `yaml:"actions"`
}

// CodeInfo — запись таксономии.
type CodeInfo struct {
	Layer string `yaml:"layer"`
	Order int    `yaml:"order"`
	Title string `yaml:"title"`
}

// Taxonomy — taxonomy.yaml.
type Taxonomy struct {
	Layers map[string]string   `yaml:"layers"`
	Codes  map[string]CodeInfo `yaml:"codes"`
	Checks map[string]string   `yaml:"checks"`
}

// Engine — загруженные правила.
type Engine struct {
	Tax    Taxonomy
	Hyps   []Hypothesis
	Compat *Compat
	Hosts  *Hosts
}

// Load читает встроенные правила и проверяет их согласованность.
func Load() (*Engine, error) { return LoadFS(data.FS) }

// LoadFS — то же из произвольной файловой системы (тесты).
func LoadFS(fsys fs.FS) (*Engine, error) {
	e := &Engine{}
	if err := readYAML(fsys, "taxonomy.yaml", &e.Tax); err != nil {
		return nil, err
	}
	files, _ := fs.Glob(fsys, "hypotheses/*.yaml")
	sort.Strings(files)
	for _, f := range files {
		var hs []Hypothesis
		if err := readYAML(fsys, f, &hs); err != nil {
			return nil, err
		}
		e.Hyps = append(e.Hyps, hs...)
	}
	e.Compat = &Compat{}
	if err := readYAML(fsys, "compat.yaml", e.Compat); err != nil {
		return nil, err
	}
	e.Hosts = &Hosts{}
	if err := readYAML(fsys, "hosts.yaml", e.Hosts); err != nil {
		return nil, err
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	sort.SliceStable(e.Hyps, func(i, j int) bool { return e.order(e.Hyps[i].Code) < e.order(e.Hyps[j].Code) })
	return e, nil
}

func readYAML(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return fmt.Errorf("правила: %s: %w", name, err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("правила: %s: %w", name, err)
	}
	return nil
}

func (e *Engine) validate() error {
	seen := map[string]bool{}
	for _, h := range e.Hyps {
		if _, ok := e.Tax.Codes[h.Code]; !ok {
			return fmt.Errorf("правила: код %s нет в taxonomy.yaml", h.Code)
		}
		if seen[h.Code] {
			return fmt.Errorf("правила: код %s описан дважды", h.Code)
		}
		seen[h.Code] = true
		switch h.Kind {
		case "", "cause", "finding", "ok":
		default:
			return fmt.Errorf("правила: %s: неизвестный kind %q", h.Code, h.Kind)
		}
		if h.Title == "" {
			return fmt.Errorf("правила: %s без title", h.Code)
		}
		if len(h.Confirmed)+len(h.Likely)+len(h.Possible) == 0 {
			return fmt.Errorf("правила: %s без условий", h.Code)
		}
		for _, c := range h.NextChecks {
			if _, ok := e.Tax.Checks[c]; !ok {
				return fmt.Errorf("правила: %s: проверки %s нет в taxonomy.yaml checks", h.Code, c)
			}
		}
		// «Вероятно» про путь — только с альтернативой (§7.3).
		if strings.HasPrefix(h.Code, "path.") && len(h.Likely) > 0 && h.Alternative == "" {
			return fmt.Errorf("правила: %s: гипотеза о пути без alternative", h.Code)
		}
		all := append([]string{}, h.Gate...)
		all = append(all, h.Excluded...)
		for _, g := range append(append(h.Confirmed, h.Likely...), h.Possible...) {
			all = append(all, g...)
		}
		for _, p := range all {
			if err := checkPred(p); err != nil {
				return fmt.Errorf("правила: %s: %w", h.Code, err)
			}
		}
	}
	return nil
}

func checkPred(p string) error {
	for _, part := range strings.Split(p, "||") {
		part = strings.TrimLeft(strings.TrimSpace(part), "!|")
		id, _, _ := strings.Cut(part, ".")
		if id == "" || strings.ContainsAny(id, " =<>~") {
			return fmt.Errorf("предикат %q: нет ID улики", p)
		}
	}
	return nil
}

func (e *Engine) order(code string) int {
	if c, ok := e.Tax.Codes[code]; ok {
		return c.Order
	}
	return 10000
}

// Result — гипотеза, оценённая на уликах.
type Result struct {
	Code        string   `json:"code"`
	Kind        string   `json:"kind"`
	Layer       string   `json:"layer"`
	LayerTitle  string   `json:"layer_title"`
	Level       Level    `json:"level"`
	LevelText   string   `json:"level_text"`
	Short       string   `json:"short"`
	Title       string   `json:"title"`
	Why         string   `json:"why,omitempty"`
	Alternative string   `json:"alternative,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Evidence    []string `json:"evidence,omitempty"` // ID улик сработавшей группы
	ExcludedBy  []string `json:"excluded_by,omitempty"`
	NextChecks  []Check  `json:"next_checks,omitempty"`
	Order       int      `json:"order"`
}

// Check — следующая проверка.
type Check struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Verdict — итог: одна причина, «также найдено», находки, возможные, исключённые.
type Verdict struct {
	Main       Result   `json:"main"`
	Also       []Result `json:"also,omitempty"`
	Findings   []Result `json:"findings,omitempty"`
	Possible   []Result `json:"possible,omitempty"`
	RuledOut   []Result `json:"ruled_out,omitempty"`
	NextChecks []Check  `json:"next_checks,omitempty"`
}

// Evaluate оценивает все гипотезы.
func (e *Engine) Evaluate(set *evidence.Set) []Result {
	var out []Result
	for _, h := range e.Hyps {
		out = append(out, e.evalOne(h, set))
	}
	return out
}

func (e *Engine) evalOne(h Hypothesis, set *evidence.Set) Result {
	info := e.Tax.Codes[h.Code]
	r := Result{Code: h.Code, Kind: h.Kind, Layer: info.Layer, LayerTitle: e.Tax.Layers[info.Layer], Short: info.Title, Order: info.Order}
	if r.Kind == "" {
		r.Kind = "cause"
	}
	fill := func() {
		r.Title = e.render(h.Title, set)
		r.Why = e.render(h.Why, set)
		r.Alternative = e.render(h.Alternative, set)
		for _, a := range h.Actions {
			r.Actions = append(r.Actions, e.render(a, set))
		}
		for _, c := range h.NextChecks {
			r.NextChecks = append(r.NextChecks, Check{ID: c, Text: e.Tax.Checks[c]})
		}
	}
	if !evidence.AllOf(set, h.Gate) {
		return r
	}
	for _, p := range h.Excluded {
		if evidence.Eval(set, p) {
			r.Level = Excluded
			r.ExcludedBy = append(r.ExcludedBy, p)
		}
	}
	if r.Level == Excluded {
		r.Evidence = evidence.IDs(r.ExcludedBy)
		fill()
		return r
	}
	for _, lv := range []struct {
		l Level
		g [][]string
	}{{Confirmed, h.Confirmed}, {Likely, h.Likely}, {Possible, h.Possible}} {
		for _, g := range lv.g {
			if evidence.AllOf(set, g) {
				r.Level = lv.l
				r.Evidence = evidence.IDs(append(append([]string{}, h.Gate...), g...))
				fill()
				return r
			}
		}
	}
	return r
}

// Decide собирает вердикт из оценённых гипотез.
func (e *Engine) Decide(set *evidence.Set) Verdict {
	res := e.Evaluate(set)
	var v Verdict
	var mainSet bool
	var okRes *Result
	for i := range res {
		r := res[i]
		switch {
		case r.Kind == "ok":
			// Самый сильный из итогов «работает»; при равенстве — первый по порядку.
			if r.Level.Rank() >= Likely.Rank() && (okRes == nil || r.Level.Rank() > okRes.Level.Rank()) {
				okRes = &res[i]
			}
		case r.Kind == "finding":
			if r.Level.Rank() >= Possible.Rank() {
				v.Findings = append(v.Findings, r)
			}
		case r.Level == Excluded:
			v.RuledOut = append(v.RuledOut, r)
		case r.Level.Rank() >= Likely.Rank():
			if !mainSet {
				v.Main, mainSet = r, true
			} else {
				v.Also = append(v.Also, r)
			}
		case r.Level == Possible:
			v.Possible = append(v.Possible, r)
		}
	}
	if !mainSet && okRes != nil {
		v.Main, mainSet = *okRes, true
	} else if okRes != nil {
		// Эталон прошёл — путь, сервер и профиль исключены: так и сказать.
		ok := *okRes
		ok.Level = Excluded
		ok.Title = "Сервер, путь до него и профиль: эталонное ядро Xray с этим профилем подключилось"
		v.RuledOut = append([]Result{ok}, v.RuledOut...)
	}
	if !mainSet {
		v.Main = e.unknown(set, v.Possible)
	}
	// Следующие проверки: из главной причины, затем из возможных — без повторов.
	seen := map[string]bool{}
	add := func(cs []Check) {
		for _, c := range cs {
			if !seen[c.ID] && !e.checkDone(set, c.ID) {
				seen[c.ID] = true
				v.NextChecks = append(v.NextChecks, c)
			}
		}
	}
	if v.Main.Level != Confirmed {
		add(v.Main.NextChecks)
	}
	for _, p := range v.Possible {
		add(p.NextChecks)
	}
	return v
}

// checkDone — проверка уже есть в уликах (повторно не предлагать).
func (e *Engine) checkDone(set *evidence.Set, id string) bool {
	switch id {
	case "S1", "S3", "P5", "C7":
		return set.Has(id)
	}
	return false
}

func (e *Engine) unknown(set *evidence.Set, possible []Result) Result {
	code := "unknown"
	need := map[string]bool{}
	for _, p := range possible {
		for _, c := range p.NextChecks {
			need[c.ID] = true
		}
	}
	switch {
	case set.Get("P1").Str("outcome") == "budget" || set.Get("P3").Str("outcome") == "budget":
		// Пробы к серверу не выполнены — без них «нужно окно сервера» было бы неправдой.
		code = "unknown.budget"
	case need["S3"] && !set.Has("S3"):
		code = "unknown.need_window"
	case need["P5"] && !set.Has("P5"):
		code = "unknown.need_other_network"
	case !set.Has("S3"):
		code = "unknown.need_window"
	}
	info := e.Tax.Codes[code]
	r := Result{Code: code, Kind: "cause", Layer: info.Layer, LayerTitle: e.Tax.Layers[info.Layer], Level: None,
		Short: info.Title, Title: info.Title, Order: info.Order}
	switch code {
	case "unknown.budget":
		r.Why = "Пробы к серверу не выполнены: к нему только что было несколько проверок, а приложение открывает не больше 3 TLS-соединений в минуту и 6 TCP за 5 минут — частые попытки сами похожи на шторм. Без проб к серверу причину не назвать."
		r.Actions = []string{"Повторить диагностику через 1–5 минут; приложение само подождёт, если до свободного слота меньше минуты"}
	case "unknown.need_window":
		r.Why = "Со стороны ПК причина не видна: нужно посмотреть, что приходит на сервер в момент попытки клиента."
		r.NextChecks = []Check{{"S3", e.Tax.Checks["S3"]}}
	case "unknown.need_other_network":
		r.Why = "Признаки указывают на сеть, но без сравнения с другой сетью блокировку от сбоя не отличить."
		r.NextChecks = []Check{{"P5", e.Tax.Checks["P5"]}}
	default:
		r.Why = "Проверки не нашли причину."
	}
	return r
}

// render подставляет {ID.key} фактами улик и {COMPAT.recommend}.
func (e *Engine) render(s string, set *evidence.Set) string {
	if !strings.Contains(s, "{") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString(e.value(s[i+1:i+j], set))
		s = s[i+j+1:]
	}
	return b.String()
}

func (e *Engine) value(ref string, set *evidence.Set) string {
	id, key, _ := strings.Cut(ref, ".")
	if id == "COMPAT" && key == "recommend" {
		return e.Compat.Recommend
	}
	ev := set.Get(id)
	if ev == nil {
		return "?"
	}
	v, ok := ev.Get(key)
	if !ok || v == nil {
		return "?"
	}
	switch t := v.(type) {
	case []string:
		if len(t) == 0 {
			return "—"
		}
		return strings.Join(t, ", ")
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "да"
		}
		return "нет"
	case string:
		if t == "" {
			return "пусто"
		}
		return t
	}
	return fmt.Sprint(v)
}

// CheckText — текст проверки из каталога.
func (e *Engine) CheckText(id string) string { return e.Tax.Checks[id] }

// CodeTitle — короткое название кода.
func (e *Engine) CodeTitle(code string) string { return e.Tax.Codes[code].Title }

// LayerOf — уровень кода.
func (e *Engine) LayerOf(code string) string { return e.Tax.Codes[code].Layer }

// Files — список встроенных файлов правил (для «Подробно»).
func Files() []string {
	var out []string
	_ = fs.WalkDir(data.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, path.Clean(p))
		}
		return nil
	})
	return out
}
