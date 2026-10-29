// Package evidence — улики диагностики и их хранилище в пределах сессии.
//
// Улика — наблюдение одной проверки (ID из матрицы проверок: C1, W2, P3, S3 …) с источником,
// временем, надёжностью и плоским набором фактов. Правила читают только улики: вывод «по
// конфигу» там, где наблюдаемо следствие, не делается.
package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Source — откуда улика.
type Source string

const (
	FromClient    Source = "client"    // файлы и состояние клиентских приложений
	FromOS        Source = "os"        // Windows
	FromNetwork   Source = "network"   // пробы приложения
	FromReference Source = "reference" // эталонное ядро
	FromServer    Source = "server"    // xm через мост или импорт
	FromLog       Source = "log"       // журналы клиентов
	FromUser      Source = "user"      // слова пользователя
)

// Reliability — надёжность: high — наблюдение; medium — лог или таблица версий; low — слова.
type Reliability string

const (
	High   Reliability = "high"
	Medium Reliability = "medium"
	Low    Reliability = "low"
)

// Evidence — одна улика. Facts — плоский словарь: строки, числа, bool, []string.
type Evidence struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Source      Source         `json:"source"`
	At          time.Time      `json:"at"`
	Reliability Reliability    `json:"reliability"`
	Facts       map[string]any `json:"facts"`
	Summary     string         `json:"summary"` // человеческим языком, уже без секретов
	Skipped     string         `json:"skipped,omitempty"`
}

// Get — факт по ключу.
func (e *Evidence) Get(key string) (any, bool) {
	if e == nil || e.Facts == nil {
		return nil, false
	}
	v, ok := e.Facts[key]
	return v, ok
}

// Str — факт строкой.
func (e *Evidence) Str(key string) string {
	v, ok := e.Get(key)
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// Num — факт числом (false — нет или не число).
func (e *Evidence) Num(key string) (float64, bool) {
	v, ok := e.Get(key)
	if !ok {
		return 0, false
	}
	return toFloat(v)
}

// Bool — факт как bool.
func (e *Evidence) Bool(key string) bool {
	v, ok := e.Get(key)
	return ok && truthy(v)
}

// Set — потокобезопасное хранилище улик сессии; по одному ID — последняя запись.
type Set struct {
	mu    sync.RWMutex
	items map[string]*Evidence
	order []string
}

func NewSet() *Set { return &Set{items: map[string]*Evidence{}} }

// Put сохраняет улику (копию фактов).
func (s *Set) Put(e Evidence) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if e.Facts == nil {
		e.Facts = map[string]any{}
	}
	f := make(map[string]any, len(e.Facts))
	for k, v := range e.Facts {
		f[k] = normalize(v)
	}
	e.Facts = f
	s.mu.Lock()
	if _, ok := s.items[e.ID]; !ok {
		s.order = append(s.order, e.ID)
	}
	s.items[e.ID] = &e
	s.mu.Unlock()
}

// Get — улика по ID.
func (s *Set) Get(id string) *Evidence {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[id]
}

// Has — есть ли улика (и не пропущена ли проверка).
func (s *Set) Has(id string) bool {
	e := s.Get(id)
	return e != nil && e.Skipped == ""
}

// All — все улики в порядке поступления.
func (s *Set) All() []Evidence {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Evidence, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, *s.items[id])
	}
	return out
}

// FromList восстанавливает набор (импорт, тесты).
func FromList(l []Evidence) *Set {
	s := NewSet()
	for _, e := range l {
		s.Put(e)
	}
	return s
}

func normalize(v any) any {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case int32:
		return float64(t)
	case uint16:
		return float64(t)
	case uint32:
		return float64(t)
	case float32:
		return float64(t)
	case time.Duration:
		return float64(t.Milliseconds())
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return v
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case bool:
		return 0, false
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != "" && t != "false" && t != "0"
	case float64:
		return t != 0
	case []string:
		return len(t) > 0
	}
	return true
}

// ─── Предикаты ───────────────────────────────────────────────────────────────
//
//   ID               улика есть и проверка не пропущена
//   ID.key           факт истинный (true, непустая строка, ненулевое число, непустой список)
//   ID.key?          факт есть (любое значение)
//   ID.key=a|b       факт равен одному из значений (для списка — содержит одно из)
//   ID.key!=a|b      факт есть и не равен ни одному
//   ID.key~a|b       список содержит одно из (то же, что = для списка)
//   ID.key>=N  <=N  >N  <N   числовое сравнение (модуль: |ID.key|>=N)
//   !P               отрицание (истинно и при отсутствии улики)
//   P || Q           любое из

// Eval вычисляет предикат на наборе улик.
func Eval(s *Set, pred string) bool {
	pred = strings.TrimSpace(pred)
	if strings.Contains(pred, "||") {
		for _, p := range strings.Split(pred, "||") {
			if Eval(s, p) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(pred, "!") {
		return !Eval(s, pred[1:])
	}
	abs := false
	if strings.HasPrefix(pred, "|") {
		abs = true
		pred = strings.Replace(strings.TrimPrefix(pred, "|"), "|", "", 1)
	}
	ops := []string{"!=", ">=", "<=", "=", "~", ">", "<"}
	var lhs, op, rhs string
	for _, o := range ops {
		if i := strings.Index(pred, o); i > 0 {
			lhs, op, rhs = pred[:i], o, pred[i+len(o):]
			break
		}
	}
	if op == "" {
		lhs = pred
	}
	id, key, _ := strings.Cut(lhs, ".")
	e := s.Get(id)
	if e == nil || e.Skipped != "" {
		return false
	}
	if key == "" {
		return op == ""
	}
	if strings.HasSuffix(key, "?") && op == "" {
		_, ok := e.Get(strings.TrimSuffix(key, "?"))
		return ok
	}
	v, ok := e.Get(key)
	if !ok {
		return false
	}
	switch op {
	case "":
		return truthy(v)
	case "=", "~":
		return matchAny(v, strings.Split(rhs, "|"))
	case "!=":
		return !matchAny(v, strings.Split(rhs, "|"))
	default:
		a, ok1 := toFloat(v)
		b, err := strconv.ParseFloat(rhs, 64)
		if !ok1 || err != nil {
			return false
		}
		if abs && a < 0 {
			a = -a
		}
		switch op {
		case ">=":
			return a >= b
		case "<=":
			return a <= b
		case ">":
			return a > b
		case "<":
			return a < b
		}
	}
	return false
}

func matchAny(v any, wants []string) bool {
	if l, ok := v.([]string); ok {
		for _, x := range l {
			for _, w := range wants {
				if x == w {
					return true
				}
			}
		}
		return false
	}
	var s string
	switch t := v.(type) {
	case bool:
		s = strconv.FormatBool(t)
	case float64:
		s = strconv.FormatFloat(t, 'f', -1, 64)
	default:
		s = fmt.Sprint(v)
	}
	for _, w := range wants {
		if s == w {
			return true
		}
	}
	return false
}

// All — все предикаты истинны.
func AllOf(s *Set, preds []string) bool {
	for _, p := range preds {
		if !Eval(s, p) {
			return false
		}
	}
	return true
}

// IDs — идентификаторы улик, упомянутых в предикатах (для «улики вердикта»).
func IDs(preds []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range preds {
		for _, part := range strings.Split(p, "||") {
			part = strings.TrimLeft(strings.TrimSpace(part), "!|")
			id := part
			for i, c := range part {
				if c == '.' || c == '=' || c == '!' || c == '>' || c == '<' || c == '~' {
					id = part[:i]
					break
				}
			}
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
