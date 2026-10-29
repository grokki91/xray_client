// Package report — вердикт для человека (docs/architecture.md §7.4) и экспорт без секретов (§8.1).
//
// Пять блоков: «Что не работает», «Где», «Причина (уровень)», «Улики», «Что делать», затем
// «Если не помогло», «Исключено», «Также найдено». Технические подробности — отдельно.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/redact"
	"github.com/grokki91/xray_client/internal/rules"
)

// View — сеанс для показа (окно, CLI): только то, что можно видеть на экране.
type View struct {
	ID        string              `json:"id"`
	When      string              `json:"when"`
	Problem   string              `json:"problem"`
	Where     string              `json:"where"`
	Level     string              `json:"level"`
	LevelCode string              `json:"level_code"`
	Code      string              `json:"code"`
	Title     string              `json:"title"`
	Why       string              `json:"why"`
	Alt       string              `json:"alternative,omitempty"`
	Evidence  []Line              `json:"evidence"`
	Actions   []string            `json:"actions"`
	Next      []string            `json:"next"`
	RuledOut  []string            `json:"ruled_out"`
	Also      []string            `json:"also"`
	Findings  []string            `json:"findings"`
	Possible  []string            `json:"possible"`
	Details   []Line              `json:"details"`
	Notes     []string            `json:"notes"`
	Logs      []string            `json:"logs"`
	Budget    string              `json:"budget"`
	Clients   []engine.ClientInfo `json:"clients"`
	Steps     []engine.Step       `json:"steps"`
}

// Line — улика строкой.
type Line struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	Source string `json:"source"`
	Rel    string `json:"rel"`
}

var sourceText = map[evidence.Source]string{
	evidence.FromClient: "клиент", evidence.FromOS: "Windows", evidence.FromNetwork: "сеть", evidence.FromReference: "эталон",
	evidence.FromServer: "сервер", evidence.FromLog: "лог", evidence.FromUser: "вы",
}

// Build — представление сеанса.
func Build(s *engine.SessionData) View {
	v := s.Verdict
	m := v.Main
	vw := View{ID: s.ID, When: s.Started.Local().Format("02.01.2006 15:04"), Code: m.Code, Title: m.Title, Why: m.Why, Alt: m.Alternative,
		Actions: m.Actions, Level: m.Level.Text(), LevelCode: string(m.Level), Where: whereText(m), Problem: problem(s),
		Notes: s.Notes, Logs: s.Logs, Clients: s.Clients, Steps: s.Steps}
	if m.Level == rules.None {
		vw.Level = "не определено"
	}
	byID := map[string]evidence.Evidence{}
	for _, e := range s.Evidence {
		byID[e.ID] = e
	}
	seen := map[string]bool{}
	for _, id := range m.Evidence {
		if e, ok := byID[id]; ok && e.Summary != "" && !seen[id] {
			seen[id] = true
			vw.Evidence = append(vw.Evidence, line(e))
		}
	}
	if len(vw.Evidence) > 5 {
		vw.Evidence = vw.Evidence[:5]
	}
	for _, c := range v.NextChecks {
		vw.Next = append(vw.Next, c.Text)
	}
	if len(vw.Next) == 0 && m.Level != rules.Confirmed {
		for _, c := range m.NextChecks {
			vw.Next = append(vw.Next, c.Text)
		}
	}
	for _, r := range v.RuledOut {
		switch {
		case r.Kind == "ok":
			vw.RuledOut = append(vw.RuledOut, r.Title)
		case r.Code == "profile.missing":
			// «Профиль найден» — не вывод, а условие проверки.
		default:
			vw.RuledOut = append(vw.RuledOut, r.Short+" — нет ("+strings.Join(r.Evidence, ", ")+")")
		}
	}
	for _, r := range v.Also {
		vw.Also = append(vw.Also, fmt.Sprintf("%s (%s)", r.Title, r.Level.Text()))
	}
	for _, r := range v.Findings {
		vw.Findings = append(vw.Findings, fmt.Sprintf("%s (%s)", r.Title, r.Level.Text()))
	}
	for _, r := range v.Possible {
		vw.Possible = append(vw.Possible, r.Title)
	}
	all := append([]evidence.Evidence(nil), s.Evidence...)
	sort.SliceStable(all, func(i, j int) bool { return order(all[i].ID) < order(all[j].ID) })
	for _, e := range all {
		vw.Details = append(vw.Details, line(e))
	}
	b := s.Budget
	vw.Budget = fmt.Sprintf("к серверу за сеанс: TLS %d, TCP %d (лимит %d TLS в минуту)", b.TotalTLS, b.TotalTCP, b.TLSMax)
	if b.Refused > 0 {
		vw.Budget += fmt.Sprintf("; отложено проб: %d", b.Refused)
	}
	return vw
}

func line(e evidence.Evidence) Line {
	return Line{ID: e.ID, Title: e.Title, Text: e.Summary, Source: sourceText[e.Source], Rel: string(e.Reliability)}
}

func order(id string) int {
	const seq = "CWNPBS"
	if id == "" {
		return 999
	}
	i := strings.IndexByte(seq, id[0])
	if i < 0 {
		i = 9
	}
	return i*100 + len(id)
}

func whereText(m rules.Result) string {
	if m.Layer == "" || m.Layer == "-" {
		return "—"
	}
	return m.Layer + " — " + m.LayerTitle
}

// problem — «что не работает» одной фразой.
func problem(s *engine.SessionData) string {
	name := s.ClientName
	if name == "" {
		for _, c := range s.Clients {
			if c.Client == s.Client {
				name = map[string]string{"hiddify": "Hiddify", "v2rayn": "v2rayN"}[c.Client]
				if c.Version != "" {
					name += " " + c.Version
				}
			}
		}
	}
	if name == "" {
		name = "VPN-клиент"
	}
	switch s.Verdict.Main.Code {
	case "ok":
		return name + ": сервер и профиль в порядке — проверяется, почему клиент пишет «таймаут»"
	case "lan.noinet":
		return "Нет интернета на этом ПК"
	case "profile.missing":
		return "Не найден профиль подключения"
	}
	return name + " не подключается к серверу («таймаут» или «Подключение…»)"
}

// Text — отчёт для терминала и буфера обмена.
func Text(v View) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("Что не работает: %s", v.Problem)
	w("Где: %s", v.Where)
	w("Причина (%s): %s", v.Level, v.Title)
	if v.Why != "" {
		w("  %s", v.Why)
	}
	if v.Alt != "" {
		w("  Альтернатива: %s", v.Alt)
	}
	if len(v.Evidence) > 0 {
		w("Улики:")
		for _, e := range v.Evidence {
			w("  • [%s] %s", e.ID, e.Text)
		}
	}
	if len(v.Actions) > 0 {
		w("Что делать:")
		for i, a := range v.Actions {
			w("  %d. %s", i+1, a)
		}
	}
	if len(v.Next) > 0 {
		w("Если не помогло:")
		for _, n := range v.Next {
			w("  – %s", n)
		}
	}
	if len(v.Also) > 0 {
		w("Также найдено:")
		for _, a := range v.Also {
			w("  – %s", a)
		}
	}
	if len(v.Findings) > 0 {
		w("Важно знать:")
		for _, a := range v.Findings {
			w("  – %s", a)
		}
	}
	if len(v.RuledOut) > 0 {
		w("Исключено:")
		for _, a := range v.RuledOut {
			w("  ✓ %s", a)
		}
	}
	if len(v.Notes) > 0 {
		w("Заметки:")
		for _, n := range v.Notes {
			w("  · %s", n)
		}
	}
	w("%s", v.Budget)
	return b.String()
}

// Details — все улики построчно.
func Details(v View) string {
	var b strings.Builder
	for _, d := range v.Details {
		fmt.Fprintf(&b, "%-4s %-34s %-8s %s\n", d.ID, d.Title, d.Source, d.Text)
	}
	if len(v.Logs) > 0 {
		b.WriteString("\nСтроки логов:\n")
		for _, l := range v.Logs {
			b.WriteString("  " + l + "\n")
		}
	}
	return b.String()
}

// Export — сеанс для передачи (в чат, в issue): без Secret, текст ещё раз через редактор.
// includeAddress — по явной галочке пользователя: адрес сервера и SNI добавляются отдельным полем.
func Export(s *engine.SessionData, includeAddress bool) ([]byte, error) {
	c := *s
	sec := c.Secret
	c.Secret = nil
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return nil, err
	}
	r := redact.New(nil)
	if sec != nil {
		r.Add(redact.Server, sec.Server)
		r.Add(redact.SNI, sec.SNI)
	}
	out := r.String(string(b))
	if leaks := redact.Leaks(out); len(leaks) > 0 {
		return nil, fmt.Errorf("экспорт остановлен: в тексте осталось %d значений, похожих на секреты", len(leaks))
	}
	if includeAddress && sec != nil {
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		m["server_address"] = map[string]any{"address": sec.Server, "port": sec.Port, "sni": sec.SNI}
		nb, _ := json.MarshalIndent(m, "", "  ")
		return nb, nil
	}
	return []byte(out), nil
}

// ExportText — текст отчёта для передачи.
func ExportText(s *engine.SessionData) string {
	v := Build(s)
	r := redact.New(nil)
	if s.Secret != nil {
		r.Add(redact.Server, s.Secret.Server)
		r.Add(redact.SNI, s.Secret.SNI)
	}
	return r.String(Text(v) + "\nПодробно:\n" + Details(v))
}
