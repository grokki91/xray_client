package engine

import (
	"time"

	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/rules"
)

// Mark — вердикт меткой: код таксономии и уровень (без текстов, в которых есть факты улик).
type Mark struct {
	Code  string      `json:"code"`
	Level rules.Level `json:"level"`
}

// Replayed — сеанс истории, заново решённый правилами текущей сборки.
type Replayed struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	App     string    `json:"app"` // версия, которой сеанс записан
	Was     Mark      `json:"was"`
	Now     Mark      `json:"now"`
	Changed bool      `json:"changed"`
	Err     string    `json:"error,omitempty"` // сеанс не прочитан (без подробностей)
}

// Replay — улики сохранённого сеанса через rules.Decide этой сборки. В сеть не ходит, сеанс и
// индекс не перезаписывает.
func (e *Engine) Replay(s *SessionData) Replayed {
	v := e.Rules.Decide(evidence.FromList(s.Evidence))
	r := Replayed{ID: s.ID, At: s.Started, App: s.App,
		Was: Mark{Code: s.Verdict.Main.Code, Level: s.Verdict.Main.Level},
		Now: Mark{Code: v.Main.Code, Level: v.Main.Level}}
	r.Changed = r.Was != r.Now
	return r
}

// ReplayHistory — Replay для каждого сеанса истории (новые первыми). Нечитаемый сеанс — строка
// с Err, остальные проверяются дальше.
func (e *Engine) ReplayHistory() []Replayed {
	var out []Replayed
	for _, ie := range e.Store.Sessions() {
		s, err := e.Load(ie.ID)
		if err != nil {
			out = append(out, Replayed{ID: ie.ID, At: ie.At, Was: Mark{Code: ie.Code, Level: rules.Level(ie.Level)},
				Err: "сеанс не прочитан"})
			continue
		}
		out = append(out, e.Replay(s))
	}
	return out
}
