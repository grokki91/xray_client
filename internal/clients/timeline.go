package clients

import (
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Хронология журналов клиента: нестабильность во времени без единой пробы к серверу
// (docs/implementation.md, решение 15). Строка со временем — отметка: сбой соединения через
// сервер или просто запись клиента. Сбои, идущие подряд, — эпизод; запись без сбоев после
// эпизода — клиент работал дальше (восстановился сам).

// Пороги эпизода: одиночный таймаут — это обычно сайт за тоннелем, а не тоннель; эпизод —
// плотная серия сбоев через сервер. Разрыв — как окно журнала здоровья сервера (5 минут).
const (
	EpisodeGap = 5 * time.Minute
	EpisodeMin = 5
)

// mark — отметка строки журнала.
type mark struct {
	t    time.Time
	fail bool // сбой соединения через сервер (не прямой выход, не ошибка самого приложения)
}

// Episode — серия сбоев через сервер без разрыва дольше EpisodeGap.
type Episode struct {
	From time.Time
	To   time.Time
	N    int
}

// Timeline — хронология журналов за окно.
type Timeline struct {
	Stamped   int           // строк со временем в окне
	Span      time.Duration // от первой до последней такой строки
	Episodes  []Episode
	Recovered int // эпизодов, после которых клиент писал в журнал без сбоев (не раньше EpisodeGap)
}

// connFail — ключи шаблонов, которые означают сбой соединения через сервер.
var connFail = map[string]bool{"reality_failed": true, "real_cert": true, "x509": true, "eof": true,
	"reset": true, "refused": true, "timeout": true}

// reStamp — время в начале строки: sing-box «+0300 2026-11-01 12:34:56», Xray
// «2026/11/01 12:34:56.123456», приложения «[2026-11-01 12:34:56.789]» / «2026-11-01T12:34:56».
var reStamp = regexp.MustCompile(`^\W{0,3}(?:([+-])(\d{2})(\d{2}) )?(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}):(\d{2}):(\d{2})`)

// stamp — время строки; без пояса в строке — местное время ПК (так пишут Xray и Hiddify).
func stamp(line string) (time.Time, bool) {
	m := reStamp.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	loc := time.Local
	if m[1] != "" {
		off := (n(m[2])*60 + n(m[3])) * 60
		if m[1] == "-" {
			off = -off
		}
		loc = time.FixedZone("", off)
	}
	mon := n(m[5])
	if mon < 1 || mon > 12 {
		return time.Time{}, false
	}
	return time.Date(n(m[4]), time.Month(mon), n(m[6]), n(m[7]), n(m[8]), n(m[9]), 0, loc), true
}

// Timeline — эпизоды сбоев через сервер за [since, now]. Отметки из будущего (часы, пояс) —
// с запасом EpisodeGap, дальше отбрасываются.
func (s *LogSummary) Timeline(now, since time.Time) Timeline {
	var ms []mark
	for _, m := range s.marks {
		if !m.t.Before(since) && !m.t.After(now.Add(EpisodeGap)) {
			ms = append(ms, m)
		}
	}
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].t.Before(ms[j].t) })
	var tl Timeline
	tl.Stamped = len(ms)
	if len(ms) == 0 {
		return tl
	}
	tl.Span = ms[len(ms)-1].t.Sub(ms[0].t)
	var cur *Episode
	flush := func() {
		if cur != nil && cur.N >= EpisodeMin {
			tl.Episodes = append(tl.Episodes, *cur)
		}
		cur = nil
	}
	for _, m := range ms {
		if !m.fail {
			continue
		}
		if cur != nil && m.t.Sub(cur.To) > EpisodeGap {
			flush()
		}
		if cur == nil {
			cur = &Episode{From: m.t, To: m.t}
		}
		cur.To, cur.N = m.t, cur.N+1
	}
	flush()
	// Восстановился: после эпизода (не раньше EpisodeGap) и до следующего — запись без сбоев.
	for i, ep := range tl.Episodes {
		until := time.Time{}
		if i+1 < len(tl.Episodes) {
			until = tl.Episodes[i+1].From
		}
		for _, m := range ms {
			if !m.fail && m.t.Sub(ep.To) >= EpisodeGap && (until.IsZero() || m.t.Before(until)) {
				tl.Recovered++
				break
			}
		}
	}
	return tl
}

// Merge — добавить сводку (вставленные логи к файлам): счётчики, строки и хронологию.
func (s *LogSummary) Merge(o LogSummary) {
	if s.Counts == nil {
		s.Counts = map[string]int{}
	}
	for k, v := range o.Counts {
		s.Counts[k] += v
	}
	s.Lines = append(s.Lines, o.Lines...)
	s.marks = append(s.marks, o.marks...)
	s.Found = s.Found || o.Found
	s.Pasted = s.Pasted || o.Pasted
}
