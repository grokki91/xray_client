// Package netprobe — активные пробы приложения: TCP, TLS (uTLS chrome), DNS, HTTP-эталоны,
// бюджет соединений к серверу и привязка сокетов к физическому адаптеру.
//
// Бюджет (docs/architecture.md, приложение C): к адресу сервера — не больше 3 TLS-хендшейков за
// любые 60 с и 6 TCP-соединений за 5 минут, включая эталонную пробу. Сверх бюджета проба не
// выполняется: приложение само не должно выглядеть как шторм.
package netprobe

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// Kind — вид соединения к серверу.
type Kind int

const (
	TCP Kind = iota // только TCP (P1)
	TLS             // TCP + TLS-хендшейк (P2, эталон)
)

// ErrBudget — проба не выполнена: исчерпан бюджет соединений к серверу.
var ErrBudget = errors.New("бюджет проб к серверу исчерпан")

// Usage — текущий расход для показа пользователю.
type Usage struct {
	TLS      int `json:"tls"`
	TLSMax   int `json:"tls_max"`
	TCP      int `json:"tcp"`
	TCPMax   int `json:"tcp_max"`
	WaitSec  int `json:"wait_sec"` // через сколько освободится слот TLS
	TotalTLS int `json:"total_tls"`
	TotalTCP int `json:"total_tcp"`
	Refused  int `json:"refused"`
}

// Budget потокобезопасен; один на сервер (адрес+порт) на всё время жизни процесса: окно
// переживает сеансы, а пробы к другому серверу его не расходуют.
type Budget struct {
	TLSMax    int
	TLSWindow time.Duration
	TCPMax    int
	TCPWindow time.Duration

	mu       sync.Mutex
	tls, tcp []time.Time
	totTLS   int
	totTCP   int
	refused  int
	now      func() time.Time
	onChange func(Usage)
}

// NewBudget — бюджет по приложению C.
func NewBudget() *Budget {
	return &Budget{TLSMax: 3, TLSWindow: 60 * time.Second, TCPMax: 6, TCPWindow: 5 * time.Minute, now: time.Now}
}

// OnChange — колбэк на каждое изменение (индикатор «к серверу: 2 из 3 за минуту»).
func (b *Budget) OnChange(f func(Usage)) {
	b.mu.Lock()
	b.onChange = f
	b.mu.Unlock()
}

func (b *Budget) prune(now time.Time) {
	b.tls = keepAfter(b.tls, now.Add(-b.TLSWindow))
	b.tcp = keepAfter(b.tcp, now.Add(-b.TCPWindow))
}

func keepAfter(ts []time.Time, t time.Time) []time.Time {
	out := ts[:0]
	for _, x := range ts {
		if x.After(t) {
			out = append(out, x)
		}
	}
	return out
}

// Can — хватит ли бюджета на соединение вида k (без списания).
func (b *Budget) Can(k Kind) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.prune(now)
	if len(b.tcp) >= b.TCPMax {
		return false
	}
	return k != TLS || len(b.tls) < b.TLSMax
}

// Acquire списывает соединение; ErrBudget — сверх бюджета.
func (b *Budget) Acquire(k Kind) error {
	b.mu.Lock()
	now := b.now()
	b.prune(now)
	if len(b.tcp) >= b.TCPMax || (k == TLS && len(b.tls) >= b.TLSMax) {
		b.refused++
		u, f := b.usageLocked(now), b.onChange
		b.mu.Unlock()
		if f != nil {
			f(u)
		}
		return ErrBudget
	}
	b.tcp = append(b.tcp, now)
	b.totTCP++
	if k == TLS {
		b.tls = append(b.tls, now)
		b.totTLS++
	}
	u, f := b.usageLocked(now), b.onChange
	b.mu.Unlock()
	if f != nil {
		f(u)
	}
	return nil
}

// Upgrade — TCP-соединение, уже списанное как TCP, стало TLS (эталон: сокет открывается до
// того, как известно, что поверх пойдёт TLS).
func (b *Budget) Upgrade() error {
	b.mu.Lock()
	now := b.now()
	b.prune(now)
	if len(b.tls) >= b.TLSMax {
		b.refused++
		b.mu.Unlock()
		return ErrBudget
	}
	b.tls = append(b.tls, now)
	b.totTLS++
	u, f := b.usageLocked(now), b.onChange
	b.mu.Unlock()
	if f != nil {
		f(u)
	}
	return nil
}

// WaitTLS — через сколько освободится слот TLS (0 — свободен).
func (b *Budget) WaitTLS() time.Duration { return b.Wait(TLS) }

// Wait — через сколько можно будет открыть соединение вида k (0 — сейчас): TLS-хендшейк
// тратит и слот TCP.
func (b *Budget) Wait(k Kind) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.prune(now)
	var w time.Duration
	if len(b.tcp) >= b.TCPMax {
		w = b.tcp[len(b.tcp)-b.TCPMax].Add(b.TCPWindow).Sub(now)
	}
	if k == TLS && len(b.tls) >= b.TLSMax {
		if t := b.tls[len(b.tls)-b.TLSMax].Add(b.TLSWindow).Sub(now); t > w {
			w = t
		}
	}
	if w < 0 {
		w = 0
	}
	return w
}

// Usage — текущий расход.
func (b *Budget) Usage() Usage {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usageLocked(b.now())
}

func (b *Budget) usageLocked(now time.Time) Usage {
	b.prune(now)
	u := Usage{TLS: len(b.tls), TLSMax: b.TLSMax, TCP: len(b.tcp), TCPMax: b.TCPMax, TotalTLS: b.totTLS, TotalTCP: b.totTCP, Refused: b.refused}
	if len(b.tls) >= b.TLSMax {
		u.WaitSec = int(b.tls[len(b.tls)-b.TLSMax].Add(b.TLSWindow).Sub(now).Seconds()) + 1
	}
	return u
}

// Since — расход за сеанс: накопленные счётчики минус снимок на его начало.
func (u Usage) Since(start Usage) Usage {
	u.TotalTLS -= start.TotalTLS
	u.TotalTCP -= start.TotalTCP
	u.Refused -= start.Refused
	return u
}

// Snapshot — отметки времени для сохранения между запусками (CLI запускается заново).
type Snapshot struct {
	TLS []time.Time `json:"tls"`
	TCP []time.Time `json:"tcp"`
}

func (b *Budget) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prune(b.now())
	return Snapshot{TLS: append([]time.Time(nil), b.tls...), TCP: append([]time.Time(nil), b.tcp...)}
}

// Restore добавляет сохранённые отметки (старые отбрасываются окном). Отметки, которые уже
// есть, не дублируются: иначе повторный Restore того же снимка в долгоживущем окне удваивал
// счётчик и следующий сеанс получал «бюджет исчерпан» без единой пробы.
func (b *Budget) Restore(s Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tls = mergeMarks(b.tls, s.TLS)
	b.tcp = mergeMarks(b.tcp, s.TCP)
	b.prune(b.now())
}

func mergeMarks(have, add []time.Time) []time.Time {
	out := append([]time.Time(nil), have...)
	for _, t := range add {
		dup := false
		for _, h := range have {
			if h.Equal(t) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}
