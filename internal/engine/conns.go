package engine

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
)

// Соединения клиента с сервером (C11) — по таблице TCP Windows (osw.TCPTable): без прав
// администратора и без единого пакета в сеть. Пока идёт запрос через клиент (C10) и пробы фазы 2,
// таблица читается раз в 50–250 мс: какие соединения с адресом и портом сервера открыл не xdiag и
// дошли ли они до SYN-ACK. Это отвечает, шлёт ли клиент к серверу вообще, — до окна сервера и
// проб пути, — и считает TLS-хендшейки самого клиента: они в том же бюджете адреса (приложение C:
// «заморозка по отпечатку» считает все хендшейки с ПК, а не только пробы xdiag).

const (
	connsFast = 50 * time.Millisecond  // во время запроса через клиент: короткий SYN_SENT не пропустить
	connsSlow = 250 * time.Millisecond // дальше — только счёт хендшейков клиента для бюджета
)

type connKey struct{ local, remote netip.AddrPort }

type seenConn struct {
	target  bool          // к серверу профиля; иначе — к серверу другого профиля клиента
	open    bool          // уже было открыто (рукопожатие TCP прошло) до начала наблюдения
	synFrom time.Time     // впервые в SYN_SENT
	synFor  time.Duration // сколько видели в SYN_SENT
	est     bool          // рукопожатие TCP прошло (ESTABLISHED или закрытие после него)
}

// connWatch — опрос таблицы соединений. Соединения самого xdiag (PID процесса) не в счёт;
// закрытые сокеты без владельца (TIME_WAIT, PID 0) — только у уже известных соединений: иначе
// пробы прошлого сеанса в TIME_WAIT посчитались бы попытками клиента.
type connWatch struct {
	table  func() ([]osw.Conn, error)
	self   int
	addr   netip.Addr // адрес сервера профиля (для проверки маршрута)
	target map[netip.AddrPort]bool
	others map[netip.AddrPort]bool
	onTLS  func(time.Time) // новое соединение клиента с сервером прошло рукопожатие TCP: за ним TLS
	now    func() time.Time

	mu    sync.Mutex
	conns map[connKey]*seenConn
	every atomic.Int64 // интервал опроса, нс
	stopc chan struct{}
	done  chan struct{}
	once  sync.Once
}

// connStats — что клиент делал с сервером за время наблюдения.
type connStats struct {
	Before      int // соединения с сервером, открытые клиентом до запроса
	New         int // попытки за время наблюдения
	Established int // прошли рукопожатие TCP (открытые до запроса и новые)
	SynOnly     int // новые, так и не прошедшие SYN_SENT
	SynMs       int // дольше всего в SYN_SENT, мс
	TLS         int // новые, прошедшие рукопожатие при наблюдении: за каждым — TLS-хендшейк
	Other       int // новые соединения с серверами других профилей клиента
}

func (s connStats) outcome() string {
	switch {
	case s.Established > 0:
		return "established"
	case s.SynOnly > 0:
		return "syn"
	}
	return "none"
}

func newConnWatch(table func() ([]osw.Conn, error), target, others []netip.AddrPort, now func() time.Time) (*connWatch, error) {
	w := &connWatch{table: table, self: os.Getpid(), target: map[netip.AddrPort]bool{}, others: map[netip.AddrPort]bool{}, now: now,
		conns: map[connKey]*seenConn{}, stopc: make(chan struct{}), done: make(chan struct{})}
	for _, a := range target {
		w.target[a] = true
	}
	if len(target) > 0 {
		w.addr = target[0].Addr()
	}
	for _, a := range others {
		if !w.target[a] {
			w.others[a] = true
		}
	}
	rows, err := table()
	if err != nil {
		return nil, err
	}
	w.scan(rows, true)
	return w, nil
}

// start — опрос в фоне до stop.
func (w *connWatch) start(every time.Duration) {
	w.every.Store(int64(every))
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stopc:
				return
			case <-time.After(time.Duration(w.every.Load())):
			}
			if rows, err := w.table(); err == nil {
				w.scan(rows, false)
			}
		}
	}()
}

func (w *connWatch) setEvery(d time.Duration) { w.every.Store(int64(d)) }

// stop — опрос завершён (повторный вызов ничего не делает).
func (w *connWatch) stop() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		close(w.stopc)
		<-w.done
	})
}

func (w *connWatch) scan(rows []osw.Conn, base bool) {
	t := w.now()
	var tls []time.Time
	w.mu.Lock()
	for _, c := range rows {
		tgt := w.target[c.Remote]
		if (!tgt && !w.others[c.Remote]) || c.PID == w.self || c.State == osw.TCPListen {
			continue
		}
		k := connKey{c.Local, c.Remote}
		s := w.conns[k]
		if s == nil {
			if c.PID == 0 || c.State == osw.TCPClosed || c.State == osw.TCPDeleteTCB {
				continue
			}
			s = &seenConn{target: tgt, open: base && c.State.Handshaked()}
			w.conns[k] = s
		}
		switch {
		case c.State == osw.TCPSynSent:
			if s.synFrom.IsZero() {
				s.synFrom = t
			}
			s.synFor = t.Sub(s.synFrom)
		case c.State.Handshaked() && !s.est:
			s.est = true
			if !s.open && s.target {
				tls = append(tls, t)
			}
		}
	}
	f := w.onTLS
	w.mu.Unlock()
	if f != nil {
		for _, x := range tls {
			f(x)
		}
	}
}

// stats — итог наблюдения на сейчас.
func (w *connWatch) stats() connStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	var s connStats
	for _, c := range w.conns {
		switch {
		case !c.target:
			if !c.open {
				s.Other++
			}
			continue
		case c.open:
			s.Before++
			s.Established++
			continue
		}
		s.New++
		if c.est {
			s.Established++
			s.TLS++
		} else if !c.synFrom.IsZero() {
			s.SynOnly++
		}
		if ms := int(c.synFor.Milliseconds()); ms > s.SynMs {
			s.SynMs = ms
		}
	}
	return s
}

// endpoint — адрес и порт профиля, если адрес — IP (имя без DNS не сопоставить).
func endpoint(p *profile.Profile) (netip.AddrPort, bool) {
	a, err := netip.ParseAddr(strings.Trim(p.Address, "[]"))
	if err != nil || p.Port <= 0 || p.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(p.Port)), true
}

// byConnections — профиль клиента, с сервером которого клиент сейчас соединён или соединяется
// (SYN_SENT, ESTABLISHED): то, что клиент делает на деле, точнее «первого VLESS + REALITY
// активного профиля». Только когда такой сервер один; несколько (URL-тест всех серверов
// подписки) или ни одного — nil, выбор как раньше.
func (r *run) byConnections(list []*profile.Profile) *profile.Profile {
	if r.e.Conns == nil {
		return nil
	}
	rows, err := r.e.Conns()
	if err != nil {
		return nil
	}
	self := os.Getpid()
	live := map[netip.AddrPort]bool{}
	for _, c := range rows {
		if c.PID != 0 && c.PID != self && (c.State == osw.TCPSynSent || c.State == osw.TCPEstablished) {
			live[c.Remote] = true
		}
	}
	var pick *profile.Profile
	var at netip.AddrPort
	for _, p := range list {
		ep, ok := endpoint(p)
		if !ok || !p.IsRealityVLESS() || !live[ep] {
			continue
		}
		switch {
		case pick == nil:
			pick, at = p, ep
		case ep != at:
			return nil // несколько серверов сразу
		case p.Active && !pick.Active:
			pick = p
		}
	}
	return pick
}

// watchClient — начать наблюдение за соединениями клиента с сервером профиля перед запросом
// через клиент (C10). nil — таблицы нет (не Windows) или адрес сервера не узнать.
func (r *run) watchClient(ctx context.Context) *connWatch {
	if r.e.Conns == nil || r.prof == nil {
		return nil
	}
	var target []netip.AddrPort
	if ep, ok := endpoint(r.prof); ok {
		target = append(target, ep)
	} else if ips, err := netprobe.LookupHost(ctx, r.res, r.prof.Address); err == nil {
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				target = append(target, netip.AddrPortFrom(a.Unmap(), uint16(r.prof.Port)))
			}
		}
	}
	if len(target) == 0 {
		return nil
	}
	var others []netip.AddrPort
	if r.active != nil {
		for _, p := range r.active.ps {
			if ep, ok := endpoint(p); ok && p != r.prof && p.IsRealityVLESS() {
				others = append(others, ep)
			}
		}
	}
	w, err := newConnWatch(r.e.Conns, target, others, r.now)
	if err != nil {
		return nil
	}
	w.onTLS = r.serverBudget().Observe
	w.start(connsFast)
	return w
}

// connEvidence — C11 по итогам запроса через клиент.
func (r *run) connEvidence(w *connWatch, c10 netprobe.ClientResult, secs int) {
	const title = "Соединения клиента с сервером"
	name := r.sess.ClientName
	if name == "" {
		name = "Клиент"
	}
	skip := func(why, note string) {
		r.put(evidence.Evidence{ID: "C11", Source: evidence.FromOS, Reliability: evidence.High, Facts: map[string]any{}, Skipped: why,
			Summary: "Не учтены: " + why})
		r.step(1, "C11", title, "skip", note)
	}
	if _, _, loop := r.route(w.addr.String()); loop {
		skip("маршрут к серверу уходит в чужой туннель — соединение в таблице не значит, что пакеты дошли до сервера", "маршрут к серверу — в чужой туннель")
		return
	}
	if r.active != nil && r.active.d.Detour {
		skip("клиент ведёт соединение с сервером внутри другого тоннеля (WARP) — в таблице TCP его не видно", "соединение с сервером — внутри WARP")
		return
	}
	s := w.stats()
	o := s.outcome()
	f := map[string]any{"outcome": o, "new": s.New, "before": s.Before, "established": s.Established, "syn_only": s.SynOnly,
		"syn_ms": s.SynMs, "tls": s.TLS, "other": s.Other, "secs": secs}
	var sum, note, st string
	switch o {
	case "none":
		sum = name + ": за время запроса через клиент он не открыл ни одного соединения с сервером профиля — до сервера запрос не дошёл"
		if s.Other > 0 {
			sum += fmt.Sprintf("; с серверами других своих профилей — %d", s.Other)
		}
		note, st = "к серверу не шлёт", "fail"
	case "syn":
		sum = fmt.Sprintf("%s шлёт к серверу SYN (попыток: %d), ответа нет: TCP не устанавливается", name, s.SynOnly)
		if s.SynMs >= 1000 {
			sum += fmt.Sprintf(" — SYN-ACK ждал до %.0f с", float64(s.SynMs)/1000)
		}
		note, st = "шлёт SYN — ответа нет", "warn"
	default:
		sum = fmt.Sprintf("%s: TCP с сервером есть (соединений: открытых до запроса %d, новых %d)", name, s.Before, s.New)
		if c10.Outcome != "ok" {
			sum += " — а запрос не прошёл: сбой после TCP"
		}
		note, st = "TCP с сервером есть", "ok"
	}
	if s.TLS >= 4 {
		sum += fmt.Sprintf("; новых TLS к серверу за запрос — %d: больше 3 в минуту — признак для «заморозки по отпечатку»", s.TLS)
	}
	r.put(evidence.Evidence{ID: "C11", Source: evidence.FromOS, Reliability: evidence.High, Facts: f, Summary: sum})
	r.step(1, "C11", title, st, note)
}

// serverBudget — бюджет сервера профиля на сеанс: создаётся при первом обращении (C11 или фаза
// 2), расход сеанса считается от этого момента.
func (r *run) serverBudget() *netprobe.Budget {
	r.mu.Lock()
	b, fresh := r.budget, false
	if b == nil {
		b, fresh = r.e.Budget(r.prof.ServerKey()), true
		r.budget, r.budgetStart = b, b.Usage()
	}
	r.mu.Unlock()
	if fresh && r.h.Budget != nil {
		b.OnChange(r.h.Budget)
		r.h.Budget(b.Usage())
	}
	return b
}
