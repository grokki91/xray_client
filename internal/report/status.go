package report

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/rules"
)

// Status — итог одной строкой для крупного баннера: работает или нет, без чтения деталей.
type Status struct {
	Kind string `json:"kind"` // ok | problem | unknown | incomplete
	Head string `json:"head"` // «Всё работает», «Не работает: причина в клиенте», …
}

// Stage — звено цепочки «Интернет → Сервер → Профиль → Клиент»: где именно ломается.
type Stage struct {
	Key   string `json:"key"`   // net | server | profile | client
	Title string `json:"title"` // подпись звена
	State string `json:"state"` // ok | fail | warn | idle | skip
	Note  string `json:"note"`  // коротко, что видно
}

// Target — что именно диагностировалось. Только для окна (локально): имя профиля и адрес
// сервера в маске, как их показывает сам клиент (Hiddify: «203.*.*.7»). В текст отчёта,
// экспорт и открытый индекс истории не попадает.
type Target struct {
	Profile   string `json:"profile,omitempty"`
	Server    string `json:"server,omitempty"`
	Transport string `json:"transport,omitempty"`
	Source    string `json:"source,omitempty"`
	Client    string `json:"client,omitempty"`
	State     string `json:"state,omitempty"` // подключён | не подключён | подключается, трафик не идёт
}

var layerPhrase = map[string]string{
	"L0": "в клиенте", "L1": "в настройках Windows", "L2": "в локальной сети", "L3": "на пути до сервера",
	"L4": "на сервере", "L5": "в профиле", "L6": "за тоннелем",
}

func status(s *engine.SessionData, m rules.Result) Status {
	switch {
	case m.Kind == "ok" && m.Code == "ok.client":
		return Status{"ok", "Всё работает"}
	case m.Kind == "ok":
		return Status{"ok", "Сервер и профиль в порядке"}
	case m.Code == "lan.noinet" && m.Level.Rank() >= rules.Likely.Rank():
		return Status{"problem", "Не работает: нет интернета"}
	case m.Code == "profile.missing":
		return Status{"incomplete", "Проверять нечего: профиль не найден"}
	case m.Level.Rank() >= rules.Likely.Rank():
		if p := layerPhrase[m.Layer]; p != "" {
			return Status{"problem", "Не работает: причина " + p}
		}
		return Status{"problem", "Не работает"}
	case s.Cancelled:
		return Status{"incomplete", "Проверка остановлена"}
	case m.Code == "unknown.budget":
		return Status{"incomplete", "Проверка не завершена"}
	}
	return Status{"unknown", "Причина не найдена"}
}

func stages(s *engine.SessionData, m rules.Result) []Stage {
	set := evidence.FromList(s.Evidence)
	str := func(id, k string) string { return set.Get(id).Str(k) }
	num := func(id, k string) int { n, _ := set.Get(id).Num(k); return int(n) }

	net := Stage{Key: "net", Title: "Интернет", State: "skip", Note: "не проверялся"}
	if n1 := set.Get("N1"); n1 != nil {
		if n1.Bool("ok") {
			net.State, net.Note = "ok", "сайты открываются"
			if n := num("N1", "hosts"); n > 0 {
				net.Note += fmt.Sprintf(" (%d из %d)", num("N1", "hosts_ok"), n)
			}
		} else {
			net.State, net.Note = "fail", "сайты не открываются"
		}
	}

	srv := Stage{Key: "server", Title: "Сервер", State: "skip", Note: "не проверялся"}
	p3 := str("P3", "outcome")
	reached := p3 == "ok" || p3 == "real_cert" || p3 == "closed_after_handshake" || str("C10", "outcome") == "ok"
	switch p1 := str("P1", "outcome"); {
	case set.Get("C3") != nil && !set.Get("C3").Bool("found"):
		srv.Note = "нет профиля"
	case p1 == "" && reached:
		srv.State, srv.Note = "ok", "отвечает"
	case p1 == "":
	case p1 == "dns":
		srv.State, srv.Note = "fail", "имя сервера не резолвится"
	case p1 == "budget":
		srv.Note = "не проверен: лимит проб"
	case p1 == "refused":
		srv.State, srv.Note = "fail", "порт закрыт (RST)"
	case p1 != "ok":
		srv.State, srv.Note = "fail", "TCP не устанавливается"
		if str("P4", "tcp") == "timeout" {
			srv.Note += " (и через 30 с)"
		}
		// P6 — SSH-порт того же адреса: открыт — молчит только порт, нет — весь адрес.
		if p6 := set.Get("P6"); p6 != nil && (p6.Bool("reach") || p6.Bool("known")) {
			srv.Note = yes(p6.Bool("reach"), "порт молчит, SSH отвечает", "не отвечают ни порт, ни SSH")
		} else if str("S0", "ssh") == "ok" {
			srv.Note = "порт молчит, SSH отвечает"
		}
	case reached:
		srv.State, srv.Note = "ok", "отвечает"
		if ms := num("P1", "ms"); ms > 0 {
			srv.Note += fmt.Sprintf(" (TCP %d мс)", ms)
		}
	case p3 == "freeze":
		srv.State, srv.Note = "warn", "данные встают: "+freezeWords(str("P3", "freeze"))
	case str("P2", "outcome") == "mask_cert":
		srv.State, srv.Note = "ok", "отвечает сайтом-маской"
	case strings.HasSuffix(str("P2", "outcome"), "_after_hello") || str("P2", "outcome") == "hello_timeout":
		srv.State, srv.Note = "fail", "ClientHello не проходит"
	default:
		srv.State, srv.Note = "ok", fmt.Sprintf("TCP есть (%d мс)", num("P1", "ms"))
	}

	prof := Stage{Key: "profile", Title: "Профиль", State: "skip", Note: "не проверялся"}
	switch {
	case set.Get("C3") != nil && !set.Get("C3").Bool("found"):
		prof.State, prof.Note = "fail", "не найден"
	case p3 == "ok":
		prof.State, prof.Note = "ok", "сервер принял (эталон)"
	case str("C10", "outcome") == "ok":
		prof.State, prof.Note = "ok", "сервер принял (клиент)"
	case p3 == "real_cert":
		prof.State, prof.Note = "fail", "REALITY не принял"
	case p3 == "closed_after_handshake":
		prof.State, prof.Note = "fail", "UUID или путь не приняты"
	case p3 == "budget":
		prof.Note = "не проверен: лимит проб"
	case srv.State == "fail":
		prof.Note = "не проверить: нет связи с сервером"
	}
	if issues := str("C3", "issues_text"); issues != "" && prof.State != "fail" {
		prof.State, prof.Note = "warn", "ошибки в профиле"
	}

	cl := Stage{Key: "client", Title: "Клиент", State: "skip", Note: "не найден"}
	if cx := set.Get("CX"); cx != nil && cx.Str("client") != "uri" {
		cl.Title = clientShort(s)
		cl.Note = "не проверялся"
		switch str("C10", "outcome") {
		case "ok":
			cl.State, cl.Note = "ok", "подключён, трафик идёт"
		case "fail":
			cl.State, cl.Note = "fail", "подключается, трафик не идёт"
		case "freeze":
			cl.State, cl.Note = "warn", "подключён, загрузка встаёт"
		case "not_listening":
			cl.State, cl.Note = "idle", "не подключён"
		}
	}

	chain := []*Stage{&net, &srv, &prof, &cl}
	anchor := -1
	// Звено главной причины — красное, с её коротким названием.
	if m.Kind == "cause" && m.Level.Rank() >= rules.Likely.Rank() {
		var st *Stage
		switch m.Layer {
		case "L1", "L2":
			st = &net
		case "L3", "L4":
			st = &srv
		case "L5":
			st = &prof
		case "L0", "L6":
			st = &cl
		}
		if st != nil {
			short := m.Short
			// «Клиент: ядро без …» → «ядро без …»: звено и так подписано.
			if pre, rest, ok := strings.Cut(short, ": "); ok && len([]rune(pre)) <= 8 {
				short = rest
			}
			if st.State != "fail" || st.Key == "client" {
				st.Note = short
			}
			st.State = "fail"
			for i, c := range chain {
				if c == st {
					anchor = i
				}
			}
		}
	}
	if anchor < 0 {
		for i, c := range chain {
			if c.State == "fail" {
				anchor = i
				break
			}
		}
	}
	// Красное — только там, где причина: клиент без связи с сервером «не работает» как
	// следствие, а не как вторая поломка.
	for i := anchor + 1; anchor >= 0 && i < len(chain); i++ {
		if chain[i].State == "fail" {
			chain[i].State, chain[i].Note = "skip", chain[i].Note+" — следствие"
		}
	}
	return []Stage{net, srv, prof, cl}
}

func freezeWords(f string) string {
	switch f {
	case "post":
		return "сразу после рукопожатия"
	case "mid":
		return "на 1–10 КБ"
	case "f16":
		return "на 10–32 КБ"
	}
	return "после 32 КБ"
}

func clientShort(s *engine.SessionData) string {
	if s.ClientName != "" {
		return s.ClientName
	}
	return "Клиент"
}

func target(s *engine.SessionData) *Target {
	t := &Target{Client: s.ClientName, State: clientState(s)}
	if s.Profile != nil {
		t.Transport = strings.ToUpper(s.Profile.Transport) + " + " + strings.ToUpper(s.Profile.Security)
		switch s.Profile.Source {
		case "hiddify":
			t.Source = "профиль из Hiddify"
			if s.Profile.Active {
				t.Source = "активный профиль Hiddify"
			}
		case "v2rayn":
			t.Source = "профиль из v2rayN"
			if strings.Contains(s.Profile.Origin, "запущенное ядро") {
				t.Source = "профиль запущенного ядра v2rayN"
			} else if s.Profile.Active {
				t.Source = "выбранный профиль v2rayN"
			}
		case "uri":
			t.Source = "профиль из настроек xdiag"
		}
	}
	if sec := s.Secret; sec != nil {
		t.Server = MaskAddress(sec.Server)
		name := sec.Name
		// Имя профиля часто — адрес или домен сервера: в окне — в той же маске.
		for _, v := range []string{sec.Server, sec.SNI} {
			if len(v) >= 4 {
				name = strings.ReplaceAll(name, v, MaskAddress(v))
			}
		}
		t.Profile = name
	}
	if t.Client == "" && t.Profile == "" && t.Server == "" {
		return nil
	}
	return t
}

func clientState(s *engine.SessionData) string {
	set := evidence.FromList(s.Evidence)
	switch set.Get("C10").Str("outcome") {
	case "ok":
		return "подключён"
	case "fail":
		return "подключается, трафик не идёт"
	case "freeze":
		return "подключён, загрузка встаёт"
	case "not_listening":
		return "не подключён"
	}
	return ""
}

// MaskAddress — адрес сервера в маске для окна: IPv4 — первый и последний октет (как в
// Hiddify), IPv6 — первая и последняя группа, домен — первая буква и зона.
func MaskAddress(a string) string {
	a = strings.Trim(strings.TrimSpace(a), "[]")
	if a == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		if ip.Is4() {
			b := ip.As4()
			return fmt.Sprintf("%d.*.*.%d", b[0], b[3])
		}
		g := strings.Split(ip.String(), ":")
		return g[0] + ":…:" + g[len(g)-1]
	}
	labels := strings.Split(strings.Trim(a, "."), ".")
	first := []rune(labels[0])
	if len(first) == 0 {
		return "***"
	}
	if len(labels) < 2 {
		return string(first[0]) + "***"
	}
	return string(first[0]) + "***." + labels[len(labels)-1]
}

func problemText(s *engine.SessionData, m rules.Result) string {
	name := clientShort(s)
	if name == "Клиент" {
		name = "VPN-клиент"
	}
	switch m.Code {
	case "ok.client":
		return name + ": подключение через клиент работает"
	case "ok.idle":
		return name + " сейчас не подключён — проверены сервер и профиль"
	case "ok":
		return "Проверены сервер и профиль (эталонное ядро Xray)"
	case "lan.noinet":
		return "Нет интернета на этом ПК"
	case "profile.missing":
		return "Не найден профиль подключения"
	case "unknown.budget":
		return "Сервер не проверен: лимит проб к серверу"
	}
	if clientState(s) == "не подключён" {
		return name + " сейчас не подключён — проверено, пройдёт ли подключение"
	}
	return name + " не подключается к серверу («таймаут» или «Подключение…»)"
}

func yes(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
