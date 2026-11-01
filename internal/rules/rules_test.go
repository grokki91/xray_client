package rules

import (
	"strings"
	"testing"

	"github.com/grokki91/xray_client/internal/evidence"
)

func ev(id string, kv ...any) evidence.Evidence {
	f := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		f[kv[i].(string)] = kv[i+1]
	}
	return evidence.Evidence{ID: id, Facts: f, Reliability: evidence.High}
}

// Базовая картина: интернет есть, профиль найден, маска по своему адресу открывается.
func base() []evidence.Evidence {
	return []evidence.Evidence{
		ev("N1", "ok", true, "hosts_ok", 4),
		ev("N2", "ru_ok", true, "foreign_ok", true),
		ev("N4", "ok", true),
		ev("C3", "found", true, "issues", []string{}, "transport", "xhttp"),
	}
}

func hiddify() evidence.Evidence {
	return ev("CX", "client", "hiddify", "client_name", "Hiddify 4.1.2", "core", "hiddify-sing-box",
		"core_family", "sing-box", "core_mlkem", false, "fp", "chrome", "fp_mlkem", false, "tun", false)
}

func v2rayn(fp string, fpMlkem bool) evidence.Evidence {
	return ev("CX", "client", "v2rayn", "client_name", "v2rayN 7.25", "core", "Xray 26.7.28", "core_family", "xray",
		"core_mlkem", true, "fp", fp, "fp_mlkem", fpMlkem, "tun", false)
}

func TestScenarios(t *testing.T) {
	e, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	type sc struct {
		name  string
		evs   []evidence.Evidence
		code  string
		level Level
	}
	with := func(extra ...evidence.Evidence) []evidence.Evidence { return append(base(), extra...) }
	cases := []sc{
		// §1.2 строка 1 — клиент не поднял ядро.
		{"ядро клиента упало", with(hiddify(), ev("C6", "core_failed", 2), ev("P3", "outcome", "ok")), "client.service.down", Likely},
		// Первый кейс MVP: Hiddify 4.1.x без сервера.
		{"hiddify без mlkem, эталон прошёл", with(hiddify(), ev("P1", "outcome", "ok"), ev("P2", "outcome", "mask_cert"),
			ev("P3", "outcome", "ok", "freeze", "none")), "client.core.mlkem", Likely},
		{"hiddify без mlkem, эталон без mlkem отвергнут", with(hiddify(), ev("P2", "outcome", "mask_cert"),
			ev("P3", "outcome", "ok"), ev("P3m", "outcome", "real_cert")), "client.core.mlkem", Confirmed},
		{"hiddify, окно сервера rd=mlkem", with(hiddify(), ev("S3", "rd_r", "mlkem", "ssh", true, "own", true)), "client.core.mlkem", Confirmed},
		{"hiddify, сервер старый — mlkem исключён", with(hiddify(), ev("P3", "outcome", "ok"), ev("P3m", "outcome", "ok")), "ok", Likely},
		{"только таблица версий", with(hiddify()), "unknown.need_window", None},
		// v2rayN на Xray: всё работает.
		{"v2rayn chrome работает", with(v2rayn("chrome", true), ev("P3", "outcome", "ok")), "ok", Likely},
		{"v2rayn fp=edge", with(v2rayn("edge", false), ev("P3", "outcome", "ok"), ev("P3m", "outcome", "real_cert")), "profile.fp", Confirmed},
		{"пустой fp", with(v2rayn("", false), ev("C3", "found", true, "issues", []string{"fp.empty"})), "profile.fp", Likely},
		// Строка 2 — профиль.
		{"pbk испорчен", with(v2rayn("chrome", true), ev("C3", "found", true, "issues", []string{"pbk.format"})), "profile.pbk", Likely},
		{"pbk не совпал с сервером", with(v2rayn("chrome", true), ev("S1", "ok", true, "match_pbk", false, "mlkem_rule", true)), "profile.pbk", Confirmed},
		{"эталон получил маску", with(v2rayn("chrome", true), ev("P2", "outcome", "mask_cert"), ev("P3", "outcome", "real_cert")), "profile.reality", Likely},
		{"сервер закрыл после рукопожатия", with(v2rayn("chrome", true), ev("P3", "outcome", "closed_after_handshake")), "profile.user", Likely},
		{"профиля нет", []evidence.Evidence{ev("N1", "ok", true), ev("C3", "found", false)}, "profile.missing", Likely},
		// Строка 3 — путь.
		{"SYN режется дважды", with(v2rayn("chrome", true), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout")), "path.ip.unreachable", Likely},
		{"SYN режется, из другой сети ок", with(v2rayn("chrome", true), ev("P1", "outcome", "timeout"), ev("P5", "p1", "ok")), "path.ip.unreachable", Confirmed},
		{"одна попытка — только возможно", with(v2rayn("chrome", true), ev("P1", "outcome", "timeout")), "unknown.need_window", None},
		{"белый список", append([]evidence.Evidence{ev("N1", "ok", true), ev("N2", "ru_ok", true, "foreign_ok", false),
			ev("C3", "found", true)}, v2rayn("chrome", true), ev("P1", "outcome", "timeout")), "path.whitelist", Likely},
		// Обязательный негатив §12.1: таймаут без интернета — не блокировка.
		{"таймаут без интернета", []evidence.Evidence{ev("N1", "ok", false, "hosts_ok", 0), ev("N4", "ok", false),
			ev("C3", "found", true), v2rayn("chrome", true), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout")}, "lan.noinet", Confirmed},
		// Строка 5 — ClientHello режется.
		{"hello режется", with(v2rayn("chrome", true), ev("P1", "outcome", "ok"), ev("P2", "outcome", "hello_timeout"),
			ev("P4", "tls", "hello_timeout"), ev("P3", "outcome", "handshake_timeout")), "path.hello", Likely},
		{"hello режется, сервер видит tcp", with(v2rayn("chrome", true), ev("P1", "outcome", "ok"), ev("P2", "outcome", "hello_timeout"),
			ev("S3", "stage", "tcp", "ssh", true)), "path.hello", Confirmed},
		// Строка 7 — заморозка.
		{"заморозка 10–32 КБ", with(v2rayn("chrome", true), ev("P2", "outcome", "mask_cert"), ev("P3", "outcome", "freeze", "freeze", "f16")), "path.freeze.f16", Likely},
		{"заморозка post подтверждена окном", with(v2rayn("chrome", true), ev("P3", "outcome", "freeze", "freeze", "post"),
			ev("S3", "after", "post", "ssh", true)), "path.freeze.post", Confirmed},
		// Строка 8 — за тоннелем.
		{"тест задержки клиента", with(v2rayn("chrome", true), ev("P3", "outcome", "ok"), ev("B3", "tunnel_ok", false)), "beyond.latency_url", Likely},
		// Сервер.
		{"сервер не слушает (самопроверка)", with(hiddify(), ev("S1", "ok", true, "self_r", "fail", "self_at", "listen")), "server.listen", Confirmed},
		{"RST на порт", with(v2rayn("chrome", true), ev("P1", "outcome", "refused")), "server.listen", Likely},
		{"UFW закрыт", with(v2rayn("chrome", true), ev("S1", "ok", true, "ufw", "closed")), "server.firewall", Confirmed},
		// Состояние клиента (C10 — запрос через его локальный прокси). Скриншоты 2026-11-01.
		{"скрин 1: Hiddify подключён, трафик идёт", with(hiddify(), ev("C10", "listening", true, "outcome", "ok"), ev("P1", "outcome", "ok"),
			ev("P3", "outcome", "ok"), ev("P3m", "outcome", "ok")), "ok.client", Confirmed},
		{"скрин 2: Hiddify не подключён, пробы к серверу съел лимит", with(hiddify(), ev("C10", "listening", false, "outcome", "not_listening"),
			ev("P1", "outcome", "budget")), "unknown.budget", None},
		{"Hiddify не подключён, сервер и профиль в порядке", with(hiddify(), ev("C10", "listening", false, "outcome", "not_listening"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "ok"), ev("P3m", "outcome", "ok")), "ok.idle", Likely},
		{"скрин 3: Hiddify «Подключение…», сервер требует X25519MLKEM768", with(hiddify(), ev("C10", "listening", true, "outcome", "fail", "error", "timeout"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "ok"), ev("P3m", "outcome", "real_cert")), "client.core.mlkem", Confirmed},
		{"скрин 4: TCP до сервера нет ни сразу, ни через 30 с", with(hiddify(), ev("C10", "listening", true, "outcome", "fail", "error", "timeout"),
			ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout", "tls", "tcp_timeout")), "path.ip.unreachable", Likely},
		{"клиент запущен, трафик не идёт, эталон прошёл", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "fail"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "ok")), "client.tunnel", Confirmed},
		{"клиент не работает, эталон получил маску — виноват профиль, не клиент", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "fail"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "real_cert"), ev("P2", "outcome", "mask_cert")), "profile.reality", Likely},
		{"клиент работает, а индикатор задержки — таймаут", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "ok"),
			ev("P3", "outcome", "ok"), ev("B3", "tunnel_ok", false)), "beyond.latency_url", Likely},
		{"клиент работает — таблица версий не спорит с фактом", with(hiddify(), ev("C10", "listening", true, "outcome", "ok")), "ok.client", Confirmed},
		// ОС.
		{"системный прокси в никуда", with(v2rayn("chrome", true), ev("W6", "system_proxy", true, "proxy_local", true, "proxy_listening", false)), "os.proxy.dead", Likely},
	}
	for _, c := range cases {
		v := e.Decide(evidence.FromList(c.evs))
		if v.Main.Code != c.code || v.Main.Level != c.level {
			t.Errorf("%s: вердикт %s/%s, ожидалось %s/%s (возможно: %v)", c.name, v.Main.Code, v.Main.Level, c.code, c.level, codes(v.Possible))
		}
		if strings.Contains(v.Main.Title, "{") || strings.Contains(strings.Join(v.Main.Actions, " "), "{") {
			t.Errorf("%s: неподставленный шаблон в %q", c.name, v.Main.Title)
		}
		if strings.HasPrefix(v.Main.Code, "path.") && v.Main.Level == Likely && v.Main.Alternative == "" {
			t.Errorf("%s: «вероятно» о пути без альтернативы", c.name)
		}
	}
}

func codes(rs []Result) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Code+"/"+string(r.Level))
	}
	return out
}

func TestMainCauseKeepsOthers(t *testing.T) {
	e, _ := Load()
	set := evidence.FromList(append(base(), hiddify(), ev("P3", "outcome", "ok"), ev("C9", "exposed", true, "ports", []string{"12334"}),
		ev("S1", "ok", true, "mlkem_rule", true, "xray_version", "26.10.21")))
	v := e.Decide(set)
	if v.Main.Code != "client.core.mlkem" {
		t.Fatalf("main %s", v.Main.Code)
	}
	var f []string
	for _, x := range v.Findings {
		f = append(f, x.Code)
	}
	if !strings.Contains(strings.Join(f, ","), "client.socks.exposed") || !strings.Contains(strings.Join(f, ","), "server.version") {
		t.Fatalf("находки: %v", f)
	}
	if len(v.RuledOut) == 0 || !strings.Contains(v.RuledOut[0].Title, "эталонное ядро") {
		t.Fatalf("исключено: %+v", v.RuledOut)
	}
	if !strings.Contains(v.Main.Title, "Hiddify 4.1.2") || !strings.Contains(v.Main.Actions[0], "v2rayN") {
		t.Fatalf("шаблон: %q / %q", v.Main.Title, v.Main.Actions)
	}
}

func TestCompat(t *testing.T) {
	e, _ := Load()
	c := e.Compat
	if r, ok := c.Hiddify("4.1.2"); !ok || r.Mlkem == nil || *r.Mlkem || r.CoreFamily != "sing-box" {
		t.Fatalf("hiddify 4.1.2: %+v", r)
	}
	if r, ok := c.Hiddify("5.0.1"); !ok || r.Mlkem != nil {
		t.Fatalf("hiddify 5: %+v", r)
	}
	for _, x := range []struct {
		ver, fp   string
		mlkem, kn bool
	}{
		{"26.7.28", "chrome", true, true}, {"25.7.25", "chrome", false, true}, {"26.3.26", "firefox", false, true},
		{"26.3.27", "firefox", true, true}, {"26.10.21", "edge", false, true}, {"26.10.21", "random", false, false},
		{"", "chrome", false, false}, {"26.10.21", "", false, true},
	} {
		m, k := c.XrayFPMlkem(x.ver, x.fp)
		if m != x.mlkem || k != x.kn {
			t.Errorf("%s %s: %v %v", x.ver, x.fp, m, k)
		}
	}
	if !c.MlkemRule("Xray 26.10.21 (Xray, Penetrates Everything.)") || c.MlkemRule("26.7.28") {
		t.Fatal("правило сервера")
	}
	if !c.Bug6797("26.10.21") || c.Bug6797("26.7.28") {
		t.Fatal("6797")
	}
}

func TestEveryCodeHasScenarioText(t *testing.T) {
	e, _ := Load()
	for _, h := range e.Hyps {
		if h.Why == "" && h.Kind != "finding" {
			t.Errorf("%s без why", h.Code)
		}
		if h.Kind == "" && len(h.Actions) == 0 {
			t.Errorf("%s без actions", h.Code)
		}
	}
}

// Скрин 3: проверка через сам клиент — в уликах подтверждённой причины.
func TestClientTunnelInEvidence(t *testing.T) {
	e, _ := Load()
	v := e.Decide(evidence.FromList(append(base(), hiddify(), ev("C10", "listening", true, "outcome", "fail"),
		ev("P1", "outcome", "ok"), ev("P3", "outcome", "ok"), ev("P3m", "outcome", "real_cert"))))
	if !strings.Contains(","+strings.Join(v.Main.Evidence, ",")+",", ",C10,") {
		t.Fatalf("улики: %v", v.Main.Evidence)
	}
	for _, r := range v.Also {
		if r.Code == "client.tunnel" {
			t.Fatal("client.tunnel дублирует client.core.mlkem")
		}
	}
}
