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
		// Профиль цел, но не VLESS + REALITY: «не поддерживается», а не «испорчен при импорте».
		{"VLESS+TLS из настроек", []evidence.Evidence{ev("N1", "ok", true), ev("N4", "ok", true), ev("CX", "client", "uri"),
			ev("C3", "found", true, "source", "uri", "security", "tls", "kind", "VLESS + TLS", "issues", []string{"security.not_reality"}),
			ev("P1", "outcome", "ok"), ev("P2", "outcome", "real_cert")}, "profile.unsupported", Likely},
		{"не VLESS", with(ev("C3", "found", true, "kind", "VMESS + REALITY", "issues", []string{"protocol.not_vless"})), "profile.unsupported", Likely},
		{"REALITY-профиль с испорченным адресом", with(v2rayn("chrome", true), ev("C3", "found", true, "issues", []string{"addr.format"})), "profile.import", Likely},
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
		// Скрин 5 (2026-11-01): TCP до порта нет ни сразу, ни через 30 с, а SSH того же адреса открыт —
		// адрес не заблокирован, молчит только порт: сначала сервер, а не «бан IP».
		{"скрин 5: порт молчит, SSH того же адреса открыт", with(hiddify(), ev("C10", "listening", true, "outcome", "fail", "error", "eof"),
			ev("P1", "outcome", "timeout"), ev("P6", "outcome", "ok", "reach", true, "banner", true, "known", false),
			ev("P4", "tcp", "timeout", "tls", "tcp_timeout")), "server.port.drop", Likely},
		{"порт молчит, мост дошёл до сервера (xm без bridge)", with(hiddify(), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout"),
			ev("S0", "error", "no_bridge", "ssh", "ok")), "server.port.drop", Likely},
		{"порт молчит, SSH открыт, из другой сети тоже молчит", with(hiddify(), ev("P1", "outcome", "timeout"),
			ev("P6", "outcome", "ok", "reach", true), ev("P5", "p1", "timeout")), "server.port.drop", Confirmed},
		{"порт молчит, SSH открыт, из другой сети порт открыт", with(hiddify(), ev("P1", "outcome", "timeout"),
			ev("P6", "outcome", "ok", "reach", true), ev("P4", "tcp", "timeout"), ev("P5", "p1", "ok")), "path.port", Confirmed},
		{"молчат и порт, и SSH из алиаса", with(hiddify(), ev("P1", "outcome", "timeout"),
			ev("P6", "outcome", "timeout", "reach", false, "known", true)), "path.ip.unreachable", Likely},
		{"порт 22 молчит, SSH-порт неизвестен — не довод", with(hiddify(), ev("P1", "outcome", "timeout"),
			ev("P6", "outcome", "timeout", "reach", false, "known", false)), "unknown.need_window", None},
		// Скрин 6 (2026-11-02): порт и SSH молчат и из другой сети (другой город) — провайдер ни при
		// чём; «проверьте из другой сети» больше не совет, а сделанная проверка.
		{"скрин 6: порт и SSH молчат из двух сетей", with(hiddify(), ev("C10", "listening", true, "outcome", "fail", "error", "eof"),
			ev("P1", "outcome", "timeout"), ev("P6", "outcome", "timeout", "reach", false, "known", true),
			ev("P4", "tcp", "timeout", "tls", "tcp_timeout"), ev("P5", "p1", "timeout", "p6", "silent", "age_min", 2)), "server.unreachable", Likely},
		{"порт молчит из двух сетей, SSH не проверен", with(hiddify(), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout"),
			ev("P5", "p1", "timeout", "age_min", 40)), "server.unreachable", Likely},
		{"порт молчит из двух сетей, в той сети SSH отвечал", with(hiddify(), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout"),
			ev("P5", "p1", "timeout", "p6", "reach")), "server.port.drop", Confirmed},
		{"hello режется, SNI маски режется и на чужом адресе", append([]evidence.Evidence{ev("N1", "ok", true), ev("N2", "ru_ok", true, "foreign_ok", true),
			ev("N4", "ok", false, "stage", "hello_timeout"), ev("N5", "passed", false), ev("C3", "found", true)}, v2rayn("chrome", true),
			ev("P1", "outcome", "ok"), ev("P2", "outcome", "hello_timeout")), "path.hello", Likely},
		{"клиент запущен, трафик не идёт, эталон прошёл", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "fail"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "ok")), "client.tunnel", Confirmed},
		{"клиент не работает, эталон получил маску — виноват профиль, не клиент", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "fail"),
			ev("P1", "outcome", "ok"), ev("P3", "outcome", "real_cert"), ev("P2", "outcome", "mask_cert")), "profile.reality", Likely},
		{"клиент работает, а индикатор задержки — таймаут", with(v2rayn("chrome", true), ev("C10", "listening", true, "outcome", "ok"),
			ev("P3", "outcome", "ok"), ev("B3", "tunnel_ok", false)), "beyond.latency_url", Likely},
		{"клиент работает — таблица версий не спорит с фактом", with(hiddify(), ev("C10", "listening", true, "outcome", "ok")), "ok.client", Confirmed},
		{"Hiddify «Подключение…», а трафик через него идёт: не открывается URL проверки", with(hiddify(),
			ev("C10", "listening", true, "outcome", "ok", "test_url_ok", false)), "beyond.latency_url", Likely},
		{"Hiddify подключён, URL проверки открывается", with(hiddify(), ev("C10", "listening", true, "outcome", "ok", "test_url_ok", true)), "ok.client", Confirmed},
		// ОС.
		{"системный прокси в никуда", with(v2rayn("chrome", true), ev("W6", "system_proxy", true, "proxy_local", true, "proxy_listening", false)), "os.proxy.dead", Likely},
		// Скрин 7 (2026-11-02): Hiddify «Подключение…», порт сервера открыт, а и эталон с
		// X25519MLKEM768, и обычный TLS с SNI профиля получили сертификат другого сайта — было
		// «Без окна сервера причину не назвать», хотя профиль не от сервера по этому адресу.
		{"скрин 7: чужой сертификат на адресе сервера, эталон отвергнут", with(append(screen7(), hiddify())...), "profile.stale", Likely},
		{"скрин 7 и SSH сервера молчит", with(append(screen7(), hiddify(), ev("P6", "outcome", "timeout", "reach", false, "known", true))...), "profile.stale", Likely},
		{"чужой сертификат, маску по её адресу не проверить", append([]evidence.Evidence{ev("N1", "ok", true), ev("N2", "ru_ok", true, "foreign_ok", true),
			ev("N4", "ok", false, "stage", "dns"), ev("C3", "found", true)}, append(screen7(), hiddify())...), "unknown.need_window", None},
		{"чужой сертификат, а мост говорит: SNI тот же", with(append(screen7(), hiddify(), ev("S1", "ok", true, "match_sni", true, "match_pbk", false))...), "profile.pbk", Confirmed},
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

// Маска молчит после ClientHello: тот же SNI на чужом адресе тоже молчит — находка «режут SNI»;
// отвечает — режут адрес маски, на REALITY это не влияет, находки нет.
func TestSNIFinding(t *testing.T) {
	e, _ := Load()
	find := func(evs ...evidence.Evidence) bool {
		set := append([]evidence.Evidence{ev("N1", "ok", true), ev("N2", "ru_ok", true, "foreign_ok", true), ev("C3", "found", true),
			ev("N4", "ok", false, "stage", "hello_timeout"), hiddify(), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout")}, evs...)
		for _, f := range e.Decide(evidence.FromList(set)).Findings {
			if f.Code == "path.sni" {
				return true
			}
		}
		return false
	}
	if !find(ev("N5", "passed", false)) {
		t.Fatal("SNI режется и на чужом адресе — находка path.sni")
	}
	if find(ev("N5", "passed", true)) || find() {
		t.Fatal("SNI на чужом адресе проходит или не проверен — находки нет")
	}
}

// Из другой сети тоже тишина: «режет путь этой сети» не остаётся ни в «также найдено», ни в
// «возможно», а совет «проверить из другой сети» не повторяется — проверка уже сделана.
func TestOtherNetworkSilentToo(t *testing.T) {
	e, _ := Load()
	v := e.Decide(evidence.FromList(append(base(), hiddify(), ev("P1", "outcome", "timeout"), ev("P4", "tcp", "timeout"),
		ev("P6", "outcome", "timeout", "reach", false, "known", true), ev("P5", "p1", "timeout", "age_min", 2))))
	if v.Main.Code != "server.unreachable" || v.Main.Alternative == "" || !strings.Contains(","+strings.Join(v.Main.Evidence, ",")+",", ",P6,") {
		t.Fatalf("вердикт %s: %v", v.Main.Code, v.Main.Evidence)
	}
	for _, r := range append(append([]Result{}, v.Also...), v.Possible...) {
		if r.Code == "path.ip.unreachable" {
			t.Fatalf("path.ip.unreachable рядом с server.unreachable: %s", r.Level)
		}
	}
	for _, c := range v.NextChecks {
		if c.ID == "P5" {
			t.Fatal("P5 предложена повторно")
		}
	}
	for _, a := range v.Main.Actions {
		if strings.Contains(a, "из другой сети") {
			t.Fatalf("совет про другую сеть после P5: %q", a)
		}
	}
}

// screen7 — улики скрина 7: Hiddify запущен и пишет «Подключение…», TCP до порта сервера есть,
// эталон (fp chrome) получил сертификат маски, обычный TLS с SNI профиля — сертификат не того
// сайта, маска по своему адресу открывается (N4 — в base()).
func screen7() []evidence.Evidence {
	return []evidence.Evidence{
		ev("C10", "listening", true, "outcome", "fail", "error", "eof", "shows", "connecting"),
		ev("P1", "outcome", "ok", "ms", 58),
		ev("P3", "outcome", "real_cert"),
		ev("P2", "outcome", "other_cert", "cert_valid", false),
	}
}

// Скрин 7: главная причина — профиль не от сервера по этому адресу; «профиль не принят REALITY»
// её не дублирует, Hiddify без X25519MLKEM768 — «возможно» (всплывёт после замены профиля), а
// когда SSH сервера молчит, мост и окно сервера не советуются — вместо них веб-консоль (K1).
func TestScreen7(t *testing.T) {
	e, _ := Load()
	v := e.Decide(evidence.FromList(append(append(base(), hiddify()), screen7()...)))
	if v.Main.Code != "profile.stale" || v.Main.Alternative == "" || !strings.Contains(strings.Join(v.Main.Evidence, ","), "P2") {
		t.Fatalf("вердикт %s/%s %v", v.Main.Code, v.Main.Level, v.Main.Evidence)
	}
	var possible []string
	for _, r := range v.Possible {
		possible = append(possible, r.Code)
	}
	if strings.Contains(strings.Join(possible, ","), "profile.reality") || !strings.Contains(strings.Join(possible, ","), "client.core.mlkem") {
		t.Fatalf("возможные: %v", possible)
	}
	ids := func(cs []Check) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(v.NextChecks); got != "S1,S3" {
		t.Fatalf("проверки без SSH-пробы: %s", got)
	}
	for _, silent := range []evidence.Evidence{
		ev("P6", "outcome", "timeout", "reach", false, "known", true),
		ev("S0", "error", "unreachable", "ssh", "unreachable"),
	} {
		v = e.Decide(evidence.FromList(append(append(base(), hiddify(), silent), screen7()...)))
		if got := ids(v.NextChecks); got != "K1" || ids(v.Main.NextChecks) != "K1" {
			t.Fatalf("%s: SSH молчит — проверки %s / %s", silent.ID, got, ids(v.Main.NextChecks))
		}
		found := false
		for _, f := range v.Findings {
			found = found || f.Code == "server.ssh.silent"
		}
		if !found {
			t.Fatalf("%s: нет находки server.ssh.silent", silent.ID)
		}
	}
	// Порт 22 молчит, а свой порт SSH неизвестен — не довод: мост и окно остаются.
	v = e.Decide(evidence.FromList(append(append(base(), hiddify(), ev("P6", "outcome", "timeout", "reach", false, "known", false)), screen7()...)))
	if got := ids(v.NextChecks); got != "S1,S3" {
		t.Fatalf("порт SSH неизвестен — проверки %s", got)
	}
	for _, f := range v.Findings {
		if f.Code == "server.ssh.silent" {
			t.Fatal("находка по порту 22 без алиаса")
		}
	}
	// Без улик о SSH окно сервера в unknown не меняется, с молчащим SSH — веб-консоль.
	u := e.Decide(evidence.FromList(append(base(), hiddify(), ev("P1", "outcome", "ok"), ev("P6", "reach", false, "known", true))))
	if u.Main.Code != "unknown.need_window" || ids(u.Main.NextChecks) != "K1" {
		t.Fatalf("unknown при молчащем SSH: %s %s", u.Main.Code, ids(u.Main.NextChecks))
	}
}

func TestMissingTexts(t *testing.T) {
	e, _ := Load()
	for _, k := range []string{"ssh_port", "ssh_port22", "reference_off", "client_logs"} {
		if e.MissingText(k) == "" {
			t.Errorf("нет текста missing.%s", k)
		}
	}
}

// Нестабильность во времени (решение 15): находки — только на уликах наблюдения. Серии сбоев в
// логах клиента при работающем сейчас тоннеле — «вероятно», совпадение с инцидентом журнала
// здоровья — «подтверждено»; сторона (сервер или путь) — только по журналу сервера, про путь —
// не выше «вероятно» и только при интернете (таймаут ≠ блокировка).
func TestInstabilityFindings(t *testing.T) {
	e, _ := Load()
	levels := func(evs ...evidence.Evidence) (string, map[string]Level) {
		v := e.Decide(evidence.FromList(append(append(base(), v2rayn("chrome", true)), evs...)))
		got := map[string]Level{}
		for _, f := range v.Findings {
			got[f.Code] = f.Level
		}
		return v.Main.Code, got
	}
	ok := ev("C10", "listening", true, "outcome", "ok")
	for _, c := range []struct {
		name string
		evs  []evidence.Evidence
		want map[string]Level
	}{
		{"одна серия, сейчас работает — мало", []evidence.Evidence{ok, ev("C6", "found", true, "episodes", 1, "recovered", 0)}, map[string]Level{}},
		{"одна серия, после неё работал", []evidence.Evidence{ev("C6", "found", true, "episodes", 1, "recovered", 1)},
			map[string]Level{"unstable.drops": Possible}},
		{"серии, сейчас работает", []evidence.Evidence{ok, ev("C6", "found", true, "episodes", 3, "recovered", 0)},
			map[string]Level{"unstable.drops": Likely}},
		{"серия совпала с заморозкой сервера", []evidence.Evidence{ok, ev("C6", "found", true, "episodes", 1),
			ev("S2", "ok", true, "overlap", 1, "overlap_freeze", 1, "overlap_server", 0)},
			map[string]Level{"unstable.drops": Confirmed, "path.freeze.episodes": Likely}},
		{"серия совпала со сбоем сервера", []evidence.Evidence{ev("P3", "outcome", "ok"), ev("C6", "found", true, "episodes", 2),
			ev("S2", "ok", true, "overlap", 1, "overlap_freeze", 1, "overlap_server", 1)},
			map[string]Level{"unstable.drops": Confirmed, "server.episodes": Likely}},
		{"только журнал сервера", []evidence.Evidence{ok, ev("S2", "ok", true, "day_server", 2, "day_freeze", 3)},
			map[string]Level{"server.episodes": Possible, "path.freeze.episodes": Possible}},
	} {
		main, got := levels(c.evs...)
		for _, code := range []string{"unstable.drops", "server.episodes", "path.freeze.episodes"} {
			if got[code] != c.want[code] {
				t.Errorf("%s: %s = %q, ожидалось %q", c.name, code, got[code], c.want[code])
			}
		}
		if c.evs[0].ID == "C10" && main != "ok.client" {
			t.Errorf("%s: находка не меняет итог «работает», а итог %s", c.name, main)
		}
	}
	// Без интернета заморозка по пути не поднимается даже при совпадении.
	v := e.Decide(evidence.FromList([]evidence.Evidence{ev("N1", "ok", false), ev("C3", "found", true), v2rayn("chrome", true),
		ev("C6", "found", true, "episodes", 2), ev("S2", "ok", true, "overlap", 1, "overlap_freeze", 1)}))
	for _, f := range v.Findings {
		if f.Code == "path.freeze.episodes" {
			t.Fatal("path.freeze.episodes без N1.ok")
		}
	}
	// Совет «журнал здоровья» — пока журнала нет или он выключен; с журналом — не повторяется.
	if !e.checkDone(evidence.FromList([]evidence.Evidence{ev("S2", "ok", true)}), "S2") ||
		e.checkDone(evidence.FromList([]evidence.Evidence{ev("S2", "ok", false)}), "S2") {
		t.Fatal("checkDone S2")
	}
}
