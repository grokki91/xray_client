package report

import (
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/redact"
	"github.com/grokki91/xray_client/internal/rules"
)

func TestBuildAndExport(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true}, Summary: "Эталонные сайты: 4 из 4"},
		{ID: "CX", Facts: map[string]any{"client_name": "Hiddify 4.1.2", "core": "hiddify-sing-box", "core_mlkem": false}, Summary: "Hiddify 4.1.2: REALITY делает ядро hiddify-sing-box — X25519MLKEM768 не шлёт"},
		{ID: "P3", Facts: map[string]any{"outcome": "ok"}, Summary: "тоннель поднят"},
		{ID: "P3m", Facts: map[string]any{"outcome": "real_cert"}, Summary: "сервер отдал сайт-маску"},
		{ID: "C3", Facts: map[string]any{"found": true}, Summary: "Профиль: XHTTP+reality"},
	})
	s := &engine.SessionData{ID: "20261029-120000-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.2",
		Evidence: set.All(), Verdict: e.Decide(set), Secret: &engine.Secret{Server: "203.0.113.7", Port: 443, SNI: "www.example.com"},
		Notes: []string{"проба к 203.0.113.7 через www.example.com"}}
	v := Build(s)
	if v.Code != "client.core.mlkem" || v.Level != "подтверждено" || len(v.Evidence) == 0 || len(v.Actions) == 0 {
		t.Fatalf("%+v", v)
	}
	txt := Text(v)
	for _, want := range []string{"Итог: Не работает: причина в клиенте", "Проверено: Hiddify 4.1.2 не подключается", "Причина (подтверждено)",
		"✗ Hiddify 4.1.2 — ядро без X25519MLKEM768", "Что делать:", "Исключено:"} {
		if !strings.Contains(txt, want) {
			t.Errorf("нет %q в\n%s", want, txt)
		}
	}
	out, err := Export(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "203.0.113.7") || strings.Contains(string(out), "www.example.com") || strings.Contains(string(out), `"secret"`) {
		t.Fatalf("адрес в экспорте:\n%s", out)
	}
	if l := redact.Leaks(ExportText(s)); len(l) > 0 {
		t.Fatalf("утечки в тексте: %v", l)
	}
	withAddr, _ := Export(s, true)
	if !strings.Contains(string(withAddr), "203.0.113.7") {
		t.Fatal("галочка «включить адрес»")
	}
}

// Что проверялось — видно в окне (имя профиля, адрес в маске, как в самом клиенте), но не в
// тексте отчёта и не в экспорте.
func TestTargetWindowOnly(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true, "hosts_ok": 3.0, "hosts": 4.0}, Summary: "Эталонные сайты: 3 из 4"},
		{ID: "CX", Facts: map[string]any{"client": "hiddify", "client_name": "Hiddify 4.1.1", "core_mlkem": false}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "C10", Facts: map[string]any{"listening": true, "outcome": "ok", "ms_204": 120.0}, Summary: "Hiddify 4.1.1: трафик через клиент идёт"},
		{ID: "P1", Facts: map[string]any{"outcome": "ok", "ms": 72.0}},
		{ID: "P3", Facts: map[string]any{"outcome": "ok"}},
		{ID: "P3m", Facts: map[string]any{"outcome": "ok"}},
	})
	s := &engine.SessionData{ID: "20261101-120000-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.1",
		Evidence: set.All(), Verdict: e.Decide(set), Profile: &profile.Summary{Source: "hiddify", Active: true, Transport: "xhttp", Security: "reality"},
		Secret: &engine.Secret{Server: "203.0.113.7", Port: 443, SNI: "www.example.com", Name: "Польша 203.0.113.7"}}
	v := Build(s)
	if v.Status.Kind != "ok" || v.Status.Head != "Всё работает" || len(v.RuledOut) != 0 || len(v.Actions) != 0 {
		t.Fatalf("итог: %+v, исключено %d, действия %v", v.Status, len(v.RuledOut), v.Actions)
	}
	tg := v.Target
	if tg == nil || tg.Server != "203.*.*.7" || tg.Profile != "Польша 203.*.*.7" || tg.State != "подключён" ||
		tg.Source != "активный профиль Hiddify" || tg.Transport != "XHTTP + REALITY" {
		t.Fatalf("цель: %+v", tg)
	}
	for _, st := range v.Stages {
		if st.State != "ok" {
			t.Fatalf("звено %+v", st)
		}
	}
	txt := ExportText(s)
	if strings.Contains(txt, "203.0.113.7") || strings.Contains(txt, "Польша") || strings.Contains(txt, "203.*.*.7") {
		t.Fatalf("имя или адрес в тексте отчёта:\n%s", txt)
	}
	out, _ := Export(s, false)
	if strings.Contains(string(out), "Польша") || strings.Contains(string(out), "203.0.113.7") {
		t.Fatal("имя или адрес в экспорте")
	}
}

func TestMaskAddress(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.7": "203.*.*.7", "vpn.example.com": "v***.com", "[2001:db8::1]": "2001:…:1", "": ""} {
		if got := MaskAddress(in); got != want {
			t.Errorf("%q → %q, ожидалось %q", in, got, want)
		}
	}
}

// Скрин 5: порт молчит, SSH того же адреса открыт — звено «Сервер» так и подписано, причина —
// на сервере, а Hiddify без X25519MLKEM768 (возможно) — в «Также найдено»: всплывёт после порта.
func TestPortSilentSSHOpen(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true, "hosts_ok": 2.0, "hosts": 4.0}, Summary: "Эталонные сайты: 2 из 4"},
		{ID: "CX", Facts: map[string]any{"client": "hiddify", "client_name": "Hiddify 4.1.1", "core": "hiddify-sing-box", "core_mlkem": false}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "C10", Facts: map[string]any{"listening": true, "outcome": "fail", "error": "eof"}},
		{ID: "P1", Facts: map[string]any{"outcome": "timeout"}, Summary: "TCP до порта сервера: таймаут"},
		{ID: "P6", Facts: map[string]any{"outcome": "ok", "reach": true, "banner": true, "known": false}, Summary: "SSH-порт того же адреса открыт"},
		{ID: "P4", Facts: map[string]any{"tcp": "timeout"}, Summary: "Повтор: TCP — таймаут"},
	})
	s := &engine.SessionData{ID: "20261101-195000-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.1",
		Evidence: set.All(), Verdict: e.Decide(set)}
	v := Build(s)
	if v.Code != "server.port.drop" || v.Status.Head != "Не работает: причина на сервере" {
		t.Fatalf("итог %s: %+v", v.Code, v.Status)
	}
	if srv := v.Stages[1]; srv.State != "fail" || srv.Note != "порт молчит, SSH отвечает" {
		t.Fatalf("звено «Сервер»: %+v", srv)
	}
	if len(v.Also) != 1 || !strings.Contains(v.Also[0], "X25519MLKEM768") || !strings.HasSuffix(v.Also[0], "(возможно)") {
		t.Fatalf("также найдено: %v", v.Also)
	}
	var ids []string
	for _, l := range v.Evidence {
		ids = append(ids, l.ID)
	}
	if !strings.Contains(strings.Join(ids, ","), "P6") {
		t.Fatalf("P6 не в уликах: %v", ids)
	}
}

// Скрин 8: маршрут по умолчанию у другого VPN, пробы мимо него не открыли ни одного сайта. Итог —
// не «нет интернета» и не «причина в настройках Windows», а другой VPN; звено «Интернет» красное.
func TestOtherVPNHoldsRoute(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": false, "hosts_ok": 0.0, "hosts": 4.0, "bound": true}, Summary: "Эталонные сайты: 0 из 4"},
		{ID: "N4", Facts: map[string]any{"ok": false, "stage": "dns"}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "W1", Facts: map[string]any{"tun_adapters": []string{}, "other_vpn": []string{"WireGuard Tunnel"}, "default_via_tun": true}},
		{ID: "W2", Facts: map[string]any{"iface_kind": "vpn", "via_tun": true, "loop": true}},
		{ID: "P1", Facts: map[string]any{"outcome": "error"}},
	})
	s := &engine.SessionData{ID: "20261103-193600-abcd", Started: time.Now(), Evidence: set.All(), Verdict: e.Decide(set)}
	v := Build(s)
	if v.Code != "os.vpn.other" || v.Status.Head != "Не работает: весь трафик — через другой VPN" || v.Stages[0].State != "fail" {
		t.Fatalf("итог %s: %+v, звено %+v", v.Code, v.Status, v.Stages[0])
	}
}

// Скрин 6: Hiddify «Подключение…», порт и SSH молчат и из другой сети. Окно говорит словами
// самого Hiddify, звено «Сервер» — что и другая сеть не помогла, причина — на сервере.
func TestSilentFromTwoNetworks(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true, "hosts_ok": 4.0, "hosts": 4.0}},
		{ID: "CX", Facts: map[string]any{"client": "hiddify", "client_name": "Hiddify 4.1.1", "core": "hiddify-sing-box", "core_mlkem": false}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "C10", Facts: map[string]any{"listening": true, "outcome": "fail", "error": "eof", "shows": "connecting"}},
		{ID: "P1", Facts: map[string]any{"outcome": "timeout"}},
		{ID: "P6", Facts: map[string]any{"outcome": "timeout", "reach": false, "known": true}},
		{ID: "P4", Facts: map[string]any{"tcp": "timeout"}},
		{ID: "P5", Facts: map[string]any{"p1": "timeout", "p6": "silent", "age_min": 2.0}},
	})
	s := &engine.SessionData{ID: "20261102-120000-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.1",
		Evidence: set.All(), Verdict: e.Decide(set), Secret: &engine.Secret{Server: "203.0.113.7", Port: 443}}
	v := Build(s)
	if v.Code != "server.unreachable" || v.Status.Head != "Не работает: причина на сервере" {
		t.Fatalf("итог %s: %+v", v.Code, v.Status)
	}
	if srv := v.Stages[1]; srv.State != "fail" || srv.Note != "не отвечают ни порт, ни SSH — и из другой сети" {
		t.Fatalf("звено «Сервер»: %+v", srv)
	}
	if cl := v.Stages[3]; !strings.Contains(cl.Note, "«Подключение…»") {
		t.Fatalf("звено клиента: %+v", cl)
	}
	if v.Problem != "Hiddify 4.1.1 пишет «Подключение…»: ядро запущено, а трафик через сервер не идёт" ||
		v.Target == nil || v.Target.State != "«Подключение…»: трафик не идёт" {
		t.Fatalf("состояние Hiddify: %q / %+v", v.Problem, v.Target)
	}
	for _, a := range v.Actions {
		if strings.Contains(a, "из другой сети") {
			t.Fatalf("совет про другую сеть после сравнения: %q", a)
		}
	}
}

// Трафик через клиент идёт, а его URL проверки — нет: итог «работает», а не «не работает: за
// тоннелем».
func TestLatencyIndicatorOnly(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true}},
		{ID: "CX", Facts: map[string]any{"client": "hiddify", "client_name": "Hiddify 4.1.1"}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "C10", Facts: map[string]any{"listening": true, "outcome": "ok", "test_url_ok": false, "shows": "connecting"}},
	})
	s := &engine.SessionData{ID: "20261102-121000-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.1",
		Evidence: set.All(), Verdict: e.Decide(set)}
	v := Build(s)
	if v.Code != "beyond.latency_url" || v.Status.Kind != "ok" || !strings.Contains(v.Problem, "хотя трафик через него идёт") {
		t.Fatalf("итог %s: %+v, %q", v.Code, v.Status, v.Problem)
	}
}

// Скрин 7: итог не спорит с цепочкой. Было: «Причина не найдена» при красном звене «Профиль» и
// голое «— следствие» у клиента. Теперь причина названа, звено «Сервер» показывает молчащий SSH,
// клиент — следствие чего, «Если не помогло» — веб-консоль вместо недоступных отсюда моста и окна.
func TestScreen7Report(t *testing.T) {
	e, _ := rules.Load()
	evs := []evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true, "hosts_ok": 3.0, "hosts": 4.0}},
		{ID: "N4", Facts: map[string]any{"ok": true}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "CX", Facts: map[string]any{"client": "hiddify", "client_name": "Hiddify 4.1.1", "core": "hiddify-sing-box", "core_mlkem": false}},
		{ID: "C10", Facts: map[string]any{"listening": true, "outcome": "fail", "error": "eof", "shows": "connecting"}},
		{ID: "P1", Facts: map[string]any{"outcome": "ok", "ms": 58.0}},
		{ID: "P3", Facts: map[string]any{"outcome": "real_cert"}, Summary: "сервер отдал сайт-маску: REALITY не узнал клиента"},
		{ID: "P2", Facts: map[string]any{"outcome": "other_cert"}, Summary: "сертификат получен, но не подходит к SNI маски"},
	}
	build := func(extra ...evidence.Evidence) View {
		set := evidence.FromList(append(append([]evidence.Evidence{}, evs...), extra...))
		return Build(&engine.SessionData{ID: "20261102-181002-abcd", Started: time.Now(), Client: "hiddify", ClientName: "Hiddify 4.1.1",
			Evidence: set.All(), Verdict: e.Decide(set), Need: []string{e.MissingText("client_logs")}})
	}
	stage := func(v View, key string) Stage {
		for _, st := range v.Stages {
			if st.Key == key {
				return st
			}
		}
		t.Fatalf("нет звена %s", key)
		return Stage{}
	}
	v := build()
	if v.Code != "profile.stale" || v.Status.Head != "Не работает: причина в профиле" {
		t.Fatalf("итог: %s %+v", v.Code, v.Status)
	}
	if c := stage(v, "client"); c.State != "skip" || !strings.HasSuffix(c.Note, "— следствие: сервер не принял профиль") {
		t.Fatalf("клиент: %+v", c)
	}
	if s := stage(v, "server"); s.State != "ok" {
		t.Fatalf("сервер без улик о SSH: %+v", s)
	}
	txt := Text(v)
	for _, want := range []string{"Также найдено:", "X25519MLKEM768", "Для точного ответа:", "Логи клиента не найдены", "sudo xm bridge on"} {
		if !strings.Contains(txt, want) {
			t.Errorf("нет %q в\n%s", want, txt)
		}
	}
	v = build(evidence.Evidence{ID: "P6", Facts: map[string]any{"outcome": "timeout", "reach": false, "known": true}})
	if s := stage(v, "server"); s.State != "warn" || !strings.Contains(s.Note, "SSH недоступен") {
		t.Fatalf("сервер при молчащем SSH: %+v", s)
	}
	txt = Text(v)
	if !strings.Contains(txt, "веб-консоль") || strings.Contains(txt, "sudo xm bridge on") || !strings.Contains(txt, "SSH сервера отсюда недоступен") {
		t.Fatalf("SSH молчит — советы:\n%s", txt)
	}
}

// Причина не названа, но звено красное — итог «не работает» с этим звеном, а не «причина не найдена».
func TestStatusUnknownWithFailedStage(t *testing.T) {
	e, _ := rules.Load()
	set := evidence.FromList([]evidence.Evidence{
		{ID: "N1", Facts: map[string]any{"ok": true}},
		{ID: "C3", Facts: map[string]any{"found": true}},
		{ID: "P1", Facts: map[string]any{"outcome": "ok", "ms": 40.0}},
		{ID: "P3", Facts: map[string]any{"outcome": "real_cert"}},
	})
	v := Build(&engine.SessionData{ID: "20261102-120000-abcd", Started: time.Now(), Evidence: set.All(), Verdict: e.Decide(set)})
	if !strings.HasPrefix(v.Code, "unknown") || v.Status.Kind != "problem" || v.Status.Head != "Не работает: сбой на звене «Профиль»" {
		t.Fatalf("%s %+v", v.Code, v.Status)
	}
	set = evidence.FromList([]evidence.Evidence{{ID: "N1", Facts: map[string]any{"ok": true}}, {ID: "C3", Facts: map[string]any{"found": true}}})
	v = Build(&engine.SessionData{ID: "20261102-120001-abcd", Started: time.Now(), Evidence: set.All(), Verdict: e.Decide(set)})
	if v.Status.Kind != "unknown" {
		t.Fatalf("без красного звена: %+v", v.Status)
	}
}
