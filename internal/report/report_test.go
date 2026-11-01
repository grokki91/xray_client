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
