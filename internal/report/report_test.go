package report

import (
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/evidence"
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
	for _, want := range []string{"Что не работает: Hiddify 4.1.2 не подключается", "Причина (подтверждено)", "Что делать:", "Исключено:"} {
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
