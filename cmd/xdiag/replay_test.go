package main

import (
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/rules"
)

func TestReplayText(t *testing.T) {
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.Local)
	l := []engine.Replayed{
		{ID: "20261101-120000-0001", At: at, Was: engine.Mark{Code: "ok", Level: rules.Likely}, Now: engine.Mark{Code: "ok", Level: rules.Likely}},
		{ID: "20261101-120000-0002", At: at, Was: engine.Mark{Code: "client.core.mlkem", Level: rules.Likely},
			Now: engine.Mark{Code: "client.core.mlkem", Level: rules.Confirmed}, Changed: true},
		{ID: "20261101-120000-0003", At: at, Err: "сеанс не прочитан"},
	}
	got := replayText(l, false)
	if strings.Contains(got, "0001") || !strings.Contains(got, "было: client.core.mlkem (вероятно) → стало: client.core.mlkem (подтверждено)") ||
		!strings.Contains(got, "0003") || !strings.Contains(got, "Проверено сеансов: 3, вердикт изменился: 1, не прочитано: 1") {
		t.Fatalf("только изменения:\n%s", got)
	}
	if got := replayText(l, true); !strings.Contains(got, "0001  01.11 12:00  без изменений: ok (вероятно)") {
		t.Fatalf("все:\n%s", got)
	}
}
