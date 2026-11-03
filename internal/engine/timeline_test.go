package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/evidence"
)

// Решение 14: серии сбоев из логов клиента сверяются с инцидентами журнала здоровья сервера
// (импорт health.json — тот же путь, что мост S2). Совпали по времени (с поправкой на часы
// сервера из S1) — находки «обрывы подтверждены» и сторона сбоя; nodata — не инцидент.
func TestHealthTimeline(t *testing.T) {
	zone := time.FixedZone("", 3*3600)
	now := time.Date(2026, 11, 1, 15, 0, 0, 0, zone)
	at := func(h, m int) time.Time { return time.Date(2026, 11, 1, h, m, 0, 0, zone) }
	var b strings.Builder
	for _, start := range []time.Time{at(10, 30), at(13, 0)} {
		for i := 0; i < 6; i++ {
			fmt.Fprintf(&b, "+0300 %s ERROR [7 5s] connection: open connection to example.com:443 using outbound/vless[proxy]: i/o timeout\n",
				start.Add(time.Duration(i)*time.Minute).Format("2006-01-02 15:04:05"))
		}
	}
	fmt.Fprintf(&b, "+0300 %s INFO [8 0ms] outbound/vless[proxy]: outbound connection to example.com:443\n", at(14, 0).Format("2006-01-02 15:04:05"))
	logs := clients.ScanText(b.String())

	// Часы ПК на 20 минут впереди сервера: заморозка по часам сервера 10:10–10:15 — это серия
	// 10:30–10:35 по часам ПК; без поправки она мимо даже с допуском окна.
	const skew = 1200
	srv := func(t time.Time) int64 { return t.Unix() - skew }
	health := fmt.Sprintf(`{"now":%d,"d7":{"windows":2016},"incidents":[
		{"from":%d,"to":%d,"why":"заморозка","vd":"freeze","n":2},
		{"from":%d,"to":%d,"why":"нет данных","vd":"nodata","n":1},
		{"from":%d,"to":%d,"why":"самопроверка","vd":"server","n":1},
		{"from":%d,"to":%d,"why":"старое","vd":"server","n":3}]}`,
		srv(now), srv(at(10, 30)), srv(at(10, 35)), srv(at(13, 0)), srv(at(13, 5)), srv(at(3, 0)), srv(at(3, 5)),
		srv(now.Add(-30*time.Hour)), srv(now.Add(-29*time.Hour)))

	run := func(offset bool) *run {
		r := probeRun(t, Options{}, nil)
		r.now = func() time.Time { return now }
		r.tl = logs.Timeline(now, now.Add(-24*time.Hour))
		if offset {
			r.put(evidence.Evidence{ID: "S1", Facts: map[string]any{"ok": true, "time_offset_s": float64(skew)}})
		}
		r.importFile(Import{Name: "health.json", Data: []byte(health)})
		return r
	}
	r := run(true)
	s2 := r.set.Get("S2")
	for k, want := range map[string]float64{"overlap": 1, "overlap_freeze": 1, "overlap_server": 0, "day_server": 1, "day_freeze": 1} {
		if v, _ := s2.Num(k); v != want {
			t.Errorf("S2.%s = %v, ожидалось %v (%s)", k, v, want, s2.Summary)
		}
	}
	if !strings.Contains(s2.Summary, "совпали с инцидентами сервера 1") {
		t.Fatalf("сводка: %s", s2.Summary)
	}
	if v, _ := run(false).set.Get("S2").Num("overlap_freeze"); v != 0 {
		t.Fatalf("без поправки часов совпадение случайное: %v", v)
	}

	if got := episodesText(r.tl, now); !strings.Contains(got, "серий сбоев через сервер 2") || !strings.Contains(got, "после 1 клиент работал дальше") {
		t.Fatalf("C6: %q", got)
	}
}
