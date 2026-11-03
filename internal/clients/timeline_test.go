package clients

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Хронология (решение 16): серии сбоев через сервер — эпизоды; одиночные таймауты, прямой выход
// и ошибки самого приложения — нет; запись без сбоев после серии — клиент работал дальше.
func TestTimeline(t *testing.T) {
	zone := time.FixedZone("", 3*3600)
	now := time.Date(2026, 11, 1, 15, 0, 0, 0, zone)
	var b strings.Builder
	line := func(at time.Time, msg string) {
		fmt.Fprintf(&b, "+0300 %s %s\n", at.Format("2006-01-02 15:04:05"), msg)
	}
	at := func(h, m, s int) time.Time { return time.Date(2026, 11, 1, h, m, s, 0, zone) }
	via := "ERROR [1234 5s] connection: open connection to example.com:443 using outbound/vless[proxy]: "
	// Позавчера — вне окна суток.
	for i := 0; i < 8; i++ {
		line(at(9, 0, i).Add(-48*time.Hour), via+"i/o timeout")
	}
	line(at(10, 0, 0), "INFO [1 0ms] inbound/mixed[in]: inbound connection to example.com:443")
	for i := 0; i < 6; i++ { // 10:30–10:35, шаг 1 мин — эпизод 1
		line(at(10, 30+i, 0), via+"i/o timeout")
	}
	line(at(11, 0, 0), "INFO [2 0ms] outbound/vless[proxy]: outbound connection to example.com:443")
	line(at(12, 0, 0), via+"i/o timeout") // одиночные — не эпизод
	line(at(12, 1, 0), via+"i/o timeout")
	for i := 0; i < 5; i++ { // 13:00–13:04 — эпизод 2
		line(at(13, i, 0), via+"EOF")
	}
	for i := 0; i < 20; i++ { // прямой DNS в те же минуты — не про сервер
		line(at(13, 0, i), "ERROR dns/direct[dns-direct]: lookup example.com: i/o timeout")
	}
	line(at(13, 6, 0), "ERROR [9] start service: core failed") // ошибка приложения — не «работал»
	line(at(13, 20, 0), "INFO [3 0ms] outbound/vless[proxy]: outbound connection to example.com:443")
	for i := 0; i < 6; i++ { // разрыв дольше 5 минут — каждая строка сама по себе, не эпизод
		line(at(14, 0, 0).Add(time.Duration(i)*6*time.Minute), via+"connection reset by peer")
	}

	s := ScanText(b.String())
	tl := s.Timeline(now, now.Add(-24*time.Hour))
	if len(tl.Episodes) != 2 || tl.Recovered != 2 {
		t.Fatalf("эпизоды %d, восстановился %d: %+v", len(tl.Episodes), tl.Recovered, tl.Episodes)
	}
	e1, e2 := tl.Episodes[0], tl.Episodes[1]
	if !e1.From.Equal(at(10, 30, 0)) || !e1.To.Equal(at(10, 35, 0)) || e1.N != 6 || e2.N != 5 || !e2.To.Equal(at(13, 4, 0)) {
		t.Fatalf("границы: %+v %+v", e1, e2)
	}
	if s.Counts["direct_failed"] != 20 || s.Counts["core_failed"] != 1 {
		t.Fatalf("счётчики: %v", s.Counts)
	}

	// Последняя серия без записи после неё — клиент не восстановился (или журнал кончился).
	cut := ScanText(strings.SplitAfter(b.String(), "13:04:00 "+via+"EOF\n")[0])
	if tl := cut.Timeline(now, now.Add(-24*time.Hour)); len(tl.Episodes) != 2 || tl.Recovered != 1 {
		t.Fatalf("без записи после серии: %d / %d", len(tl.Episodes), tl.Recovered)
	}

	// Вставленные логи — к файлам: хронология общая.
	var files LogSummary
	files.Merge(cut)
	files.Merge(ScanText(fmt.Sprintf("+0300 %s INFO ok", at(14, 0, 0).Format("2006-01-02 15:04:05"))))
	if tl := files.Timeline(now, now.Add(-24*time.Hour)); tl.Recovered != 2 || !files.Pasted {
		t.Fatalf("слияние: %+v", tl)
	}
}

func TestStamp(t *testing.T) {
	for _, c := range []struct {
		line string
		want string
	}{
		{"+0300 2026-11-01 12:34:56 ERROR x", "2026-11-01T09:34:56Z"},
		{"-0130 2026-11-01 12:34:56 INFO x", "2026-11-01T14:04:56Z"},
		{"2026/11/01 12:34:56.123456 [Warning] x", "local"},
		{"[2026-11-01 12:34:56.789] app", "local"},
		{"2026-11-01T12:34:56 app", "local"},
		{"error at 2026-11-01 12:34:56", ""}, // время не в начале строки — не отметка
		{"2026-13-01 12:34:56 x", ""},
	} {
		ts, ok := stamp(c.line)
		switch {
		case c.want == "" && ok:
			t.Errorf("%q: лишняя отметка %v", c.line, ts)
		case c.want == "local" && (!ok || ts.Location() != time.Local || ts.Hour() != 12):
			t.Errorf("%q: %v %v", c.line, ts, ok)
		case c.want != "" && c.want != "local" && (!ok || ts.UTC().Format(time.RFC3339) != c.want):
			t.Errorf("%q: %v", c.line, ts.UTC())
		}
	}
}
