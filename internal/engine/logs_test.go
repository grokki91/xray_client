package engine

import (
	"testing"

	"github.com/grokki91/xray_client/internal/clients"
)

// C6 — тремя группами: через сервер, сам клиент, мимо сервера. Сбои прямого DNS клиента не
// выдаются за таймауты к серверу (скрин 7: было «таймаут ×372»).
func TestLogSummary(t *testing.T) {
	for _, c := range []struct {
		l    clients.LogSummary
		want string
	}{
		{clients.LogSummary{}, "Логи клиента не найдены"},
		{clients.LogSummary{Found: true, Counts: map[string]int{}}, "Логи клиента: характерных ошибок нет"},
		{clients.LogSummary{Found: true, Counts: map[string]int{"direct_failed": 372}},
			"Логи клиента: через сервер — ошибок нет; мимо сервера (прямые проверки и DNS клиента) — сбоев ×372"},
		{clients.LogSummary{Found: true, Counts: map[string]int{"aborted": 8, "reset": 1}},
			"Логи клиента: через сервер — обрыв по тишине (Windows закрыл соединение: сервер не подтверждал данные) ×8, обрыв (RST) ×1"},
		{clients.LogSummary{Found: true, Counts: map[string]int{"eof": 12, "timeout": 3, "tun_error": 1, "direct_failed": 40}},
			"Логи клиента: через сервер — соединение закрыто (EOF) ×12, таймаут ×3; сам клиент — ошибка TUN ×1; " +
				"мимо сервера (прямые проверки и DNS клиента) — сбоев ×40"},
	} {
		if got := logSummary(c.l); got != c.want {
			t.Errorf("%v:\n%q\nожидалось\n%q", c.l.Counts, got, c.want)
		}
	}
}
