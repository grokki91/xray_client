package netprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBudgetWindows(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	b := NewBudget()
	b.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if err := b.Acquire(TLS); err != nil {
			t.Fatalf("TLS %d: %v", i, err)
		}
	}
	if err := b.Acquire(TLS); !errors.Is(err, ErrBudget) {
		t.Fatal("четвёртый TLS за минуту должен быть отклонён")
	}
	if b.Acquire(TCP) != nil {
		t.Fatal("TCP в пределах 6 за 5 минут")
	}
	if w := b.WaitTLS(); w != 60*time.Second {
		t.Fatalf("ожидание %v", w)
	}
	now = now.Add(61 * time.Second)
	if err := b.Acquire(TLS); err != nil {
		t.Fatalf("через минуту слот свободен: %v", err)
	}
	// TCP: уже 5 за 5 минут (4 TLS + 1 TCP) — шестой можно, седьмой нет.
	if b.Acquire(TCP) != nil || b.Acquire(TCP) == nil {
		t.Fatalf("лимит TCP: %+v", b.Usage())
	}
	s := b.Snapshot()
	b2 := NewBudget()
	b2.now = b.now
	b2.Restore(s)
	if b2.Can(TCP) {
		t.Fatal("бюджет переживает перезапуск")
	}
}

// TLS-хендшейки самого клиента к тому же серверу — в окне TLS для ожидания слота: пробы
// приложения поверх них не выводят сумму за 3 в минуту («заморозка по отпечатку» считает все
// хендшейки с адреса ПК). Проба, уже дождавшаяся слота, из-за них отказа не получает; в TCP-лимит
// приложения и в снимок между запусками они не входят.
func TestBudgetCountsClientHandshakes(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	b := NewBudget()
	b.now = func() time.Time { return now }
	b.Observe(now.Add(-10 * time.Second))
	b.Observe(now.Add(-5 * time.Second))
	if b.WaitTLS() != 0 {
		t.Fatal("два TLS клиента за минуту — третий ещё можно")
	}
	if err := b.Acquire(TLS); err != nil {
		t.Fatalf("третий TLS за минуту: %v", err)
	}
	if w := b.WaitTLS(); w != 50*time.Second {
		t.Fatalf("четвёртый — когда из окна уйдёт первый хендшейк клиента: %v", w)
	}
	if !b.Can(TLS) || !b.Can(TCP) {
		t.Fatal("отказ проба получает только по своим соединениям")
	}
	u := b.Usage()
	if u.TLS != 3 || u.Client != 2 || u.TotalClient != 2 || u.TotalTLS != 1 || u.WaitSec != 51 {
		t.Fatalf("расход: %+v", u)
	}
	if s := b.Snapshot(); len(s.TLS) != 1 {
		t.Fatalf("в снимок — только свои пробы: %+v", s)
	}
	if d := b.Usage().Since(Usage{TotalClient: 1}); d.TotalClient != 1 {
		t.Fatalf("за сеанс: %+v", d)
	}
	now = now.Add(51 * time.Second)
	if err := b.Acquire(TLS); err != nil {
		t.Fatalf("первый хендшейк клиента вышел из окна: %v", err)
	}
}

// Окно живёт долго и каждый сеанс восстанавливает снимок из файла: тот же снимок не должен
// удваивать счётчик (было: второй сеанс подряд — «бюджет исчерпан» без единой пробы).
func TestBudgetRestoreIdempotentAndWait(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	b := NewBudget()
	b.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		_ = b.Acquire(TLS)
		_ = b.Acquire(TCP)
	}
	start := b.Usage()
	s := b.Snapshot()
	b.Restore(s)
	b.Restore(s)
	if u := b.Usage(); u.TCP != 4 || u.TLS != 2 {
		t.Fatalf("после двух Restore: %+v", u)
	}
	if w := b.Wait(TLS); w != 0 {
		t.Fatalf("слот TLS свободен, ожидание %v", w)
	}
	_ = b.Acquire(TLS)
	if w := b.Wait(TLS); w != 60*time.Second {
		t.Fatalf("TLS: %v", w)
	}
	if w := b.Wait(TCP); w != 0 {
		t.Fatalf("TCP свободен: %v", w)
	}
	_ = b.Acquire(TCP)
	if w := b.Wait(TCP); w != 5*time.Minute {
		t.Fatalf("TCP: %v", w)
	}
	if u := b.Usage().Since(start); u.TotalTLS != 1 || u.TotalTCP != 2 {
		t.Fatalf("за сеанс: %+v", u)
	}
}

func TestClassifyAndProbes(t *testing.T) {
	for err, want := range map[error]string{
		io.EOF: "eof", context.DeadlineExceeded: "timeout", ErrBudget: "budget",
		errors.New("dial tcp: connectex: No connection could be made because the target machine actively refused it."): "refused",
		errors.New("wsarecv: An existing connection was forcibly closed by the remote host."):                          "reset",
		errors.New("connect: network is unreachable"):                                                                  "unreachable",
	} {
		if got := Classify(err); got != want {
			t.Errorf("%v → %s, ожидалось %s", err, got, want)
		}
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	d := &Dialer{Timeout: 2 * time.Second}
	if r := ProbeTCP(context.Background(), d, nil, addr); r.Outcome != "ok" {
		t.Fatalf("TCP %+v", r)
	}
	if r := ProbeTLS(context.Background(), d, nil, addr, "www.example.com", time.Second); r.Outcome != "hello_timeout" {
		t.Fatalf("молчащий сервер: %+v", r)
	}
	ln.Close()
	if r := ProbeTCP(context.Background(), d, nil, addr); r.Outcome != "refused" {
		t.Fatalf("закрытый порт: %+v", r)
	}
}

// P6: SSH-сервер сам шлёт баннер; молчащий сервер — TCP есть, баннера нет; бюджет списывается.
func TestProbeBanner(t *testing.T) {
	serve := func(greet string) string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				if greet != "" {
					_, _ = c.Write([]byte(greet))
				}
				go func() { time.Sleep(time.Second); c.Close() }()
			}
		}()
		return ln.Addr().String()
	}
	d := &Dialer{Timeout: 2 * time.Second}
	b := NewBudget()
	if r, ok := ProbeBanner(context.Background(), d, b, serve("SSH-2.0-test\r\n"), "SSH-", time.Second); r.Outcome != "ok" || !ok {
		t.Fatalf("SSH: %+v %v", r, ok)
	}
	if r, ok := ProbeBanner(context.Background(), d, b, serve(""), "SSH-", 200*time.Millisecond); r.Outcome != "ok" || ok {
		t.Fatalf("молчит: %+v %v", r, ok)
	}
	if r, ok := ProbeBanner(context.Background(), d, b, serve("HTTP/1.1 400"), "SSH-", time.Second); r.Outcome != "ok" || ok {
		t.Fatalf("не SSH: %+v %v", r, ok)
	}
	if u := b.Usage(); u.TotalTCP != 3 {
		t.Fatalf("бюджет: %+v", u)
	}
}
