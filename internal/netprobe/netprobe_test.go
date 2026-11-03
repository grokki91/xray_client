package netprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/hello"
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
	if r := ProbeTLS(context.Background(), d, nil, addr, "www.example.com", "", time.Second); r.Outcome != "hello_timeout" {
		t.Fatalf("молчащий сервер: %+v", r)
	}
	ln.Close()
	if r := ProbeTCP(context.Background(), d, nil, addr); r.Outcome != "refused" {
		t.Fatalf("закрытый порт: %+v", r)
	}
}

// TLS-проба шлёт ClientHello отпечатком клиента: другой отпечаток к серверу во время заморозки
// продлевает её до 10 минут (landscape.md сервера). chrome — с X25519MLKEM768, edge — без него;
// пусто — chrome, как у Xray.
func TestProbeTLSFingerprint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan *hello.Hello, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var buf []byte
			tmp := make([]byte, 4096)
			for {
				n, err := c.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if h, perr := hello.Parse(buf); perr == nil {
					got <- h
					break
				}
				if err != nil {
					got <- nil
					break
				}
			}
			c.Close()
		}
	}()
	d := &Dialer{Timeout: 2 * time.Second}
	for _, c := range []struct {
		fp    string
		mlkem bool
	}{{"chrome", true}, {"", true}, {"edge", false}, {"EDGE", false}} {
		ProbeTLS(context.Background(), d, nil, ln.Addr().String(), "www.example.com", c.fp, time.Second)
		h := <-got
		if h == nil {
			t.Fatalf("fp=%q: ClientHello не разобран", c.fp)
		}
		if m := slices.Contains(h.ShareNames(), "X25519MLKEM768"); m != c.mlkem {
			t.Fatalf("fp=%q: X25519MLKEM768 в долях — %v, ждали %v (%v)", c.fp, m, c.mlkem, h.ShareNames())
		}
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
