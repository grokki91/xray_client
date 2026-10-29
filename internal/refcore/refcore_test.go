package refcore

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/sim"
)

func prof(t *testing.T, s *sim.Sim) *profile.Profile {
	p, err := profile.ParseURI(s.URI("chrome"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func opts(s *sim.Sim, p *profile.Profile, fp string, b *netprobe.Budget) Options {
	return Options{Profile: p, Fingerprint: fp, ServerIPs: []net.IP{net.ParseIP("127.0.0.1")}, Budget: b,
		Probe204: s.URL("/generate_204"), Download: s.URL("/down?bytes=65536"), DownloadBytes: 65536,
		Extra: map[string]string{"latency_url": s.URL("/generate_204")}, Timeout: 30 * time.Second, Stall: 3 * time.Second}
}

func TestReferenceProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	s, err := sim.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	t.Run("chrome проходит, 204 и 64 КБ", func(t *testing.T) {
		b := netprobe.NewBudget()
		r := Run(ctx, opts(s, prof(t, s), "chrome", b))
		if r.Outcome != "ok" || r.Status != 204 || r.Bytes < 65536 || r.Freeze != "none" || !r.Extra["latency_url"] {
			t.Fatalf("%+v\n%s", r, strings.Join(r.Logs, "\n"))
		}
		if r.Conns != 1 || b.Usage().TotalTLS != 1 {
			t.Fatalf("к серверу должно быть одно TLS-соединение: conns=%d budget=%+v", r.Conns, b.Usage())
		}
	})

	t.Run("edge без X25519MLKEM768 — сервер отдаёт маску", func(t *testing.T) {
		r := Run(ctx, opts(s, prof(t, s), "edge", netprobe.NewBudget()))
		if r.Outcome != "real_cert" {
			t.Fatalf("%+v\n%s", r, strings.Join(r.Logs, "\n"))
		}
	})

	t.Run("чужой ключ — сервер отдаёт маску", func(t *testing.T) {
		p := prof(t, s)
		p.PublicKey = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
		r := Run(ctx, opts(s, p, "chrome", netprobe.NewBudget()))
		if r.Outcome != "real_cert" {
			t.Fatalf("%+v\n%s", r, strings.Join(r.Logs, "\n"))
		}
	})

	t.Run("чужой UUID — закрыто после рукопожатия", func(t *testing.T) {
		p := prof(t, s)
		p.UUID = "00000000-0000-4000-8000-0000000000ff"
		r := Run(ctx, opts(s, p, "chrome", netprobe.NewBudget()))
		if r.Outcome != "closed_after_handshake" {
			t.Fatalf("%+v\n%s", r, strings.Join(r.Logs, "\n"))
		}
	})

	t.Run("заморозка на 4 КБ", func(t *testing.T) {
		o := opts(s, prof(t, s), "chrome", netprobe.NewBudget())
		o.Download = s.URL("/stall")
		r := Run(ctx, o)
		if r.Outcome != "freeze" || r.Freeze == "none" || r.Bytes >= 65536 {
			t.Fatalf("%+v", r)
		}
	})

	t.Run("бюджет исчерпан — проба не идёт", func(t *testing.T) {
		b := netprobe.NewBudget()
		for i := 0; i < 3; i++ {
			_ = b.Acquire(netprobe.TLS)
		}
		r := Run(ctx, opts(s, prof(t, s), "chrome", b))
		if r.Outcome != "budget" || r.Conns != 0 {
			t.Fatalf("%+v", r)
		}
	})
}

func TestReferenceTCPFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой симулятор")
	}
	pk := sim.PublicKey()
	mk := func(port int) *profile.Profile {
		p, _ := profile.ParseURI("vless://" + sim.UUID + "@127.0.0.1:" + itoa(port) + "?security=reality&sni=" + sim.SNI +
			"&fp=chrome&pbk=" + pk + "&sid=" + sim.ShortID + "&type=xhttp&path=" + sim.Path)
		return p
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // порт закрыт — RST
	r := Run(context.Background(), Options{Profile: mk(port), Fingerprint: "chrome", ServerIPs: []net.IP{net.ParseIP("127.0.0.1")},
		Probe204: "http://127.0.0.1:9/generate_204", Timeout: 15 * time.Second})
	if r.Outcome != "tcp_refused" {
		t.Fatalf("закрытый порт: %+v\n%s", r, strings.Join(r.Logs, "\n"))
	}

	// Принимает и молчит — ClientHello без ответа.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(20 * time.Second); c.Close() }()
		}
	}()
	r = Run(context.Background(), Options{Profile: mk(ln2.Addr().(*net.TCPAddr).Port), Fingerprint: "chrome",
		ServerIPs: []net.IP{net.ParseIP("127.0.0.1")}, Probe204: "http://127.0.0.1:9/generate_204", Timeout: 12 * time.Second})
	if r.Outcome != "handshake_timeout" || r.SocketIn != 0 {
		t.Fatalf("молчащий порт: %+v", r)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
