package redact

import (
	"strings"
	"testing"
)

func TestRedactSecretsAndPatterns(t *testing.T) {
	r := New([]byte("salt-for-tests!!"))
	r.Add(Server, "192.0.2.10")
	r.Add(SNI, "www.example.com")
	r.Add(Path, "/xh-secret")
	r.Add(SID, "0123abcd")
	r.Keep("www.gstatic.com")
	in := strings.Join([]string{
		"dial tcp 192.0.2.10:443: i/o timeout",
		"REALITY: received real certificate from www.example.com",
		"uuid 00000000-0000-4000-8000-0000000000aa and key Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
		"sub https://sub.example.net/api/v1/client/subscribe?token=abc123",
		"probe https://www.gstatic.com/generate_204",
		"vless://00000000-0000-4000-8000-0000000000aa@192.0.2.10:443?sid=0123abcd",
		"peer 198.51.100.20 and 198.51.100.77 and 203.0.113.1, loopback 127.0.0.1 any 0.0.0.0",
		"v6 2001:db8::5 path xh-secret sid 0123abcd",
		`C:\Users\Ivan\AppData\Roaming\Hiddify\hiddify\box.log`,
		"time 12:34:56 mac aa:bb:cc:dd:ee:ff",
	}, "\n")
	out := r.String(in)
	for _, bad := range []string{"192.0.2.10", "www.example.com", "xh-secret", "0123abcd", "0000000000aa",
		"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "sub.example.net", "token=abc", "198.51.100", "203.0.113", "2001:db8", "Ivan"} {
		if strings.Contains(out, bad) {
			t.Errorf("осталось %q в:\n%s", bad, out)
		}
	}
	for _, good := range []string{"https://www.gstatic.com/generate_204", "127.0.0.1", "0.0.0.0", "[server]", "[sni]",
		"[ip:A] and [ip:A] and [ip:B]", "12:34:56", "aa:bb:cc:dd:ee:ff", `C:\Users\[user]\AppData`} {
		if !strings.Contains(out, good) {
			t.Errorf("нет %q в:\n%s", good, out)
		}
	}
	if l := Leaks(out); len(l) != 0 {
		t.Fatalf("утечки: %v", l)
	}
}

func TestHashStableAndSalted(t *testing.T) {
	a := HashWith([]byte("a"), "x")
	if a != HashWith([]byte("a"), "x") || a == HashWith([]byte("b"), "x") || len(a) != 12 {
		t.Fatal(a)
	}
	if HashWith([]byte("a"), "") != "" {
		t.Fatal("пустое значение — пустой хэш")
	}
}

func TestAnyWalksJSON(t *testing.T) {
	r := New(nil)
	r.Add(Server, "203.0.113.9")
	v := r.Any(map[string]any{"server_ip": "203.0.113.9", "actions": []any{"Test-NetConnection 203.0.113.9 -Port 443"}, "n": 1.0})
	m := v.(map[string]any)
	if m["server_ip"] != "[server]" || !strings.Contains(m["actions"].([]any)[0].(string), "[server]") || m["n"] != 1.0 {
		t.Fatalf("%v", m)
	}
}
