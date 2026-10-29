package hello

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Те же ClientHello, на которых проверяется doctor.py сервера: клиент Xray-core 26.10.21.
func TestParseFixtures(t *testing.T) {
	b, err := os.ReadFile("../../testdata/hello/xray-26.10.21.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		ServerName string `json:"serverName"`
		Hellos     map[string]struct {
			Hex string `json:"hex"`
		} `json:"hellos"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"chrome": true, "firefox": true, "edge": false}
	for fp, mlkem := range want {
		raw, _ := hex.DecodeString(fx.Hellos[fp].Hex)
		h, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", fp, err)
		}
		if h.SNI != fx.ServerName || !h.TLS13() {
			t.Fatalf("%s: SNI %q TLS13 %v", fp, h.SNI, h.TLS13())
		}
		if h.MLKEMRule() != mlkem {
			t.Fatalf("%s: правило долей %v, ожидалось %v (%v)", fp, h.MLKEMRule(), mlkem, h.ShareNames())
		}
		if mlkem && !strings.Contains(strings.Join(h.ShareNames(), "+"), "X25519MLKEM768") {
			t.Fatalf("%s: %v", fp, h.ShareNames())
		}
		// Неполный ClientHello — ErrPartial, как стадия partial у doctor.
		if _, err := Parse(raw[:len(raw)/2]); err != ErrPartial {
			t.Fatalf("%s: половина ClientHello: %v", fp, err)
		}
	}
	if _, err := Parse([]byte("GET / HTTP/1.1\r\n")); err != ErrNotTLS {
		t.Fatal("не TLS")
	}
}
