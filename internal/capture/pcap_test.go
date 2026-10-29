package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/redact"
)

func fixtureHello(t *testing.T, fp string) []byte {
	b, err := os.ReadFile("../../testdata/hello/xray-26.10.21.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Hellos map[string]struct{ Hex string } `json:"hellos"`
	}
	_ = json.Unmarshal(b, &fx)
	raw, _ := hex.DecodeString(fx.Hellos[fp].Hex)
	return raw
}

// frame — Ethernet + IPv4 + TCP.
func frame(src, dst net.IP, sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)+len(payload)))
	ip[9] = 6
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	return append(append(append(eth, ip...), tcp...), payload...)
}

// pcapng — SHB + IDB (Ethernet) + EPB на каждый кадр.
func pcapng(frames [][]byte, t0 time.Time, step time.Duration) []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		l := uint32(12 + len(body))
		_ = binary.Write(&b, le, typ)
		_ = binary.Write(&b, le, l)
		b.Write(body)
		_ = binary.Write(&b, le, l)
	}
	shb := make([]byte, 16)
	le.PutUint32(shb, 0x1A2B3C4D)
	le.PutUint16(shb[4:], 1)
	for i := 8; i < 16; i++ {
		shb[i] = 0xff
	}
	block(0x0A0D0D0A, shb)
	idb := make([]byte, 8)
	le.PutUint16(idb, 1)
	block(1, idb)
	for i, f := range frames {
		ts := uint64(t0.Add(time.Duration(i) * step).UnixMicro())
		body := make([]byte, 20)
		le.PutUint32(body[4:], uint32(ts>>32))
		le.PutUint32(body[8:], uint32(ts))
		le.PutUint32(body[12:], uint32(len(f)))
		le.PutUint32(body[16:], uint32(len(f)))
		block(6, append(body, f...))
	}
	return b.Bytes()
}

func TestAnalyzeSplitHelloWithDuplicates(t *testing.T) {
	client, server := net.ParseIP("192.0.2.20"), net.ParseIP("198.51.100.30")
	salt := []byte("s")
	for _, c := range []struct {
		fp    string
		mlkem bool
	}{{"chrome", true}, {"edge", false}} {
		h := fixtureHello(t, c.fp)
		isn := uint32(1000)
		half := len(h) / 2
		frames := [][]byte{
			frame(client, server, 50000, 443, isn, synFlag, nil),
			frame(server, client, 443, 50000, 7000, synFlag|ackFlag, nil),
			frame(client, server, 50000, 443, isn+1+uint32(half), ackFlag, h[half:]), // вне порядка
			frame(client, server, 50000, 443, isn+1, ackFlag, h[:half]),
			frame(client, server, 50000, 443, isn+1, ackFlag, h[:half]), // дубль pktmon
		}
		r := Analyze(pcapng(frames, time.Now(), 10*time.Millisecond), server, 443, salt, redact.HashWith(salt, "www.example.com"))
		if r.Err != "" || !r.SYNSeen || !r.SYNACKSeen || r.Conns != 1 || !r.HelloSeen || r.MLKEM != c.mlkem || !r.SNIMatch || !r.TLS13 {
			t.Fatalf("%s: %+v", c.fp, r)
		}
	}
}

func TestAnalyzeNoSYN(t *testing.T) {
	server := net.ParseIP("198.51.100.30")
	r := Analyze(pcapng(nil, time.Now(), 0), server, 443, nil, "")
	if r.Err != "" || r.SYNSeen || r.HelloSeen {
		t.Fatalf("%+v", r)
	}
}
