// Package capture — C7: что клиент на самом деле шлёт серверу. Захват pktmon (встроен в
// Windows, нужны права администратора) по адресу и порту сервера на время одной попытки
// клиента, затем pcapng разбирается здесь: был ли SYN, ответил ли сервер, есть ли в ClientHello
// X25519MLKEM768 перед X25519, сколько TLS-хендшейков за минуту. Файлы захвата удаляются сразу
// после разбора; в результат адреса не попадают.
package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/grokki91/xray_client/internal/hello"
	"github.com/grokki91/xray_client/internal/redact"
)

// Result — итог разбора.
type Result struct {
	Ran         bool     `json:"ran"`
	Err         string   `json:"err,omitempty"`
	Packets     int      `json:"packets"`
	SYNSeen     bool     `json:"syn_seen"`
	SYNACKSeen  bool     `json:"synack_seen"`
	Conns       int      `json:"conns"`
	HelloSeen   bool     `json:"hello_seen"`
	Hellos      int      `json:"hellos"`
	Partial     int      `json:"partial"`
	MLKEM       bool     `json:"mlkem"`     // последний ClientHello проходит правило долей
	MLKEMAll    bool     `json:"mlkem_all"` // все ClientHello проходят
	Shares      []string `json:"shares"`
	ALPN        []string `json:"alpn"`
	SNIMatch    bool     `json:"sni_match"`
	TLS13       bool     `json:"tls13"`
	HellosPer60 int      `json:"hellos_per_60s"`
}

type pkt struct {
	t       time.Time
	src     net.IP
	dst     net.IP
	sport   uint16
	dport   uint16
	seq     uint32
	flags   byte
	payload []byte
}

const (
	synFlag = 0x02
	ackFlag = 0x10
)

// Analyze разбирает pcapng (или классический pcap) с пакетами к серверу ip:port.
// sniHash — HMAC SNI профиля на соли salt: SNI на проводе сверяется без передачи самого имени.
func Analyze(data []byte, ip net.IP, port int, salt []byte, sniHash string) Result {
	r := Result{Ran: true, MLKEMAll: true}
	pkts, err := readPackets(data)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	type flow struct {
		t0   time.Time
		isn  uint32
		segs map[uint32][]byte
		done bool
	}
	flows := map[string]*flow{}
	var helloTimes []time.Time
	for _, p := range pkts {
		toServer := p.dst.Equal(ip) && int(p.dport) == port
		fromServer := p.src.Equal(ip) && int(p.sport) == port
		if !toServer && !fromServer {
			continue
		}
		r.Packets++
		if toServer {
			key := p.src.String() + ":" + itoa(int(p.sport))
			f := flows[key]
			if p.flags&synFlag != 0 && p.flags&ackFlag == 0 {
				r.SYNSeen = true
				if f == nil || f.isn != p.seq {
					flows[key] = &flow{t0: p.t, isn: p.seq, segs: map[uint32][]byte{}}
					r.Conns++
				}
				continue
			}
			if f == nil || f.done || len(p.payload) == 0 {
				continue
			}
			rel := p.seq - f.isn - 1
			if rel > 20480 {
				continue
			}
			if _, dup := f.segs[rel]; !dup {
				f.segs[rel] = append([]byte(nil), p.payload...)
			}
			buf := assemble(f.segs)
			h, err := hello.Parse(buf)
			switch {
			case errors.Is(err, hello.ErrPartial):
				continue
			case err != nil:
				f.done = true
				continue
			}
			f.done = true
			r.HelloSeen = true
			r.Hellos++
			helloTimes = append(helloTimes, p.t)
			r.MLKEM = h.MLKEMRule()
			if !r.MLKEM {
				r.MLKEMAll = false
			}
			r.Shares, r.ALPN, r.TLS13 = h.ShareNames(), h.ALPN, h.TLS13()
			r.SNIMatch = sniHash != "" && redact.HashWith(salt, h.SNI) == sniHash
		} else if p.flags&synFlag != 0 && p.flags&ackFlag != 0 {
			r.SYNACKSeen = true
		}
	}
	for _, f := range flows {
		if !f.done && len(f.segs) > 0 {
			r.Partial++
		}
	}
	if !r.HelloSeen {
		r.MLKEMAll = false
	}
	sort.Slice(helloTimes, func(i, j int) bool { return helloTimes[i].Before(helloTimes[j]) })
	for i := range helloTimes {
		n := 0
		for j := i; j < len(helloTimes) && helloTimes[j].Sub(helloTimes[i]) <= time.Minute; j++ {
			n++
		}
		if n > r.HellosPer60 {
			r.HellosPer60 = n
		}
	}
	return r
}

func assemble(segs map[uint32][]byte) []byte {
	keys := make([]uint32, 0, len(segs))
	for k := range segs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var buf []byte
	for _, k := range keys {
		seg := segs[k]
		if int(k) > len(buf) {
			break
		}
		if int(k)+len(seg) > len(buf) {
			buf = append(buf, seg[len(buf)-int(k):]...)
		}
	}
	return buf
}

func itoa(n int) string {
	return string(appendInt(nil, n))
}

func appendInt(b []byte, n int) []byte {
	if n >= 10 {
		b = appendInt(b, n/10)
	}
	return append(b, byte('0'+n%10))
}

// ─── pcap / pcapng ───────────────────────────────────────────────────────────

func readPackets(data []byte) ([]pkt, error) {
	if len(data) < 24 {
		return nil, errors.New("файл захвата пуст")
	}
	switch {
	case bytes.Equal(data[:4], []byte{0x0A, 0x0D, 0x0D, 0x0A}):
		return readPcapNG(data)
	case binary.LittleEndian.Uint32(data) == 0xa1b2c3d4 || binary.BigEndian.Uint32(data) == 0xa1b2c3d4 ||
		binary.LittleEndian.Uint32(data) == 0xa1b23c4d || binary.BigEndian.Uint32(data) == 0xa1b23c4d:
		return readPcap(data)
	}
	return nil, errors.New("неизвестный формат захвата")
}

func readPcap(data []byte) ([]pkt, error) {
	var bo binary.ByteOrder = binary.LittleEndian
	magic := bo.Uint32(data)
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		bo = binary.BigEndian
		magic = bo.Uint32(data)
	}
	nano := magic == 0xa1b23c4d
	link := int(bo.Uint32(data[20:]))
	var out []pkt
	for off := 24; off+16 <= len(data); {
		sec, frac := bo.Uint32(data[off:]), bo.Uint32(data[off+4:])
		cl := int(bo.Uint32(data[off+8:]))
		off += 16
		if off+cl > len(data) {
			break
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		if p, ok := decode(link, data[off:off+cl]); ok {
			p.t = time.Unix(int64(sec), ns)
			out = append(out, p)
		}
		off += cl
	}
	return out, nil
}

func readPcapNG(data []byte) ([]pkt, error) {
	var bo binary.ByteOrder = binary.LittleEndian
	var links []int
	var res []int64 // делитель метки времени на интерфейс (единиц в секунду)
	var out []pkt
	for off := 0; off+12 <= len(data); {
		typ := bo.Uint32(data[off:])
		if typ == 0x0A0D0D0A && off+12 <= len(data) {
			if binary.BigEndian.Uint32(data[off+8:]) == 0x1A2B3C4D {
				bo = binary.BigEndian
			} else {
				bo = binary.LittleEndian
			}
			links, res = nil, nil
		}
		blen := int(bo.Uint32(data[off+4:]))
		if blen < 12 || off+blen > len(data) {
			break
		}
		body := data[off+8 : off+blen-4]
		switch typ {
		case 1: // Interface Description
			if len(body) >= 8 {
				links = append(links, int(bo.Uint16(body)))
				res = append(res, tsResol(body[8:], bo))
			}
		case 6: // Enhanced Packet
			if len(body) >= 20 {
				ifid := int(bo.Uint32(body))
				ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
				cl := int(bo.Uint32(body[12:]))
				if 20+cl <= len(body) && ifid < len(links) {
					if p, ok := decode(links[ifid], body[20:20+cl]); ok {
						div := res[ifid]
						p.t = time.Unix(int64(ts/uint64(div)), int64(ts%uint64(div))*int64(time.Second)/div)
						out = append(out, p)
					}
				}
			}
		case 3: // Simple Packet
			if len(body) >= 4 && len(links) > 0 {
				if p, ok := decode(links[0], body[4:]); ok {
					out = append(out, p)
				}
			}
		}
		off += blen
	}
	return out, nil
}

// tsResol — опция if_tsresol (код 9); по умолчанию микросекунды.
func tsResol(opts []byte, bo binary.ByteOrder) int64 {
	for len(opts) >= 4 {
		code, l := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+l > len(opts) {
			break
		}
		if code == 9 && l >= 1 {
			v := opts[4]
			if v&0x80 == 0 {
				d := int64(1)
				for i := 0; i < int(v); i++ {
					d *= 10
				}
				return d
			}
			return int64(1) << (v & 0x7f)
		}
		opts = opts[4+(l+3)/4*4:]
	}
	return 1_000_000
}

// decode — кадр канального уровня до TCP.
func decode(link int, b []byte) (pkt, bool) {
	switch link {
	case 1: // Ethernet
		if len(b) < 14 {
			return pkt{}, false
		}
		et := binary.BigEndian.Uint16(b[12:])
		b = b[14:]
		for et == 0x8100 || et == 0x88a8 {
			if len(b) < 4 {
				return pkt{}, false
			}
			et = binary.BigEndian.Uint16(b[2:])
			b = b[4:]
		}
		if et != 0x0800 && et != 0x86DD {
			return pkt{}, false
		}
	case 0, 108: // BSD loopback: 4 байта семейства
		if len(b) < 4 {
			return pkt{}, false
		}
		b = b[4:]
	case 101, 12, 14, 228, 229: // сырой IP
	case 113: // Linux cooked
		if len(b) < 16 {
			return pkt{}, false
		}
		b = b[16:]
	default:
		return pkt{}, false
	}
	return decodeIP(b)
}

func decodeIP(b []byte) (pkt, bool) {
	if len(b) < 20 {
		return pkt{}, false
	}
	var p pkt
	var t []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&15) * 4
		if b[9] != 6 || len(b) < ihl+20 {
			return pkt{}, false
		}
		total := int(binary.BigEndian.Uint16(b[2:]))
		if total > len(b) || total < ihl {
			total = len(b)
		}
		p.src, p.dst = net.IP(append([]byte(nil), b[12:16]...)), net.IP(append([]byte(nil), b[16:20]...))
		t = b[ihl:total]
	case 6:
		if len(b) < 60 || b[6] != 6 {
			return pkt{}, false
		}
		pl := int(binary.BigEndian.Uint16(b[4:]))
		end := 40 + pl
		if end > len(b) {
			end = len(b)
		}
		p.src, p.dst = net.IP(append([]byte(nil), b[8:24]...)), net.IP(append([]byte(nil), b[24:40]...))
		t = b[40:end]
	default:
		return pkt{}, false
	}
	if len(t) < 20 {
		return pkt{}, false
	}
	p.sport, p.dport = binary.BigEndian.Uint16(t), binary.BigEndian.Uint16(t[2:])
	p.seq = binary.BigEndian.Uint32(t[4:])
	off := int(t[12]>>4) * 4
	p.flags = t[13]
	if off > len(t) {
		return pkt{}, false
	}
	p.payload = t[off:]
	return p, true
}
