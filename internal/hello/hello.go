// Package hello — разбор ClientHello TLS (порт parse_hello из grokki91/xray ui/doctor.py):
// SNI, ALPN, версии, группы, доли key_share — чтобы увидеть, шлёт ли клиент X25519MLKEM768
// перед X25519 (правило REALITY ≥ v26.9.9).
package hello

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	X25519 = 0x001D
	MLKEM  = 0x11EC // X25519MLKEM768
	TLS13  = 0x0304
	// В доле X25519MLKEM768: 1184 байта ключа ML-KEM-768 и 32 байта X25519.
	MLKEMShare = 1184 + 32
)

// Hello — разобранный ClientHello.
type Hello struct {
	SNI      string   `json:"sni"`
	ALPN     []string `json:"alpn"`
	Versions []uint16 `json:"versions"`
	Groups   []uint16 `json:"groups"`
	Shares   []Share  `json:"shares"`
	Exts     []uint16 `json:"exts"`
	SIDLen   int      `json:"sid_len"`
	Grease   bool     `json:"grease"`
	Size     int      `json:"size"`
}

// Share — доля key_share.
type Share struct {
	Group uint16 `json:"group"`
	Len   int    `json:"len"`
}

// ErrPartial — данных меньше, чем нужно для целого ClientHello.
var ErrPartial = errors.New("ClientHello пришёл не целиком")

// ErrNotTLS — поток не начинается с записи Handshake TLS.
var ErrNotTLS = errors.New("не TLS")

func grease(v uint16) bool { return v&0x0F0F == 0x0A0A && v>>8 == v&0xFF }

// Parse разбирает ClientHello из начала потока клиента (может быть в нескольких записях).
func Parse(buf []byte) (*Hello, error) {
	if len(buf) < 5 {
		return nil, ErrPartial
	}
	if buf[0] != 0x16 || buf[1] != 3 {
		return nil, ErrNotTLS
	}
	var hs []byte
	off := 0
	for {
		if off+5 > len(buf) {
			return nil, ErrPartial
		}
		if buf[off] != 0x16 {
			return nil, errors.New("не Handshake")
		}
		rl := int(binary.BigEndian.Uint16(buf[off+3:]))
		if off+5+rl > len(buf) {
			return nil, ErrPartial
		}
		hs = append(hs, buf[off+5:off+5+rl]...)
		off += 5 + rl
		if len(hs) >= 4 {
			if hs[0] != 1 {
				return nil, errors.New("не ClientHello")
			}
			need := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if len(hs) >= need {
				hs = hs[:need]
				break
			}
		}
	}
	h, err := fields(hs)
	if err != nil {
		return nil, err
	}
	h.Size = len(hs)
	return h, nil
}

func fields(hs []byte) (h *Hello, err error) {
	defer func() {
		if r := recover(); r != nil {
			h, err = nil, fmt.Errorf("ClientHello испорчен: %v", r)
		}
	}()
	h = &Hello{}
	p := 4 + 2 + 32
	n := int(hs[p])
	h.SIDLen = n
	p += 1 + n
	n = int(binary.BigEndian.Uint16(hs[p:]))
	p += 2 + n
	p += 1 + int(hs[p])
	end := p + 2 + int(binary.BigEndian.Uint16(hs[p:]))
	p += 2
	for p+4 <= end {
		t := binary.BigEndian.Uint16(hs[p:])
		n := int(binary.BigEndian.Uint16(hs[p+2:]))
		d := hs[p+4 : p+4+n]
		p += 4 + n
		h.Exts = append(h.Exts, t)
		switch t {
		case 0:
			if len(d) >= 5 && d[2] == 0 {
				l := int(binary.BigEndian.Uint16(d[3:]))
				h.SNI = string(d[5 : 5+l])
			}
		case 10:
			l := int(binary.BigEndian.Uint16(d))
			for i := 2; i < 2+l; i += 2 {
				h.Groups = append(h.Groups, binary.BigEndian.Uint16(d[i:]))
			}
		case 16:
			e := 2 + int(binary.BigEndian.Uint16(d))
			for q := 2; q < e; {
				l := int(d[q])
				h.ALPN = append(h.ALPN, string(d[q+1:q+1+l]))
				q += 1 + l
			}
		case 43:
			for i := 1; i < 1+int(d[0]); i += 2 {
				h.Versions = append(h.Versions, binary.BigEndian.Uint16(d[i:]))
			}
		case 51:
			e := 2 + int(binary.BigEndian.Uint16(d))
			for q := 2; q+4 <= e; {
				g := binary.BigEndian.Uint16(d[q:])
				l := int(binary.BigEndian.Uint16(d[q+2:]))
				h.Shares = append(h.Shares, Share{Group: g, Len: l})
				q += 4 + l
			}
		}
	}
	for _, x := range append(append([]uint16{}, h.Exts...), h.Groups...) {
		if grease(x) {
			h.Grease = true
		}
	}
	return h, nil
}

// ShareNames — имена долей без GREASE.
func (h *Hello) ShareNames() []string {
	var out []string
	for _, s := range h.Shares {
		if !grease(s.Group) {
			out = append(out, GroupName(s.Group))
		}
	}
	return out
}

// GroupName — имя группы.
func GroupName(g uint16) string {
	switch g {
	case X25519:
		return "X25519"
	case MLKEM:
		return "X25519MLKEM768"
	case 0x0017:
		return "P-256"
	case 0x0018:
		return "P-384"
	}
	return fmt.Sprintf("0x%04x", g)
}

// MLKEMRule — прошёл бы ClientHello правило долей REALITY ≥ v26.9.9: X25519MLKEM768 есть, без
// повторов, и идёт перед X25519 (порядок — как в XTLS/REALITY tls.go 8cdf7bf).
func (h *Hello) MLKEMRule() bool {
	var seenM, seenX bool
	for _, s := range h.Shares {
		switch {
		case s.Group == MLKEM && s.Len == MLKEMShare:
			if seenM {
				return false
			}
			seenM = true
		case s.Group == X25519 && s.Len == 32:
			if seenX {
				return false
			}
			seenX = true
			return seenM
		}
	}
	return seenM
}

// TLS13 — в supported_versions есть TLS 1.3.
func (h *Hello) TLS13() bool {
	for _, v := range h.Versions {
		if v == TLS13 {
			return true
		}
	}
	return false
}
