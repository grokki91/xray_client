package sim

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

// Proxy — локальный SOCKS5 «клиента» для тестов C10: Works — соединяет с целью (клиент
// подключён), иначе отвечает «успех» и молчит (клиент «Подключение…», тоннель не поднялся).
type Proxy struct {
	Port  int
	Works bool
	ln    net.Listener
}

// StartProxy поднимает SOCKS5 на 127.0.0.1.
func StartProxy(works bool) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{Port: ln.Addr().(*net.TCPAddr).Port, Works: works, ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p, nil
}

func (p *Proxy) Close() { _ = p.ln.Close() }

func (p *Proxy) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, h[1])); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		_, _ = io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		_, _ = io.ReadFull(c, l)
		b := make([]byte, l[0])
		_, _ = io.ReadFull(c, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		_, _ = io.ReadFull(c, b)
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if !p.Works {
		_, _ = io.Copy(io.Discard, c)
		return
	}
	t, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))), 5*time.Second)
	if err != nil {
		return
	}
	defer t.Close()
	go func() { _, _ = io.Copy(t, c) }()
	_, _ = io.Copy(c, t)
}
