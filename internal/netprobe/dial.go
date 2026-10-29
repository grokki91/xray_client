package netprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Dialer открывает сокеты проб. IfIndex > 0 — сокет привязывается к этому интерфейсу
// (Windows: IP_UNICAST_IF): при включённом TUN клиента пробы идут мимо него, напрямую.
type Dialer struct {
	IfIndex int
	Timeout time.Duration
}

// NetDialer — net.Dialer с привязкой.
func (d *Dialer) NetDialer() *net.Dialer {
	t := d.Timeout
	if t == 0 {
		t = 8 * time.Second
	}
	nd := &net.Dialer{Timeout: t}
	if d.IfIndex > 0 {
		idx := d.IfIndex
		nd.Control = func(network, address string, c syscall.RawConn) error { return bindInterface(network, c, idx) }
	}
	return nd
}

// Control — функция привязки для чужих диалеров (эталонное ядро); nil — без привязки.
func (d *Dialer) Control() func(network, address string, c syscall.RawConn) error {
	if d == nil || d.IfIndex <= 0 {
		return nil
	}
	idx := d.IfIndex
	return func(network, address string, c syscall.RawConn) error { return bindInterface(network, c, idx) }
}

// DialContext — TCP/UDP-соединение.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.NetDialer().DialContext(ctx, network, addr)
}

// Resolver — резолвер, который ходит к публичным DNS через тот же диалер: при TUN клиента
// системный DNS уходит в TUN и не отвечает.
func (d *Dialer) Resolver(servers []string) *net.Resolver {
	if d.IfIndex <= 0 || len(servers) == 0 {
		return net.DefaultResolver
	}
	var n atomic.Uint32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		s := servers[int(n.Add(1))%len(servers)]
		return d.DialContext(ctx, network, s)
	}}
}

// Classify — исход сетевой ошибки: timeout | refused | unreachable | reset | eof | error.
func Classify(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, ErrBudget) {
		return "budget"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "eof"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "unreachable"), strings.Contains(s, "no route"):
		return "unreachable"
	case strings.Contains(s, "reset"), strings.Contains(s, "forcibly closed"), strings.Contains(s, "aborted"):
		return "reset"
	case strings.Contains(s, "timed out"), strings.Contains(s, "timeout"), strings.Contains(s, "did not properly respond"):
		return "timeout"
	case strings.Contains(s, "eof"), strings.Contains(s, "closed by the remote"):
		return "eof"
	}
	return "error"
}

// CountConn считает байты в обе стороны и отмечает первый ответ.
type CountConn struct {
	net.Conn
	In, Out   atomic.Int64
	FirstByte atomic.Int64 // UnixNano первого принятого байта
}

func (c *CountConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if c.In.Add(int64(n)) == int64(n) {
			c.FirstByte.Store(time.Now().UnixNano())
		}
	}
	return n, err
}

func (c *CountConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.Out.Add(int64(n))
	return n, err
}
