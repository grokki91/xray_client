package netprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

// LocalListening — слушает ли кто-то 127.0.0.1:port (локальный прокси клиента). Не зависит от
// PowerShell: подключён ли клиент, видно и без фактов Windows.
func LocalListening(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 700*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ClientResult — C10: запрос через сам клиент (его ядро, его профиль, его тоннель).
type ClientResult struct {
	Outcome string `json:"outcome"` // ok | fail | freeze
	Status  int    `json:"status"`
	Ms204   int    `json:"ms_204"`
	Bytes   int64  `json:"bytes"`
	Error   string `json:"error,omitempty"` // timeout | refused | reset | eof | status | error
}

// ProbeViaClient — GET probe204 (ожидается 204), затем до limit байт с download. port > 0 — через
// SOCKS5 127.0.0.1:port (локальный прокси клиента, имя резолвит клиент); port = 0 — по
// системному маршруту (режим TUN без локального прокси). Сертификат за тоннелем не проверяется:
// при сбитых часах ПК проверка дала бы ложную «поломку клиента».
func ProbeViaClient(ctx context.Context, port int, probe204, download string, limit int) ClientResult {
	tr := &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 12 * time.Second, ResponseHeaderTimeout: 12 * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	if port > 0 {
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	r := ClientResult{}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	t0 := time.Now()
	req, err := http.NewRequestWithContext(c, http.MethodGet, probe204, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		var resp *http.Response
		if resp, err = hc.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			r.Status = resp.StatusCode
		}
	}
	cancel()
	r.Ms204 = int(time.Since(t0).Milliseconds())
	switch {
	case err != nil:
		r.Outcome, r.Error = "fail", Classify(err)
		if r.Error == "budget" {
			r.Error = "error"
		}
		return r
	case r.Status != http.StatusNoContent:
		r.Outcome, r.Error = "fail", "status"
		return r
	}
	r.Outcome = "ok"
	if download != "" {
		n, _, stalled := Download(ctx, hc, download, limit, 8*time.Second)
		r.Bytes = n
		if stalled {
			r.Outcome = "freeze"
		}
	}
	return r
}

// Download читает до limit байт; stalled — не было прогресса дольше stall (или 30 с на всё).
func Download(ctx context.Context, hc *http.Client, u string, limit int, stall time.Duration) (int64, int, bool) {
	if limit <= 0 {
		limit = 65536
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	t0 := time.Now()
	req, err := http.NewRequestWithContext(c, http.MethodGet, u, nil)
	if err != nil {
		return 0, 0, false
	}
	var n atomic.Int64
	done := make(chan error, 1)
	go func() {
		resp, err := hc.Do(req)
		if err != nil {
			done <- err
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 8192)
		for n.Load() < int64(limit) {
			k, err := resp.Body.Read(buf)
			n.Add(int64(k))
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				done <- err
				return
			}
		}
		done <- nil
	}()
	last, lastN := time.Now(), int64(0)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return n.Load(), int(time.Since(t0).Milliseconds()), err != nil && Classify(err) == "timeout"
		case <-tick.C:
			if cur := n.Load(); cur != lastN {
				last, lastN = time.Now(), cur
			} else if time.Since(last) > stall {
				cancel()
				return cur, int(time.Since(t0).Milliseconds()), true
			}
		case <-c.Done():
			return n.Load(), int(time.Since(t0).Milliseconds()), true
		}
	}
}
