// Package refcore — эталонная проба: Xray-core как библиотека выполняет одну настоящую попытку
// VLESS+REALITY+XHTTP с профилем пользователя (docs/architecture.md §3.2).
//
// Эталон прошёл, а клиент пишет «таймаут» — причина в клиенте. Эталон не прошёл — в сети,
// сервере или профиле, и по стадии видно, где. Ядро поднимается в процессе на время пробы: без
// inbound, без локального SOCKS, без изменения системного прокси. Все сокеты ядра идут через
// диалер приложения: соединения к серверу списываются с бюджета и привязываются к физическому
// интерфейсу (мимо TUN клиента), байты считаются — отсюда стадия обрыва и класс заморозки.
package refcore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport/internet"

	// Только то, что нужно клиенту VLESS+REALITY+XHTTP/TCP.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"

	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/profile"
)

// Options — одна проба.
type Options struct {
	Profile     *profile.Profile
	Fingerprint string   // переопределение fp: chrome (P3), edge (P3m — без X25519MLKEM768)
	ServerIPs   []net.IP // адреса сервера (уже разрешённые): соединения к ним — в бюджет
	Dialer      *netprobe.Dialer
	Resolver    *net.Resolver
	Budget      *netprobe.Budget

	Probe204      string // URL через тоннель, ожидается 204
	Download      string // URL через тоннель для классов заморозки
	DownloadBytes int
	Extra         map[string]string // имя → URL: дополнительные запросы через тот же тоннель (B2, B3)

	Timeout time.Duration // на всю пробу; по умолчанию 40 с
	Stall   time.Duration // нет прогресса — заморозка; по умолчанию 8 с
}

// Result — исход.
type Result struct {
	// ok | real_cert | handshake_timeout | tcp_timeout | tcp_refused | tcp_unreachable | reset | eof |
	// closed_after_handshake | fp_unsupported | freeze | http_error | config_error | budget | error
	Outcome    string          `json:"outcome"`
	Freeze     string          `json:"freeze"` // none | post | mid | f16 | late
	Status     int             `json:"status"`
	Ms204      int             `json:"ms_204"`
	Bytes      int64           `json:"bytes"`       // скачано через тоннель
	SocketIn   int64           `json:"socket_in"`   // принято от сервера на уровне TCP
	SocketOut  int64           `json:"socket_out"`  // отправлено серверу
	Conns      int             `json:"conns"`       // сокетов к серверу
	DownloadMs int             `json:"download_ms"` // время скачивания
	Extra      map[string]bool `json:"extra,omitempty"`
	Logs       []string        `json:"-"` // сообщения ядра — наружу только через redact
	Err        string          `json:"-"`
}

// ─── Системный диалер ядра ───────────────────────────────────────────────────

type probeState struct {
	opts    Options
	servers map[string]bool // "ip:port"
	mu      sync.Mutex
	conns   []*trackedConn
	dialErr []string
	logs    []string
}

type trackedConn struct {
	*netprobe.CountConn
	server bool
	t0     time.Time
}

var (
	current     atomic.Pointer[probeState]
	installOnce sync.Once
	runMu       sync.Mutex // одна проба за раз: диалер и журнал ядра глобальны в процессе
)

type sysDialer struct{}

func (sysDialer) DestIpAddress() net.IP { return nil }

func (sysDialer) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	st := current.Load()
	network := dest.Network.SystemString()
	host := dest.Address.String()
	port := dest.Port.String()
	if dest.Address.Family().IsDomain() {
		r := net.DefaultResolver
		if st != nil && st.opts.Resolver != nil {
			r = st.opts.Resolver
		}
		ips, err := netprobe.LookupHost(ctx, r, host)
		if err != nil {
			return nil, err
		}
		host = ips[0].String()
	}
	addr := net.JoinHostPort(host, port)
	isServer := st != nil && st.servers[addr]
	var d *net.Dialer
	if isServer {
		// Каждый TCP к серверу у ядра — REALITY-хендшейк: списывается как TLS.
		if st.opts.Budget != nil {
			if err := st.opts.Budget.Acquire(netprobe.TLS); err != nil {
				return nil, err
			}
		}
		d = st.opts.Dialer.NetDialer()
	} else {
		d = &net.Dialer{Timeout: 10 * time.Second}
	}
	t0 := time.Now()
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		if isServer {
			st.mu.Lock()
			st.dialErr = append(st.dialErr, netprobe.Classify(err))
			st.mu.Unlock()
		}
		return nil, err
	}
	tc := &trackedConn{CountConn: &netprobe.CountConn{Conn: c}, server: isServer, t0: t0}
	if st != nil {
		st.mu.Lock()
		st.conns = append(st.conns, tc)
		st.mu.Unlock()
	}
	return tc, nil
}

type logSink struct{}

func (logSink) Handle(m log.Message) {
	if st := current.Load(); st != nil {
		st.mu.Lock()
		if len(st.logs) < 400 {
			st.logs = append(st.logs, m.String())
		}
		st.mu.Unlock()
	}
}

func install() {
	installOnce.Do(func() { internet.UseAlternativeSystemDialer(sysDialer{}) })
}

// ─── Проба ───────────────────────────────────────────────────────────────────

// Run выполняет пробу. Ошибки не возвращает: всё — в Result.Outcome.
func Run(ctx context.Context, o Options) Result {
	runMu.Lock()
	defer runMu.Unlock()
	install()
	if o.Timeout == 0 {
		o.Timeout = 40 * time.Second
	}
	if o.Stall == 0 {
		o.Stall = 8 * time.Second
	}
	if o.Dialer == nil {
		o.Dialer = &netprobe.Dialer{}
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	res := Result{Freeze: "none", Extra: map[string]bool{}}
	if o.Budget != nil && !o.Budget.Can(netprobe.TLS) {
		res.Outcome = "budget"
		return res
	}
	p := o.Profile
	if len(o.ServerIPs) == 0 {
		res.Outcome, res.Err = "config_error", "адрес сервера не разрешён"
		return res
	}
	st := &probeState{opts: o, servers: map[string]bool{}}
	for _, ip := range o.ServerIPs {
		st.servers[net.JoinHostPort(ip.String(), strconv.Itoa(p.Port))] = true
	}
	cfgJSON, err := ConfigJSON(p, o.ServerIPs[0].String(), o.Fingerprint)
	if err != nil {
		res.Outcome, res.Err = "config_error", err.Error()
		return res
	}
	jc, err := serial.DecodeJSONConfig(strings.NewReader(cfgJSON))
	if err != nil {
		res.Outcome, res.Err = "config_error", err.Error()
		return res
	}
	cc, err := jc.Build()
	if err != nil {
		res.Outcome, res.Err = classifyConfigErr(err), err.Error()
		return res
	}
	current.Store(st)
	defer current.Store(nil)
	inst, err := core.New(cc)
	if err != nil {
		res.Outcome, res.Err = classifyConfigErr(err), err.Error()
		return res
	}
	if err := inst.Start(); err != nil {
		res.Outcome, res.Err = "config_error", err.Error()
		return res
	}
	log.RegisterHandler(logSink{})
	defer func() {
		_ = inst.Close()
		st.mu.Lock()
		for _, c := range st.conns {
			_ = c.Close() // в т. ч. соединение «паука» REALITY после настоящего сертификата
		}
		st.mu.Unlock()
	}()

	hc := tunnelClient(ctx, inst)
	t0 := time.Now()
	status, err := get204(ctx, hc, o.Probe204)
	res.Ms204 = int(time.Since(t0).Milliseconds())
	res.Status = status
	if err == nil && status == http.StatusNoContent {
		if o.Download != "" {
			n, ms, stalled := download(ctx, hc, o.Download, o.DownloadBytes, o.Stall)
			res.Bytes, res.DownloadMs = n, ms
			if stalled {
				res.Outcome = "freeze"
			}
		}
		for name, u := range o.Extra {
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			s, err := getStatus(c, hc, u)
			cancel()
			res.Extra[name] = err == nil && s > 0 && s < 500
		}
		if res.Outcome == "" {
			res.Outcome = "ok"
		}
	} else if err != nil {
		res.Err = err.Error()
	}
	st.mu.Lock()
	for _, c := range st.conns {
		if c.server {
			res.Conns++
			res.SocketIn += c.In.Load()
			res.SocketOut += c.Out.Load()
		}
	}
	res.Logs = append([]string(nil), st.logs...)
	dialErr := append([]string(nil), st.dialErr...)
	st.mu.Unlock()
	if res.Outcome == "" {
		res.Outcome = classify(res, dialErr, err, status)
	}
	if res.Outcome == "freeze" {
		res.Freeze = FreezeClass(res.SocketIn)
	}
	return res
}

// reHTTPStatus — отказ сервера на запрос XHTTP («unexpected status 404», «status code: 403»),
// а не любые три цифры в логе (номер порта «:40404» — не статус).
var reHTTPStatus = regexp.MustCompile(`(?:unexpected status|status code|statuscode)\W{0,3}[45]\d\d\b`)

// FreezeClass — класс заморозки по байтам, принятым от сервера (границы — ui/health.py).
func FreezeClass(in int64) string {
	switch {
	case in < 1024:
		return "post"
	case in < 10240:
		return "mid"
	case in <= 32768:
		return "f16"
	}
	return "late"
}

func classify(r Result, dialErr []string, err error, status int) string {
	logs := strings.ToLower(strings.Join(r.Logs, "\n"))
	errs := ""
	if err != nil {
		errs = strings.ToLower(err.Error())
	}
	switch {
	case strings.Contains(logs, "received real certificate") || strings.Contains(logs, "processed invalid connection"):
		return "real_cert"
	case strings.Contains(logs, "x509:") || strings.Contains(errs, "x509:"):
		// Сервер не узнал клиента и отдал сайт-маску, но её сертификат не прошёл проверку
		// (самоподписанный, чужой, MITM по пути): REALITY-аутентификации не было в любом случае.
		return "real_cert"
	case strings.Contains(logs, "does not support tls 1.3") || strings.Contains(logs, "failed to get fingerprint"):
		return "fp_unsupported"
	case strings.Contains(errs, "budget") || strings.Contains(logs, "бюджет"):
		return "budget"
	}
	if r.Conns == 0 {
		if len(dialErr) > 0 {
			return "tcp_" + dialErr[len(dialErr)-1]
		}
		return "error"
	}
	if r.SocketIn == 0 {
		switch netprobe.Classify(err) {
		case "reset":
			return "reset"
		case "eof":
			return "eof"
		}
		return "handshake_timeout"
	}
	// Рукопожатие было (от сервера пришли байты), запрос через тоннель не прошёл.
	if status >= 400 || reHTTPStatus.MatchString(logs) ||
		strings.Contains(logs, "invalid request user id") || strings.Contains(logs, "failed to read response header") {
		return "closed_after_handshake"
	}
	if netprobe.Classify(err) == "timeout" {
		return "freeze"
	}
	if err != nil && (netprobe.Classify(err) == "eof" || netprobe.Classify(err) == "reset") {
		return "closed_after_handshake"
	}
	if status != 0 && status != http.StatusNoContent {
		return "http_error"
	}
	return "error"
}

func classifyConfigErr(err error) string {
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "fingerprint") {
		return "fp_unsupported"
	}
	return "config_error"
}

// tunnelClient — HTTP-клиент, каждое соединение которого — сессия VLESS через эталонное ядро.
func tunnelClient(ctx context.Context, inst *core.Instance) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
			host, ps, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			pn, _ := strconv.Atoi(ps)
			return core.Dial(c, inst, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(pn)))
		},
		// Сертификат эталона за тоннелем не предмет проверки: при сбитых часах ПК проверка
		// упала бы и выдала ложную «поломку тоннеля».
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 20 * time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get204(ctx context.Context, hc *http.Client, u string) (int, error) {
	c, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return getStatus(c, hc, u)
}

func getStatus(ctx context.Context, hc *http.Client, u string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// download читает до limit байт; stalled — не было прогресса stall.
func download(ctx context.Context, hc *http.Client, u string, limit int, stall time.Duration) (int64, int, bool) {
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
			return n.Load(), int(time.Since(t0).Milliseconds()), err != nil && netprobe.Classify(err) == "timeout"
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

// ConfigJSON — конфиг ядра: один outbound VLESS по профилю, адрес — уже разрешённый IP.
// xmux задан явно одним параметром: по умолчанию XHTTP открывает по соединению на каждую из
// первых maxConnections сессий — это лишние TLS к серверу сверх бюджета.
func ConfigJSON(p *profile.Profile, ip, fp string) (string, error) {
	if !p.IsRealityVLESS() {
		return "", errors.New("профиль не VLESS+REALITY")
	}
	if fp == "" {
		fp = p.Fingerprint
	}
	user := map[string]any{"id": strings.TrimSpace(p.UUID), "encryption": "none"}
	if p.Encryption != "" {
		user["encryption"] = p.Encryption
	}
	if p.Flow != "" {
		user["flow"] = p.Flow
	}
	rs := map[string]any{"serverName": p.SNI, "fingerprint": fp, "publicKey": strings.TrimSpace(p.PublicKey),
		"shortId": p.ShortID, "spiderX": p.SpiderX}
	if p.Mldsa65Verify != "" {
		rs["mldsa65Verify"] = p.Mldsa65Verify
	}
	ss := map[string]any{"security": "reality", "realitySettings": rs}
	switch p.Transport() {
	case "xhttp":
		xs := map[string]any{"path": p.Path, "xmux": map[string]any{"maxConcurrency": "16-32"}}
		if p.Host != "" {
			xs["host"] = p.Host
		}
		if p.Mode != "" {
			xs["mode"] = p.Mode
		}
		ss["network"] = "xhttp"
		ss["xhttpSettings"] = xs
	case "tcp":
		ss["network"] = "raw"
	default:
		return "", fmt.Errorf("транспорт %s эталон не проверяет", p.Transport())
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "debug", "access": "none"},
		"outbounds": []any{map[string]any{
			"protocol": "vless", "tag": "ref",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": ip, "port": p.Port, "users": []any{user}}}},
			"streamSettings": ss,
		}},
	}
	b, err := json.Marshal(cfg)
	return string(b), err
}
