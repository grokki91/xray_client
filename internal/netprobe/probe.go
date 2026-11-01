package netprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TCPResult — P1: TCP до порта.
type TCPResult struct {
	Outcome string `json:"outcome"` // ok | timeout | refused | unreachable | reset | error | budget
	Ms      int    `json:"ms"`
}

// ProbeTCP открывает и сразу закрывает TCP-соединение. budget != nil — соединение к серверу.
func ProbeTCP(ctx context.Context, d *Dialer, b *Budget, addr string) TCPResult {
	if b != nil {
		if err := b.Acquire(TCP); err != nil {
			return TCPResult{Outcome: "budget"}
		}
	}
	t0 := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	ms := int(time.Since(t0).Milliseconds())
	if err != nil {
		return TCPResult{Outcome: Classify(err), Ms: ms}
	}
	_ = c.Close()
	return TCPResult{Outcome: "ok", Ms: ms}
}

// ProbeBanner — P6: TCP к addr и до wait ждёт первые байты сервера (SSH-сервер сам шлёт
// «SSH-2.0-…»). banner — ответ начинается с prefix: соединение принял именно этот сервер, а не
// промежуточный узел. Текст ответа не сохраняется. budget != nil — соединение к серверу.
func ProbeBanner(ctx context.Context, d *Dialer, b *Budget, addr, prefix string, wait time.Duration) (TCPResult, bool) {
	if b != nil {
		if err := b.Acquire(TCP); err != nil {
			return TCPResult{Outcome: "budget"}, false
		}
	}
	t0 := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	ms := int(time.Since(t0).Milliseconds())
	if err != nil {
		return TCPResult{Outcome: Classify(err), Ms: ms}, false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, len(prefix))
	n, _ := io.ReadFull(c, buf)
	return TCPResult{Outcome: "ok", Ms: ms}, prefix != "" && string(buf[:n]) == prefix
}

// TLSResult — P2/N4: TLS-хендшейк с отпечатком chrome.
type TLSResult struct {
	// cert — сертификат получен (CertValid — валиден для SNI); tcp_* — TCP не установился;
	// hello_timeout — после ClientHello ни байта; reset_after_hello / eof_after_hello — обрыв без
	// ответа; tls_alert — сервер ответил alert; tls_error — иное; budget — сверх бюджета.
	Outcome   string `json:"outcome"`
	Ms        int    `json:"ms"`
	CertValid bool   `json:"cert_valid"`
	BytesIn   int64  `json:"bytes_in"`
	ALPN      string `json:"alpn,omitempty"`
	Detail    string `json:"-"` // текст ошибки — только в память, наружу через redact
}

// ProbeTLS — TCP к addr, затем ClientHello uTLS HelloChrome_Auto с SNI. Сертификат проверяется
// по системным корням (Windows CryptoAPI) — так видно, отдал ли адрес настоящую маску.
func ProbeTLS(ctx context.Context, d *Dialer, b *Budget, addr, sni string, timeout time.Duration) TLSResult {
	if b != nil {
		if err := b.Acquire(TLS); err != nil {
			return TLSResult{Outcome: "budget"}
		}
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t0 := time.Now()
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSResult{Outcome: "tcp_" + Classify(err), Ms: int(time.Since(t0).Milliseconds()), Detail: err.Error()}
	}
	cc := &CountConn{Conn: raw}
	defer cc.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = cc.SetDeadline(dl)
	}
	u := utls.UClient(cc, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	err = u.HandshakeContext(ctx)
	r := TLSResult{Ms: int(time.Since(t0).Milliseconds()), BytesIn: cc.In.Load()}
	if err != nil {
		r.Detail = err.Error()
		cls := Classify(err)
		switch {
		case r.BytesIn == 0 && cls == "timeout":
			r.Outcome = "hello_timeout"
		case r.BytesIn == 0 && cls == "reset":
			r.Outcome = "reset_after_hello"
		case r.BytesIn == 0 && cls == "eof":
			r.Outcome = "eof_after_hello"
		case strings.Contains(strings.ToLower(err.Error()), "alert"):
			r.Outcome = "tls_alert"
		case cls == "timeout":
			r.Outcome = "hello_timeout"
		default:
			r.Outcome = "tls_error"
		}
		return r
	}
	st := u.ConnectionState()
	r.Outcome = "cert"
	r.ALPN = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		inter := x509.NewCertPool()
		for _, c := range st.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, verr := st.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter})
		r.CertValid = verr == nil
	}
	return r
}

// HTTPResult — эталонный хост (N1, B3).
type HTTPResult struct {
	Name    string    `json:"name"`
	Region  string    `json:"region"`
	OK      bool      `json:"ok"`
	Status  int       `json:"status"`
	Ms      int       `json:"ms"`
	Outcome string    `json:"outcome"`
	Date    time.Time `json:"-"` // заголовок Date — для оценки часов (W7)
	Mid     time.Time `json:"-"` // середина запроса по часам ПК
}

// HTTPCheck — ожидание ответа.
type HTTPCheck struct {
	Name, URL, Region string
	ExpectStatus      int
	ExpectStatusMax   int
	ExpectBody        string
}

// HTTPClient — клиент без системного прокси (режим «системный прокси» клиента иначе завернёт
// пробы в тоннель) и с привязанным диалером.
func HTTPClient(d *Dialer, resolver *net.Resolver, timeout time.Duration) *http.Client {
	nd := d.NetDialer()
	nd.Resolver = resolver
	tr := &http.Transport{Proxy: nil, DialContext: nd.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ProbeHTTP — GET и проверка ожидания.
func ProbeHTTP(ctx context.Context, c *http.Client, chk HTTPCheck) HTTPResult {
	r := HTTPResult{Name: chk.Name, Region: chk.Region}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chk.URL, nil)
	if err != nil {
		r.Outcome = "error"
		return r
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	t0 := time.Now()
	resp, err := c.Do(req)
	r.Ms = int(time.Since(t0).Milliseconds())
	r.Mid = t0.Add(time.Since(t0) / 2)
	if err != nil {
		r.Outcome = Classify(err)
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	r.Status = resp.StatusCode
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		r.Date = d
	}
	switch {
	case chk.ExpectBody != "":
		r.OK = resp.StatusCode == 200 && strings.Contains(string(body), chk.ExpectBody)
	case chk.ExpectStatus != 0:
		r.OK = resp.StatusCode == chk.ExpectStatus
	case chk.ExpectStatusMax != 0:
		r.OK = resp.StatusCode > 0 && resp.StatusCode <= chk.ExpectStatusMax
	default:
		r.OK = resp.StatusCode < 500
	}
	r.Outcome = "ok"
	if !r.OK {
		r.Outcome = "unexpected"
	}
	return r
}

// ClockOffset — оценка расхождения часов ПК (секунды, ПК минус точное время) по заголовкам
// Date эталонов: медиана. ok=false — данных нет.
func ClockOffset(rs []HTTPResult) (float64, bool) {
	var ds []float64
	for _, r := range rs {
		if !r.Date.IsZero() && !r.Mid.IsZero() {
			ds = append(ds, r.Mid.Sub(r.Date).Seconds())
		}
	}
	if len(ds) == 0 {
		return 0, false
	}
	for i := 1; i < len(ds); i++ {
		for j := i; j > 0 && ds[j] < ds[j-1]; j-- {
			ds[j], ds[j-1] = ds[j-1], ds[j]
		}
	}
	m := ds[len(ds)/2]
	// Date — с точностью до секунды: смещение меньше 2 с — шум.
	if m > -2 && m < 2 {
		m = 0
	}
	return float64(int(m)), true
}

// LookupHost — адреса имени через резолвер; IP возвращается как есть.
func LookupHost(ctx context.Context, r *net.Resolver, host string) ([]net.IP, error) {
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if a.IP.To4() != nil {
			out = append([]net.IP{a.IP}, out...)
		} else {
			out = append(out, a.IP)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("нет адресов")
	}
	return out, nil
}
