package engine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/refcore"
)

// phase1 — интернет, DNS провайдера, настоящий адрес маски. К серверу — ничего.
func (r *run) phase1(ctx context.Context) {
	h := r.hosts()
	hc := netprobe.HTTPClient(r.dial, r.res, 8*time.Second)
	r.step(1, "N1", "Интернет: эталонные сайты", "run", "")
	results := make([]netprobe.HTTPResult, len(h.Internet))
	var wg sync.WaitGroup
	for i, x := range h.Internet {
		wg.Add(1)
		go func(i int, chk netprobe.HTTPCheck) {
			defer wg.Done()
			results[i] = netprobe.ProbeHTTP(ctx, hc, chk)
		}(i, netprobe.HTTPCheck{Name: x.Name, URL: x.URL, Region: x.Region, ExpectStatus: x.ExpectStatus,
			ExpectStatusMax: x.ExpectStatusMax, ExpectBody: x.ExpectBody})
	}
	// Параллельно — DNS провайдера и маска по своему адресу.
	var dnsCmp *netprobe.DNSCompare
	if h.DNSProbe.Name != "" && len(h.DNSProbe.Resolvers) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := netprobe.CompareDNS(ctx, r.dial, hc, h.DNSProbe.Name, h.DNSProbe.Resolvers[0], h.DNSProbe.DoH)
			dnsCmp = &c
		}()
	}
	var mask *netprobe.TLSResult
	var maskErr string
	if r.prof != nil && r.prof.SNI != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := netprobe.LookupHost(ctx, r.res, r.prof.SNI)
			if err != nil {
				maskErr = "имя маски не резолвится"
				return
			}
			t := netprobe.ProbeTLS(ctx, r.dial, nil, net.JoinHostPort(ips[0].String(), "443"), r.prof.SNI, 10*time.Second)
			mask = &t
		}()
	}
	wg.Wait()

	okN, foreign, ru := 0, false, false
	var parts []string
	for _, x := range results {
		if x.OK {
			okN++
			if x.Region == "ru" {
				ru = true
			} else {
				foreign = true
			}
		}
		parts = append(parts, fmt.Sprintf("%s — %s", x.Name, yesno(x.OK, "ок", x.Outcome)))
	}
	n1 := map[string]any{"ok": okN > 0, "hosts_ok": okN, "hosts": len(results), "foreign_ok": foreign, "ru_ok": ru, "bound": r.dial.IfIndex > 0}
	r.put(evidence.Evidence{ID: "N1", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: n1,
		Summary: fmt.Sprintf("Эталонные сайты: %d из %d (%s)", okN, len(results), strings.Join(parts, "; "))})
	r.step(1, "N1", "Интернет: эталонные сайты", yesno(okN > 0, "ok", "fail"), fmt.Sprintf("%d из %d", okN, len(results)))
	r.put(evidence.Evidence{ID: "N2", Source: evidence.FromNetwork, Reliability: evidence.High,
		Facts:   map[string]any{"ru_ok": ru, "foreign_ok": foreign},
		Summary: fmt.Sprintf("Российский эталон: %s; зарубежные: %s", yesno(ru, "открывается", "нет"), yesno(foreign, "открываются", "нет"))})

	if off, ok := netprobe.ClockOffset(results); ok {
		r.put(evidence.Evidence{ID: "W7", Source: evidence.FromNetwork, Reliability: evidence.High,
			Facts:   map[string]any{"offset_s": off, "synced": r.facts.TimeSynced},
			Summary: fmt.Sprintf("Часы ПК: %+.0f с к точному времени (заголовки Date эталонов)%s", off, yesno(r.facts.Collected && !r.facts.TimeSynced, "; синхронизация Windows выключена", ""))})
	}
	if dnsCmp != nil {
		var a []string
		for _, x := range dnsCmp.Answers {
			a = append(a, x.Method+": "+x.Rcode)
		}
		r.put(evidence.Evidence{ID: "N3", Source: evidence.FromNetwork, Reliability: evidence.Medium,
			Facts: map[string]any{"mismatch": dnsCmp.Mismatch, "nxdomain_udp_only": dnsCmp.NXDomainUDPOnly},
			Summary: yesno(dnsCmp.Mismatch, "DNS по UDP/53 отвечает иначе, чем TCP/53 и DoH — подмена провайдером", "DNS: UDP, TCP и DoH согласны") +
				" (" + strings.Join(a, ", ") + ")"})
	}
	switch {
	case mask != nil:
		ok := mask.Outcome == "cert" && mask.CertValid
		r.put(evidence.Evidence{ID: "N4", Source: evidence.FromNetwork, Reliability: evidence.High,
			Facts:   map[string]any{"ok": ok, "stage": mask.Outcome, "cert_valid": mask.CertValid, "ms": mask.Ms},
			Summary: yesno(ok, fmt.Sprintf("Сайт-маска по своему адресу открывается (%d мс)", mask.Ms), "Сайт-маска по своему адресу: "+tlsText(mask.Outcome, mask.CertValid))})
	case maskErr != "":
		r.put(evidence.Evidence{ID: "N4", Source: evidence.FromNetwork, Reliability: evidence.Medium,
			Facts: map[string]any{"ok": false, "stage": "dns"}, Summary: "Сайт-маска: " + maskErr})
	}
	if okN > 0 && ctx.Err() == nil {
		r.clientTunnel(ctx)
	}
}

// phase2 — сервер снаружи, в бюджете этого сервера. Порядок экономит соединения: TCP (P1) →
// эталон (P3, при необходимости P3m) → обычный TLS с SNI маски (P2) — только если эталон не
// прошёл: тогда он отличает «сервер жив, профиль не принят» от «ClientHello режется». TCP не
// установился — эталону и TLS не на чем работать: один повтор через 30 с (P4).
func (r *run) phase2(ctx context.Context) {
	if r.prof == nil {
		r.step(2, "P", "Сервер снаружи", "skip", "нет профиля")
		return
	}
	key := r.prof.ServerKey()
	r.budget = r.e.Budget(key)
	r.budgetStart = r.budget.Usage()
	if r.h.Budget != nil {
		r.budget.OnChange(r.h.Budget)
		r.h.Budget(r.budget.Usage())
	}
	if r.e.Store != nil {
		if lp := r.e.Store.LoadBudget().For(key).LastPath; !lp.IsZero() && r.now().Sub(lp) < 2*time.Minute {
			r.note("Прошлый сеанс меньше 2 минут назад закончился вердиктом о пути: частые пробы сами похожи на шторм — лучше подождать")
		}
	}
	ips, err := netprobe.LookupHost(ctx, r.res, r.prof.Address)
	if err != nil {
		r.put(evidence.Evidence{ID: "P1", Source: evidence.FromNetwork, Reliability: evidence.High,
			Facts: map[string]any{"outcome": "dns"}, Summary: "Адрес сервера из профиля не резолвится"})
		r.step(2, "P1", "TCP до сервера", "fail", "имя сервера не резолвится")
		return
	}
	r.serverIP = ips
	ip := ips[0]
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(r.prof.Port))
	r.routeEvidence(ip.String())

	r.step(2, "P1", "TCP до сервера", "run", "")
	if !r.slot(ctx, netprobe.TCP, "P1", "TCP до сервера") {
		if ctx.Err() != nil {
			return
		}
		r.put(evidence.Evidence{ID: "P1", Source: evidence.FromNetwork, Reliability: evidence.High,
			Facts: map[string]any{"outcome": "budget"}, Summary: "TCP до порта сервера: " + tcpText(netprobe.TCPResult{Outcome: "budget"})})
		r.step(2, "P1", "TCP до сервера", "skip", tcpText(netprobe.TCPResult{Outcome: "budget"}))
		return
	}
	p1 := netprobe.ProbeTCP(ctx, r.dial, r.budget, addr)
	r.put(evidence.Evidence{ID: "P1", Source: evidence.FromNetwork, Reliability: evidence.High,
		Facts: map[string]any{"outcome": p1.Outcome, "ms": p1.Ms}, Summary: "TCP до порта сервера: " + tcpText(p1)})
	r.step(2, "P1", "TCP до сервера", stepStatus(p1.Outcome == "ok"), tcpText(p1))
	if ctx.Err() != nil || p1.Outcome == "budget" {
		return
	}
	if p1.Outcome != "ok" {
		r.step(2, "P3", refTitle, "skip", "не выполнялось: TCP до сервера не установился")
		r.repeat(ctx, addr)
		return
	}

	if r.o.Reference && r.prof.IsRealityVLESS() {
		if o := r.reference(ctx); o == "ok" || o == "budget" || ctx.Err() != nil {
			return
		}
	}
	r.step(2, "P2", "TLS к серверу с SNI маски", "run", "")
	if !r.slot(ctx, netprobe.TLS, "P2", "TLS к серверу с SNI маски") {
		r.step(2, "P2", "TLS к серверу с SNI маски", "skip", tlsText("budget", false))
		return
	}
	p2 := netprobe.ProbeTLS(ctx, r.dial, r.budget, addr, r.prof.SNI, 10*time.Second)
	p2o := tlsOutcome(p2)
	r.put(evidence.Evidence{ID: "P2", Source: evidence.FromNetwork, Reliability: evidence.High,
		Facts:   map[string]any{"outcome": p2o, "cert_valid": p2.CertValid, "ms": p2.Ms, "bytes_in": p2.BytesIn},
		Summary: "Обычный TLS (fp chrome, SNI маски) на адрес сервера: " + tlsText(p2.Outcome, p2.CertValid)})
	r.step(2, "P2", "TLS к серверу с SNI маски", stepStatus(p2o == "mask_cert"), tlsText(p2.Outcome, p2.CertValid))
	if isHelloFail(p2o) {
		r.repeat(ctx, addr)
	}
}

const refTitle = "Эталонное ядро Xray с профилем (fp chrome)"

// repeat — P4: один повтор через 30 с, если первая попытка не прошла (снимает единичную потерю).
func (r *run) repeat(ctx context.Context, addr string) {
	if r.o.SkipRepeat || ctx.Err() != nil {
		return
	}
	r.stepWait(2, "P4", "Повтор через 30 с", 30, "повтор через 30 с: единичную потерю пакета не путать с блокировкой")
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	r.step(2, "P4", "Повтор через 30 с", "run", "")
	if !r.slot(ctx, netprobe.TCP, "P4", "Повтор через 30 с") {
		r.step(2, "P4", "Повтор через 30 с", "skip", tcpText(netprobe.TCPResult{Outcome: "budget"}))
		return
	}
	t := netprobe.ProbeTCP(ctx, r.dial, r.budget, addr)
	f := map[string]any{"tcp": t.Outcome}
	sum := "Повтор: TCP — " + tcpText(t)
	if t.Outcome == "ok" && r.budget.Can(netprobe.TLS) {
		s := netprobe.ProbeTLS(ctx, r.dial, r.budget, addr, r.prof.SNI, 10*time.Second)
		f["tls"] = tlsOutcome(s)
		sum += "; TLS — " + tlsText(s.Outcome, s.CertValid)
	} else if t.Outcome != "ok" {
		f["tls"] = "tcp_" + t.Outcome
	}
	r.put(evidence.Evidence{ID: "P4", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: f, Summary: sum})
	r.step(2, "P4", "Повтор через 30 с", stepStatus(t.Outcome == "ok"), sum)
}

// slot — дождаться слота бюджета сервера для пробы. Пауза до 65 с — сама (шаг ведёт отсчёт),
// дольше — с согласия пользователя. false — проба не выполняется.
func (r *run) slot(ctx context.Context, k netprobe.Kind, id, title string) bool {
	w := r.budget.Wait(k)
	if w <= 0 {
		return true
	}
	secs := int(w.Seconds()) + 1
	if w > 65*time.Second && !r.confirm(ctx, Consent{Kind: "wait", Text: fmt.Sprintf("К этому серверу только что было несколько проверок. "+
		"Чтобы диагностика сама не выглядела как шторм, приложение открывает к серверу не больше %d TLS-соединений в минуту и %d TCP за 5 минут. "+
		"Следующая проба — через %s. Подождать?", r.budget.TLSMax, r.budget.TCPMax, humanSecs(secs))}) {
		r.note(title + ": пропущено — лимит проб к серверу (повторите диагностику через " + humanSecs(secs) + ")")
		return false
	}
	r.stepWait(2, id, title, secs, fmt.Sprintf("пауза %s: не больше %d TLS к серверу в минуту", humanSecs(secs), r.budget.TLSMax))
	select {
	case <-ctx.Done():
		return false
	case <-time.After(w + time.Second):
	}
	r.step(2, id, title, "run", "")
	return true
}

func humanSecs(s int) string {
	if s < 90 {
		return fmt.Sprintf("%d с", s)
	}
	return fmt.Sprintf("%d мин %02d с", s/60, s%60)
}

// clientTunnel — C10: работает ли сам клиент — запрос через его локальный прокси (тот же путь,
// что у браузера через VPN). Это единственная проверка, которая видит «клиент подключён и
// трафик идёт», а не только «сервер и профиль исправны».
func (r *run) clientTunnel(ctx context.Context) {
	if r.active == nil || r.e.ProbeClient == nil {
		return
	}
	cr := r.active
	name := r.sess.ClientName
	title := "Подключение через " + cr.a.Title()
	port := cr.d.ProxyPort
	via := "proxy"
	if !cr.state.CoreListening {
		// Режим VPN без локального прокси: трафик Windows уже идёт в TUN клиента.
		if cr.state.TunAdapter && r.facts.DefaultViaTUN {
			port, via = 0, "tun"
		} else {
			r.put(evidence.Evidence{ID: "C10", Source: evidence.FromClient, Reliability: evidence.High,
				Facts:   map[string]any{"listening": false, "outcome": "not_listening", "port": port},
				Summary: fmt.Sprintf("%s не подключён: локальный прокси :%d не слушает", name, port)})
			r.step(1, "C10", title, "skip", "клиент не подключён")
			return
		}
	}
	r.step(1, "C10", title, "run", "")
	h := r.hosts()
	res := r.e.ProbeClient(ctx, port, h.Tunnel.Probe204, h.Tunnel.Download, h.Tunnel.DownloadBytes)
	f := map[string]any{"listening": true, "outcome": res.Outcome, "ms_204": res.Ms204, "bytes": res.Bytes, "via": via, "port": port}
	if res.Error != "" {
		f["error"] = res.Error
	}
	where := fmt.Sprintf("через локальный прокси :%d", port)
	if via == "tun" {
		where = "через TUN клиента"
	}
	var sum, note, st string
	switch res.Outcome {
	case "ok":
		sum = fmt.Sprintf("%s: трафик через клиент идёт (%s) — 204 за %d мс, скачано %d КБ", name, where, res.Ms204, res.Bytes/1024)
		note, st = fmt.Sprintf("трафик идёт: 204 за %d мс", res.Ms204), "ok"
	case "freeze":
		sum = fmt.Sprintf("%s: через клиент 204 получен, но загрузка встала на %d КБ", name, res.Bytes/1024)
		note, st = "загрузка встала", "warn"
	default:
		sum = fmt.Sprintf("%s запущен, но запрос через него не прошёл (%s): %s", name, where, clientErrText(res))
		note, st = "трафик не идёт: "+clientErrText(res), "fail"
	}
	r.put(evidence.Evidence{ID: "C10", Source: evidence.FromClient, Reliability: evidence.High, Facts: f, Summary: sum})
	r.step(1, "C10", title, st, note)
}

func clientErrText(c netprobe.ClientResult) string {
	switch c.Error {
	case "timeout":
		return "таймаут"
	case "refused":
		return "прокси отказал в соединении"
	case "reset", "eof":
		return "соединение оборвано"
	case "status":
		return fmt.Sprintf("ответ %d вместо 204", c.Status)
	}
	return "ошибка"
}

func isHelloFail(o string) bool {
	switch o {
	case "hello_timeout", "reset_after_hello", "eof_after_hello", "tcp_timeout":
		return true
	}
	return false
}

// routeEvidence — W2: через какой адаптер ОС отправит пакет серверу.
func (r *run) routeEvidence(ip string) {
	if !r.facts.Collected {
		return
	}
	idx := osw.BestInterface(ip)
	a := r.facts.Adapter(idx)
	if a == nil {
		return
	}
	viaTun := a.Kind == "tun" || a.Kind == "vpn"
	// Петля — маршрут к серверу ловит чужой TUN/VPN; свой TUN клиент обходит привязкой ядра.
	clientTun := r.active != nil && r.active.d.TUN
	loop := viaTun && (!clientTun || a.Kind == "vpn")
	r.put(evidence.Evidence{ID: "W2", Source: evidence.FromOS, Reliability: evidence.Medium,
		Facts:   map[string]any{"iface_kind": a.Kind, "via_tun": viaTun, "loop": loop},
		Summary: "Маршрут к серверу: через " + a.Kind + yesno(loop, " — чужой туннель перехватывает соединение с сервером", "")})
}

// reference — P3 (fp chrome) и, если клиент X25519MLKEM768 не шлёт, P3m (fp edge — без него):
// одна и та же попытка с одним отличием — доля X25519MLKEM768. Возвращает исход P3.
func (r *run) reference(ctx context.Context) string {
	h := r.hosts()
	extra := map[string]string{}
	if r.active != nil && r.active.d.TestURL != "" {
		extra["latency_url"] = r.active.d.TestURL
	}
	if h.Tunnel.RUProbe != "" {
		extra["ru"] = h.Tunnel.RUProbe
	}
	opts := func(fp string, ex map[string]string) refcore.Options {
		return refcore.Options{Profile: r.prof, Fingerprint: fp, ServerIPs: r.serverIP, Dialer: r.dial, Resolver: r.res, Budget: r.budget,
			Probe204: h.Tunnel.Probe204, Download: h.Tunnel.Download, DownloadBytes: h.Tunnel.DownloadBytes, Extra: ex}
	}
	r.step(2, "P3", refTitle, "run", "")
	if !r.slot(ctx, netprobe.TLS, "P3", refTitle) {
		if ctx.Err() != nil {
			return "cancelled"
		}
		r.put(evidence.Evidence{ID: "P3", Source: evidence.FromReference, Reliability: evidence.High,
			Facts: map[string]any{"outcome": "budget"}, Summary: refText(refcore.Result{Outcome: "budget"})})
		r.step(2, "P3", refTitle, "skip", refText(refcore.Result{Outcome: "budget"}))
		return "budget"
	}
	res := r.e.RunRef(ctx, opts("chrome", extra))
	for _, l := range res.Logs {
		if strings.Contains(l, "REALITY") || strings.Contains(l, "failed") || strings.Contains(l, "x509") {
			r.sess.Logs = append(r.sess.Logs, r.red.String("эталон: "+l))
		}
	}
	f := map[string]any{"outcome": res.Outcome, "freeze": res.Freeze, "status": res.Status, "ms_204": res.Ms204, "bytes": res.Bytes,
		"socket_in": res.SocketIn, "conns": res.Conns}
	r.put(evidence.Evidence{ID: "P3", Source: evidence.FromReference, Reliability: evidence.High, Facts: f, Summary: refText(res)})
	r.step(2, "P3", refTitle, stepStatus(res.Outcome == "ok"), refText(res))
	if res.Outcome == "ok" {
		r.put(evidence.Evidence{ID: "B1", Source: evidence.FromReference, Reliability: evidence.High,
			Facts: map[string]any{"dns_ok": true}, Summary: "Имена за тоннелем разрешаются (запрос по имени через сервер прошёл)"})
		if u, ok := extra["latency_url"]; ok {
			okT := res.Extra["latency_url"]
			r.put(evidence.Evidence{ID: "B3", Source: evidence.FromReference, Reliability: evidence.High,
				Facts: map[string]any{"tunnel_ok": okT}, Summary: "URL теста задержки клиента через тоннель: " + yesno(okT, "открывается", "не открывается") + " (" + u + ")"})
		}
		if _, ok := extra["ru"]; ok {
			okR := res.Extra["ru"]
			r.put(evidence.Evidence{ID: "B2", Source: evidence.FromReference, Reliability: evidence.High,
				Facts: map[string]any{"ran": true, "ru_ok": okR}, Summary: "Российский сайт через тоннель: " + yesno(okR, "открывается", "закрыт (правило сервера или блокировка)")})
		}
	}
	// P3m — только если ответ что-то меняет: клиент сам X25519MLKEM768 не шлёт.
	cx := r.set.Get("CX")
	needM := res.Outcome == "ok" && cx != nil && (cx.Str("core_mlkem") == "false" || cx.Str("fp_mlkem") == "false")
	if !needM || ctx.Err() != nil {
		return res.Outcome
	}
	const mTitle = "Эталон без X25519MLKEM768 (fp edge)"
	r.step(2, "P3m", mTitle, "run", "")
	if !r.slot(ctx, netprobe.TLS, "P3m", mTitle) {
		r.step(2, "P3m", mTitle, "skip", "пропущено: лимит проб к серверу")
		return res.Outcome
	}
	m := r.e.RunRef(ctx, opts("edge", nil))
	r.put(evidence.Evidence{ID: "P3m", Source: evidence.FromReference, Reliability: evidence.High,
		Facts:   map[string]any{"outcome": m.Outcome, "conns": m.Conns},
		Summary: "Тот же профиль без X25519MLKEM768 (fp edge): " + refText(m)})
	client := "клиент"
	if r.sess.ClientName != "" {
		client = r.sess.ClientName
	}
	switch m.Outcome {
	case "ok":
		r.step(2, "P3m", mTitle, "ok", "сервер пускает и без X25519MLKEM768 — "+client+" с ним совместим")
	case "real_cert":
		r.step(2, "P3m", mTitle, "fail", "сервер не пускает ClientHello без X25519MLKEM768 — "+client+" не подключится")
	default:
		r.step(2, "P3m", mTitle, "warn", refText(m))
	}
	return res.Outcome
}

func stepStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}

func tcpText(t netprobe.TCPResult) string {
	switch t.Outcome {
	case "ok":
		return fmt.Sprintf("соединение установлено за %d мс", t.Ms)
	case "timeout":
		return "таймаут: ответа на SYN нет"
	case "refused":
		return "отказ (RST): порт закрыт"
	case "unreachable":
		return "сеть недоступна"
	case "budget":
		return "пропущено: лимит проб к серверу"
	}
	return t.Outcome
}

func tlsOutcome(t netprobe.TLSResult) string {
	if t.Outcome == "cert" {
		if t.CertValid {
			return "mask_cert"
		}
		return "other_cert"
	}
	return t.Outcome
}

func tlsText(o string, valid bool) string {
	switch o {
	case "cert":
		if valid {
			return "получен настоящий сертификат маски"
		}
		return "сертификат получен, но не подходит к SNI маски"
	case "hello_timeout":
		return "после ClientHello — тишина"
	case "reset_after_hello":
		return "после ClientHello — сброс (RST)"
	case "eof_after_hello":
		return "после ClientHello соединение закрыто"
	case "tls_alert":
		return "ответ TLS alert"
	case "tcp_timeout":
		return "TCP не установился (таймаут)"
	case "tcp_refused":
		return "TCP: отказ (RST)"
	case "tcp_unreachable":
		return "TCP: сеть недоступна"
	case "budget":
		return "пропущено: лимит проб к серверу"
	}
	return o
}

func refText(r refcore.Result) string {
	switch r.Outcome {
	case "ok":
		return fmt.Sprintf("тоннель поднят: 204 за %d мс, скачано %d КБ без заморозки", r.Ms204, r.Bytes/1024)
	case "real_cert":
		return "сервер отдал сайт-маску: REALITY не узнал клиента"
	case "handshake_timeout":
		return "TCP есть, ответа на ClientHello нет"
	case "tcp_timeout":
		return "TCP до сервера не установился"
	case "tcp_refused":
		return "TCP: отказ (RST)"
	case "reset", "eof":
		return "соединение оборвано до ответа сервера"
	case "closed_after_handshake":
		return "рукопожатие прошло, но сервер закрыл запрос (UUID или путь)"
	case "freeze":
		return fmt.Sprintf("тоннель поднят, но данные встали (%s, принято %d КБ)", freezeText(r.Freeze), r.SocketIn/1024)
	case "fp_unsupported":
		return "отпечаток не поддерживает TLS 1.3"
	case "budget":
		return "пропущено: лимит проб к серверу"
	case "config_error":
		return "профиль не собирается в конфиг Xray"
	}
	return "ошибка: " + r.Outcome
}

func freezeText(f string) string {
	switch f {
	case "post":
		return "сразу после рукопожатия"
	case "mid":
		return "на 1–10 КБ"
	case "f16":
		return "на 10–32 КБ"
	case "late":
		return "после 32 КБ"
	}
	return f
}
