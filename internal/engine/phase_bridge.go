package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/capture"
	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/redact"
)

// phase3 — сервер изнутри: мост SSH и/или импорт файлов xm.
func (r *run) phase3(ctx context.Context) {
	for _, im := range r.o.Imports {
		r.importFile(im)
	}
	if r.o.Bridge != "ssh" || r.o.SSHAlias == "" {
		if len(r.o.Imports) > 0 {
			r.sess.Bridge = "manual"
		}
		return
	}
	// Алиас от другого сервера: факты и окно были бы про другой сервер — сверка хэшей «уличила» бы
	// профиль, который здесь ни при чём.
	if r.aliasOther(r.o.SSHAlias) {
		r.note("Мост пропущен: SSH-алиас в «Настройках» ведёт на другой сервер (его HostName — не адрес профиля)")
		r.missing("bridge_other_server")
		r.step(3, "S1", "Сервер: мост SSH", "skip", "алиас — от другого сервера")
		return
	}
	if !r.confirm(ctx, Consent{Kind: "bridge", Text: "Подключиться к серверу по SSH (" + r.o.SSHAlias + ") и выполнить только чтение: " +
		"`sudo -n xm bridge facts`, `health`, `doctor`? На сервер уйдёт только случайная соль сессии."}) {
		r.note("Мост к серверу: пользователь отказался")
		return
	}
	r.sess.Bridge = "ssh"
	b, err := r.e.NewSSH(r.o.SSHAlias)
	if err != nil {
		r.bridgeFail(err)
		return
	}
	r.step(3, "S1", "Сервер: факты (xm bridge facts)", "run", "")
	f, err := b.Facts(ctx, r.red.SaltHex())
	if err != nil {
		r.bridgeFail(err)
		return
	}
	r.put(evidence.Evidence{ID: "S0", Source: evidence.FromNetwork, Reliability: evidence.High,
		Facts: map[string]any{"ssh": "ok"}, Summary: "SSH-мост: подключение к серверу есть"})
	r.factsEvidence(f, true)
	r.step(3, "S1", "Сервер: факты (xm bridge facts)", "ok", "Xray "+f.Xray.Version)

	r.step(3, "S2", "Сервер: журнал здоровья", "run", "")
	if h, err := b.Health(ctx); err == nil {
		r.healthEvidence(h)
		r.step(3, "S2", "Сервер: журнал здоровья", "ok", "")
	} else {
		r.step(3, "S2", "Сервер: журнал здоровья", "warn", r.red.String(err.Error()))
	}

	live := r.o.LiveSeconds
	what := "Нажмите «Подключить» в клиенте ОДИН раз в течение окна"
	if !r.confirm(ctx, Consent{Kind: "window", Text: fmt.Sprintf("Окно сервера %d с: сервер посмотрит, что приходит с этого ПК. %s. Приложение в это время к серверу не обращается.", live, what)}) {
		r.note("Окно xm doctor пропущено")
		return
	}
	r.step(3, "S3", "Сервер: окно xm doctor", "run", fmt.Sprintf("%d с", live))
	if r.h.Window != nil {
		go r.h.Window(ctx, what, live)
	}
	d, _, err := b.Doctor(ctx, live)
	if err != nil {
		r.step(3, "S3", "Сервер: окно xm doctor", "fail", r.red.String(err.Error()))
		return
	}
	if !r.doctorEvidence(d, "bridge") {
		r.step(3, "S3", "Сервер: окно xm doctor", "warn", "с другого сервера — не учтено")
		return
	}
	r.step(3, "S3", "Сервер: окно xm doctor", "ok", d.Verdict.Code)
}

// profileIPs — адреса сервера профиля: разрешённые в фазе 2, иначе IP из профиля или DNS.
func (r *run) profileIPs() []netip.Addr {
	var out []netip.Addr
	for _, ip := range r.serverIP {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	if len(out) > 0 || r.prof == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ips, _ := netprobe.LookupHost(ctx, r.res, r.prof.Address)
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// otherServer — IP не из адресов сервера профиля: вывод xm снят на другом сервере (у владельца
// их несколько, окно легко снять не там). Не IP или адрес профиля не узнать — не судим.
func (r *run) otherServer(addr string) bool {
	a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(addr), "[]"))
	if err != nil {
		return false
	}
	ips := r.profileIPs()
	for _, ip := range ips {
		if ip == a.Unmap() {
			return false
		}
	}
	return len(ips) > 0
}

// aliasOther — HostName SSH-алиаса — IP другого сервера (имя без DNS не сверить — не судим).
func (r *run) aliasOther(alias string) bool {
	if r.e.SSHConfig == nil || r.prof == nil {
		return false
	}
	cfg := r.e.SSHConfig()
	if cfg == nil {
		return false
	}
	h, _ := cfg.Resolve(alias)
	return r.otherServer(h)
}

func (r *run) bridgeFail(err error) {
	f := map[string]any{"error": bridgeCode(err)}
	switch code := f["error"]; {
	case code == "unreachable":
		f["ssh"] = "unreachable"
	case code == "host_key" || code == "auth" || code == "sudo" || code == "no_bridge" || code == "newer" || code == "older":
		f["ssh"] = "ok" // отказ ключа, sudo или xm — уже после соединения: адрес по SSH доступен
	}
	r.put(evidence.Evidence{ID: "S0", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: f, Summary: "SSH-мост: " + err.Error()})
	r.step(3, "S1", "Сервер: мост SSH", "fail", err.Error())
	r.note("Мост не сработал — ручной режим: на сервере `" + strings.Join(bridge.ManualCommands(r.o.LiveSeconds), "`, `") + "`, затем «Импорт»")
}

func bridgeCode(err error) string {
	for code, e := range map[string]error{"alias": bridge.ErrAlias, "no_ssh": bridge.ErrNoSSH, "host_key": bridge.ErrHostKey,
		"auth": bridge.ErrAuth, "resolve": bridge.ErrResolve, "unreachable": bridge.ErrUnreachable, "sudo": bridge.ErrSudo,
		"no_bridge": bridge.ErrNoBridge, "newer": bridge.ErrNewerContract, "older": bridge.ErrOlderContract} {
		if errors.Is(err, e) {
			return code
		}
	}
	return "error"
}

// importFile — ручной режим: файл doctor/health/facts с сервера.
func (r *run) importFile(im Import) {
	switch bridge.Detect(im.Data) {
	case "doctor":
		d, err := bridge.ParseDoctor(im.Data)
		if err != nil {
			r.note("Импорт " + im.Name + ": " + err.Error())
			return
		}
		if !r.doctorEvidence(d, "import") {
			r.step(3, "S3", "Импорт xm doctor", "warn", "с другого сервера — не учтено")
			return
		}
		r.step(3, "S3", "Импорт xm doctor", "ok", d.Verdict.Code)
	case "health":
		h, err := bridge.ParseHealth(im.Data)
		if err != nil {
			r.note("Импорт " + im.Name + ": " + err.Error())
			return
		}
		r.healthEvidence(h)
		r.step(3, "S2", "Импорт xm health", "ok", "")
	case "facts":
		f, err := bridge.ParseFacts(im.Data)
		if err != nil {
			r.note("Импорт " + im.Name + ": " + err.Error())
			return
		}
		// Соль у файла чужая: хэши профиля с ним не сверить.
		r.factsEvidence(f, false)
		r.step(3, "S1", "Импорт xm bridge facts", "ok", "")
	default:
		r.note("Импорт " + im.Name + ": не вывод xm doctor/health/bridge facts")
	}
}

func (r *run) factsEvidence(f *bridge.Facts, salted bool) {
	r.red.Add(redact.SNI, f.Public.SNI)
	c := r.e.Rules.Compat
	mlkem := c.MlkemRule(f.Xray.Version)
	if f.Xray.MlkemRule != nil {
		mlkem = *f.Xray.MlkemRule
	}
	facts := map[string]any{"ok": true, "xray_version": f.Xray.Version, "mlkem_rule": mlkem, "port_custom": f.Public.Port != 0 && f.Public.Port != 443,
		"transport": f.Public.Transport, "ufw": f.Firewall.UFW, "self_r": f.Self.R, "self_at": f.Self.At,
		"health_enabled": f.Health.Enabled, "ru_block": f.RUBlock}
	if f.Time > 0 {
		facts["time_offset_s"] = float64(r.now().Unix() - f.Time)
	}
	if f.Health.LastTraffic > 0 {
		facts["last_traffic_age_h"] = float64(r.now().Unix()-f.Health.LastTraffic) / 3600
	}
	var bad []string
	if r.prof != nil {
		if salted {
			for k, v := range f.Match(r.prof.Hashes(r.red.Salt())) {
				facts["match_"+k] = v
				if !v {
					bad = append(bad, k)
				}
			}
		}
		if _, ok := facts["match_port"]; !ok && f.Public.Port > 0 {
			facts["match_port"] = f.Public.Port == r.prof.Port
		}
		if f.Public.Transport != "" {
			t := r.prof.Transport()
			facts["match_transport"] = t == f.Public.Transport || (t == "tcp" && f.Public.TCPInbound)
		}
	}
	sum := fmt.Sprintf("Сервер: Xray %s%s, самопроверка %s, UFW %s", f.Xray.Version, yesno(mlkem, " (правило X25519MLKEM768)", ""),
		orEmpty(f.Self.R), orEmpty(f.Firewall.UFW))
	if len(bad) > 0 {
		sum += "; профиль не совпал по: " + strings.Join(bad, ", ")
	} else if salted && f.Profile != nil {
		sum += "; профиль совпадает с сервером"
	}
	r.put(evidence.Evidence{ID: "S1", Source: evidence.FromServer, Reliability: evidence.High, Facts: facts, Summary: sum})
}

func (r *run) healthEvidence(h *bridge.Health) {
	if h.Empty() {
		r.put(evidence.Evidence{ID: "S2", Source: evidence.FromServer, Reliability: evidence.High,
			Facts: map[string]any{"ok": false}, Summary: "Журнал здоровья на сервере выключен (`sudo xm health on`)"})
		return
	}
	v, t := h.LastXrayVersion()
	f := map[string]any{"ok": true, "incidents_freeze": h.Count("freeze"), "incidents_server": h.Count("server")}
	sum := fmt.Sprintf("Журнал здоровья: заморозок %d, сбоев сервера %d за 7 дней", h.Count("freeze"), h.Count("server"))
	if v != "" {
		f["ver_xray"] = v
		f["ver_xray_mlkem"] = r.e.Rules.Compat.MlkemRule(v)
		sum += fmt.Sprintf("; Xray обновлён до %s %s", v, time.Unix(t, 0).Format("02.01 15:04"))
	}
	sum += r.healthTimeline(h, f)
	r.put(evidence.Evidence{ID: "S2", Source: evidence.FromServer, Reliability: evidence.High, Facts: f, Summary: sum})
}

// incidentClass — вердикт окна журнала здоровья → сторона сбоя: сервер сам (самопроверка), путь
// (заморозки по tcp_info соединений клиентов) или другое. nodata/monitor — не сбой: клиентов не
// было или журнал только наблюдал.
func incidentClass(vd string) string {
	switch vd {
	case "server":
		return "server"
	case "freeze":
		return "freeze"
	case "degraded", "suspect":
		return "other"
	}
	return ""
}

// healthTimeline — S2 по времени (решение 16): инциденты за сутки и совпадения с эпизодами
// сбоев из логов клиента (C6). Время ПК → часы сервера — по сдвигу из фактов (S1), допуск —
// окно журнала (EpisodeGap).
func (r *run) healthTimeline(h *bridge.Health, f map[string]any) string {
	now := h.Now
	if now == 0 {
		now = r.now().Unix()
	}
	day := map[string]int{}
	for _, x := range h.Overlaps(now-24*3600, now) {
		if c := incidentClass(x.VD); c != "" {
			day[c]++
		}
	}
	f["day_server"], f["day_freeze"], f["day_other"] = day["server"], day["freeze"], day["other"]
	if len(r.tl.Episodes) == 0 {
		return ""
	}
	off := int64(0)
	if v, ok := r.set.Get("S1").Num("time_offset_s"); ok {
		off = int64(v) // время ПК минус время сервера
	}
	gap := int64(clients.EpisodeGap / time.Second)
	match := map[string]int{}
	for _, ep := range r.tl.Episodes {
		seen := map[string]bool{}
		for _, x := range h.Overlaps(ep.From.Unix()-off-gap, ep.To.Unix()-off+gap) {
			if c := incidentClass(x.VD); c != "" && !seen[c] {
				seen[c] = true
				match[c]++
			}
		}
		if len(seen) > 0 {
			match["any"]++
		}
	}
	f["overlap"], f["overlap_server"], f["overlap_freeze"], f["overlap_other"] = match["any"], match["server"], match["freeze"], match["other"]
	return fmt.Sprintf("; серий сбоев клиента %d, из них совпали с инцидентами сервера %d (сбой сервера %d, заморозки %d)",
		len(r.tl.Episodes), match["any"], match["server"], match["freeze"])
}

// doctorEvidence — S3 (и S1 из doctor, если фактов моста не было). false — окно снято на другом
// сервере (его адрес — не адрес профиля): не учитывается, иначе «до сервера ничего не доходит»
// с чужого сервера выдавалось бы за поведение этого.
func (r *run) doctorEvidence(d *bridge.Doctor, src string) bool {
	d.Register(r.red)
	if r.otherServer(d.Server.ServerIP) {
		r.note("Окно xm doctor — с другого сервера: адрес в его выводе не совпадает с адресом профиля, окно не учтено")
		r.missing("doctor_other_server")
		return false
	}
	f := map[string]any{"ok": true, "code": d.Verdict.Code, "live": d.Window(), "source": src, "xver": d.Server.XVer}
	a, ssh, own, n := d.Pick()
	f["ssh"], f["own"], f["attempts"] = ssh, own, n
	if a != nil {
		f["stage"] = a.St
		if a.After != "" {
			f["after"] = a.After
		}
		if a.RD != nil {
			f["rd_r"], f["core"], f["mlkem_rule"] = a.RD.R, a.RD.Core, a.RD.MLKEMRule
		}
	}
	// Код doctor → самопроверка и UFW сервера (S1, если моста facts не было).
	if !r.set.Has("S1") {
		r.put(evidence.Evidence{ID: "S1", Source: evidence.FromServer, Reliability: evidence.High,
			Facts: map[string]any{"ok": true, "self_r": d.Server.Self.R, "self_at": d.Server.Self.At, "ufw": d.Server.UFW,
				"xray_version": d.Server.XVer, "mlkem_rule": r.e.Rules.Compat.MlkemRule(d.Server.XVer)},
			Summary: fmt.Sprintf("Сервер (из xm doctor): Xray %s, самопроверка %s, UFW %s", orEmpty(d.Server.XVer), orEmpty(d.Server.Self.R), orEmpty(d.Server.UFW))})
	}
	sum := "xm doctor: " + d.Verdict.Code + " — " + d.Verdict.Title
	if len(d.Verdict.Evidence) > 0 {
		sum += " (" + strings.Join(d.Verdict.Evidence, "; ") + ")"
	}
	r.put(evidence.Evidence{ID: "S3", Source: evidence.FromServer, Reliability: evidence.High, Facts: f, Summary: sum})
	return true
}

// phaseCapture — C7: pktmon с UAC на время одной попытки клиента.
func (r *run) phaseCapture(ctx context.Context) {
	if r.prof == nil || len(r.serverIP) == 0 {
		r.note("Захват пропущен: адрес сервера не определён")
		return
	}
	if !capture.Available() || r.e.Store == nil {
		r.note("Захват недоступен: нужен pktmon (Windows 10 2004+)")
		return
	}
	secs := r.o.CaptureSecs
	if !r.confirm(ctx, Consent{Kind: "uac", Text: fmt.Sprintf("Захват ClientHello клиента: Windows спросит права администратора (pktmon). "+
		"Фильтр — только адрес и порт сервера, %d с; фильтры pktmon на это время сбрасываются, файл захвата удаляется сразу после разбора. "+
		"В окно захвата нажмите «Подключить» в клиенте один раз.", secs)}) {
		r.note("Захват: пользователь отказался")
		return
	}
	sni := ""
	if r.prof != nil {
		sni = redact.HashWith(r.red.Salt(), r.prof.SNI)
	}
	job, err := capture.WriteJob(filepath.Join(r.e.Store.Dir, "tmp"), capture.Job{IP: r.serverIP[0].String(), Port: r.prof.Port, Seconds: secs,
		Salt: r.red.Salt(), SNIHash: sni})
	if err != nil {
		r.note("Захват: " + err.Error())
		return
	}
	defer os.Remove(job)
	r.step(4, "C7", "Захват ClientHello (pktmon)", "run", fmt.Sprintf("%d с", secs))
	if r.h.Window != nil {
		go r.h.Window(ctx, "Нажмите «Подключить» в клиенте ОДИН раз — идёт захват", secs)
	}
	run := r.e.Capture
	if run == nil {
		run = func(ctx context.Context, job, self string) error { return capture.RunElevated(ctx, self, job) }
	}
	if err := run(ctx, job, r.o.SelfExe); err != nil {
		r.step(4, "C7", "Захват ClientHello (pktmon)", "fail", err.Error())
		return
	}
	res, err := capture.ReadResult(job)
	if err != nil || res.Err != "" {
		msg := res.Err
		if err != nil {
			msg = err.Error()
		}
		r.step(4, "C7", "Захват ClientHello (pktmon)", "fail", msg)
		return
	}
	f := map[string]any{"ran": true, "syn_seen": res.SYNSeen, "synack_seen": res.SYNACKSeen, "hello_seen": res.HelloSeen,
		"mlkem": res.MLKEM, "shares": res.Shares, "sni_match": res.SNIMatch, "conns": res.Conns, "tls_hellos": res.HellosPer60, "partial": res.Partial}
	sum := "Захват: " + yesno(res.SYNSeen, fmt.Sprintf("соединений клиента %d", res.Conns), "клиент не отправил к серверу ни одного SYN")
	if res.HelloSeen {
		sum += fmt.Sprintf("; ClientHello: доли %s — %s", strings.Join(res.Shares, "+"), yesno(res.MLKEM, "X25519MLKEM768 есть", "X25519MLKEM768 НЕТ"))
	}
	r.put(evidence.Evidence{ID: "C7", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: f, Summary: sum})
	r.step(4, "C7", "Захват ClientHello (pktmon)", "ok", sum)
}

// Titles — названия проверок (матрица §6).
var Titles = map[string]string{
	"C1": "Hiddify: версия и ядро", "C2": "v2rayN: версия и ядро", "CX": "Ядро активного клиента", "C3": "Профиль",
	"C5": "URI ↔ профиль в клиенте", "C6": "Логи клиента", "C7": "Захват ClientHello", "C8": "Состояние клиента", "C9": "Локальный прокси", "C10": "Подключение через клиент", "C11": "Соединения клиента с сервером",
	"W1": "Сетевые адаптеры", "W2": "Маршрут к серверу", "W3": "DNS Windows", "W4": "Брандмауэр", "W5": "Антивирус", "W6": "Системный прокси",
	"W7": "Часы", "W8": "IPv6", "W9": "MTU", "N1": "Интернет", "N2": "Белый список?", "N3": "Подмена DNS", "N4": "Маска по своему адресу",
	"P1": "TCP до сервера", "P2": "TLS к серверу с SNI маски", "P3": "Эталонное ядро Xray", "P3m": "Эталон без X25519MLKEM768",
	"P4": "Повтор через 30 с", "P5": "Из другой сети", "P6": "SSH-порт того же адреса", "N5": "SNI маски на чужом адресе", "B1": "DNS за тоннелем", "B2": "Российский сайт через тоннель",
	"B3": "URL теста задержки клиента", "B4": "UDP через тоннель", "S0": "SSH-мост", "S1": "Факты сервера", "S2": "Журнал здоровья сервера", "S3": "Окно xm doctor",
}
