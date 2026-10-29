package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/capture"
	"github.com/grokki91/xray_client/internal/evidence"
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
	r.doctorEvidence(d, "bridge")
	r.step(3, "S3", "Сервер: окно xm doctor", "ok", d.Verdict.Code)
}

func (r *run) bridgeFail(err error) {
	f := map[string]any{"error": bridgeCode(err)}
	if errors.Is(err, bridge.ErrUnreachable) {
		f["ssh"] = "unreachable"
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
		r.doctorEvidence(d, "import")
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
	r.put(evidence.Evidence{ID: "S2", Source: evidence.FromServer, Reliability: evidence.High, Facts: f, Summary: sum})
}

func (r *run) doctorEvidence(d *bridge.Doctor, src string) {
	d.Register(r.red)
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

// mergeOtherNetwork — P5: пробы этого сеанса сделаны из другой сети; база — улики прошлого
// сеанса (из «своей» сети), к ним добавляется сравнение.
func (r *run) mergeOtherNetwork() {
	cur := r.set
	prev := evidence.FromList(r.o.Prev.Evidence)
	f := map[string]any{"ran": true, "network_changed": true}
	parts := []string{}
	if e := cur.Get("P1"); e != nil {
		f["p1"] = e.Str("outcome")
		parts = append(parts, "TCP — "+e.Str("outcome"))
	}
	if e := cur.Get("P2"); e != nil {
		f["p2"] = e.Str("outcome")
		parts = append(parts, "TLS — "+e.Str("outcome"))
	}
	if e := cur.Get("P3"); e != nil {
		f["p3"] = e.Str("outcome")
		parts = append(parts, "эталон — "+e.Str("outcome"))
	}
	merged := evidence.NewSet()
	for _, e := range prev.All() {
		if e.ID != "P5" {
			merged.Put(e)
		}
	}
	// Клиент и Windows — свежие: они от сети не зависят.
	for _, e := range cur.All() {
		if strings.HasPrefix(e.ID, "C") || strings.HasPrefix(e.ID, "W") || strings.HasPrefix(e.ID, "S") {
			merged.Put(e)
		}
	}
	r.set = merged
	r.put(evidence.Evidence{ID: "P5", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: f,
		Summary: "Из другой сети: " + strings.Join(parts, ", ")})
}

// Titles — названия проверок (матрица §6).
var Titles = map[string]string{
	"C1": "Hiddify: версия и ядро", "C2": "v2rayN: версия и ядро", "CX": "Ядро активного клиента", "C3": "Профиль",
	"C5": "URI ↔ профиль в клиенте", "C6": "Логи клиента", "C7": "Захват ClientHello", "C8": "Состояние клиента", "C9": "Локальный прокси",
	"W1": "Сетевые адаптеры", "W2": "Маршрут к серверу", "W3": "DNS Windows", "W4": "Брандмауэр", "W5": "Антивирус", "W6": "Системный прокси",
	"W7": "Часы", "W8": "IPv6", "W9": "MTU", "N1": "Интернет", "N2": "Белый список?", "N3": "Подмена DNS", "N4": "Маска по своему адресу",
	"P1": "TCP до сервера", "P2": "TLS к серверу с SNI маски", "P3": "Эталонное ядро Xray", "P3m": "Эталон без X25519MLKEM768",
	"P4": "Повтор через 30 с", "P5": "Из другой сети", "B1": "DNS за тоннелем", "B2": "Российский сайт через тоннель",
	"B3": "URL теста задержки клиента", "S0": "SSH-мост", "S1": "Факты сервера", "S2": "Журнал здоровья сервера", "S3": "Окно xm doctor",
}
