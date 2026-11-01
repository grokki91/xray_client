package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
)

// phase0 — факты без сети.
func (r *run) phase0(ctx context.Context) {
	r.step(0, "W", "Факты Windows", "run", "")
	r.facts = r.e.CollectOS(ctx, nil)
	if r.facts.Collected {
		r.step(0, "W", "Факты Windows", "ok", fmt.Sprintf("адаптеров: %d", len(r.facts.Adapters)))
	} else {
		r.step(0, "W", "Факты Windows", "warn", "не собраны ("+r.facts.Err+"): проверки Windows пропущены")
		r.note("Факты Windows не собраны: " + r.facts.Err)
	}
	env := r.e.NewEnv(&r.facts)
	env.HiddifyDir, env.V2rayNDir = r.o.HiddifyDir, r.o.V2rayNDir

	r.step(0, "C", "Клиенты: Hiddify, v2rayN", "run", "")
	for _, a := range r.e.Adapters {
		cr := &clientRun{a: a}
		cr.d = a.Detect(ctx, env)
		if cr.d.Installed {
			cr.ps, cr.perr = a.Profiles(ctx, env, cr.d)
			cr.logs = a.Logs(env, cr.d, r.now().Add(-24*time.Hour))
			cr.state = a.State(env, cr.d)
			// Подключён ли клиент — по самому порту, без PowerShell: факты Windows могут не
			// собраться, а порт отвечает сейчас.
			if r.e.LocalOpen != nil && cr.d.ProxyPort > 0 {
				cr.state.CoreListening = r.e.LocalOpen(cr.d.ProxyPort)
				if cr.state.CoreListening {
					cr.state.Running = true
				}
			}
		}
		r.all = append(r.all, cr)
		for _, p := range cr.ps {
			p.Register(r.red)
		}
	}
	r.clientEvidence()
	r.chooseProfile()
	r.profileEvidence()
	r.osEvidence()
}

// clientEvidence — C1 (Hiddify), C2 (v2rayN), C8, C9 и выбор активного клиента.
func (r *run) clientEvidence() {
	ids := map[string]string{"hiddify": "C1", "v2rayn": "C2"}
	var found []string
	for _, cr := range r.all {
		d := cr.d
		info := ClientInfo{Client: d.Client, Installed: d.Installed, Version: d.Version, Core: d.Core, CoreFamily: d.CoreFamily,
			CoreMlkem: d.CoreMlkem, Mode: d.Mode, Running: cr.state.Running, Profiles: len(cr.ps), Support: d.Support, Portable: d.Portable}
		if cr.perr != nil {
			info.ProfilesErr = r.red.String(cr.perr.Error())
		}
		r.sess.Clients = append(r.sess.Clients, info)
		id := ids[d.Client]
		if id == "" {
			continue
		}
		f := map[string]any{"installed": d.Installed}
		sum := cr.a.Title() + ": не найден"
		if d.Installed {
			found = append(found, cr.a.Title())
			f["version"] = d.Version
			f["portable"] = d.Portable
			f["core"] = d.Core
			f["core_family"] = d.CoreFamily
			f["core_version"] = d.CoreVersion
			if d.CoreMlkem != nil {
				f["core_mlkem"] = *d.CoreMlkem
			}
			f["running"] = cr.state.Running
			f["mode"] = d.Mode
			f["tun"] = d.TUN
			f["proxy_port"] = d.ProxyPort
			f["lan"] = d.LAN
			f["profiles"] = len(cr.ps)
			f["support"] = d.Support
			ver := d.Version
			if ver == "" {
				ver = "версия ?"
			}
			sum = fmt.Sprintf("%s %s: ядро %s, режим %s, профилей %d%s", cr.a.Title(), ver, d.Core, modeText(d.Mode), len(cr.ps),
				map[bool]string{true: ", запущен", false: ", не запущен"}[cr.state.Running])
			if d.Note != "" {
				sum += ". " + d.Note
			}
		}
		rel := evidence.High
		if d.Version == "" {
			rel = evidence.Medium
		}
		r.put(evidence.Evidence{ID: id, Source: evidence.FromClient, Reliability: rel, Facts: f, Summary: sum})
	}
	r.active = r.pickClient()
	if r.active == nil {
		r.step(0, "C", "Клиенты: Hiddify, v2rayN", "warn", "не найдено ни одного клиента")
		return
	}
	r.sess.Client = r.active.d.Client
	r.sess.ClientName = r.active.a.Title()
	if r.active.d.Version != "" {
		r.sess.ClientName += " " + r.active.d.Version
	}
	r.step(0, "C", "Клиенты: Hiddify, v2rayN", "ok", "найдено: "+strings.Join(found, ", ")+"; проверяется "+r.active.a.Title())
	st := r.active.state
	proc := yesno(st.Running, "запущен", "не запущен")
	if !r.facts.Collected && !st.Running {
		proc = "неизвестно (нет фактов Windows)"
	}
	r.put(evidence.Evidence{ID: "C8", Source: evidence.FromOS, Reliability: evidence.High, Facts: map[string]any{
		"client_running": st.Running, "core_listening": st.CoreListening, "tun_adapter": st.TunAdapter, "service": st.Service,
		"proxy_port": r.active.d.ProxyPort},
		Summary: fmt.Sprintf("%s: %s (локальный прокси :%d %s), процесс %s%s", r.active.a.Title(),
			yesno(st.CoreListening || st.TunAdapter, "подключён", "не подключён"), r.active.d.ProxyPort, yesno(st.CoreListening, "слушает", "не слушает"),
			proc, yesno(st.TunAdapter, ", адаптер TUN есть", ""))})
	var exposed []string
	for _, cr := range r.all {
		for _, p := range cr.state.Exposed {
			exposed = append(exposed, fmt.Sprint(p))
		}
	}
	r.put(evidence.Evidence{ID: "C9", Source: evidence.FromOS, Reliability: evidence.High,
		Facts:   map[string]any{"exposed": len(exposed) > 0, "ports": exposed},
		Summary: yesno(len(exposed) > 0, "Локальный прокси слушает все интерфейсы: порты "+strings.Join(exposed, ", "), "Локальный прокси клиентов открыт только на петле")})
	logs := r.active.logs
	if r.o.PastedLogs != "" {
		p := clients.ScanText(r.o.PastedLogs)
		for k, v := range p.Counts {
			if logs.Counts == nil {
				logs.Counts = map[string]int{}
			}
			logs.Counts[k] += v
		}
		logs.Lines = append(logs.Lines, p.Lines...)
		logs.Found, logs.Pasted = true, true
	}
	lf := map[string]any{"found": logs.Found, "files": logs.Files, "age_min": logs.AgeMin, "pasted": logs.Pasted}
	var parts []string
	keys := make([]string, 0, len(logs.Counts))
	for k := range logs.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lf[k] = logs.Counts[k]
		parts = append(parts, fmt.Sprintf("%s ×%d", logTitles[k], logs.Counts[k]))
	}
	sum := "Логи клиента не найдены"
	if logs.Found {
		sum = "Логи клиента: " + yesno(len(parts) > 0, strings.Join(parts, ", "), "характерных ошибок нет")
	}
	r.put(evidence.Evidence{ID: "C6", Source: evidence.FromLog, Reliability: evidence.Medium, Facts: lf, Summary: sum})
	for _, l := range logs.Lines {
		r.sess.Logs = append(r.sess.Logs, r.red.String(l))
	}
}

var logTitles = map[string]string{
	"reality_failed": "reality verification failed", "real_cert": "received real certificate", "invalid_conn": "processed invalid connection",
	"timeout": "таймаут", "tun_error": "ошибка TUN", "port_busy": "порт занят", "core_failed": "ядро не запустилось",
	"empty_fp": "пустой fingerprint", "dns_error": "ошибка DNS",
}

func modeText(m string) string {
	switch m {
	case "vpn", "tun":
		return "VPN (TUN)"
	case "system-proxy":
		return "системный прокси"
	case "proxy":
		return "только прокси"
	}
	return m
}

func yesno(b bool, y, n string) string {
	if b {
		return y
	}
	return n
}

// pickClient — какой клиент диагностируется: явно заданный, иначе подключённый, запущенный,
// с активным профилем; при равенстве — Hiddify (основной клиент владельца).
func (r *run) pickClient() *clientRun {
	var cands []*clientRun
	for _, cr := range r.all {
		if cr.d.Installed {
			if r.o.Client != "" && r.o.Client != "auto" {
				if cr.d.Client == r.o.Client {
					return cr
				}
				continue
			}
			cands = append(cands, cr)
		}
	}
	score := func(cr *clientRun) int {
		s := 0
		if cr.state.CoreListening {
			s += 4
		}
		if cr.state.Running {
			s += 2
		}
		for _, p := range cr.ps {
			if p.Active && p.IsRealityVLESS() {
				s++
				break
			}
		}
		return s
	}
	sort.SliceStable(cands, func(i, j int) bool { return score(cands[i]) > score(cands[j]) })
	if len(cands) == 0 {
		return nil
	}
	return cands[0]
}

// chooseProfile — профиль для проверки: активный профиль клиента (что клиент реально делает),
// иначе профиль из настроек, иначе любой VLESS+REALITY.
func (r *run) chooseProfile() {
	if r.o.ProfileURI != "" {
		if ps := profile.FindURIs(r.o.ProfileURI); len(ps) > 0 {
			r.uriProf = ps[0]
			r.uriProf.Source, r.uriProf.Origin = "uri", "настройки xdiag"
			r.uriProf.Register(r.red)
		} else {
			r.note("Профиль в настройках не разбирается как vless://")
		}
	}
	var list []*profile.Profile
	if r.active != nil {
		list = append(list, r.active.ps...)
	}
	pick := func(pred func(*profile.Profile) bool) *profile.Profile {
		for _, p := range list {
			if p.IsRealityVLESS() && pred(p) {
				return p
			}
		}
		return nil
	}
	// Для v2rayN конфиг запущенного ядра — самое точное; дальше — выбранный профиль.
	r.prof = pick(func(p *profile.Profile) bool { return p.ID == "running" })
	if r.prof == nil {
		r.prof = pick(func(p *profile.Profile) bool { return p.Active })
	}
	if r.prof == nil && r.uriProf != nil {
		r.prof = r.uriProf
	}
	if r.prof == nil {
		r.prof = pick(func(*profile.Profile) bool { return true })
	}
	if r.prof == nil {
		// У других клиентов.
		for _, cr := range r.all {
			for _, p := range cr.ps {
				if r.prof == nil && p.IsRealityVLESS() {
					r.prof = p
				}
			}
		}
	}
	n := 0
	for _, cr := range r.all {
		n += len(cr.ps)
	}
	r.sess.Profiles = n
}

// profileEvidence — C3, C5, CX.
func (r *run) profileEvidence() {
	if r.prof == nil {
		r.put(evidence.Evidence{ID: "C3", Source: evidence.FromClient, Reliability: evidence.High,
			Facts: map[string]any{"found": false}, Summary: "Профиль VLESS+REALITY не найден ни в клиентах, ни в настройках"})
	} else {
		s := r.prof.Summary()
		var texts []string
		for _, i := range r.prof.Validate() {
			texts = append(texts, i.Text)
		}
		f := map[string]any{"found": true, "source": s.Source, "transport": s.Transport, "security": s.Security, "fp": s.Fingerprint,
			"port_custom": s.PortCustom, "server_is_ip": s.ServerIsIP, "issues": s.Issues, "issues_text": strings.Join(texts, "; "), "has_sid": s.HasSID,
			"has_path": s.HasPath, "mode": s.Mode, "flow": s.Flow, "pq": s.PQ}
		sum := fmt.Sprintf("Профиль (%s): %s+%s, fp=%s, порт %s", s.Origin, strings.ToUpper(s.Transport), s.Security, orEmpty(s.Fingerprint),
			yesno(s.PortCustom, "нестандартный", "443"))
		if len(texts) > 0 {
			sum += "; проблемы: " + strings.Join(texts, "; ")
		} else {
			sum += "; синтаксис в порядке"
		}
		r.put(evidence.Evidence{ID: "C3", Source: evidence.FromClient, Reliability: evidence.High, Facts: f, Summary: sum})
	}
	if r.uriProf != nil && r.prof != nil && r.prof != r.uriProf && profile.Same(r.uriProf, r.prof) {
		d := profile.Diff(r.uriProf, r.prof)
		r.put(evidence.Evidence{ID: "C5", Source: evidence.FromClient, Reliability: evidence.High,
			Facts:   map[string]any{"differs": d, "same_server": true},
			Summary: yesno(len(d) > 0, "Профиль в клиенте отличается от URI из настроек: "+strings.Join(d, ", "), "Профиль в клиенте совпадает с URI из настроек")})
	}
	r.clientCore()
}

func orEmpty(s string) string {
	if s == "" {
		return "пусто"
	}
	return s
}

// clientCore — CX: какое ядро делает REALITY и шлёт ли X25519MLKEM768.
func (r *run) clientCore() {
	f := map[string]any{}
	c := r.e.Rules.Compat
	fp := ""
	if r.prof != nil {
		fp = strings.ToLower(r.prof.Fingerprint)
	}
	f["fp"] = fp
	if r.active == nil {
		f["client"], f["client_name"] = "uri", "профиль из настроек"
		r.put(evidence.Evidence{ID: "CX", Source: evidence.FromClient, Reliability: evidence.Medium, Facts: f,
			Summary: "Клиент не найден: проверяется только профиль"})
		return
	}
	d := r.active.d
	family, core, ver, mlkem := d.CoreFamily, d.Core, d.CoreVersion, d.CoreMlkem
	if r.prof != nil && r.prof.CoreOverride != "" && d.Client == "v2rayn" {
		if ci, ok := c.V2rayNCore(r.prof.CoreOverride); ok {
			family, core, mlkem = ci.Family, r.prof.CoreOverride, ci.Mlkem
			if family == "xray" {
				if m, known := c.XrayCoreMlkem(ver); known {
					mlkem = &m
				}
			} else {
				ver = ""
			}
		}
	}
	if mlkem == nil && d.Client == "hiddify" && d.Version == "" {
		no := false // все вышедшие релизы Hiddify — sing-box без X25519MLKEM768
		mlkem = &no
	}
	name := r.active.a.Title()
	if d.Version != "" {
		name += " " + d.Version
	}
	f["client"], f["client_name"], f["core"], f["core_family"], f["core_version"], f["tun"] = d.Client, name, core, family, ver, d.TUN
	if mlkem != nil {
		f["core_mlkem"] = *mlkem
	}
	switch family {
	case "xray":
		if m, known := c.XrayFPMlkem(ver, fp); known {
			f["fp_mlkem"] = m
		}
		f["bug6797"] = c.Bug6797(ver)
	default:
		f["fp_mlkem"] = false
	}
	if cm, ok := f["core_mlkem"].(bool); ok {
		if fm, ok := f["fp_mlkem"].(bool); ok {
			f["mlkem"] = cm && fm
		}
	}
	if d.RUDirect != nil {
		f["ru_direct"] = *d.RUDirect
	}
	rel := evidence.Medium // таблица версий
	sum := fmt.Sprintf("%s: REALITY делает ядро %s", name, core)
	switch v := f["mlkem"].(type) {
	case bool:
		sum += yesno(v, " — X25519MLKEM768 шлёт", " — X25519MLKEM768 не шлёт")
		if fp != "" {
			sum += " (fp=" + fp + ")"
		}
	default:
		sum += " — шлёт ли X25519MLKEM768, по таблице не определить"
	}
	r.put(evidence.Evidence{ID: "CX", Source: evidence.FromClient, Reliability: rel, Facts: f, Summary: sum})
}

// osEvidence — W1, W3–W9 из фактов Windows (W2 и W7 — в фазах с сетью).
func (r *run) osEvidence() {
	f := r.facts
	if !f.Collected {
		return
	}
	var tuns, other []string
	for _, a := range f.Adapters {
		if !a.Up {
			continue
		}
		switch a.Kind {
		case "tun":
			tuns = append(tuns, genericAdapter(a))
		case "vpn":
			other = append(other, genericAdapter(a))
		}
	}
	// «Другой VPN» — TUN не активного клиента тоже считается.
	if r.active != nil {
		mine := map[string][]string{"hiddify": {"hiddify"}, "v2rayn": {"singbox", "sing-box", "xray", "wintun"}}[r.active.d.Client]
		for _, t := range tuns {
			ok := false
			for _, m := range mine {
				if strings.Contains(strings.ToLower(t), m) {
					ok = true
				}
			}
			if !ok {
				other = append(other, t)
			}
		}
	}
	r.put(evidence.Evidence{ID: "W1", Source: evidence.FromOS, Reliability: evidence.High,
		Facts: map[string]any{"up": len(f.Adapters), "tun_adapters": tuns, "other_vpn": other, "default_via_tun": f.DefaultViaTUN},
		Summary: fmt.Sprintf("Адаптеры: TUN — %s; другие VPN — %s; маршрут по умолчанию %s", listOr(tuns), listOr(other),
			yesno(f.DefaultViaTUN, "идёт в тоннель", "через физический адаптер"))})
	r.put(evidence.Evidence{ID: "W3", Source: evidence.FromOS, Reliability: evidence.High,
		Facts:   map[string]any{"dns_servers": f.DNSServers, "doh": f.DoH, "smhnr_off": f.SMHNROff, "nrpt": f.NRPT},
		Summary: fmt.Sprintf("DNS Windows: серверов %d, DoH %s, правил NRPT %d", f.DNSServers, yesno(f.DoH, "настроен", "нет"), f.NRPT)})
	r.put(evidence.Evidence{ID: "W4", Source: evidence.FromOS, Reliability: evidence.High,
		Facts:   map[string]any{"fw_on": f.FirewallOn, "block_rules": len(f.BlockRules), "programs": f.BlockRules},
		Summary: fmt.Sprintf("Брандмауэр %s; блокирующих правил для клиентов: %d %s", yesno(f.FirewallOn, "включён", "выключен"), len(f.BlockRules), listParen(f.BlockRules))})
	r.put(evidence.Evidence{ID: "W5", Source: evidence.FromOS, Reliability: evidence.Medium,
		Facts:   map[string]any{"av": f.AV, "third_party": f.ThirdPartyAV},
		Summary: "Антивирус: " + listOr(f.AV)})
	local, listening := proxyLocal(f)
	r.put(evidence.Evidence{ID: "W6", Source: evidence.FromOS, Reliability: evidence.High,
		Facts: map[string]any{"system_proxy": f.ProxyEnable, "proxy_local": local, "proxy_listening": listening, "pac": f.ProxyPAC, "winhttp": f.WinHTTP},
		Summary: yesno(f.ProxyEnable, "Системный прокси включён"+yesno(local, yesno(listening, " (локальный порт слушается)", " (локальный порт НЕ слушается)"), ""),
			"Системный прокси выключен")})
	r.put(evidence.Evidence{ID: "W8", Source: evidence.FromOS, Reliability: evidence.High,
		Facts: map[string]any{"global_v6": f.GlobalV6}, Summary: yesno(f.GlobalV6, "Глобальный IPv6 есть", "Глобального IPv6 нет")})
	mtu := 0
	if a := f.Adapter(f.DefaultIfIndex); a != nil {
		mtu = a.MTU
	}
	if mtu > 0 {
		r.put(evidence.Evidence{ID: "W9", Source: evidence.FromOS, Reliability: evidence.High,
			Facts: map[string]any{"mtu": mtu}, Summary: fmt.Sprintf("MTU основного адаптера: %d", mtu)})
	}
	// Привязка проб к физическому адаптеру — когда маршрут по умолчанию ушёл в тоннель.
	if f.DefaultViaTUN && f.DefaultIfIndex > 0 {
		r.dial = &netprobe.Dialer{IfIndex: f.DefaultIfIndex}
		r.res = r.dial.Resolver(r.hosts().Bootstrap)
		r.note("Маршрут по умолчанию идёт в тоннель: пробы привязаны к физическому адаптеру, мимо TUN")
	}
}

func genericAdapter(a osw.Adapter) string {
	n := a.Desc
	if n == "" {
		n = a.Name
	}
	return n
}

func listOr(l []string) string {
	if len(l) == 0 {
		return "нет"
	}
	return strings.Join(l, ", ")
}

func listParen(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return "(" + strings.Join(l, ", ") + ")"
}

// proxyLocal — системный прокси на петле и слушает ли его порт кто-нибудь.
func proxyLocal(f osw.Facts) (local, listening bool) {
	s := strings.ToLower(f.ProxyServer)
	if s == "" {
		return false, false
	}
	// «127.0.0.1:12334» или «http=127.0.0.1:10808;https=…».
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' }) {
		if i := strings.IndexByte(part, '='); i >= 0 {
			part = part[i+1:]
		}
		host, port := part, ""
		if i := strings.LastIndexByte(part, ':'); i >= 0 {
			host, port = part[:i], part[i+1:]
		}
		if host == "127.0.0.1" || host == "localhost" || host == "[::1]" {
			local = true
			var p int
			fmt.Sscan(port, &p)
			if len(f.ListeningOn(p)) > 0 {
				listening = true
			}
		}
	}
	return
}
