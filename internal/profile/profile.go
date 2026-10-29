// Package profile — нормализованная модель профиля VLESS+REALITY и разбор форматов, в которых
// его держат клиенты: URI vless://, outbound sing-box (Hiddify), outbound Xray (v2rayN,
// binConfigs\config.json), строка таблицы ProfileItem v2rayN.
//
// Секреты профиля (UUID, pbk, shortId, путь, адрес) живут только в памяти: наружу — через
// Summary (без значений) и Hashes (HMAC на соли сессии).
package profile

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/grokki91/xray_client/internal/redact"
)

// Profile — то, что нужно для подключения к серверу и для сверки с ним.
type Profile struct {
	Source string // hiddify | v2rayn | uri | singbox | xray
	Origin string // откуда взят: «Hiddify: configs/<id>.json», «v2rayN: guiNDB.db» (без секретов)
	Name   string // имя профиля у пользователя (может содержать что угодно — показывать через redact)
	ID     string // локальный id у клиента
	Active bool   // выбран в клиенте
	SubURL string // URL подписки, из которой профиль (секрет)

	CoreOverride string // ядро, заданное профилю в клиенте (v2rayN: CoreType)

	Protocol   string // vless
	Address    string
	Port       int
	UUID       string
	Flow       string
	Encryption string

	Network  string // xhttp | tcp | ws | grpc | httpupgrade | raw
	Security string // reality | tls | none

	SNI           string
	Fingerprint   string
	PublicKey     string
	ShortID       string
	SpiderX       string
	Mldsa65Verify string
	ALPN          []string

	Path  string
	Host  string
	Mode  string // режим XHTTP
	Extra string // xhttp extra (JSON) как есть
}

// Issue — найденная проблема синтаксиса профиля.
type Issue struct {
	Code string // uuid.format, pbk.format, sid.format, fp.empty, sni.empty, …
	Text string // по-русски, без значений
}

var (
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex  = regexp.MustCompile(`^[0-9a-fA-F]*$`)
)

// KnownFingerprints — пресеты uTLS, которые принимает Xray-core.
var KnownFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true,
	"360": true, "qq": true, "random": true, "randomized": true, "randomizednoalpn": true, "unsafe": true,
}

// Validate проверяет профиль без сервера: то, что сломано в нём самом.
func (p *Profile) Validate() []Issue {
	var out []Issue
	add := func(code, text string) { out = append(out, Issue{code, text}) }
	if p.Protocol != "" && p.Protocol != "vless" {
		add("protocol.not_vless", "протокол профиля не VLESS")
	}
	if strings.TrimSpace(p.Address) == "" {
		add("addr.empty", "в профиле нет адреса сервера")
	} else if strings.ContainsAny(p.Address, " \t/") {
		add("addr.format", "адрес сервера с пробелом или лишними символами")
	}
	if p.Port <= 0 || p.Port > 65535 {
		add("port.invalid", "порт вне 1–65535")
	}
	switch {
	case p.UUID == "":
		add("uuid.empty", "нет UUID")
	case p.UUID != strings.TrimSpace(p.UUID):
		add("uuid.space", "UUID с пробелами по краям (испорчен при копировании)")
	case !reUUID.MatchString(p.UUID) && len(p.UUID) > 30:
		// Xray принимает и «текстовый» id до 30 символов (его хэш — UUID), длиннее — ошибка.
		add("uuid.format", "UUID не в формате 8-4-4-4-12")
	}
	if p.Security != "reality" {
		add("security.not_reality", "в профиле не REALITY (security="+safeToken(p.Security)+")")
		return out
	}
	if p.PublicKey == "" {
		add("pbk.empty", "нет публичного ключа REALITY (pbk)")
	} else if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p.PublicKey, "=")); err != nil || len(b) != 32 {
		add("pbk.format", "публичный ключ REALITY не base64url из 32 байт (обычно 43 символа)")
	}
	if p.ShortID != "" {
		if !reHex.MatchString(p.ShortID) || len(p.ShortID)%2 == 1 || len(p.ShortID) > 16 {
			add("sid.format", "shortId не hex чётной длины до 16 символов")
		}
	}
	if p.SNI == "" {
		add("sni.empty", "нет SNI (serverName)")
	}
	fp := strings.ToLower(p.Fingerprint)
	switch {
	case fp == "":
		add("fp.empty", "не задан отпечаток (fp): REALITY без него не собирается")
	case !KnownFingerprints[fp]:
		add("fp.unknown", "неизвестный отпечаток fp="+safeToken(fp))
	}
	switch p.Network {
	case "xhttp", "splithttp":
		if p.Path == "" {
			add("path.empty", "XHTTP без пути (path)")
		}
		if p.Mode != "" && !map[string]bool{"auto": true, "packet-up": true, "stream-up": true, "stream-one": true}[p.Mode] {
			add("mode.unknown", "неизвестный режим XHTTP mode="+safeToken(p.Mode))
		}
	case "tcp", "raw":
	case "":
		add("transport.empty", "не указан транспорт (type)")
	default:
		add("transport.other", "транспорт "+safeToken(p.Network)+" — не XHTTP и не TCP")
	}
	if p.Flow != "" && p.Flow != "xtls-rprx-vision" && p.Flow != "xtls-rprx-vision-udp443" {
		add("flow.unknown", "неизвестный flow")
	}
	if (p.Network == "xhttp" || p.Network == "splithttp") && strings.HasPrefix(p.Flow, "xtls-rprx-vision") {
		add("flow.xhttp", "flow Vision с транспортом XHTTP: Vision работает только на TCP")
	}
	return out
}

// safeToken — короткое значение без секретов (имя пресета, транспорта) для текста проблемы.
func safeToken(s string) string {
	if len(s) > 24 {
		s = s[:24] + "…"
	}
	if s == "" {
		return "пусто"
	}
	return s
}

// ServerIsIP — адрес сервера задан IP.
func (p *Profile) ServerIsIP() bool {
	_, err := netip.ParseAddr(strings.Trim(p.Address, "[]"))
	return err == nil
}

// Transport — транспорт в именах сервера: xhttp | tcp | другое.
func (p *Profile) Transport() string {
	switch p.Network {
	case "splithttp", "xhttp":
		return "xhttp"
	case "raw", "tcp", "":
		return "tcp"
	}
	return p.Network
}

// Register регистрирует секреты профиля в редакторе.
func (p *Profile) Register(r *redact.Redactor) {
	r.Add(redact.Server, strings.Trim(p.Address, "[]"))
	r.Add(redact.SNI, p.SNI)
	if p.Host != "" && p.Host != p.SNI {
		r.Add(redact.SNI, p.Host)
	}
	r.Add(redact.UUID, p.UUID)
	r.Add(redact.Key, p.PublicKey)
	r.Add(redact.SID, p.ShortID)
	r.Add(redact.Path, p.Path)
	r.Add(redact.Other, p.Mldsa65Verify)
	r.Add(redact.URL, p.SubURL)
	if p.Name != "" {
		// Имя профиля пользователь часто называет адресом или доменом сервера.
		r.Add(redact.Other, p.Name)
	}
}

// Hashes — HMAC-хэши полей на соли (формат сверки с xm bridge facts).
func (p *Profile) Hashes(salt []byte) map[string]string {
	h := func(v string) string { return redact.HashWith(salt, v) }
	out := map[string]string{
		"uuid": h(strings.ToLower(strings.TrimSpace(p.UUID))),
		"pbk":  h(strings.TrimSpace(p.PublicKey)),
		"sid":  h(strings.ToLower(p.ShortID)),
		"path": h(p.Path),
		"sni":  h(strings.ToLower(p.SNI)),
	}
	if p.Port > 0 {
		out["port"] = h(fmt.Sprint(p.Port))
	}
	for k, v := range out {
		if v == "" {
			delete(out, k)
		}
	}
	return out
}

// Summary — описание профиля без секретов: для улик и отчёта.
type Summary struct {
	Source      string   `json:"source"`
	Origin      string   `json:"origin,omitempty"`
	Active      bool     `json:"active"`
	Transport   string   `json:"transport"`
	Security    string   `json:"security"`
	Fingerprint string   `json:"fp"`
	Port        int      `json:"port"` // только 443; нестандартный порт — данные установки, 0
	PortCustom  bool     `json:"port_custom,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Flow        string   `json:"flow,omitempty"`
	ServerIsIP  bool     `json:"server_is_ip"`
	HasSID      bool     `json:"has_sid"`
	HasPath     bool     `json:"has_path"`
	PQ          bool     `json:"pq,omitempty"` // mldsa65Verify задан
	Issues      []string `json:"issues,omitempty"`
}

func (p *Profile) Summary() Summary {
	s := Summary{Source: p.Source, Origin: p.Origin, Active: p.Active, Transport: p.Transport(), Security: p.Security,
		Fingerprint: strings.ToLower(p.Fingerprint), Mode: p.Mode, Flow: p.Flow,
		ServerIsIP: p.ServerIsIP(), HasSID: p.ShortID != "", HasPath: p.Path != "", PQ: p.Mldsa65Verify != ""}
	if p.Port == 443 {
		s.Port = 443
	} else {
		s.PortCustom = p.Port > 0
	}
	for _, i := range p.Validate() {
		s.Issues = append(s.Issues, i.Code)
	}
	return s
}

// Key — ключ профиля для сравнения «тот же ли это сервер и профиль» без секретов в памяти
// дольше нужного: хэш адреса, порта, UUID и pbk.
func (p *Profile) Key() string {
	return redact.HashWith([]byte("xdiag/profile-key"), strings.Join([]string{
		strings.ToLower(strings.Trim(p.Address, "[]")), fmt.Sprint(p.Port), strings.ToLower(p.UUID), p.PublicKey}, "|"))
}

// ServerKey — ключ сервера (адрес+порт) для бюджета проб между сессиями.
func (p *Profile) ServerKey() string {
	return redact.HashWith([]byte("xdiag/server-key"), strings.ToLower(strings.Trim(p.Address, "[]"))+"|"+fmt.Sprint(p.Port))
}

// IsRealityVLESS — профиль, который приложение умеет диагностировать.
func (p *Profile) IsRealityVLESS() bool {
	return (p.Protocol == "" || p.Protocol == "vless") && p.Security == "reality"
}

// Same — два профиля об одном и том же (адрес, порт, UUID, ключ).
func Same(a, b *Profile) bool { return a != nil && b != nil && a.Key() == b.Key() }

// Diff — какие поля различаются (имена полей, без значений).
func Diff(a, b *Profile) []string {
	var out []string
	cmp := func(name, x, y string) {
		if x != y {
			out = append(out, name)
		}
	}
	cmp("address", strings.ToLower(a.Address), strings.ToLower(b.Address))
	cmp("port", fmt.Sprint(a.Port), fmt.Sprint(b.Port))
	cmp("uuid", strings.ToLower(a.UUID), strings.ToLower(b.UUID))
	cmp("pbk", a.PublicKey, b.PublicKey)
	cmp("sid", strings.ToLower(a.ShortID), strings.ToLower(b.ShortID))
	cmp("sni", strings.ToLower(a.SNI), strings.ToLower(b.SNI))
	cmp("fp", strings.ToLower(a.Fingerprint), strings.ToLower(b.Fingerprint))
	cmp("transport", a.Transport(), b.Transport())
	cmp("path", a.Path, b.Path)
	cmp("mode", normMode(a.Mode), normMode(b.Mode))
	cmp("flow", a.Flow, b.Flow)
	return out
}

func normMode(m string) string {
	if m == "" {
		return "auto"
	}
	return m
}
