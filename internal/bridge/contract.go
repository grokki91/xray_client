// Package bridge — связь с xm на сервере: SSH-мост (`ssh <алиас> sudo -n xm bridge …`) и ручной
// импорт файлов `xm doctor --json` / `xm health --json` (docs/architecture.md §4, приложение B).
//
// Сервер — только чтение. Клиент вызывает три команды из списка (facts, doctor, health) и ничего
// больше; на сервер уходят соль сессии (stdin) и длина окна. Вывод проверяется по контракту до
// разбора. JSON сервера может нести адрес сервера (doctor: server.server_ip и тексты действий) —
// перед показом и сохранением он проходит редактор.
package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/grokki91/xray_client/internal/redact"
)

// Schema — версия контракта.
type Schema struct {
	Name  string `json:"name"`
	Major int    `json:"major"`
	Minor int    `json:"minor"`
}

// Поддерживаемые major: 0 — вывод xm до поля schema (doctor, health), 1 — с ним.
var supported = map[string][2]int{"bridge-facts": {1, 1}, "doctor": {0, 1}, "health": {0, 1}}

// ErrNewerContract — сервер новее приложения.
var ErrNewerContract = errors.New("контракт сервера новее приложения: обновите xdiag")

// ErrOlderContract — сервер старее приложения.
var ErrOlderContract = errors.New("контракт сервера старее приложения: на сервере `sudo xm self-update`")

func checkSchema(name string, s *Schema) error {
	r := supported[name]
	major := 0
	if s != nil {
		if s.Name != "" && s.Name != name {
			return fmt.Errorf("ожидался вывод %s, пришёл %s", name, s.Name)
		}
		major = s.Major
	}
	switch {
	case major > r[1]:
		return ErrNewerContract
	case major < r[0]:
		return ErrOlderContract
	}
	return nil
}

// ─── bridge-facts ────────────────────────────────────────────────────────────

// Facts — `xm bridge facts` (приложение B).
type Facts struct {
	Schema *Schema `json:"schema"`
	XM     struct {
		Commit string `json:"commit"`
		Branch string `json:"branch"`
	} `json:"xm"`
	Time int64 `json:"time"`
	Xray struct {
		Version      string `json:"version"`
		Active       bool   `json:"active"`
		MlkemRule    *bool  `json:"mlkem_rule"`
		MinClientVer string `json:"min_client_ver"`
	} `json:"xray"`
	Public struct {
		Port       int    `json:"port"`
		Transport  string `json:"transport"`
		Mode       string `json:"mode"`
		FP         string `json:"fp"`
		SNI        string `json:"sni"`
		Front      bool   `json:"front"`
		TCPInbound bool   `json:"tcp_inbound"`
		PQ         bool   `json:"pq"`
	} `json:"public"`
	Firewall struct {
		UFW string `json:"ufw"`
	} `json:"firewall"`
	DNS struct {
		DoH      bool   `json:"doh"`
		Hijack53 bool   `json:"hijack53"`
		NonIP    string `json:"nonip"`
	} `json:"dns"`
	RUBlock bool `json:"ru_block"`
	Self    struct {
		R  string `json:"r"`
		At string `json:"at"`
		MS int    `json:"ms"`
	} `json:"self"`
	Health struct {
		Enabled    bool `json:"enabled"`
		LastWindow struct {
			T  int64  `json:"t"`
			VD string `json:"vd"`
		} `json:"last_window"`
		LastTraffic int64 `json:"last_traffic"`
	} `json:"health"`
	Profile *struct {
		Salted   bool              `json:"salted"`
		Clients  map[string]string `json:"clients"`
		PBK      string            `json:"pbk"`
		ShortIDs []string          `json:"short_ids"`
		Path     string            `json:"path"`
		SNI      []string          `json:"sni"`
		Port     string            `json:"port"`
	} `json:"profile"`
}

// ParseFacts — разбор и проверка контракта.
func ParseFacts(b []byte) (*Facts, error) {
	var f Facts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("bridge facts: не JSON: %w", err)
	}
	if f.Schema == nil {
		return nil, errors.New("bridge facts: нет поля schema")
	}
	if err := checkSchema("bridge-facts", f.Schema); err != nil {
		return nil, err
	}
	if f.Xray.Version == "" {
		return nil, errors.New("bridge facts: нет версии Xray")
	}
	return &f, nil
}

// Match — сверка хэшей профиля (HMAC на той же соли) с сервером: поле → совпало ли.
// Поля, которых сервер не прислал, не попадают в результат (неизвестно ≠ не совпало).
func (f *Facts) Match(h map[string]string) map[string]bool {
	out := map[string]bool{}
	if f.Profile == nil || !f.Profile.Salted {
		return out
	}
	if v := h["uuid"]; v != "" && len(f.Profile.Clients) > 0 {
		ok := false
		for _, c := range f.Profile.Clients {
			if c == v {
				ok = true
			}
		}
		out["uuid"] = ok
	}
	if v := h["pbk"]; v != "" && f.Profile.PBK != "" {
		out["pbk"] = v == f.Profile.PBK
	}
	if v := h["sid"]; v != "" && len(f.Profile.ShortIDs) > 0 {
		out["sid"] = contains(f.Profile.ShortIDs, v)
	} else if h["sid"] == "" && len(f.Profile.ShortIDs) > 0 {
		// Пустой shortId у клиента допустим, только если он есть в списке сервера (пустая строка).
		out["sid"] = contains(f.Profile.ShortIDs, "")
	}
	if v := h["path"]; v != "" && f.Profile.Path != "" {
		out["path"] = v == f.Profile.Path
	}
	if v := h["sni"]; v != "" && len(f.Profile.SNI) > 0 {
		out["sni"] = contains(f.Profile.SNI, v)
	}
	if v := h["port"]; v != "" && f.Profile.Port != "" {
		out["port"] = v == f.Profile.Port
	}
	return out
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ─── xm doctor --json ────────────────────────────────────────────────────────

// Doctor — вывод ui/doctor.py run --json.
type Doctor struct {
	Schema *Schema `json:"schema"`
	Server struct {
		Self struct {
			R  string `json:"r"`
			At string `json:"at"`
			MS any    `json:"ms"`
		} `json:"self"`
		XVer     string           `json:"xver"`
		Port     int              `json:"port"`
		UFW      string           `json:"ufw"`
		SSHPeer  bool             `json:"ssh_peer"`
		ServerIP string           `json:"server_ip"`
		Traffic  map[string]int64 `json:"traffic"`
	} `json:"server"`
	Timeline struct {
		Windows     int   `json:"windows"`
		LastTraffic int64 `json:"last_traffic"`
		After       []struct {
			T    int64  `json:"t"`
			E    string `json:"e"`
			Text string `json:"text"`
		} `json:"after"`
		SelfLast string `json:"self_last"`
	} `json:"timeline"`
	Profile struct {
		Backups   int      `json:"backups"`
		Changed   []string `json:"changed"`
		Before    float64  `json:"before"`
		SameSince float64  `json:"same_since"`
	} `json:"profile"`
	Groups []struct {
		Label    string    `json:"label"`
		SSH      bool      `json:"ssh"`
		Own      bool      `json:"own"`
		Attempts []Attempt `json:"attempts"`
	} `json:"groups"`
	Live *struct {
		Seconds int    `json:"seconds"`
		Old     int    `json:"old"`
		Drops   int    `json:"drops"`
		Error   string `json:"error"`
	} `json:"live"`
	Verdict struct {
		Code     string   `json:"code"`
		Title    string   `json:"title"`
		Evidence []string `json:"evidence"`
		Actions  []string `json:"actions"`
		RuledOut []string `json:"ruled_out"`
	} `json:"verdict"`
}

// Attempt — одна попытка в окне.
type Attempt struct {
	T     float64 `json:"t"`
	SYN   int     `json:"syn"`
	C     int64   `json:"c"`
	S     int64   `json:"s"`
	Acked int64   `json:"acked"`
	St    string  `json:"st"`
	Have  int     `json:"have"`
	Need  int     `json:"need"`
	After string  `json:"after"`
	RD    *struct {
		SNI       string   `json:"sni"`
		MLKEM     bool     `json:"mlkem"`
		Shares    []string `json:"shares"`
		Own       bool     `json:"own"`
		MLKEMRule bool     `json:"mlkem_rule"`
		Core      string   `json:"core"`
		DT        int      `json:"dt"`
		SIDOK     bool     `json:"sid_ok"`
		R         string   `json:"r"`
	} `json:"rd"`
}

// ParseDoctor — разбор с проверкой контракта.
func ParseDoctor(b []byte) (*Doctor, error) {
	var d Doctor
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("doctor: не JSON: %w", err)
	}
	if err := checkSchema("doctor", d.Schema); err != nil {
		return nil, err
	}
	if d.Verdict.Code == "" {
		return nil, errors.New("doctor: нет verdict.code — это не вывод `xm doctor --json`")
	}
	return &d, nil
}

// Register — адрес сервера из doctor в редактор (до показа и сохранения).
func (d *Doctor) Register(r *redact.Redactor) {
	r.Add(redact.Server, d.Server.ServerIP)
}

// Window — была ли живая попытка в окне.
func (d *Doctor) Window() bool { return d.Live != nil && d.Live.Error == "" && d.Live.Seconds > 0 }

// Pick — попытка, которая про этот ПК: сеть SSH-сеанса, иначе сеть с ключом сервера.
// ssh — попытка из сети SSH-сеанса (= сети ПК, если мост шёл с этого ПК).
func (d *Doctor) Pick() (a *Attempt, ssh, own bool, n int) {
	idx := -1
	for i, g := range d.Groups {
		if g.SSH {
			idx = i
			break
		}
	}
	if idx < 0 {
		for i, g := range d.Groups {
			if g.Own {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return nil, false, false, 0
	}
	g := d.Groups[idx]
	if len(g.Attempts) == 0 {
		return nil, g.SSH, g.Own, 0
	}
	// Предпочтение — попытке с ключом этого сервера: её решение REALITY точное.
	best := &g.Attempts[len(g.Attempts)-1]
	for i := range g.Attempts {
		if g.Attempts[i].RD != nil && g.Attempts[i].RD.Own {
			best = &g.Attempts[i]
		}
	}
	return best, g.SSH, g.Own, len(g.Attempts)
}

// ─── xm health --json ────────────────────────────────────────────────────────

// Health — вывод ui/health.py report --json ({} — журнала нет).
type Health struct {
	Schema *Schema `json:"schema"`
	Now    int64   `json:"now"`
	D7     *struct {
		Windows        int      `json:"windows"`
		SelfRuns       int      `json:"self_runs"`
		SelfOK         int      `json:"self_ok"`
		TrafficWindows int      `json:"traffic_windows"`
		TrafficOK      int      `json:"traffic_ok"`
		ReadyPct       *float64 `json:"ready_pct"`
		SessionsPct    *float64 `json:"sessions_pct"`
	} `json:"d7"`
	Incidents []struct {
		From int64  `json:"from"`
		To   int64  `json:"to"`
		Why  string `json:"why"`
		VD   string `json:"vd"`
		N    int    `json:"n"`
	} `json:"incidents"`
	Events []struct {
		T int64  `json:"t"`
		E string `json:"e"`
	} `json:"events"`
	Last *struct {
		T  int64  `json:"t"`
		VD string `json:"vd"`
		TR *int64 `json:"tr"`
	} `json:"last"`
}

// ParseHealth — разбор с проверкой контракта.
func ParseHealth(b []byte) (*Health, error) {
	var h Health
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("health: не JSON: %w", err)
	}
	if err := checkSchema("health", h.Schema); err != nil {
		return nil, err
	}
	return &h, nil
}

// Empty — журнал здоровья на сервере выключен или пуст.
func (h *Health) Empty() bool { return h.D7 == nil && h.Last == nil }

// LastXrayVersion — последняя смена версии Xray в событиях («ver_xray:26.10.21»).
func (h *Health) LastXrayVersion() (string, int64) {
	evs := append([]struct {
		T int64  `json:"t"`
		E string `json:"e"`
	}{}, h.Events...)
	sort.Slice(evs, func(i, j int) bool { return evs[i].T < evs[j].T })
	for i := len(evs) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(evs[i].E, "ver_xray:"); ok {
			return v, evs[i].T
		}
	}
	return "", 0
}

// Count — инциденты вида vd.
func (h *Health) Count(vd string) int {
	n := 0
	for _, x := range h.Incidents {
		if x.VD == vd {
			n += x.N
		}
	}
	return n
}

// ─── Импорт ──────────────────────────────────────────────────────────────────

// Detect — что за файл: doctor | health | facts.
func Detect(b []byte) string {
	var probe map[string]json.RawMessage
	if json.Unmarshal(b, &probe) != nil {
		return ""
	}
	if s, ok := probe["schema"]; ok {
		var sc Schema
		if json.Unmarshal(s, &sc) == nil && sc.Name == "bridge-facts" {
			return "facts"
		}
	}
	switch {
	case probe["verdict"] != nil && probe["server"] != nil:
		return "doctor"
	case probe["d7"] != nil || probe["band"] != nil || len(probe) == 0:
		return "health"
	}
	return ""
}
