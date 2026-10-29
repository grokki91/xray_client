// Package osw — факты Windows (L1): адаптеры, маршрут по умолчанию, DNS, файрвол, антивирус,
// системный прокси, часы, IPv6, MTU, процессы и слушающие порты клиентов.
//
// Сбор — одним вызовом PowerShell с выводом JSON (быстрее десятка утилит и без разбора
// локализованного текста), только чтение. Вне Windows — пустые факты с пометкой.
package osw

import (
	"context"
	"encoding/json"
	"strings"
)

// Adapter — сетевой адаптер.
type Adapter struct {
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	IfIndex int    `json:"if_index"`
	Up      bool   `json:"up"`
	Kind    string `json:"kind"` // physical | tun | vpn | virtual | loopback
	MTU     int    `json:"mtu"`
}

// Process — процесс клиента.
type Process struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

// Listen — слушающий TCP-сокет.
type Listen struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	PID  int    `json:"pid"`
}

// Facts — всё собранное.
type Facts struct {
	Collected bool   `json:"collected"`
	Err       string `json:"err,omitempty"`

	Adapters       []Adapter `json:"adapters"`
	DefaultIfIndex int       `json:"default_if_index"` // физический адаптер с маршрутом по умолчанию
	DefaultViaTUN  bool      `json:"default_via_tun"`  // маршрут по умолчанию сейчас идёт в TUN/VPN

	DNSServers int  `json:"dns_servers"`
	DoH        bool `json:"doh"`
	SMHNROff   bool `json:"smhnr_off"`
	NRPT       int  `json:"nrpt"`

	FirewallOn bool     `json:"firewall_on"`
	BlockRules []string `json:"block_rules"` // программы клиентов под правилом «Блокировать»

	AV           []string `json:"av"`
	ThirdPartyAV bool     `json:"third_party_av"`

	ProxyEnable bool   `json:"proxy_enable"`
	ProxyServer string `json:"proxy_server"`
	ProxyPAC    bool   `json:"proxy_pac"`
	WinHTTP     bool   `json:"winhttp"`

	TimeSynced bool   `json:"time_synced"`
	TimeSource string `json:"time_source"`

	GlobalV6 bool `json:"global_v6"`

	Processes []Process         `json:"processes"`
	Listening []Listen          `json:"listening"`
	Services  map[string]string `json:"services"`
}

// Collect собирает факты. clientPaths — exe клиентов для версии файла (Hiddify, v2rayN).
func Collect(ctx context.Context, clientPaths []string) Facts {
	return collect(ctx, clientPaths)
}

// AdapterKind — вид адаптера по имени и описанию.
func AdapterKind(name, desc string) string {
	s := strings.ToLower(name + " " + desc)
	switch {
	case strings.Contains(s, "loopback"):
		return "loopback"
	case containsAny(s, "hiddify", "sing-box", "singbox", "wintun", "xray", "v2ray", "clash", "mihomo", "tun2socks"):
		return "tun"
	case containsAny(s, "wireguard", "openvpn", "tap-windows", "tap adapter", "amnezia", "outline", "vpn", "zerotier", "tailscale", "nordlynx", "cisco anyconnect", "fortinet", "proton", "warp", "cloudflare"):
		return "vpn"
	case containsAny(s, "hyper-v", "vethernet", "vmware", "virtualbox", "npcap", "wsl", "docker", "bluetooth", "kernel debug", "teredo", "isatap", "6to4"):
		return "virtual"
	}
	return "physical"
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// Adapter — адаптер по индексу.
func (f *Facts) Adapter(idx int) *Adapter {
	for i := range f.Adapters {
		if f.Adapters[i].IfIndex == idx {
			return &f.Adapters[i]
		}
	}
	return nil
}

// Up — адаптеры в состоянии Up заданного вида.
func (f *Facts) Up(kind string) []Adapter {
	var out []Adapter
	for _, a := range f.Adapters {
		if a.Up && a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// ProcessByName — процессы по имени без .exe, без учёта регистра.
func (f *Facts) ProcessByName(names ...string) []Process {
	var out []Process
	for _, p := range f.Processes {
		n := strings.TrimSuffix(strings.ToLower(p.Name), ".exe")
		for _, x := range names {
			if n == strings.ToLower(x) {
				out = append(out, p)
			}
		}
	}
	return out
}

// ListeningOn — сокеты на порту.
func (f *Facts) ListeningOn(port int) []Listen {
	var out []Listen
	for _, l := range f.Listening {
		if l.Port == port {
			out = append(out, l)
		}
	}
	return out
}

// asList — PowerShell ConvertTo-Json отдаёт одиночный элемент объектом, а не массивом.
func asList(raw json.RawMessage) []json.RawMessage {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] == '[' {
		var l []json.RawMessage
		_ = json.Unmarshal(raw, &l)
		return l
	}
	return []json.RawMessage{raw}
}
