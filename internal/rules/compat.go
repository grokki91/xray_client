package rules

import (
	"regexp"
	"strconv"
	"strings"
)

// Compat — rules/compat.yaml.
type Compat struct {
	Updated string `yaml:"updated"`
	Source  string `yaml:"source"`
	Server  struct {
		MlkemRuleFrom string `yaml:"mlkem_rule_from"`
	} `yaml:"server"`
	XrayFingerprints map[string]FPInfo `yaml:"xray_fingerprints"`
	XrayBug6797From  string            `yaml:"xray_bug6797_from"`
	Clients          struct {
		Hiddify []HiddifyRow `yaml:"hiddify"`
		V2rayN  struct {
			Cores map[string]CoreInfo `yaml:"cores"`
		} `yaml:"v2rayn"`
	} `yaml:"clients"`
	Recommend string `yaml:"recommend"`
}

// FPInfo — пресет отпечатка в ядре Xray.
type FPInfo struct {
	MlkemFrom *string `yaml:"mlkem_from"`
	Random    bool    `yaml:"random"`
}

// HiddifyRow — строка таблицы версий Hiddify.
type HiddifyRow struct {
	Versions   string `yaml:"versions"`
	Core       string `yaml:"core"`
	CoreFamily string `yaml:"core_family"`
	Mlkem      *bool  `yaml:"mlkem"`
	Note       string `yaml:"note"`
}

// CoreInfo — ядро v2rayN.
type CoreInfo struct {
	Family string `yaml:"family"`
	Mlkem  *bool  `yaml:"mlkem"`
	Note   string `yaml:"note"`
}

// Version — версия x.y.z; нули, если не разобрать.
type Version [3]int

var reVer = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// ParseVersion достаёт первую версию из строки («Xray 26.10.21 (…)», «v4.1.2+40402», «4.1.2 (FileVersion)»).
func ParseVersion(s string) (Version, bool) {
	m := reVer.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var v Version
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return v, true
}

func (v Version) String() string {
	return strconv.Itoa(v[0]) + "." + strconv.Itoa(v[1]) + "." + strconv.Itoa(v[2])
}

// Less — v < o.
func (v Version) Less(o Version) bool {
	for i := 0; i < 3; i++ {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false
}

// AtLeast — v ≥ строка-версия.
func (v Version) AtLeast(s string) bool {
	o, ok := ParseVersion(s)
	return ok && !v.Less(o)
}

// match — версия v в диапазоне вида "<5.0.0", ">=5.0.0", "4.1.x", "4.1.2".
func match(rng string, v Version) bool {
	rng = strings.TrimSpace(rng)
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(rng, op) {
			o, ok := ParseVersion(rng[len(op):])
			if !ok {
				return false
			}
			switch op {
			case ">=":
				return !v.Less(o)
			case "<=":
				return !o.Less(v)
			case ">":
				return o.Less(v)
			case "<":
				return v.Less(o)
			default:
				return v == o
			}
		}
	}
	if strings.HasSuffix(rng, ".x") {
		return strings.HasPrefix(v.String()+".", strings.TrimSuffix(rng, "x"))
	}
	o, ok := ParseVersion(rng)
	return ok && o == v
}

// Hiddify — строка таблицы для версии приложения.
func (c *Compat) Hiddify(ver string) (HiddifyRow, bool) {
	v, ok := ParseVersion(ver)
	if !ok {
		return HiddifyRow{}, false
	}
	for _, r := range c.Clients.Hiddify {
		if match(r.Versions, v) {
			return r, true
		}
	}
	return HiddifyRow{}, false
}

// V2rayNCore — сведения о ядре v2rayN по имени (Xray, sing_box, mihomo).
func (c *Compat) V2rayNCore(name string) (CoreInfo, bool) {
	ci, ok := c.Clients.V2rayN.Cores[name]
	return ci, ok
}

// XrayFPMlkem — шлёт ли ядро Xray версии coreVer с пресетом fp долю X25519MLKEM768.
// known=false — нельзя сказать (версия неизвестна или пресет случайный).
func (c *Compat) XrayFPMlkem(coreVer, fp string) (mlkem, known bool) {
	fp = strings.ToLower(strings.TrimSpace(fp))
	if fp == "" {
		return false, true
	}
	info, ok := c.XrayFingerprints[fp]
	if !ok {
		return false, false
	}
	if info.Random {
		return false, false
	}
	if info.MlkemFrom == nil {
		return false, true
	}
	v, ok := ParseVersion(coreVer)
	if !ok {
		return false, false
	}
	return v.AtLeast(*info.MlkemFrom), true
}

// XrayCoreMlkem — умеет ли ядро Xray версии coreVer X25519MLKEM768 хоть с каким-то пресетом
// (с chrome). known=false — версия неизвестна.
func (c *Compat) XrayCoreMlkem(coreVer string) (mlkem, known bool) {
	return c.XrayFPMlkem(coreVer, "chrome")
}

// MlkemRule — действует ли правило X25519MLKEM768 на сервере этой версии.
func (c *Compat) MlkemRule(serverVer string) bool {
	v, ok := ParseVersion(serverVer)
	return ok && v.AtLeast(c.Server.MlkemRuleFrom)
}

// Bug6797 — ядро Xray с открытой #6797.
func (c *Compat) Bug6797(coreVer string) bool {
	v, ok := ParseVersion(coreVer)
	return ok && c.XrayBug6797From != "" && v.AtLeast(c.XrayBug6797From)
}

// Hosts — rules/hosts.yaml.
type Hosts struct {
	Internet []struct {
		Name            string `yaml:"name" json:"name"`
		URL             string `yaml:"url" json:"url"`
		ExpectBody      string `yaml:"expect_body" json:"expect_body,omitempty"`
		ExpectStatus    int    `yaml:"expect_status" json:"expect_status,omitempty"`
		ExpectStatusMax int    `yaml:"expect_status_max" json:"expect_status_max,omitempty"`
		Region          string `yaml:"region" json:"region"`
	} `yaml:"internet"`
	DNSProbe struct {
		Name      string   `yaml:"name"`
		Resolvers []string `yaml:"resolvers"`
		DoH       string   `yaml:"doh"`
	} `yaml:"dns_probe"`
	Tunnel struct {
		Probe204      string `yaml:"probe_204"`
		Download      string `yaml:"download"`
		DownloadBytes int    `yaml:"download_bytes"`
		RUProbe       string `yaml:"ru_probe"`
	} `yaml:"through_tunnel"`
	Bootstrap []string `yaml:"bootstrap_resolvers"`
}

// PublicHosts — хосты эталонов: их в отчёте прятать незачем.
func (h *Hosts) PublicHosts() []string {
	var out []string
	add := func(u string) {
		if i := strings.Index(u, "://"); i >= 0 {
			u = u[i+3:]
		}
		if j := strings.IndexAny(u, "/?:"); j >= 0 {
			u = u[:j]
		}
		if u != "" {
			out = append(out, u)
		}
	}
	for _, x := range h.Internet {
		add(x.URL)
	}
	add(h.DNSProbe.DoH)
	add(h.Tunnel.Probe204)
	add(h.Tunnel.Download)
	add(h.Tunnel.RUProbe)
	out = append(out, "captive.apple.com", "connectivitycheck.gstatic.com", "detectportal.firefox.com", "cp.cloudflare.com")
	return out
}
