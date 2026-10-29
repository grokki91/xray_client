package clients

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/rules"
)

// V2rayN — v2rayN 7.x (.NET, портативный каталог).
//
// Пути — по исходникам 2dust/v2rayN (main, 2026-10-20): StartupPath — каталог exe или
// %LOCALAPPDATA%\v2rayN при V2RAYN_LOCAL_APPLICATION_DATA_V2=1; guiConfigs\guiNConfig.json
// (IndexId выбранного профиля, TunModeItem, Inbound, CoreTypeItem), guiConfigs\guiNDB.db
// (таблица ProfileItem; поля Path/Extra/Flow/Id переехали в TransportExtra/ProtoExtra/Password —
// читаются обе схемы), binConfigs\config.json — конфиг запущенного ядра, guiLogs\, ядра —
// bin\xray, bin\sing_box. Ядро профиля — ProfileItem.CoreType, иначе CoreTypeItem по типу,
// иначе Xray; в режиме TUN sing-box поднимает только TUN, REALITY делает ядро профиля.
type V2rayN struct{}

func (*V2rayN) Name() string  { return "v2rayn" }
func (*V2rayN) Title() string { return "v2rayN" }

var v2CoreTypes = map[int]string{1: "v2fly", 2: "Xray", 4: "v2fly_v5", 13: "mihomo", 24: "sing_box"}

type v2Config struct {
	IndexID     string `json:"IndexId"`
	TunModeItem struct {
		EnableTun bool `json:"EnableTun"`
	} `json:"TunModeItem"`
	CoreBasicItem struct {
		LogEnabled bool `json:"LogEnabled"`
	} `json:"CoreBasicItem"`
	Inbound []struct {
		LocalPort    int  `json:"LocalPort"`
		AllowLANConn bool `json:"AllowLANConn"`
	} `json:"Inbound"`
	CoreTypeItem []struct {
		ConfigType int `json:"ConfigType"`
		CoreType   int `json:"CoreType"`
	} `json:"CoreTypeItem"`
	SpeedTestItem struct {
		SpeedPingTestURL string `json:"SpeedPingTestUrl"`
	} `json:"SpeedTestItem"`
	SystemProxyItem struct {
		SysProxyType int `json:"SysProxyType"`
	} `json:"SystemProxyItem"`
}

func (v *V2rayN) roots(env *Env) []string {
	var out []string
	add := func(p string) {
		if p != "" {
			out = append(out, p)
		}
	}
	add(env.V2rayNDir)
	if env.OS != nil {
		for _, p := range env.OS.ProcessByName("v2rayn") {
			if p.Path != "" {
				add(filepath.Dir(p.Path))
			}
		}
	}
	if env.LocalAppData != "" {
		add(filepath.Join(env.LocalAppData, "v2rayN"))
	}
	for _, base := range []string{env.UserProfile, filepath.Join(env.UserProfile, "Desktop"), filepath.Join(env.UserProfile, "Downloads"),
		filepath.Join(env.UserProfile, "Documents"), env.ProgramFiles, `C:\`, `D:\`} {
		if base == "" {
			continue
		}
		for _, pat := range []string{"v2rayN*", filepath.Join("v2rayN*", "v2rayN*")} {
			m, _ := filepath.Glob(filepath.Join(base, pat))
			out = append(out, m...)
		}
	}
	return out
}

func (v *V2rayN) Detect(ctx context.Context, env *Env) Detection {
	d := Detection{Client: "v2rayn", Portable: true, Support: "full"}
	for _, r := range v.roots(env) {
		if exists(filepath.Join(r, "guiConfigs", "guiNConfig.json")) || exists(filepath.Join(r, "v2rayN.exe")) {
			d.DataDir, d.Installed = r, true
			break
		}
	}
	if !d.Installed {
		return d
	}
	if exe := filepath.Join(d.DataDir, "v2rayN.exe"); exists(exe) {
		d.ExePath = exe
		if env.FileVersion != nil {
			d.Version = env.FileVersion(exe)
		}
	}
	if d.Version == "" && env.OS != nil {
		for _, p := range env.OS.ProcessByName("v2rayn") {
			if p.Version != "" {
				d.Version = p.Version
			}
		}
	}
	cfg := v.config(d.DataDir)
	d.TUN = cfg.TunModeItem.EnableTun
	d.Mode = "proxy"
	if cfg.SystemProxyItem.SysProxyType == 1 {
		d.Mode = "system-proxy"
	}
	if d.TUN {
		d.Mode = "vpn"
	}
	if len(cfg.Inbound) > 0 {
		d.ProxyPort, d.LAN = cfg.Inbound[0].LocalPort, cfg.Inbound[0].AllowLANConn
	}
	if d.ProxyPort == 0 {
		d.ProxyPort = 10808
	}
	d.TestURL = cfg.SpeedTestItem.SpeedPingTestURL
	core := "Xray"
	for _, ct := range cfg.CoreTypeItem {
		if ct.ConfigType == 5 { // VLESS
			if n, ok := v2CoreTypes[ct.CoreType]; ok {
				core = n
			}
		}
	}
	v.setCore(ctx, env, &d, core)
	return d
}

// setCore — ядро, версия и X25519MLKEM768 по имени ядра v2rayN.
func (v *V2rayN) setCore(ctx context.Context, env *Env, d *Detection, core string) {
	d.Core = core
	var ci rules.CoreInfo
	if env.Compat != nil {
		ci, _ = env.Compat.V2rayNCore(core)
	}
	d.CoreFamily = ci.Family
	if d.CoreFamily == "" {
		d.CoreFamily = strings.ToLower(core)
	}
	d.Note = ci.Note
	var exe string
	switch core {
	case "Xray":
		exe = filepath.Join(d.DataDir, "bin", "xray", "xray.exe")
		if !exists(exe) {
			exe = filepath.Join(d.DataDir, "bin", "xray.exe")
		}
	case "sing_box":
		exe = filepath.Join(d.DataDir, "bin", "sing_box", "sing-box.exe")
	case "mihomo":
		exe = filepath.Join(d.DataDir, "bin", "mihomo", "mihomo.exe")
	}
	if exe != "" && exists(exe) && env.RunVersion != nil {
		if out, err := env.RunVersion(ctx, exe, "version"); err == nil || len(out) > 0 {
			if ver, ok := rules.ParseVersion(firstLine(string(out))); ok {
				d.CoreVersion = ver.String()
			}
		}
	}
	switch {
	case ci.Mlkem != nil:
		d.CoreMlkem = ci.Mlkem
	case d.CoreFamily == "xray" && env.Compat != nil:
		if m, known := env.Compat.XrayCoreMlkem(d.CoreVersion); known {
			d.CoreMlkem = boolp(m)
		}
	}
	d.Core = core
	if d.CoreVersion != "" {
		d.Core = core + " " + d.CoreVersion
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (v *V2rayN) config(dir string) v2Config {
	var c v2Config
	b, err := os.ReadFile(filepath.Join(dir, "guiConfigs", "guiNConfig.json"))
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func (v *V2rayN) Profiles(ctx context.Context, env *Env, d Detection) ([]*profile.Profile, error) {
	if d.DataDir == "" {
		return nil, nil
	}
	cfg := v.config(d.DataDir)
	out, err := v.dbProfiles(env, d.DataDir, cfg.IndexID)
	// Конфиг запущенного ядра — то, с чем клиент реально подключается.
	if b, rerr := os.ReadFile(filepath.Join(d.DataDir, "binConfigs", "config.json")); rerr == nil {
		ps, _ := profile.ParseXray(b)
		if len(ps) == 0 {
			ps, _ = profile.ParseSingBox(b)
		}
		for _, p := range ps {
			p.Source = "v2rayn"
			p.Origin = "v2rayN: binConfigs\\config.json (запущенное ядро)"
			p.ID = "running"
			out = append(out, p)
		}
	}
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return out, nil
}

func (v *V2rayN) dbProfiles(env *Env, dir, active string) ([]*profile.Profile, error) {
	src := filepath.Join(dir, "guiConfigs", "guiNDB.db")
	if !exists(src) {
		return nil, os.ErrNotExist
	}
	tmp, cleanup, err := copyToTemp(src, env.TempDir)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(tmp)+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT * FROM ProfileItem`)
	if err != nil {
		return nil, fmt.Errorf("guiNDB.db: %w", err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []*profile.Profile
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if rows.Scan(ptrs...) != nil {
			continue
		}
		m := map[string]string{}
		for i, c := range cols {
			if vals[i] != nil {
				switch t := vals[i].(type) {
				case []byte:
					m[strings.ToLower(c)] = string(t)
				default:
					m[strings.ToLower(c)] = fmt.Sprint(t)
				}
			}
		}
		if m["configtype"] != "5" { // только VLESS
			continue
		}
		out = append(out, v2Row(m, active))
	}
	return out, rows.Err()
}

// v2Row — строка ProfileItem в профиль; обе схемы (старые поля и *Extra-JSON).
func v2Row(m map[string]string, active string) *profile.Profile {
	first := func(ks ...string) string {
		for _, k := range ks {
			if v := strings.TrimSpace(m[k]); v != "" {
				return m[k]
			}
		}
		return ""
	}
	var te struct {
		Path, Host, XhttpMode, XhttpExtra string
	}
	_ = json.Unmarshal([]byte(m["transportextra"]), &te)
	var pe struct {
		Flow, VlessEncryption string
	}
	_ = json.Unmarshal([]byte(m["protoextra"]), &pe)
	port, _ := strconv.Atoi(m["port"])
	p := &profile.Profile{Source: "v2rayn", Origin: "v2rayN: guiNDB.db", Protocol: "vless", ID: m["indexid"],
		Name: m["remarks"], Address: m["address"], Port: port, UUID: first("password", "id"),
		Flow: firstNonEmpty(pe.Flow, m["flow"]), Encryption: firstNonEmpty(pe.VlessEncryption, m["security"], "none"),
		Network: strings.ToLower(firstNonEmpty(m["network"], "tcp")), Security: strings.ToLower(firstNonEmpty(m["streamsecurity"], "none")),
		SNI: m["sni"], Fingerprint: m["fingerprint"], PublicKey: m["publickey"], ShortID: m["shortid"], SpiderX: m["spiderx"],
		Mldsa65Verify: m["mldsa65verify"], Path: firstNonEmpty(te.Path, m["path"]), Host: firstNonEmpty(te.Host, m["requesthost"]),
		Mode: firstNonEmpty(te.XhttpMode, m["headertype"]), Extra: firstNonEmpty(te.XhttpExtra, m["extra"])}
	if p.Network == "splithttp" {
		p.Network = "xhttp"
	}
	if p.Network == "raw" {
		p.Network = "tcp"
	}
	if p.Network != "xhttp" {
		p.Mode = "" // HeaderType у TCP — тип заголовка, не режим XHTTP
	}
	if p.Encryption == "" || p.Encryption == "auto" {
		p.Encryption = "none"
	}
	p.Active = p.ID != "" && p.ID == active
	if ct, err := strconv.Atoi(m["coretype"]); err == nil {
		p.CoreOverride = v2CoreTypes[ct]
	}
	return p
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (v *V2rayN) Logs(env *Env, d Detection, since time.Time) LogSummary {
	if d.DataDir == "" {
		return LogSummary{Counts: map[string]int{}}
	}
	return ScanLogs(newest(filepath.Join(d.DataDir, "guiLogs", "*.txt"), 3), env.Now())
}

func (v *V2rayN) State(env *Env, d Detection) State {
	var s State
	if env.OS == nil {
		return s
	}
	s.Running = len(env.OS.ProcessByName("v2rayn")) > 0
	listening, exposed := listeningState(env.OS, d.ProxyPort)
	s.CoreListening = listening && len(env.OS.ProcessByName("xray", "sing-box", "mihomo")) > 0
	if exposed || d.LAN {
		if listening && exposed {
			s.Exposed = []int{d.ProxyPort}
		}
	}
	for _, a := range env.OS.Adapters {
		n := strings.ToLower(a.Name + " " + a.Desc)
		if a.Up && (strings.Contains(n, "singbox") || strings.Contains(n, "sing-box") || strings.Contains(n, "xray_tun") || strings.Contains(n, "wintun")) {
			s.TunAdapter = true
		}
	}
	return s
}

func (v *V2rayN) Hints(d Detection) []string {
	var out []string
	if d.TUN {
		out = append(out, "v2rayN в режиме TUN: TUN поднимает sing-box, REALITY делает ядро профиля ("+d.Core+")")
	}
	return out
}
