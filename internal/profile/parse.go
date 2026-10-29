package profile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var reVLESS = regexp.MustCompile(`(?i)vless://[^\s"'<>\x60\\]+`)

// ParseURI разбирает vless://UUID@host:port?params#name.
func ParseURI(raw string) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "vless://") {
		return nil, errors.New("не vless:// URI")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Частая порча: неэкранированные символы в имени после #.
		if i := strings.IndexByte(raw, '#'); i > 0 {
			u, err = url.Parse(raw[:i])
		}
		if err != nil {
			return nil, errors.New("URI не разбирается: испорчен при копировании")
		}
	}
	p := &Profile{Source: "uri", Origin: "URI", Protocol: "vless", Encryption: "none", Network: "tcp"}
	if u.User != nil {
		p.UUID = u.User.Username()
	}
	p.Address = u.Hostname()
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil {
			return nil, errors.New("порт в URI не число")
		}
		p.Port = n
	}
	if f := u.Fragment; f != "" {
		p.Name = f
	}
	q := u.Query()
	get := func(k ...string) string {
		for _, x := range k {
			if v := q.Get(x); v != "" {
				return v
			}
		}
		return ""
	}
	if v := get("type"); v != "" {
		p.Network = strings.ToLower(v)
	}
	p.Security = strings.ToLower(get("security"))
	if p.Security == "" {
		p.Security = "none"
	}
	if v := get("encryption"); v != "" {
		p.Encryption = v
	}
	p.Flow = get("flow")
	p.SNI = get("sni", "serverName")
	p.Fingerprint = get("fp")
	p.PublicKey = get("pbk", "password")
	p.ShortID = get("sid")
	p.SpiderX = get("spx")
	p.Mldsa65Verify = get("pqv")
	p.Path = get("path")
	p.Host = get("host")
	p.Mode = get("mode")
	p.Extra = get("extra")
	if a := get("alpn"); a != "" {
		p.ALPN = strings.Split(a, ",")
	}
	if p.Network == "splithttp" {
		p.Network = "xhttp"
	}
	if p.Network == "raw" {
		p.Network = "tcp"
	}
	return p, nil
}

// FindURIs — все vless:// в тексте (подписка, буфер обмена, лог).
func FindURIs(text string) []*Profile {
	var out []*Profile
	// Подписка часто в base64 целиком.
	if !strings.Contains(text, "://") {
		if b, err := decodeB64(strings.TrimSpace(text)); err == nil {
			text = string(b)
		}
	}
	for _, m := range reVLESS.FindAllString(text, -1) {
		if p, err := ParseURI(m); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func decodeB64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

// ─── sing-box (Hiddify) ──────────────────────────────────────────────────────

type sbOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	TLS        *struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		ALPN       []string `json:"alpn"`
		UTLS       *struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
		Reality *struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
	} `json:"tls"`
	Transport *struct {
		Type    string          `json:"type"`
		Path    string          `json:"path"`
		Host    json.RawMessage `json:"host"`
		Mode    string          `json:"mode"`
		Headers map[string]any  `json:"headers"`
	} `json:"transport"`
}

// ParseSingBox достаёт VLESS-outbound'ы из конфига sing-box (полного или только outbounds).
func ParseSingBox(data []byte) ([]*Profile, error) {
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("не JSON: %w", err)
	}
	var out []*Profile
	for _, raw := range doc.Outbounds {
		var o sbOutbound
		if json.Unmarshal(raw, &o) != nil || o.Type != "vless" {
			continue
		}
		p := &Profile{Source: "singbox", Protocol: "vless", Name: o.Tag, Address: o.Server, Port: o.ServerPort,
			UUID: o.UUID, Flow: o.Flow, Encryption: "none", Network: "tcp", Security: "none"}
		if o.TLS != nil && o.TLS.Enabled {
			p.Security = "tls"
			p.SNI = o.TLS.ServerName
			p.ALPN = o.TLS.ALPN
			if o.TLS.UTLS != nil && o.TLS.UTLS.Enabled {
				p.Fingerprint = o.TLS.UTLS.Fingerprint
			}
			if o.TLS.Reality != nil && o.TLS.Reality.Enabled {
				p.Security = "reality"
				p.PublicKey = o.TLS.Reality.PublicKey
				p.ShortID = o.TLS.Reality.ShortID
			}
		}
		if t := o.Transport; t != nil && t.Type != "" {
			p.Network = strings.ToLower(t.Type)
			if p.Network == "splithttp" {
				p.Network = "xhttp"
			}
			p.Path = t.Path
			p.Mode = t.Mode
			p.Host = firstString(t.Host)
		}
		out = append(out, p)
	}
	return out, nil
}

func firstString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var l []string
	if json.Unmarshal(raw, &l) == nil && len(l) > 0 {
		return l[0]
	}
	return ""
}

// ─── Xray (v2rayN binConfigs, ручной конфиг) ─────────────────────────────────

type xrUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Encryption string `json:"encryption"`
}

type xrOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
	Settings struct {
		Vnext []struct {
			Address string   `json:"address"`
			Port    int      `json:"port"`
			Users   []xrUser `json:"users"`
		} `json:"vnext"`
		// Упрощённая запись Xray: адрес и пользователь прямо в settings.
		Address    string `json:"address"`
		Port       int    `json:"port"`
		ID         string `json:"id"`
		Flow       string `json:"flow"`
		Encryption string `json:"encryption"`
	} `json:"settings"`
	StreamSettings struct {
		Network         string `json:"network"`
		Security        string `json:"security"`
		RealitySettings struct {
			ServerName    string `json:"serverName"`
			Fingerprint   string `json:"fingerprint"`
			PublicKey     string `json:"publicKey"`
			Password      string `json:"password"`
			ShortID       string `json:"shortId"`
			SpiderX       string `json:"spiderX"`
			Mldsa65Verify string `json:"mldsa65Verify"`
		} `json:"realitySettings"`
		XHTTPSettings *struct {
			Path  string          `json:"path"`
			Host  string          `json:"host"`
			Mode  string          `json:"mode"`
			Extra json.RawMessage `json:"extra"`
		} `json:"xhttpSettings"`
		SplitHTTPSettings *struct {
			Path string `json:"path"`
			Host string `json:"host"`
			Mode string `json:"mode"`
		} `json:"splithttpSettings"`
	} `json:"streamSettings"`
}

// ParseXray достаёт VLESS-outbound'ы из конфига Xray.
func ParseXray(data []byte) ([]*Profile, error) {
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("не JSON: %w", err)
	}
	var out []*Profile
	for _, raw := range doc.Outbounds {
		var o xrOutbound
		if json.Unmarshal(raw, &o) != nil || o.Protocol != "vless" {
			continue
		}
		p := &Profile{Source: "xray", Protocol: "vless", Name: o.Tag, Encryption: "none"}
		s := o.Settings
		if len(s.Vnext) > 0 {
			p.Address, p.Port = s.Vnext[0].Address, s.Vnext[0].Port
			if len(s.Vnext[0].Users) > 0 {
				u := s.Vnext[0].Users[0]
				p.UUID, p.Flow = u.ID, u.Flow
				if u.Encryption != "" {
					p.Encryption = u.Encryption
				}
			}
		} else {
			p.Address, p.Port, p.UUID, p.Flow = s.Address, s.Port, s.ID, s.Flow
			if s.Encryption != "" {
				p.Encryption = s.Encryption
			}
		}
		ss := o.StreamSettings
		p.Network = strings.ToLower(ss.Network)
		switch p.Network {
		case "", "raw":
			p.Network = "tcp"
		case "splithttp":
			p.Network = "xhttp"
		}
		p.Security = strings.ToLower(ss.Security)
		if p.Security == "" {
			p.Security = "none"
		}
		rs := ss.RealitySettings
		p.SNI, p.Fingerprint, p.ShortID, p.SpiderX, p.Mldsa65Verify = rs.ServerName, rs.Fingerprint, rs.ShortID, rs.SpiderX, rs.Mldsa65Verify
		p.PublicKey = rs.PublicKey
		if p.PublicKey == "" {
			p.PublicKey = rs.Password
		}
		if x := ss.XHTTPSettings; x != nil {
			p.Path, p.Host, p.Mode = x.Path, x.Host, x.Mode
			if len(x.Extra) > 0 && string(x.Extra) != "null" {
				p.Extra = string(x.Extra)
			}
		} else if x := ss.SplitHTTPSettings; x != nil {
			p.Path, p.Host, p.Mode = x.Path, x.Host, x.Mode
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseAny пробует JSON sing-box, JSON Xray и текст с vless:// — что подойдёт.
func ParseAny(data []byte) []*Profile {
	t := strings.TrimSpace(string(data))
	if strings.HasPrefix(t, "{") {
		if ps, err := ParseXray(data); err == nil && len(ps) > 0 {
			return ps
		}
		if ps, err := ParseSingBox(data); err == nil && len(ps) > 0 {
			return ps
		}
	}
	return FindURIs(t)
}
