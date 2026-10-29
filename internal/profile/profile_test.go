package profile

import (
	"strings"
	"testing"
)

// Тестовые значения: адреса — RFC 5737, домены — example.com, ключ сгенерирован для теста.
const (
	testUUID = "00000000-0000-4000-8000-000000000001"
	testPBK  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
	testURI  = "vless://" + testUUID + "@192.0.2.10:443?encryption=none&security=reality&sni=www.example.com" +
		"&fp=chrome&pbk=" + testPBK + "&sid=0123abcd&type=xhttp&path=%2Fxh-test&mode=auto#test%20profile"
)

func TestParseURI(t *testing.T) {
	p, err := ParseURI(testURI)
	if err != nil {
		t.Fatal(err)
	}
	if p.Address != "192.0.2.10" || p.Port != 443 || p.UUID != testUUID || p.PublicKey != testPBK ||
		p.ShortID != "0123abcd" || p.Network != "xhttp" || p.Path != "/xh-test" || p.Mode != "auto" ||
		p.SNI != "www.example.com" || p.Fingerprint != "chrome" || p.Name != "test profile" || p.Security != "reality" {
		t.Fatalf("разбор: %+v", p)
	}
	if is := p.Validate(); len(is) != 0 {
		t.Fatalf("ожидалось без проблем, есть %+v", is)
	}
	if !p.ServerIsIP() || p.Transport() != "xhttp" {
		t.Fatal("ServerIsIP/Transport")
	}
}

func TestParseURIIPv6AndSplitHTTP(t *testing.T) {
	p, err := ParseURI("vless://" + testUUID + "@[2001:db8::1]:8443?security=reality&type=splithttp&pbk=" + testPBK + "&fp=firefox&sni=example.com&path=/p")
	if err != nil {
		t.Fatal(err)
	}
	if p.Address != "2001:db8::1" || p.Port != 8443 || p.Network != "xhttp" {
		t.Fatalf("%+v", p)
	}
}

func TestValidateIssues(t *testing.T) {
	cases := []struct {
		mut  func(p *Profile)
		want string
	}{
		{func(p *Profile) { p.Fingerprint = "" }, "fp.empty"},
		{func(p *Profile) { p.PublicKey = "abc" }, "pbk.format"},
		{func(p *Profile) { p.ShortID = "xyz" }, "sid.format"},
		{func(p *Profile) { p.ShortID = "abc" }, "sid.format"},
		{func(p *Profile) { p.SNI = "" }, "sni.empty"},
		{func(p *Profile) { p.UUID = " " + testUUID }, "uuid.space"},
		{func(p *Profile) { p.UUID = strings.Repeat("z", 36) }, "uuid.format"},
		{func(p *Profile) { p.Path = "" }, "path.empty"},
		{func(p *Profile) { p.Flow = "xtls-rprx-vision" }, "flow.xhttp"},
		{func(p *Profile) { p.Security = "tls" }, "security.not_reality"},
		{func(p *Profile) { p.Port = 0 }, "port.invalid"},
	}
	for _, c := range cases {
		p, _ := ParseURI(testURI)
		c.mut(p)
		found := false
		for _, is := range p.Validate() {
			if is.Code == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("нет проблемы %s: %+v", c.want, p.Validate())
		}
	}
}

func TestParseSingBox(t *testing.T) {
	js := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"vless","tag":"§ test","server":"198.51.100.7","server_port":443,
	"uuid":"` + testUUID + `","tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
	"reality":{"enabled":true,"public_key":"` + testPBK + `","short_id":"0123abcd"}},"transport":{"type":"xhttp","path":"/xh","mode":"auto","host":"www.example.com"}}]}`
	ps, err := ParseSingBox([]byte(js))
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %d", err, len(ps))
	}
	p := ps[0]
	if p.Security != "reality" || p.Network != "xhttp" || p.Path != "/xh" || p.PublicKey != testPBK || p.Fingerprint != "chrome" {
		t.Fatalf("%+v", p)
	}
	if len(ParseAny([]byte(js))) != 1 {
		t.Fatal("ParseAny sing-box")
	}
}

func TestParseXray(t *testing.T) {
	js := `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"203.0.113.5","port":443,
	"users":[{"id":"` + testUUID + `","encryption":"none","flow":""}]}]},"streamSettings":{"network":"xhttp","security":"reality",
	"realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","password":"` + testPBK + `","shortId":"ab","spiderX":"/"},
	"xhttpSettings":{"path":"/x","mode":"auto"}}},{"protocol":"freedom","tag":"direct"}]}`
	ps, err := ParseXray([]byte(js))
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %d", err, len(ps))
	}
	p := ps[0]
	if p.Address != "203.0.113.5" || p.PublicKey != testPBK || p.ShortID != "ab" || p.Path != "/x" {
		t.Fatalf("%+v", p)
	}
	if len(p.Validate()) != 0 {
		t.Fatalf("%+v", p.Validate())
	}
}

func TestFindURIsBase64Subscription(t *testing.T) {
	sub := "dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDFAMTkyLjAuMi4xMDo0NDM/c2VjdXJpdHk9cmVhbGl0eSZ0eXBlPXRjcA=="
	ps := FindURIs(sub)
	if len(ps) != 1 || ps[0].Address != "192.0.2.10" {
		t.Fatalf("%d", len(ps))
	}
}

func TestHashesAndDiff(t *testing.T) {
	a, _ := ParseURI(testURI)
	b, _ := ParseURI(testURI)
	salt := []byte("0123456789abcdef")
	if a.Hashes(salt)["pbk"] != b.Hashes(salt)["pbk"] || a.Hashes(salt)["pbk"] == a.Hashes([]byte("other"))["pbk"] {
		t.Fatal("хэши")
	}
	b.ShortID = "ff"
	b.Fingerprint = "edge"
	d := Diff(a, b)
	if strings.Join(d, ",") != "sid,fp" {
		t.Fatalf("diff %v", d)
	}
	if !Same(a, b) {
		t.Fatal("тот же сервер и ключ — Same")
	}
	sum := a.Summary()
	if sum.Transport != "xhttp" || sum.Fingerprint != "chrome" || !sum.ServerIsIP {
		t.Fatalf("%+v", sum)
	}
}
