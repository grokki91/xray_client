package netprobe

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSAnswer — ответ одного способа (N3).
type DNSAnswer struct {
	Method string   `json:"method"` // udp | tcp | doh
	Rcode  string   `json:"rcode"`  // NOERROR | NXDOMAIN | … | timeout | error
	IPs    []string `json:"-"`      // адреса — только в память
}

// DNSCompare — N3: одно имя тремя способами; Mismatch — подмена по UDP.
type DNSCompare struct {
	Answers         []DNSAnswer `json:"answers"`
	Mismatch        bool        `json:"mismatch"`
	NXDomainUDPOnly bool        `json:"nxdomain_udp_only"`
}

// CompareDNS спрашивает name по UDP/53 и TCP/53 у resolver и по DoH.
func CompareDNS(ctx context.Context, d *Dialer, hc *http.Client, name, resolver, doh string) DNSCompare {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	var out DNSCompare
	ask := func(method string) DNSAnswer {
		c := &dns.Client{Net: method, Timeout: 5 * time.Second, Dialer: d.NetDialer()}
		addr := resolver
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		m, _, err := c.ExchangeContext(ctx, q.Copy(), addr)
		return toAnswer(method, m, err)
	}
	out.Answers = append(out.Answers, ask("udp"), ask("tcp"))
	if doh != "" && hc != nil {
		out.Answers = append(out.Answers, askDoH(ctx, hc, doh, q))
	}
	udp := out.Answers[0]
	var honest *DNSAnswer
	for i := 1; i < len(out.Answers); i++ {
		if a := out.Answers[i]; a.Rcode == "NOERROR" && len(a.IPs) > 0 {
			honest = &out.Answers[i]
			break
		}
	}
	if honest != nil {
		switch {
		case udp.Rcode == "NXDOMAIN":
			out.Mismatch, out.NXDomainUDPOnly = true, true
		case udp.Rcode == "NOERROR" && !overlap(udp.IPs, honest.IPs):
			out.Mismatch = true
		}
	}
	return out
}

func askDoH(ctx context.Context, hc *http.Client, url string, q *dns.Msg) DNSAnswer {
	wire, err := q.Pack()
	if err != nil {
		return DNSAnswer{Method: "doh", Rcode: "error"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return DNSAnswer{Method: "doh", Rcode: "error"}
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := hc.Do(req)
	if err != nil {
		return DNSAnswer{Method: "doh", Rcode: Classify(err)}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 65535))
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return DNSAnswer{Method: "doh", Rcode: "error"}
	}
	return toAnswer("doh", m, nil)
}

func toAnswer(method string, m *dns.Msg, err error) DNSAnswer {
	if err != nil {
		return DNSAnswer{Method: method, Rcode: Classify(err)}
	}
	a := DNSAnswer{Method: method, Rcode: dns.RcodeToString[m.Rcode]}
	for _, rr := range m.Answer {
		if x, ok := rr.(*dns.A); ok {
			a.IPs = append(a.IPs, x.A.String())
		}
	}
	sort.Strings(a.IPs)
	return a
}

func overlap(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if set[x] {
			return true
		}
	}
	return false
}

// IsLoopbackAddr — адрес петли.
func IsLoopbackAddr(s string) bool {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.IsLoopback()
}
