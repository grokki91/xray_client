package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/profile"
	"github.com/grokki91/xray_client/internal/redact"
	"github.com/grokki91/xray_client/internal/refcore"
)

// otherNetworkWindow — насколько старый сеанс из другой сети ещё сравним с этим: за часы сервер
// мог упасть или подняться, и сравнение стало бы про разное время, а не про разные сети.
const otherNetworkWindow = 3 * time.Hour

// networkKey — отпечаток сети ПК: хэш MAC шлюза маршрута по умолчанию (роутер дома, телефон в
// режиме модема), а если MAC не узнать (модем точка-точка) — хэш адаптера. Хранится только в
// DPAPI-файле сеанса (Secret). Пусто — сеть не определить, сравнения нет.
func networkKey(f *osw.Facts) string {
	if f == nil || !f.Collected {
		return ""
	}
	if f.GatewayMAC != "" {
		return redact.HashWith([]byte("xdiag/network"), "gw|"+f.GatewayMAC)
	}
	if a := f.Adapter(f.DefaultIfIndex); a != nil && a.Desc != "" {
		return redact.HashWith([]byte("xdiag/network"), "if|"+strings.ToLower(a.Desc))
	}
	return ""
}

// otherNetwork — P5 без участия пользователя: последний сеанс к тому же серверу из другой сети
// (другой шлюз) за otherNetworkWindow. Улики этого сеанса не трогаются: P5 — только сравнение
// проб к серверу. Так «из другой сети» срабатывает в обе стороны — с какой сети ни запусти
// второй раз, — и не верит на слово галочке, что сеть сменилась.
func (r *run) otherNetwork() {
	if r.e.Store == nil || r.prof == nil {
		return
	}
	cur := r.set.Get("P1").Str("outcome")
	key := networkKey(&r.facts)
	if !comparableTCP(cur) || key == "" {
		return
	}
	loaded := 0
	for _, ie := range r.e.Store.Sessions() {
		age := r.sess.Started.Sub(ie.At)
		if age > otherNetworkWindow || loaded >= 20 {
			return
		}
		if age <= 0 {
			continue
		}
		loaded++
		prev, err := r.e.Load(ie.ID)
		if err != nil || prev.Secret == nil || prev.Secret.Network == "" || prev.Secret.Network == key || !sameServer(prev.Secret, r.prof) {
			continue
		}
		pe := evidence.FromList(prev.Evidence)
		p1 := pe.Get("P1")
		if p1 == nil || !comparableTCP(p1.Str("outcome")) {
			continue
		}
		r.putOtherNetwork(pe, p1, age, cur)
		return
	}
}

func (r *run) putOtherNetwork(pe *evidence.Set, p1 *evidence.Evidence, age time.Duration, cur string) {
	o := p1.Str("outcome")
	f := map[string]any{"ran": true, "network_changed": true, "p1": o, "age_min": int(age.Minutes())}
	parts := []string{"TCP до порта сервера — " + otherTCPText(o)}
	if x := pe.Get("P2").Str("outcome"); x != "" {
		f["p2"] = x
	}
	if x := pe.Get("P3").Str("outcome"); x != "" {
		f["p3"] = x
		parts = append(parts, "эталон — "+otherRefText(x))
	}
	// SSH того же адреса из той сети: отвечает — адрес жив; молчит (порт из алиаса) — молчит весь адрес.
	if p6 := pe.Get("P6"); p6 != nil {
		switch {
		case p6.Bool("reach"):
			f["p6"] = "reach"
			parts = append(parts, "SSH отвечает")
		case p6.Bool("known"):
			f["p6"] = "silent"
			parts = append(parts, "SSH молчит")
		}
	}
	same := yesno(o == cur, "так же, как из этой сети", "иначе, чем из этой сети")
	r.put(evidence.Evidence{ID: "P5", Source: evidence.FromNetwork, Reliability: evidence.High, Facts: f, At: p1.At,
		Summary: fmt.Sprintf("Из другой сети (сеанс %s назад): %s — %s", humanAge(age), strings.Join(parts, "; "), same)})
	r.step(2, "P5", "Из другой сети", yesno(o == "ok", "ok", "warn"),
		fmt.Sprintf("сеанс %s назад: TCP — %s, %s", humanAge(age), otherTCPText(o), same))
	r.sess.OtherNetwork = true
}

// comparableTCP — исход P1, который говорит о сети: проба состоялась и дала ответ или тишину.
func comparableTCP(o string) bool {
	return o == "ok" || o == "timeout" || o == "refused" || o == "unreachable"
}

func sameServer(s *Secret, p *profile.Profile) bool {
	return strings.EqualFold(strings.Trim(s.Server, "[]"), strings.Trim(p.Address, "[]")) && s.Port == p.Port
}

func otherTCPText(o string) string {
	switch o {
	case "ok":
		return "открывается"
	case "timeout":
		return "таймаут"
	case "refused":
		return "отказ (RST)"
	}
	return "сеть недоступна"
}

func otherRefText(o string) string {
	switch o {
	case "ok":
		return "тоннель поднялся"
	case "freeze":
		return "тоннель поднялся, данные встали"
	}
	return refText(refcore.Result{Outcome: o})
}

func humanAge(d time.Duration) string {
	m := int(d.Minutes())
	switch {
	case m < 1:
		return "меньше минуты"
	case m < 60:
		return fmt.Sprintf("%d мин", m)
	}
	return fmt.Sprintf("%d ч %02d мин", m/60, m%60)
}
