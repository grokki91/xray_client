package evidence

import "testing"

func TestEval(t *testing.T) {
	s := NewSet()
	s.Put(Evidence{ID: "P3", Facts: map[string]any{"outcome": "ok", "bytes": 65536, "ok": true}})
	s.Put(Evidence{ID: "W7", Facts: map[string]any{"offset_s": -700}})
	s.Put(Evidence{ID: "C3", Facts: map[string]any{"issues": []string{"fp.empty", "sid.format"}, "empty": ""}})
	s.Put(Evidence{ID: "X", Skipped: "нет профиля"})
	cases := map[string]bool{
		"P3":                      true,
		"P9":                      false,
		"X":                       false,
		"P3.ok":                   true,
		"P3.ok=true":              true,
		"P3.outcome=ok":           true,
		"P3.outcome=real_cert|ok": true,
		"P3.outcome!=ok":          false,
		"P3.outcome!=freeze":      true,
		"P9.outcome!=ok":          false,
		"!P9.outcome=ok":          true,
		"P3.bytes>=65536":         true,
		"P3.bytes>65536":          false,
		"W7.offset_s>=600":        false,
		"|W7.offset_s|>=600":      true,
		"C3.issues~fp.empty":      true,
		"C3.issues=sid.format":    true,
		"C3.issues~pbk.format":    false,
		"C3.empty":                false,
		"C3.empty?":               true,
		"C3.none?":                false,
		"P9.x || P3.outcome=ok":   true,
	}
	for p, want := range cases {
		if got := Eval(s, p); got != want {
			t.Errorf("%s = %v, ожидалось %v", p, got, want)
		}
	}
	if ids := IDs([]string{"P3.outcome=ok", "!S3.rd_r=mlkem || C7.mlkem=false", "|W7.offset_s|>=1"}); len(ids) != 4 {
		t.Fatalf("%v", ids)
	}
}
