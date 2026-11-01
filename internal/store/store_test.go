package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVaultSessionsRetention(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.Dir, "README.txt")); !strings.Contains(string(b), "ProtectedData") {
		t.Fatal("README.txt с инструкцией расшифровки")
	}
	v := Vault{SSHAlias: "xm-ui", ProfileURI: "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443"}
	if err := s.SaveVault(v); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "vault.dpapi"))
	if s.Protected && strings.Contains(string(raw), "192.0.2.1") {
		t.Fatal("в зашифрованном файле открытый текст")
	}
	got, err := s.LoadVault()
	if err != nil || got != v {
		t.Fatalf("%v %+v", err, got)
	}
	now := time.Now()
	old := NewID(now.AddDate(0, 0, -40), 1)
	fresh := NewID(now, 2)
	for _, e := range []IndexEntry{{ID: old, At: now.AddDate(0, 0, -40), Code: "ok"}, {ID: fresh, At: now, Code: "client.core.mlkem"}} {
		if err := s.SaveSession(e, map[string]any{"id": e.ID, "server": "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if l := s.Sessions(); len(l) != 2 || l[0].ID != fresh {
		t.Fatalf("%+v", l)
	}
	if n := s.Prune(30, now); n != 1 {
		t.Fatalf("удалено %d", n)
	}
	var sess map[string]any
	if err := s.LoadSession(fresh, &sess); err != nil || sess["server"] != "192.0.2.1" {
		t.Fatalf("%v %v", err, sess)
	}
	if err := s.LoadSession("../../etc/passwd", &sess); err == nil {
		t.Fatal("путь вне каталога сеансов")
	}
	if err := s.ClearHistory(); err != nil || len(s.Sessions()) != 0 {
		t.Fatal("очистка истории")
	}
	st := s.LoadSettings()
	if st.RetentionDays != 30 || st.ExportIncludeAddress || st.Client != "auto" {
		t.Fatalf("%+v", st)
	}
}

func TestBudgetFilePerServer(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	old := BudgetFile{Server: "aaa", TLS: []time.Time{now.Add(-30 * time.Second)}, TCP: []time.Time{now.Add(-30 * time.Second)}}
	if m := old.For("aaa"); len(m.TLS) != 1 || len(old.For("bbb").TCP) != 0 {
		t.Fatalf("старый формат: %+v", m)
	}
	old.Set("bbb", ServerMarks{TCP: []time.Time{now}}, now)
	if old.Server != "" || len(old.For("aaa").TLS) != 1 || len(old.For("bbb").TCP) != 1 {
		t.Fatalf("перенос: %+v", old)
	}
	old.Set("bbb", ServerMarks{TCP: []time.Time{now.Add(11 * time.Minute)}}, now.Add(11*time.Minute))
	if _, ok := old.Servers["aaa"]; ok {
		t.Fatal("сервер без отметок за 10 минут не забыт")
	}
}
