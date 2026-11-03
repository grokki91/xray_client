package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/evidence"
	"github.com/grokki91/xray_client/internal/rules"
	"github.com/grokki91/xray_client/internal/store"
)

// Повтор истории: изменившийся вердикт виден, совпавший — нет, нечитаемый сеанс не мешает
// остальным; файлы истории не меняются.
func TestReplayHistory(t *testing.T) {
	re, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Rules: re, Store: st}
	evs := []evidence.Evidence{{ID: "N1", Facts: map[string]any{"ok": true}}, {ID: "P1", Facts: map[string]any{"outcome": "timeout", "ms": 3000}}}
	cur := re.Decide(evidence.FromList(evs)).Main
	now := time.Now()
	same := &SessionData{ID: store.NewID(now.Add(-2*time.Hour), 1), Started: now.Add(-2 * time.Hour), Evidence: evs}
	same.Verdict.Main = cur
	// Записан прежними правилами: тот же набор улик, другой вердикт.
	old := &SessionData{ID: store.NewID(now.Add(-time.Hour), 2), Started: now.Add(-time.Hour), Evidence: evs}
	old.Verdict.Main = rules.Result{Code: "client.core.mlkem", Level: rules.Confirmed}
	for _, s := range []*SessionData{same, old} {
		if err := e.Save(s); err != nil {
			t.Fatal(err)
		}
	}
	broken := store.NewID(now, 3)
	if err := st.SaveSession(store.IndexEntry{ID: broken, At: now, Code: "ok"}, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(st.Dir, "sessions", broken+".dpapi")
	if err := os.WriteFile(bp, []byte("не DPAPI"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := func() map[string][]byte {
		m := map[string][]byte{}
		fs, _ := filepath.Glob(filepath.Join(st.Dir, "sessions", "*"))
		for _, f := range fs {
			m[f], _ = os.ReadFile(f)
		}
		return m
	}
	before := snap()

	l := e.ReplayHistory()
	if len(l) != 3 {
		t.Fatalf("%+v", l)
	}
	if l[0].ID != broken || l[0].Err == "" || l[0].Changed {
		t.Errorf("нечитаемый: %+v", l[0])
	}
	if l[1].ID != old.ID || !l[1].Changed || l[1].Was.Code != "client.core.mlkem" || l[1].Now.Code != cur.Code || l[1].Now.Level != cur.Level {
		t.Errorf("изменившийся: %+v (сейчас %s/%s)", l[1], cur.Code, cur.Level)
	}
	if l[2].ID != same.ID || l[2].Changed {
		t.Errorf("совпавший: %+v", l[2])
	}
	// Тот же код с другим уровнем — тоже изменение.
	same.Verdict.Main.Level = rules.Possible
	if cur.Level != rules.Possible && !e.Replay(same).Changed {
		t.Error("смена уровня не замечена")
	}
	after := snap()
	if len(after) != len(before) {
		t.Fatalf("файлов было %d, стало %d", len(before), len(after))
	}
	for f, b := range before {
		if !bytes.Equal(after[f], b) {
			t.Errorf("перезаписан %s", filepath.Base(f))
		}
	}
}
