package capture

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Окно захвата отменили: помощник по стоп-файлу сразу останавливает pktmon и снимает фильтр —
// сам, не дожидаясь конца окна. Раньше отмена убивала помощника, и захват pktmon на всех
// адаптерах шёл до перезагрузки.
func TestCaptureStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	stop := StopPath(filepath.Join(dir, "capture-job.json"))
	var mu sync.Mutex
	var calls []string
	pm := func(args ...string) error {
		mu.Lock()
		calls = append(calls, args[0]+" "+strings.Join(args[1:], " "))
		mu.Unlock()
		return nil
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(stop, nil, 0o600)
	}()
	t0 := time.Now()
	r := runCapture(pm, Job{IP: "192.0.2.1", Port: 443}, dir, stop, 10*time.Second)
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("отмена не услышана: окно шло %v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	var ops []string
	for _, c := range calls {
		ops = append(ops, strings.Fields(c)[0]+map[bool]string{true: " remove", false: ""}[strings.HasPrefix(c, "filter remove")])
	}
	got := strings.Join(ops, ", ")
	if got != "filter remove, filter, start, stop, filter remove" || r.Err != "захват отменён" {
		t.Fatalf("вызовы pktmon: %s; итог %+v", got, r)
	}
}
