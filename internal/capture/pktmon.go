package capture

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Job — задание вспомогательному процессу с правами администратора. Передаётся файлом в
// каталоге данных приложения (не командной строкой), результат — файлом рядом.
type Job struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Seconds int    `json:"seconds"`
	Salt    []byte `json:"salt"`
	SNIHash string `json:"sni_hash"`
	Out     string `json:"out"`
}

// MaxSeconds — потолок окна захвата (приложение C: ≤ 90 с).
const MaxSeconds = 90

// WriteJob сохраняет задание и возвращает путь.
func WriteJob(dir string, j Job) (string, error) {
	if j.Seconds <= 0 || j.Seconds > MaxSeconds {
		return "", errors.New("окно захвата — 1–90 с")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "capture-job.json")
	j.Out = filepath.Join(dir, "capture-result.json")
	_ = os.Remove(j.Out)
	_ = os.Remove(StopPath(p))
	b, _ := json.Marshal(j)
	return p, os.WriteFile(p, b, 0o600)
}

// ReadResult читает результат и удаляет файлы задания.
func ReadResult(jobPath string) (Result, error) {
	defer os.Remove(jobPath)
	defer os.Remove(StopPath(jobPath))
	b, err := os.ReadFile(jobPath)
	if err != nil {
		return Result{}, err
	}
	var j Job
	_ = json.Unmarshal(b, &j)
	defer os.Remove(j.Out)
	rb, err := os.ReadFile(j.Out)
	if err != nil {
		return Result{}, errors.New("захват не дал результата (UAC отклонён или pktmon недоступен)")
	}
	var r Result
	err = json.Unmarshal(rb, &r)
	return r, err
}

// RunJob — тело вспомогательного процесса: pktmon → pcapng → разбор → результат. Вызывается
// командой `xdiag capture-helper ФАЙЛ` уже с правами администратора.
func RunJob(jobPath string) error {
	b, err := os.ReadFile(jobPath)
	if err != nil {
		return err
	}
	var j Job
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	if j.Seconds <= 0 || j.Seconds > MaxSeconds {
		return errors.New("окно захвата — 1–90 с")
	}
	dir := filepath.Dir(jobPath)
	r := runCapture(pktmon, j, dir, StopPath(jobPath), time.Duration(j.Seconds)*time.Second)
	rb, _ := json.Marshal(r)
	return os.WriteFile(j.Out, rb, 0o600)
}

// StopPath — файл-сигнал помощнику «закончить захват раньше» (окно или сеанс отменили). Помощник
// сам останавливает pktmon и снимает фильтр: убитый посреди окна, он оставил бы захват на всех
// адаптерах идти до перезагрузки, а файл .etl — расти в каталоге данных.
func StopPath(jobPath string) string { return jobPath + ".stop" }

// runCapture — тело захвата: фильтр, pktmon start, окно (d или до стоп-файла), stop, pcapng,
// разбор. Фильтры pktmon — общее состояние системы: свой ставится и снимается, чужие на время
// захвата снимаются (иначе захват уйдёт по ним), о чём сказано в окне согласия.
func runCapture(pm func(args ...string) error, j Job, dir, stop string, d time.Duration) Result {
	etl := filepath.Join(dir, "xdiag-capture.etl")
	pcap := filepath.Join(dir, "xdiag-capture.pcapng")
	defer os.Remove(etl)
	defer os.Remove(pcap)
	_ = pm("filter", "remove")
	defer pm("filter", "remove")
	if err := pm("filter", "add", "xdiag", "-i", j.IP, "-t", "TCP", "-p", strconv.Itoa(j.Port)); err != nil {
		return Result{Err: err.Error()}
	}
	if err := pm("start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", etl); err != nil {
		return Result{Err: err.Error()}
	}
	cancelled := waitWindow(stop, d)
	if err := pm("stop"); err != nil {
		return Result{Err: err.Error()}
	}
	if cancelled {
		return Result{Err: "захват отменён"}
	}
	if err := pm("etl2pcap", etl, "--out", pcap); err != nil {
		return Result{Err: err.Error()}
	}
	data, err := os.ReadFile(pcap)
	if err != nil {
		return Result{Err: err.Error()}
	}
	return Analyze(data, net.ParseIP(j.IP), j.Port, j.Salt, j.SNIHash)
}

// waitWindow ждёт d или появления файла stop; true — окно закончили раньше.
func waitWindow(stop string, d time.Duration) bool {
	end := time.Now().Add(d)
	for {
		if _, err := os.Stat(stop); err == nil {
			return true
		}
		left := time.Until(end)
		if left <= 0 {
			return false
		}
		time.Sleep(min(left, 200*time.Millisecond))
	}
}
