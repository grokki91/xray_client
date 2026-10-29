package capture

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	b, _ := json.Marshal(j)
	return p, os.WriteFile(p, b, 0o600)
}

// ReadResult читает результат и удаляет файлы задания.
func ReadResult(jobPath string) (Result, error) {
	defer os.Remove(jobPath)
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
	r := pktmonCapture(j, dir, time.Duration(j.Seconds)*time.Second)
	rb, _ := json.Marshal(r)
	return os.WriteFile(j.Out, rb, 0o600)
}
