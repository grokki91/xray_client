// Package store — локальные данные xdiag на этом ПК (docs/architecture.md §8.2).
//
// Каталог — %LOCALAPPDATA%\xdiag (переопределяется XDIAG_HOME). Всё, что идентифицирует
// установку (профиль vless://, SSH-алиас, адрес сервера, история сеансов), лежит только здесь и
// только зашифрованным DPAPI (CurrentUser): прочитать может лишь эта учётная запись Windows на
// этом ПК. Посмотреть руками — `xdiag data show` или PowerShell (README.txt в каталоге).
// В репозиторий, экспорт и телеметрию это не попадает: телеметрии нет.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entropy — дополнительная энтропия DPAPI (известна: она для разделения данных приложений,
// не секрет; без неё расшифровка в PowerShell — та же команда без второго аргумента).
const Entropy = "xdiag/v1"

// Settings — несекретные настройки (открытый JSON).
type Settings struct {
	RetentionDays        int    `json:"retention_days"`
	ExportIncludeAddress bool   `json:"export_include_address"`
	Client               string `json:"client"`       // auto | hiddify | v2rayn
	LiveSeconds          int    `json:"live_seconds"` // окно xm doctor
	UseBridge            bool   `json:"use_bridge"`
	Reference            bool   `json:"reference"` // эталонная проба
}

// DefaultSettings — умолчания (§13: 30 дней, экспорт без адреса).
func DefaultSettings() Settings {
	return Settings{RetentionDays: 30, Client: "auto", LiveSeconds: 60, Reference: true}
}

// Vault — секретные настройки (DPAPI).
type Vault struct {
	SSHAlias   string `json:"ssh_alias,omitempty"`
	ProfileURI string `json:"profile_uri,omitempty"`
	HiddifyDir string `json:"hiddify_dir,omitempty"`
	V2rayNDir  string `json:"v2rayn_dir,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// IndexEntry — строка истории без секретов (открытый индекс).
type IndexEntry struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Code   string    `json:"code"`
	Level  string    `json:"level"`
	Short  string    `json:"short"`
	Client string    `json:"client"`
	Other  bool      `json:"other_network,omitempty"`
}

// Store — каталог данных.
type Store struct {
	Dir       string
	Protected bool // DPAPI доступен (Windows)
	mu        sync.Mutex
}

var reID = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$`)

// DefaultDir — каталог данных.
func DefaultDir() string {
	if d := os.Getenv("XDIAG_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if l := os.Getenv("LOCALAPPDATA"); l != "" {
			return filepath.Join(l, "xdiag")
		}
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "xdiag")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".local", "share", "xdiag")
}

// Open открывает (создаёт) каталог.
func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(filepath.Join(dir, "sessions"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, Protected: dpapiAvailable}
	s.writeReadme()
	return s, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// ─── Шифрование ──────────────────────────────────────────────────────────────

// Seal — DPAPI (Windows) или открытый текст с пометкой (вне Windows — только разработка).
func (s *Store) Seal(plain []byte) ([]byte, error) { return protect(plain) }

// Unseal — обратное Seal.
func (s *Store) Unseal(blob []byte) ([]byte, error) { return unprotect(blob) }

func (s *Store) writeSealed(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	blob, err := s.Seal(b)
	if err != nil {
		return fmt.Errorf("DPAPI: %w", err)
	}
	return atomicWrite(s.path(name), blob)
}

func (s *Store) readSealed(name string, v any) error {
	blob, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	b, err := s.Unseal(blob)
	if err != nil {
		return fmt.Errorf("DPAPI: %w (файл создан другой учётной записью или на другом ПК)", err)
	}
	return json.Unmarshal(b, v)
}

func atomicWrite(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ─── Настройки и хранилище секретов ──────────────────────────────────────────

// LoadSettings — настройки (нет файла — умолчания).
func (s *Store) LoadSettings() Settings {
	st := DefaultSettings()
	if b, err := os.ReadFile(s.path("settings.json")); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.RetentionDays < 0 || st.RetentionDays > 365 {
		st.RetentionDays = 30
	}
	if st.LiveSeconds < 10 || st.LiveSeconds > 120 {
		st.LiveSeconds = 60
	}
	if st.Client == "" {
		st.Client = "auto"
	}
	return st
}

// SaveSettings — сохранить настройки.
func (s *Store) SaveSettings(st Settings) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return atomicWrite(s.path("settings.json"), b)
}

// LoadVault — секреты (нет файла — пусто).
func (s *Store) LoadVault() (Vault, error) {
	var v Vault
	err := s.readSealed("vault.dpapi", &v)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	return v, err
}

// SaveVault — сохранить секреты.
func (s *Store) SaveVault(v Vault) error { return s.writeSealed("vault.dpapi", v) }

// ─── История ─────────────────────────────────────────────────────────────────

// NewID — идентификатор сеанса: время и 4 hex.
func NewID(t time.Time, rnd uint16) string {
	return fmt.Sprintf("%s-%04x", t.Format("20060102-150405"), rnd)
}

// SaveSession — сеанс (JSON) под DPAPI и строка индекса.
func (s *Store) SaveSession(e IndexEntry, session any) error {
	if !reID.MatchString(e.ID) {
		return errors.New("неверный id сеанса")
	}
	if err := s.writeSealed(filepath.Join("sessions", e.ID+".dpapi"), session); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.index()
	idx = append(idx, e)
	return s.saveIndex(idx)
}

// LoadSession — сеанс в v.
func (s *Store) LoadSession(id string, v any) error {
	if !reID.MatchString(id) {
		return errors.New("неверный id сеанса")
	}
	return s.readSealed(filepath.Join("sessions", id+".dpapi"), v)
}

// Sessions — история, новые первыми.
func (s *Store) Sessions() []IndexEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.index()
	sort.Slice(idx, func(i, j int) bool { return idx[i].At.After(idx[j].At) })
	return idx
}

func (s *Store) index() []IndexEntry {
	var idx []IndexEntry
	if b, err := os.ReadFile(s.path(filepath.Join("sessions", "index.json"))); err == nil {
		_ = json.Unmarshal(b, &idx)
	}
	return idx
}

func (s *Store) saveIndex(idx []IndexEntry) error {
	b, _ := json.MarshalIndent(idx, "", "  ")
	return atomicWrite(s.path(filepath.Join("sessions", "index.json")), b)
}

// DeleteSession — удалить один сеанс.
func (s *Store) DeleteSession(id string) error {
	if !reID.MatchString(id) {
		return errors.New("неверный id сеанса")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(s.path(filepath.Join("sessions", id+".dpapi")))
	var keep []IndexEntry
	for _, e := range s.index() {
		if e.ID != id {
			keep = append(keep, e)
		}
	}
	return s.saveIndex(keep)
}

// ClearHistory — удалить всю историю. На SSD безвозвратность стирания не гарантируется.
func (s *Store) ClearHistory() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, _ := filepath.Glob(s.path(filepath.Join("sessions", "*")))
	for _, f := range files {
		_ = os.Remove(f)
	}
	return nil
}

// Prune — удалить сеансы старше days дней (0 — не хранить вовсе).
func (s *Store) Prune(days int, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.AddDate(0, 0, -days)
	var keep []IndexEntry
	n := 0
	for _, e := range s.index() {
		if days == 0 || e.At.Before(cut) {
			_ = os.Remove(s.path(filepath.Join("sessions", e.ID+".dpapi")))
			n++
			continue
		}
		keep = append(keep, e)
	}
	if n > 0 {
		_ = s.saveIndex(keep)
	}
	return n
}

// ─── Бюджет проб между запусками ─────────────────────────────────────────────

// BudgetFile — отметки соединений к серверу (без адреса: ключ — хэш).
type BudgetFile struct {
	Server   string      `json:"server"`
	TLS      []time.Time `json:"tls"`
	TCP      []time.Time `json:"tcp"`
	LastPath time.Time   `json:"last_path_verdict,omitempty"` // последний сеанс с вердиктом path.*
}

func (s *Store) LoadBudget() BudgetFile {
	var b BudgetFile
	if raw, err := os.ReadFile(s.path("budget.json")); err == nil {
		_ = json.Unmarshal(raw, &b)
	}
	return b
}

func (s *Store) SaveBudget(b BudgetFile) error {
	raw, _ := json.MarshalIndent(b, "", "  ")
	return atomicWrite(s.path("budget.json"), raw)
}

// ─── README ──────────────────────────────────────────────────────────────────

func (s *Store) writeReadme() {
	p := s.path("README.txt")
	if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), readmeVersion) {
		return
	}
	_ = os.WriteFile(p, []byte(strings.ReplaceAll(readme, "\n", "\r\n")), 0o600)
}

const readmeVersion = "xdiag-readme-v1"

const readme = `xdiag — данные на этом ПК (` + readmeVersion + `)
=========================================

Здесь лежит всё, что xdiag хранит. Ничего из этого не отправляется ни на какие серверы
и не попадает в экспорт отчёта.

  settings.json            настройки без секретов (открытый текст)
  vault.dpapi              секреты: профиль vless://, SSH-алиас, папки клиентов
  sessions\index.json      список сеансов: дата и код вердикта (без адресов)
  sessions\<id>.dpapi      сеанс целиком: улики, вердикт, адрес сервера и SNI
  budget.json              время последних проб к серверу (без адреса)

Файлы *.dpapi зашифрованы Windows DPAPI для текущей учётной записи: открыть их может
только этот пользователь на этом ПК.

Посмотреть руками
-----------------
1) Через xdiag:
     xdiag data show                 настройки и секреты
     xdiag data show --session <id>  один сеанс целиком
     xdiag history                   список сеансов

2) Без xdiag, в Windows PowerShell:

   Add-Type -AssemblyName System.Security
   $f = "$env:LOCALAPPDATA\xdiag\vault.dpapi"
   $b = [IO.File]::ReadAllBytes($f)
   $e = [Text.Encoding]::UTF8.GetBytes("` + Entropy + `")
   [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b, $e, 'CurrentUser'))

   Для сеанса — тот же код с путём sessions\<id>.dpapi.

Удалить
-------
  xdiag history clear     вся история
  или удалить эту папку целиком.
На SSD безвозвратность удаления файлов не гарантируется.
`
