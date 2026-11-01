// Package setup — проверка настроек для окна: что работает, а что нет, до запуска диагностики.
//
// Без сети и без PowerShell — профиль из настроек (разбор и Validate), SSH-алиас и ssh.exe,
// папки клиентов (адаптеры Detect по файлам). По кнопке — мост: ssh → sudo -n xm bridge facts
// (только чтение, как фаза 3). Тексты — без секретов: профиль описан протоколом, транспортом и
// проблемами, не значениями; результат проверки нигде не сохраняется.
package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/clients"
	"github.com/grokki91/xray_client/internal/profile"
)

// Состояния настройки.
const (
	OK   = "ok"   // работает
	Warn = "warn" // работает частично или есть замечания
	Bad  = "bad"  // не работает
	Off  = "off"  // не задано (и не обязательно)
	Idle = "idle" // задано, проверяется только по кнопке
)

// Item — состояние одной настройки: коротко (Text) и подробнее (Note, `команды` — в обратных
// кавычках).
type Item struct {
	State string `json:"state"`
	Text  string `json:"text"`
	Note  string `json:"note,omitempty"`
}

// Input — что проверять: значения формы, в том числе ещё не сохранённые.
type Input struct {
	ProfileURI string
	SSHAlias   string
	HiddifyDir string
	V2rayNDir  string
}

// Client — клиент на этом ПК. Dir — локальный путь, только для окна (в отчёт не идёт).
type Client struct {
	Item
	Client  string `json:"client"`
	Title   string `json:"title"`
	Version string `json:"version,omitempty"`
	Dir     string `json:"dir,omitempty"`    // папка, которую возьмёт диагностика
	Manual  bool   `json:"manual,omitempty"` // папка задана в настройках
}

// Status — всё, что проверяется без сети.
type Status struct {
	Profile Item     `json:"profile"`
	Bridge  Item     `json:"bridge"`
	Clients []Client `json:"clients"`
}

// Check — проверка без сети. lookSSH — есть ли ssh.exe (exec.LookPath; в тестах — подставной).
func Check(ctx context.Context, in Input, env *clients.Env, lookSSH func() error) Status {
	return Status{Profile: Profile(in.ProfileURI), Bridge: BridgeOffline(in.SSHAlias, lookSSH), Clients: Clients(ctx, env, in)}
}

// Profile — профиль из настроек так, как его возьмёт диагностика (profile.FindURIs).
func Profile(uri string) Item {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return Item{Off, "Не задан", "Не обязателен: диагностика берёт профиль из клиента."}
	}
	ps := profile.FindURIs(uri)
	if len(ps) == 0 {
		return Item{Bad, "Не разбирается", "Нужна ссылка vless://… целиком — как её копирует клиент или xm."}
	}
	p := ps[0]
	desc := Describe(p)
	if len(ps) > 1 {
		desc += " · профилей в тексте: " + strconv.Itoa(len(ps)) + ", берётся первый"
	}
	if iss := p.Validate(); len(iss) > 0 {
		t := make([]string, 0, len(iss))
		for _, i := range iss {
			t = append(t, i.Text)
		}
		return Item{Warn, "Есть замечания", desc + ". " + upperFirst(strings.Join(t, "; ")) + "."}
	}
	return Item{OK, "В порядке", desc}
}

// Describe — профиль без секретов: «VLESS · REALITY · XHTTP · порт 443». Нестандартный порт —
// данные установки: только «нестандартный порт».
func Describe(p *profile.Profile) string {
	parts := []string{"VLESS"}
	if p.Security != "" && p.Security != "none" {
		parts = append(parts, strings.ToUpper(p.Security))
	}
	parts = append(parts, strings.ToUpper(p.Transport()))
	switch {
	case p.Port == 443:
		parts = append(parts, "порт 443")
	case p.Port > 0:
		parts = append(parts, "нестандартный порт")
	}
	return strings.Join(parts, " · ")
}

// BridgeOffline — мост без подключения: алиас и ssh.exe.
func BridgeOffline(alias string, lookSSH func() error) Item {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return Item{Off, "Не настроен", "Без моста факты с сервера — импортом doctor.json (ручной режим, вкладка «Данные»)."}
	}
	if _, err := bridge.Args(alias, "facts", 0); err != nil {
		return Item{Bad, "Неверный алиас", err.Error()}
	}
	if lookSSH != nil && lookSSH() != nil {
		return Item{Bad, "Нет ssh.exe", bridge.ErrNoSSH.Error()}
	}
	return Item{Idle, "Не проверен", ""}
}

// Facter — мост для проверки (bridge.SSH; в тестах — подставной).
type Facter interface {
	Facts(ctx context.Context, saltHex string) (*bridge.Facts, error)
}

// Bridge — проверка моста по кнопке: тот же `xm bridge facts`, что в фазе 3, со случайной солью.
func Bridge(ctx context.Context, alias string, dial func(alias string) (Facter, error)) Item {
	if it := BridgeOffline(alias, nil); it.State == Off || it.State == Bad {
		return it
	}
	b, err := dial(strings.TrimSpace(alias))
	if err != nil {
		return BridgeResult(nil, err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return BridgeResult(nil, err)
	}
	return BridgeResult(b.Facts(ctx, hex.EncodeToString(salt)))
}

// BridgeResult — ответ моста для окна: на каком звене остановилось (ssh.exe → алиас → сеть →
// ключ хоста → ключ → sudo → xm bridge → контракт).
func BridgeResult(f *bridge.Facts, err error) Item {
	if err == nil {
		note := "SSH, sudo и `xm bridge` отвечают"
		if f != nil && f.Xray.Version != "" {
			note += " · на сервере Xray " + f.Xray.Version
		}
		return Item{OK, "Работает", note}
	}
	msg := upperFirst(err.Error())
	for _, c := range []struct {
		err   error
		state string
		text  string
	}{
		{bridge.ErrNoBridge, Warn, "SSH работает, моста на сервере нет"},
		{bridge.ErrSudo, Warn, "SSH работает, нет правила sudo"},
		{bridge.ErrOlderContract, Warn, "Сервер старее приложения"},
		{bridge.ErrNewerContract, Warn, "Сервер новее приложения"},
		{bridge.ErrNoSSH, Bad, "Нет ssh.exe"},
		{bridge.ErrAlias, Bad, "Неверный алиас"},
		{bridge.ErrResolve, Bad, "Алиас не найден"},
		{bridge.ErrHostKey, Bad, "Ключ хоста не подтверждён"},
		{bridge.ErrAuth, Bad, "Ключ не принят"},
		{bridge.ErrUnreachable, Bad, "Сервер недоступен по SSH"},
	} {
		if errors.Is(err, c.err) {
			return Item{c.state, c.text, msg}
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return Item{Bad, "Нет ответа", "SSH не ответил вовремя"}
	}
	return Item{Bad, "Не работает", msg}
}

// Clients — клиенты на ПК так, как их найдёт диагностика, и годится ли папка из настроек.
func Clients(ctx context.Context, env *clients.Env, in Input) []Client {
	manual := map[string]string{"hiddify": strings.TrimSpace(in.HiddifyDir), "v2rayn": strings.TrimSpace(in.V2rayNDir)}
	auto := *env
	auto.HiddifyDir, auto.V2rayNDir = "", ""
	var out []Client
	for _, a := range clients.All() {
		c := Client{Client: a.Name(), Title: a.Title()}
		m := manual[a.Name()]
		d := a.Detect(ctx, &auto)
		if m != "" {
			if why := clients.CheckDir(a.Name(), m); why != "" {
				c.Item, c.Dir, c.Manual = Item{Bad, "Папка не подходит", upperFirst(why) + "."}, m, true
				if d.Installed && d.DataDir != "" {
					c.Note += " Найден сам: " + d.DataDir + " — «Искать автоматически»."
				}
				out = append(out, c)
				continue
			}
			if d.Installed && samePath(d.DataDir, m) {
				c.Note = "Совпадает с найденной автоматически — указывать не обязательно."
			}
			byHand := *env
			byHand.HiddifyDir, byHand.V2rayNDir = manual["hiddify"], manual["v2rayn"]
			d = a.Detect(ctx, &byHand)
			c.Manual = true
		}
		c.Version, c.Dir = d.Version, d.DataDir
		if d.Installed {
			c.State, c.Text = OK, "Найден"
		} else {
			c.Item = Item{Off, "Не найден", "Не установлен или стоит в нестандартной папке — укажите её."}
		}
		out = append(out, c)
	}
	return out
}

func samePath(a, b string) bool {
	clean := func(p string) string { return strings.ToLower(strings.TrimRight(filepath.Clean(p), `\/`)) }
	return a != "" && b != "" && clean(a) == clean(b)
}

func upperFirst(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}
