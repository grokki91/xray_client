package bridge

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SSHConfig — блоки Host из ~/.ssh/config: по ним приложение само находит алиас сервера (Host,
// у которого HostName — адрес из профиля) и его порт SSH, без настройки. Читаются только Host,
// Match (как граница блока), HostName, Port и Include; ключи, known_hosts и остальные параметры —
// нет. Найденное живёт в памяти сеанса: в улики и отчёт имя алиаса и адрес не попадают.
type SSHConfig struct {
	blocks []hostBlock
}

type hostBlock struct {
	patterns []string // nil — блок Match: его условия не разбираются, параметры не берутся
	hostName string
	port     int
}

// sshMaxIncludeDepth — глубина Include (у OpenSSH — 16; здесь хватает и меньшего).
const sshMaxIncludeDepth = 4

// DefaultSSHConfigPath — %USERPROFILE%\.ssh\config (на других ОС — ~/.ssh/config).
func DefaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}

// ReadSSHConfig — разбор файла; нет файла — пустой конфиг (не ошибка: SSH не обязателен).
func ReadSSHConfig(path string) *SSHConfig {
	c := &SSHConfig{}
	if path != "" {
		// Строки до первого Host действуют для всех хостов — и, раз они первые, побеждают
		// (у ssh для каждого параметра берётся первое значение): неявный блок «Host *».
		c.blocks = append(c.blocks, hostBlock{patterns: []string{"*"}})
		c.read(path, filepath.Dir(path), 0, 0)
	}
	return c
}

// read — строки файла; cur — индекс блока, к которому относятся строки до первого Host (у
// включённого файла — блок, где стоит Include). Индекс, а не указатель: Include дописывает
// блоки, и слайс переезжает.
func (c *SSHConfig) read(path, base string, depth, cur int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	block := func() *hostBlock {
		if cur < 0 || c.blocks[cur].patterns == nil {
			return nil
		}
		return &c.blocks[cur]
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 16<<10), 256<<10)
	for n := 0; sc.Scan() && n < 10000; n++ {
		key, args := sshLine(sc.Text())
		switch key {
		case "host":
			c.blocks = append(c.blocks, hostBlock{patterns: args})
			cur = len(c.blocks) - 1
		case "match":
			c.blocks = append(c.blocks, hostBlock{})
			cur = len(c.blocks) - 1
		case "hostname":
			// В одном блоке действует первое значение, как у ssh.
			if b := block(); b != nil && b.hostName == "" && len(args) > 0 {
				b.hostName = args[0]
			}
		case "port":
			if b := block(); b != nil && b.port == 0 && len(args) > 0 {
				if p, err := strconv.Atoi(args[0]); err == nil && p > 0 && p < 65536 {
					b.port = p
				}
			}
		case "include":
			if depth >= sshMaxIncludeDepth {
				continue
			}
			for _, a := range args {
				if strings.HasPrefix(a, "~") {
					if home, err := os.UserHomeDir(); err == nil {
						a = filepath.Join(home, a[1:])
					}
				} else if !filepath.IsAbs(a) {
					a = filepath.Join(base, a)
				}
				files, _ := filepath.Glob(a)
				for _, inc := range files {
					c.read(inc, base, depth+1, cur)
				}
			}
			// Как в OpenSSH (readconf.c, oInclude): Host и Match внутри включённого файла не
			// меняют блок, в котором стоит Include, — строки после него относятся к нему же.
		}
	}
}

// sshLine — «Ключ значения» или «Ключ=значения»; ключ — в нижнем регистре, значения в
// двойных кавычках — целиком. Комментарии и пустые строки — "".
func sshLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil
	}
	key := strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var args []string
	for rest != "" {
		if rest[0] == '#' {
			break
		}
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				args = append(args, rest[1:])
				break
			}
			args = append(args, rest[1:1+end])
			rest = strings.TrimLeft(rest[2+end:], " \t")
			continue
		}
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			args = append(args, rest)
			break
		}
		args = append(args, rest[:end])
		rest = strings.TrimLeft(rest[end:], " \t")
	}
	return key, args
}

// Aliases — конкретные имена из строк Host (без масок и отрицаний), в порядке файла.
func (c *SSHConfig) Aliases() []string {
	var out []string
	seen := map[string]bool{}
	for _, b := range c.blocks {
		for _, p := range b.patterns {
			if strings.ContainsAny(p, "*?!") || seen[p] || !reAlias.MatchString(p) {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Resolve — HostName и Port, которые ssh возьмёт для алиаса: первое значение из подходящих
// блоков по порядку (как у ssh), %h — сам алиас; без HostName — алиас, без Port — 22.
func (c *SSHConfig) Resolve(alias string) (host string, port int) {
	for _, b := range c.blocks {
		if b.patterns == nil || !hostMatch(b.patterns, alias) {
			continue
		}
		if host == "" && b.hostName != "" {
			host = strings.ReplaceAll(strings.ReplaceAll(b.hostName, "%h", alias), "%%", "%")
		}
		if port == 0 && b.port > 0 {
			port = b.port
		}
	}
	if host == "" {
		host = alias
	}
	if port == 0 {
		port = 22
	}
	return host, port
}

// Find — первый алиас, у которого итоговый HostName совпадает с одним из адресов сервера (IP или
// имя из профиля): алиас и его порт SSH. ok=false — такого Host нет.
func (c *SSHConfig) Find(addrs ...string) (alias string, port int, ok bool) {
	want := map[string]bool{}
	for _, a := range addrs {
		if a = normHost(a); a != "" {
			want[a] = true
		}
	}
	if len(want) == 0 || c == nil {
		return "", 0, false
	}
	for _, al := range c.Aliases() {
		h, p := c.Resolve(al)
		if want[normHost(h)] {
			return al, p, true
		}
	}
	return "", 0, false
}

func normHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(h), "[]"), "."))
}

// hostMatch — подходит ли имя под шаблоны строки Host: хотя бы один шаблон совпал и ни одно
// отрицание (!шаблон) не совпало.
func hostMatch(patterns []string, host string) bool {
	ok := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		if globMatch(strings.ToLower(strings.TrimPrefix(p, "!")), strings.ToLower(host)) {
			if neg {
				return false
			}
			ok = true
		}
	}
	return ok
}

// globMatch — шаблон ssh: * — любая строка, ? — один символ.
func globMatch(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := 0; i <= len(s); i++ {
				if globMatch(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}
