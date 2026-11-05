package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Ошибки моста — каждая с подсказкой владельцу.
var (
	ErrAlias       = errors.New("SSH-алиас: только буквы, цифры и . _ @ - (например xm-ui из ~/.ssh/config)")
	ErrNoSSH       = errors.New("нет ssh.exe: Параметры → Система → Дополнительные компоненты → «Клиент OpenSSH»")
	ErrHostKey     = errors.New("ключ хоста не подтверждён: один раз выполнить `ssh <алиас>` в терминале и сверить отпечаток")
	ErrAuth        = errors.New("SSH: ключ не принят (Permission denied) — проверить IdentityFile в ~/.ssh/config и агент")
	ErrResolve     = errors.New("SSH: алиас не найден — добавить Host <алиас> в ~/.ssh/config")
	ErrUnreachable = errors.New("SSH: сервер недоступен по SSH (таймаут/отказ) — это тоже улика: адрес режется целиком")
	ErrSudo        = errors.New("на сервере нет правила sudo без пароля для xm bridge: один раз `sudo xm bridge on`")
	ErrNoBridge    = errors.New("на сервере xm без команды bridge: `sudo xm self-update` (пока — ручной режим: импорт doctor.json)")
	// ErrPassphrase — сервер ключ принял, но ключ под паролем: ssh в BatchMode пароль не спрашивает, а
	// xdiag паролей не вводит и не хранит. Агент Windows держит ключ и после перезагрузки.
	ErrPassphrase = errors.New("SSH: сервер ключ принял, но ключ защищён паролем — введите его в поле «Пароль ключа» и нажмите «Проверить» " +
		"(или один раз загрузите ключ в ssh-agent: PowerShell от администратора `Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`, затем `ssh-add`)")
	// ErrBadPassphrase — пароль ключа из «Настроек» ключ не открыл.
	ErrBadPassphrase = errors.New("SSH: сервер ключ принял, но пароль ключа не подошёл — проверьте поле «Пароль ключа» (как в терминале при `ssh <алиас>`)")
	// ErrAskpass — пароль ключа задан, но ssh.exe его не спросил (старый OpenSSH без SSH_ASKPASS).
	ErrAskpass = errors.New("SSH: ssh.exe не спросил пароль ключа у xdiag (OpenSSH без SSH_ASKPASS?) — загрузите ключ в ssh-agent: PowerShell от администратора " +
		"`Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`, затем `ssh-add`")
	// ErrOtherServer — алиас из «Настроек» ведёт на другой сервер (HostName — не адрес профиля), а Host
	// сервера профиля в ~/.ssh/config нет: факты и окно были бы про чужой сервер.
	ErrOtherServer = errors.New("SSH-алиас в «Настройках» ведёт на другой сервер (его HostName — не адрес проверяемого профиля), а Host с адресом этого сервера в ~/.ssh/config нет — " +
		"укажите алиас сервера этого профиля (адрес — у итога, «сервер …») или очистите поле")
)

var reAlias = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Runner — запуск процесса (подменяется в тестах); env — добавка к окружению процесса.
type Runner func(ctx context.Context, exe string, args []string, stdin []byte, env []string) (stdout, stderr []byte, err error)

// SSH — мост через системный ssh.exe: ~/.ssh/config, агент и known_hosts — у ОС; приложение
// ключей не читает. Passphrase — пароль ключа из «Настроек» (DPAPI): его ssh.exe получает от
// помощника SSH_ASKPASS (Self — этот же exe), как пароль из терминала, но без окна.
type SSH struct {
	Alias      string
	Exe        string
	Run        Runner
	Passphrase string
	Self       string
}

// NewSSH — мост к алиасу; passphrase — пароль ключа или "" (агент, ключ без пароля).
func NewSSH(alias, passphrase string) (*SSH, error) {
	if !reAlias.MatchString(alias) {
		return nil, ErrAlias
	}
	exe, err := exec.LookPath("ssh")
	if err != nil {
		return nil, ErrNoSSH
	}
	s := &SSH{Alias: alias, Exe: exe, Run: runProcess, Passphrase: passphrase}
	if passphrase != "" {
		if s.Self, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("мост: путь к xdiag для пароля ключа: %v", err)
		}
	}
	return s, nil
}

// Переменные окружения помощника пароля: метка режима и сам пароль. Окружение процесса видно
// только этой учётной записи и администратору, командная строка — всем (AGENTS.md).
const (
	envAskpass    = "XDIAG_ASKPASS"
	envPassphrase = "XDIAG_SSH_PASSPHRASE"
)

// askpassArgs — вместо BatchMode: ssh спрашивает пароль ключа у помощника, а пароль сервера и
// keyboard-interactive выключены — пароль ключа не уйдёт на сервер даже по ошибке; одна попытка.
var askpassArgs = []string{"-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=1"}

// env — окружение ssh.exe: с паролем ключа — помощник SSH_ASKPASS (этот же exe, AskpassMain).
func (s *SSH) env() []string {
	if s.Passphrase == "" || s.Self == "" {
		return nil
	}
	e := []string{"SSH_ASKPASS=" + s.Self, "SSH_ASKPASS_REQUIRE=force", envAskpass + "=1", envPassphrase + "=" + s.Passphrase}
	if os.Getenv("DISPLAY") == "" {
		e = append(e, "DISPLAY=xdiag") // OpenSSH до 8.4 без DISPLAY помощника не зовёт
	}
	return e
}

// AskpassMain — режим помощника SSH_ASKPASS: ssh.exe запускает этот же exe с текстом запроса.
// Отвечает только на «Enter passphrase for key …»: любой другой запрос (пароль сервера, PIN) —
// отказ. false — процесс не помощник, работает как обычно.
func AskpassMain(args []string, out io.Writer) (handled bool, code int) {
	if os.Getenv(envAskpass) != "1" {
		return false, 0
	}
	pass := os.Getenv(envPassphrase)
	if len(args) == 0 || pass == "" || !strings.Contains(strings.ToLower(args[0]), "passphrase for") {
		return true, 1
	}
	fmt.Fprintln(out, pass)
	return true, 0
}

// Args — командная строка ssh. Разрешены только facts, doctor [--live N], health.
func Args(alias, cmd string, live int) ([]string, error) { return args(alias, cmd, live, false) }

func args(alias, cmd string, live int, askpass bool) ([]string, error) {
	if !reAlias.MatchString(alias) {
		return nil, ErrAlias
	}
	remote := []string{"sudo", "-n", "xm", "bridge"}
	switch cmd {
	case "facts", "health":
		remote = append(remote, cmd)
	case "doctor":
		remote = append(remote, cmd)
		if live > 0 {
			if live < 10 || live > 120 {
				return nil, errors.New("окно doctor — 10–120 с")
			}
			remote = append(remote, "--live", strconv.Itoa(live))
		}
	default:
		return nil, fmt.Errorf("команда %q не из списка моста", cmd)
	}
	// -v: по строке «Server accepts key» ключ под паролем отличается от ключа, которого сервер не
	// знает (classify); stderr нигде не сохраняется.
	a := []string{"-v", "-o", "BatchMode=yes"}
	if askpass {
		// BatchMode пароль ключа не спросит даже у помощника.
		a = append([]string{"-v"}, askpassArgs...)
	}
	a = append(a, "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"-o", "StrictHostKeyChecking=yes", "-T", "--", alias)
	return append(a, remote...), nil
}

func (s *SSH) call(ctx context.Context, cmd string, live int, stdin []byte, timeout time.Duration) ([]byte, error) {
	env := s.env()
	args, err := args(s.Alias, cmd, live, env != nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, serr, err := s.Run(ctx, s.Exe, args, stdin, env)
	t := bytes.TrimSpace(out)
	if err != nil || len(t) == 0 || t[0] != '{' {
		// Без JSON: ошибка ssh/sudo или xm без bridge напечатал справку.
		return nil, classify(string(serr), string(out), err, env != nil)
	}
	return out, nil
}

// classify — ошибка моста по stderr ssh и xm. Строки отладки ssh (-v) читаются только ради
// «Server accepts key», остальное — по сообщениям ssh, sudo и xm.
func classify(stderr, stdout string, err error, askpass bool) error {
	var msg []string
	accepted, asked := false, false
	for _, l := range strings.Split(stderr, "\n") {
		if t := strings.ToLower(strings.TrimSpace(l)); strings.HasPrefix(t, "debug") {
			accepted = accepted || strings.Contains(t, "server accepts key")
			asked = asked || strings.Contains(t, "requested to askpass")
			continue
		}
		msg = append(msg, l)
	}
	s := strings.ToLower(strings.Join(msg, "\n") + "\n" + stdout)
	switch {
	case strings.Contains(s, "host key verification failed"), strings.Contains(s, "no ecdsa host key"), strings.Contains(s, "host key for"):
		return ErrHostKey
	case strings.Contains(s, "permission denied"):
		// Принятый сервером ключ не подписал: в BatchMode так бывает с ключом под паролем без агента.
		// Права на файл ключа («bad permissions») — та же пара строк, но другая причина.
		switch {
		case !accepted || strings.Contains(s, "bad permissions"):
		case askpass && asked && !strings.Contains(s, "ssh_askpass"):
			return ErrBadPassphrase // помощник ответил, ключ не открылся
		case askpass:
			return ErrAskpass // ssh.exe не позвал помощника или не смог его запустить
		default:
			return ErrPassphrase
		}
		return ErrAuth
	case strings.Contains(s, "could not resolve hostname"):
		return ErrResolve
	case strings.Contains(s, "connection timed out"), strings.Contains(s, "connection refused"), strings.Contains(s, "operation timed out"),
		strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return ErrUnreachable
	case strings.Contains(s, "a password is required"), strings.Contains(s, "a terminal is required"), strings.Contains(s, "sudo: "):
		return ErrSudo
	case strings.Contains(s, "менеджер xray"), strings.Contains(s, "неизвестн"), strings.Contains(s, "unknown command"):
		return ErrNoBridge
	case strings.Contains(s, "command not found"):
		return errors.New("на сервере нет xm (`/usr/local/bin/xm`)")
	}
	if err != nil {
		return fmt.Errorf("мост: %v", err)
	}
	return errors.New("мост: пустой ответ сервера")
}

// Facts — `xm bridge facts`, соль — в stdin (32 hex).
func (s *SSH) Facts(ctx context.Context, saltHex string) (*Facts, error) {
	out, err := s.call(ctx, "facts", 0, []byte(saltHex+"\n"), 60*time.Second)
	if err != nil {
		return nil, err
	}
	return ParseFacts(out)
}

// Doctor — `xm bridge doctor --live N`: окно N с, за ним разбор.
func (s *SSH) Doctor(ctx context.Context, live int) (*Doctor, []byte, error) {
	out, err := s.call(ctx, "doctor", live, nil, time.Duration(live+90)*time.Second)
	if err != nil {
		return nil, nil, err
	}
	d, err := ParseDoctor(out)
	return d, out, err
}

// Health — `xm bridge health`.
func (s *SSH) Health(ctx context.Context) (*Health, error) {
	out, err := s.call(ctx, "health", 0, nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	return ParseHealth(out)
}

// Port — порт SSH алиаса по `ssh -G`: ssh.exe печатает итоговый конфиг, к серверу не
// подключаясь. 0 — узнать не удалось.
func (s *SSH) Port(ctx context.Context) int {
	if !reAlias.MatchString(s.Alias) {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _, err := s.Run(ctx, s.Exe, []string{"-G", "--", s.Alias}, nil, nil)
	if err != nil {
		return 0
	}
	return ParsePort(out)
}

// ParsePort — значение строки «port N» из вывода `ssh -G`.
func ParsePort(out []byte) int {
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok || !strings.EqualFold(k, "port") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 0
}

// ManualCommands — что выполнить на сервере в ручном режиме (без SSH из приложения).
func ManualCommands(live int) []string {
	if live <= 0 {
		live = 60
	}
	return []string{
		fmt.Sprintf("sudo xm doctor --live %d --json > doctor.json", live),
		"sudo xm health --json > health.json",
	}
}
