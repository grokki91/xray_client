package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
)

var reAlias = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Runner — запуск процесса (подменяется в тестах).
type Runner func(ctx context.Context, exe string, args []string, stdin []byte) (stdout, stderr []byte, err error)

// SSH — мост через системный ssh.exe: ~/.ssh/config, агент и known_hosts — у ОС; приложение
// ключей не хранит и не читает.
type SSH struct {
	Alias string
	Exe   string
	Run   Runner
}

// NewSSH — мост к алиасу.
func NewSSH(alias string) (*SSH, error) {
	if !reAlias.MatchString(alias) {
		return nil, ErrAlias
	}
	exe, err := exec.LookPath("ssh")
	if err != nil {
		return nil, ErrNoSSH
	}
	return &SSH{Alias: alias, Exe: exe, Run: runProcess}, nil
}

// Args — командная строка ssh. Разрешены только facts, doctor [--live N], health.
func Args(alias, cmd string, live int) ([]string, error) {
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
	a := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
		"-o", "StrictHostKeyChecking=yes", "-T", "--", alias}
	return append(a, remote...), nil
}

func (s *SSH) call(ctx context.Context, cmd string, live int, stdin []byte, timeout time.Duration) ([]byte, error) {
	args, err := Args(s.Alias, cmd, live)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, serr, err := s.Run(ctx, s.Exe, args, stdin)
	t := bytes.TrimSpace(out)
	if err != nil || len(t) == 0 || t[0] != '{' {
		// Без JSON: ошибка ssh/sudo или xm без bridge напечатал справку.
		return nil, classify(string(serr), string(out), err)
	}
	return out, nil
}

// classify — ошибка моста по stderr ssh и xm.
func classify(stderr, stdout string, err error) error {
	s := strings.ToLower(stderr + "\n" + stdout)
	switch {
	case strings.Contains(s, "host key verification failed"), strings.Contains(s, "no ecdsa host key"), strings.Contains(s, "host key for"):
		return ErrHostKey
	case strings.Contains(s, "permission denied"):
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
