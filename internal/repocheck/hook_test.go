package repocheck

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCommitGuard — хук .claude/hooks/commit-guard.sh на JSON, как его даёт Claude Code.
// Проект — временный git-репозиторий с копией repocheck_test.go (этот файл не копируется,
// рекурсии нет), в нём по случаю — файл с не-документационным адресом.
func TestCommitGuard(t *testing.T) {
	for _, b := range []string{"bash", "jq", "git", "go"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip("нет " + b)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("хук — для агентов на Linux")
	}
	if testing.Short() {
		t.Skip("short: вложенный go test")
	}
	src := root(t)
	hook := filepath.Join(src, ".claude", "hooks", "commit-guard.sh")
	code, err := os.ReadFile(filepath.Join(src, "internal", "repocheck", "repocheck_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	goLine := "go 1.26\n" // та же версия, что у проекта, — без скачивания другого toolchain
	for _, l := range strings.Split(string(mod), "\n") {
		if strings.HasPrefix(l, "go ") || strings.HasPrefix(l, "toolchain ") {
			goLine = l + "\n"
			break
		}
	}
	// Негативные примеры собираются из частей: этот файл тоже проходит проверку.
	ip := "45.10." + "20.30"
	uuid := strings.Join([]string{"1b671a64", "40d5", "491e", "99b0", "da01ff1f3341"}, "-")

	project := func(t *testing.T, leak bool) string {
		d := t.TempDir()
		write := func(name, s string) {
			p := filepath.Join(d, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("go.mod", "module example.com/rc\n\n"+goLine)
		write("internal/repocheck/repocheck_test.go", string(code))
		if leak {
			write("notes.md", "сервер "+ip+"\n")
		}
		if out, err := exec.Command("git", "-C", d, "init", "-q").CombinedOutput(); err != nil {
			t.Fatalf("git init: %v %s", err, out)
		}
		return d
	}
	clean, leaky := project(t, false), project(t, true)

	// noJQ — PATH только с bash: хук не находит jq.
	noJQ := t.TempDir()
	if p, _ := exec.LookPath("bash"); p != "" {
		if err := os.Symlink(p, filepath.Join(noJQ, "bash")); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range []struct {
		name, dir, input, path string
		code                   int
	}{
		{"не git", clean, cmdJSON("grep -n " + ip + " README.md"), "", 0},
		{"чужое слово с git", clean, cmdJSON("legit-git commit " + ip), "", 0},
		{"чистый коммит", clean, cmdJSON("git add -A && git commit -m 'фикс'"), "", 0},
		{"адрес в сообщении", clean, cmdJSON("git commit -m 'фикс для " + ip + "'"), "", 2},
		{"push через -C", clean, cmdJSON("git -C /home/x push origin b # " + ip), "", 2},
		{"документационный адрес", clean, cmdJSON("git commit -m 'пример 192.0.2.1'"), "", 0},
		{"UUID в сообщении", clean, cmdJSON("git commit -m 'клиент " + uuid + "'"), "", 2},
		{"UUID в локальном пути", clean, cmdJSON("cd /tmp/s/" + uuid + "/x && git commit -m 'тест'"), "", 0},
		{"адрес в файле: commit", leaky, cmdJSON("git commit -m 'фикс'"), "", 2},
		{"адрес в файле: push", leaky, cmdJSON("git push -u origin b"), "", 2},
		{"нет поля command", leaky, `{"tool_input":{}}`, "", 0},
		{"не JSON", leaky, `git commit`, "", 0},
		{"нет jq", leaky, cmdJSON("git commit -m 'фикс'"), noJQ, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command("bash", hook)
			cmd.Stdin = strings.NewReader(c.input)
			cmd.Env = append(os.Environ(), "CLAUDE_PROJECT_DIR="+c.dir, "REPOCHECK_EXTRA=")
			if c.path != "" {
				cmd.Env = append(cmd.Env, "PATH="+c.path)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			got := 0
			if e, ok := err.(*exec.ExitError); ok {
				got = e.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if got != c.code {
				t.Errorf("код %d, ждали %d\n%s", got, c.code, stderr.String())
			}
			if c.code == 2 && !strings.Contains(stderr.String(), "остановлен") {
				t.Errorf("нет причины в stderr:\n%s", stderr.String())
			}
		})
	}
}

func cmdJSON(c string) string {
	b, _ := json.Marshal(map[string]any{"tool_input": map[string]string{"command": c}})
	return string(b)
}
