package repocheck

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Windows PowerShell 5.1 читает .ps1 без BOM в кодовой странице ANSI: кириллица в UTF-8
// даёт байты 0x91–0x94, а это ‘ ’ “ ” — для PowerShell кавычки, и скрипт не разбирается.
func TestPS1HasBOM(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(root(t), "*.ps1"))
	if len(files) == 0 {
		t.Fatal("нет *.ps1 в корне")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		ascii := true
		for _, c := range b {
			if c >= 0x80 {
				ascii = false
				break
			}
		}
		if !ascii && !bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("%s: не-ASCII без UTF-8 BOM — Windows PowerShell 5.1 его не разберёт", filepath.Base(f))
		}
	}
}

// try-pr.ps1 ищет workflow и артефакт по именам из build.yml.
func TestTryPRMatchesWorkflow(t *testing.T) {
	r := root(t)
	ps, err := os.ReadFile(filepath.Join(r, "try-pr.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.ReadFile(filepath.Join(r, ".github", "workflows", "build.yml"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(re string) string {
		m := regexp.MustCompile(re).FindSubmatch(ps)
		if m == nil {
			t.Fatalf("в try-pr.ps1 нет %s", re)
		}
		return string(m[1])
	}
	if w := get(`\$Workflow = '([^']+)'`); w != "build.yml" {
		t.Errorf("$Workflow = %q, а файл workflow — build.yml", w)
	}
	a := get(`\$Artifact = '([^']+)'`)
	if !regexp.MustCompile(`(?m)^\s+name: ` + regexp.QuoteMeta(a) + `\s*$`).Match(wf) {
		t.Errorf("артефакта %q нет в build.yml", a)
	}
	if !bytes.Contains(wf, []byte("SHA256SUMS.txt")) {
		t.Error("build.yml больше не кладёт SHA256SUMS.txt, а try-pr.ps1 его сверяет")
	}
}

// Команда проверки PR в README, скилле и шапке скрипта — одна и та же и не зависит от
// локальной копии: try-pr.ps1 скачивается из main в %TEMP%.
func TestTryPRCommandFromTemp(t *testing.T) {
	r := root(t)
	const cmd = `iwr https://raw.githubusercontent.com/grokki91/xray_client/main/try-pr.ps1 -UseBasicParsing -OutFile $env:TEMP\try-pr.ps1; powershell -ep Bypass -f $env:TEMP\try-pr.ps1 `
	for _, f := range []string{"README.md", "try-pr.ps1", ".claude/skills/pr-description/SKILL.md"} {
		b, err := os.ReadFile(filepath.Join(r, f))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(cmd)) {
			t.Errorf("%s: нет команды запуска try-pr.ps1 из %%TEMP%%", f)
		}
		if regexp.MustCompile(`-f(?:ile)? \.\\try-pr\.ps1`).Match(b) {
			t.Errorf("%s: запуск .\\try-pr.ps1 из папки проекта — локальная копия бывает старше main", f)
		}
	}
}
