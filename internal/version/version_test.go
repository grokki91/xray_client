package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	c, err := Parse("a.md", []byte("\ufeffMinor\r\n- вкладка «О программе»\r\n"))
	if err != nil || c.Bump != Minor || c.Text != "- вкладка «О программе»" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{"", "patch\n", "fix\n- текст", "minor: текст\n"} {
		if _, err := Parse("b.md", []byte(bad)); err == nil {
			t.Errorf("%q: нет ошибки", bad)
		}
	}
}

func TestApply(t *testing.T) {
	v := Semver{1, 0, 0}
	for _, s := range []struct {
		b    Bump
		want string
	}{{Patch, "1.0.1"}, {Patch, "1.0.2"}, {Minor, "1.1.0"}, {Patch, "1.1.1"}, {Major, "2.0.0"}, {Minor, "2.1.0"}} {
		if v = v.Apply(s.b); v.String() != s.want {
			t.Fatalf("%s: %s, ждали %s", s.b, v, s.want)
		}
	}
}

func TestAppFile(t *testing.T) {
	for p, want := range map[string]bool{
		"cmd/xdiag-ui/frontend/app.js": true, "internal/engine/engine.go": true, "rules/taxonomy.yaml": true, "go.mod": true,
		"internal/engine/engine_test.go": false, "internal/bridge/testdata/x.json": false, "README.md": false,
		"docs/architecture.md": false, ".claude/skills/x/SKILL.md": false, "AGENTS.md": false, "changes/a.md": false,
	} {
		if AppFile(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}

// TestRepoChanges — файлы changes/ этого репозитория разбираются (опечатка в уровне —
// провал до слияния, а не «dev» в сборке).
func TestRepoChanges(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	if _, err := Load(filepath.Join(filepath.Dir(file), "..", "..", Dir)); err != nil {
		t.Fatal(err)
	}
}

// repo — временный git-репозиторий для сценариев параллельных веток.
type repo struct {
	t   *testing.T
	dir string
}

func newRepo(t *testing.T) *repo {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("нет git")
	}
	r := &repo{t, t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.write("cmd/app/main.go", "package main\n")
	r.commit("начало")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *repo) write(name, s string) {
	r.t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) commit(msg string) {
	r.git("add", "-A")
	r.git("commit", "-q", "-m", msg)
}

// branch — ветка от main с правкой приложения и файлом изменений.
func (r *repo) branch(name, bump string) {
	r.git("checkout", "-q", "-b", name, "main")
	r.write("cmd/app/"+name+".go", "package main\n")
	r.write("changes/"+name+".md", bump+"\n- "+name+"\n")
	r.commit(name)
	r.git("checkout", "-q", "main")
}

func (r *repo) merge(name string) {
	r.git("checkout", "-q", "main")
	r.git("merge", "-q", "--no-ff", "-m", "merge "+name, name)
}

func (r *repo) version(ref string) string {
	r.t.Helper()
	r.git("checkout", "-q", ref)
	inf, err := FromRepo(r.dir, "main")
	if err != nil {
		r.t.Fatal(err)
	}
	return inf.Version.String()
}

// TestParallelBranches — две сессии параллельно: обе ветки от 1.0.0 видят 1.0.1, слияние без
// конфликтов, после обоих — 1.0.2; номер main только растёт.
func TestParallelBranches(t *testing.T) {
	r := newRepo(t)
	if v := r.version("main"); v != "1.0.0" {
		t.Fatalf("main: %s", v)
	}
	r.branch("a", "patch")
	r.branch("b", "patch")
	if va, vb := r.version("a"), r.version("b"); va != "1.0.1" || vb != "1.0.1" {
		t.Fatalf("ветки: %s %s", va, vb)
	}
	r.merge("b")
	if v := r.version("main"); v != "1.0.1" {
		t.Fatalf("main после b: %s", v)
	}
	// Ветка a без свежего main: в её дереве только своё изменение. Сборка CI для PR собирает
	// refs/pull/N/merge — там уже оба, номер как после слияния.
	if v := r.version("a"); v != "1.0.1" {
		t.Fatalf("a после слияния b: %s", v)
	}
	r.git("checkout", "-q", "-b", "pr-a", "main")
	r.git("merge", "-q", "--no-ff", "-m", "pr merge", "a")
	if v := r.version("pr-a"); v != "1.0.2" {
		t.Fatalf("merge-коммит PR a: %s", v)
	}
	r.merge("a") // без конфликта: файлы изменений разные
	if v := r.version("main"); v != "1.0.2" {
		t.Fatalf("main после a и b: %s", v)
	}
}

// TestOrderIsMergeOrder — порядок — по слиянию в main, а не по дате коммита: старая ветка с
// patch, слитая после новой с minor, даёт 1.1.1, а не откатывает номер к 1.1.0.
func TestOrderIsMergeOrder(t *testing.T) {
	r := newRepo(t)
	r.branch("old", "patch")
	r.branch("feat", "minor")
	r.merge("feat")
	if v := r.version("main"); v != "1.1.0" {
		t.Fatalf("main: %s", v)
	}
	r.merge("old")
	if v := r.version("main"); v != "1.1.1" {
		t.Fatalf("main: %s", v)
	}
}

// TestBranchMergedMain — ветка, в которую влили свежий main, всё равно на шаг впереди main.
func TestBranchMergedMain(t *testing.T) {
	r := newRepo(t)
	r.branch("a", "patch")
	r.branch("b", "minor")
	r.merge("b")
	r.git("checkout", "-q", "a")
	r.git("merge", "-q", "--no-ff", "-m", "main → a", "main")
	if v := r.version("a"); v != "1.1.1" {
		t.Fatalf("a: %s", v)
	}
}

func TestUncommittedChange(t *testing.T) {
	r := newRepo(t)
	r.write("changes/local.md", "minor\n- локально\n")
	inf, err := FromRepo(r.dir, "main")
	if err != nil || inf.Version.String() != "1.1.0" || !strings.HasSuffix(inf.Commit, "-dirty") {
		t.Fatalf("%+v %v", inf, err)
	}
}

func TestShallow(t *testing.T) {
	r := newRepo(t)
	r.branch("a", "patch")
	r.merge("a")
	clone := filepath.Join(t.TempDir(), "c")
	r.git("clone", "-q", "--depth", "1", "file://"+r.dir, clone)
	if _, err := FromRepo(clone, "origin/main"); err != ErrShallow {
		t.Fatalf("ждали ErrShallow: %v", err)
	}
}

func TestCheck(t *testing.T) {
	r := newRepo(t)
	r.branch("ok", "patch")

	r.git("checkout", "-q", "-b", "nochange", "main")
	r.write("cmd/app/x.go", "package main\n\nfunc x() {}\n")
	r.commit("x")
	if _, err := Check(r.dir, "main"); err == nil {
		t.Fatal("правка приложения без файла изменений прошла")
	}

	r.git("checkout", "-q", "-b", "docs", "main")
	r.write("README.md", "текст\n")
	r.write("cmd/app/x_test.go", "package main\n")
	r.commit("docs")
	if _, err := Check(r.dir, "main"); err != nil {
		t.Fatal(err)
	}

	r.git("checkout", "-q", "ok")
	if added, err := Check(r.dir, "main"); err != nil || len(added) != 1 || added[0] != "changes/ok.md" {
		t.Fatal(added, err)
	}
}
