// Package version — версия приложения из файлов изменений changes/*.md.
//
// Каждый PR, меняющий приложение, добавляет свой файл changes/<ветка>.md (первая строка —
// patch | minor | major, дальше — что изменилось). Имена у параллельных веток разные, общего
// файла с номером нет — конфликтов при слиянии не бывает. Номер считается при сборке: от Base
// применяются все изменения по порядку, в котором они попали в main (первые родители
// истории git), изменения ветки — после изменений main. Так у ветки виден номер «как если
// слить сейчас», а две параллельные ветки после слияния обеих дают два шага подряд.
package version

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Base — версия до первого файла изменений.
var Base = Semver{1, 0, 0}

// Dir — каталог файлов изменений относительно корня репозитория.
const Dir = "changes"

// Bump — уровень изменения.
type Bump int

const (
	Patch Bump = iota + 1 // исправление, мелкая правка
	Minor                 // новая возможность
	Major                 // несовместимое изменение (формат данных, контракт моста)
)

var bumpNames = map[string]Bump{"patch": Patch, "minor": Minor, "major": Major}

func (b Bump) String() string {
	for k, v := range bumpNames {
		if v == b {
			return k
		}
	}
	return "?"
}

// Semver — major.minor.patch.
type Semver [3]int

func (v Semver) String() string { return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) }

// Apply — следующая версия: младшие разряды обнуляются, как принято в semver.
func (v Semver) Apply(b Bump) Semver {
	switch b {
	case Major:
		return Semver{v[0] + 1, 0, 0}
	case Minor:
		return Semver{v[0], v[1] + 1, 0}
	default:
		return Semver{v[0], v[1], v[2] + 1}
	}
}

// Change — один файл изменений.
type Change struct {
	Name string // имя файла в changes/
	Bump Bump
	Text string // что изменилось — для людей
}

// IsChange — файл в changes/ считается изменением (README.md — описание формата).
func IsChange(name string) bool {
	return strings.HasSuffix(name, ".md") && !strings.EqualFold(name, "README.md") && !strings.HasPrefix(name, ".")
}

// Parse разбирает файл: первая непустая строка — уровень, остальное — текст (обязателен).
func Parse(name string, data []byte) (Change, error) {
	c := Change{Name: name}
	head, rest, _ := strings.Cut(strings.TrimLeft(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n \t\ufeff"), "\n")
	b, ok := bumpNames[strings.ToLower(strings.TrimSpace(head))]
	if !ok {
		return c, fmt.Errorf("%s: первая строка — patch, minor или major, а не %q", name, strings.TrimSpace(head))
	}
	c.Bump, c.Text = b, strings.TrimSpace(rest)
	if c.Text == "" {
		return c, fmt.Errorf("%s: после строки %s — что изменилось", name, head)
	}
	return c, nil
}

// Load читает все изменения каталога, по имени.
func Load(dir string) ([]Change, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Change
	var errs []error
	for _, e := range ents {
		if e.IsDir() || !IsChange(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		c, err := Parse(e.Name(), data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, c)
	}
	return out, errors.Join(errs...)
}

// Sort упорядочивает изменения по ключу из order (порядок попадания в историю); изменений,
// которых нет в истории (ещё не закоммичены), — в конце, по имени.
func Sort(cs []Change, order map[string]int) {
	sort.SliceStable(cs, func(i, j int) bool {
		oi, iok := order[cs[i].Name]
		oj, jok := order[cs[j].Name]
		switch {
		case iok && jok && oi != oj:
			return oi < oj
		case iok != jok:
			return iok
		}
		return cs[i].Name < cs[j].Name
	})
}

// Compute — версия после применения изменений к base по порядку.
func Compute(base Semver, cs []Change) Semver {
	v := base
	for _, c := range cs {
		v = v.Apply(c.Bump)
	}
	return v
}

func git(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// ErrShallow — история обрезана (git clone --depth): порядок изменений не восстановить.
var ErrShallow = errors.New("история git неполная (shallow): нужна полная история, git fetch --unshallow")

// GitOrder — порядок появления файлов changes/ в истории первых родителей refs: сначала
// всё, что пришло по refs[0] (обычно origin/main), затем новое по следующим (HEAD).
// Несуществующие refs (кроме последнего) пропускаются.
func GitOrder(repo string, refs ...string) (map[string]int, error) {
	if s, err := git(repo, "rev-parse", "--is-shallow-repository"); err != nil {
		return nil, err
	} else if strings.TrimSpace(s) == "true" {
		return nil, ErrShallow
	}
	order := map[string]int{}
	for i, ref := range refs {
		if _, err := git(repo, "rev-parse", "--verify", "-q", ref+"^{commit}"); err != nil {
			if i == len(refs)-1 {
				return nil, fmt.Errorf("нет коммита %s", ref)
			}
			continue
		}
		out, err := git(repo, "log", "--first-parent", "--reverse", "--diff-merges=first-parent", "--no-renames",
			"--diff-filter=A", "--name-only", "--format=", ref, "--", Dir)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(out, "\n") {
			l = strings.TrimSpace(l)
			if path.Dir(l) != Dir {
				continue
			}
			name := path.Base(l)
			if _, ok := order[name]; !ok && IsChange(name) {
				order[name] = len(order)
			}
		}
	}
	return order, nil
}

// Info — версия рабочего дерева репозитория.
type Info struct {
	Version Semver
	Commit  string // короткий хэш HEAD, «-dirty» при незакоммиченных правках
	Changes []Change
}

// FromRepo считает версию дерева repo: изменения из changes/, порядок — main, затем HEAD.
func FromRepo(repo, mainRef string) (Info, error) {
	cs, err := Load(filepath.Join(repo, Dir))
	if err != nil {
		return Info{}, err
	}
	order, err := GitOrder(repo, mainRef, "HEAD")
	if err != nil {
		return Info{}, err
	}
	Sort(cs, order)
	inf := Info{Version: Compute(Base, cs), Changes: cs}
	if s, err := git(repo, "rev-parse", "--short=7", "HEAD"); err == nil {
		inf.Commit = strings.TrimSpace(s)
		if st, err := git(repo, "status", "--porcelain"); err == nil && strings.TrimSpace(st) != "" {
			inf.Commit += "-dirty"
		}
	}
	return inf, nil
}

// AppFile — файл влияет на собранное приложение (а не только на тесты, документацию,
// инструкции агентов или CI).
func AppFile(p string) bool {
	if strings.HasSuffix(p, "_test.go") || strings.Contains("/"+p, "/testdata/") {
		return false
	}
	if p == "go.mod" || p == "go.sum" {
		return true
	}
	for _, d := range []string{"cmd/", "internal/", "rules/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// Check — проверка PR: если ветка меняет приложение относительно base, она добавляет файл
// изменений. Возвращает добавленные изменения.
func Check(repo, base string) ([]string, error) {
	out, err := git(repo, "diff", "--name-only", "--no-renames", base+"...HEAD")
	if err != nil {
		return nil, err
	}
	var app, added []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" && AppFile(l) {
			app = append(app, l)
		}
	}
	out, err = git(repo, "diff", "--name-only", "--no-renames", "--diff-filter=A", base+"...HEAD", "--", Dir)
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); path.Dir(l) == Dir && IsChange(path.Base(l)) {
			added = append(added, l)
		}
	}
	if len(app) > 0 && len(added) == 0 {
		return nil, fmt.Errorf("ветка меняет приложение (%s), но не добавляет файл %s/<ветка>.md — см. %s/README.md",
			strings.Join(first(app, 3), ", "), Dir, Dir)
	}
	return added, nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "…")
	}
	return s
}
