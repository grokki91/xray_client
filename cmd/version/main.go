// version — номер версии приложения для сборки (internal/version, файлы changes/*.md).
//
//	go run ./cmd/version            1.2.3
//	go run ./cmd/version -ldflags   -X …engine.Version=1.2.3 -X …engine.Commit=abc1234
//	go run ./cmd/version -changes   версия и список изменений по порядку
//	go run ./cmd/version -check origin/main   PR меняет приложение — значит, добавляет changes/*.md
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/grokki91/xray_client/internal/version"
)

const pkg = "github.com/grokki91/xray_client/internal/engine"

func main() {
	repo := flag.String("C", ".", "корень репозитория")
	mainRef := flag.String("main", "origin/main", "ветка, в порядке которой считаются слитые изменения")
	ld := flag.Bool("ldflags", false, "вывести -X для go build -ldflags")
	list := flag.Bool("changes", false, "вывести изменения по порядку")
	check := flag.String("check", "", "проверить, что ветка относительно этого ref добавляет файл изменений")
	flag.Parse()

	if *check != "" {
		added, err := version.Check(*repo, *check)
		if err != nil {
			fail(err)
		}
		for _, a := range added {
			fmt.Println("изменение:", a)
		}
	}
	inf, err := version.FromRepo(*repo, *mainRef)
	if err != nil {
		fail(err)
	}
	switch {
	case *ld:
		fmt.Printf("-X %s.Version=%s -X %s.Commit=%s\n", pkg, inf.Version, pkg, inf.Commit)
	case *list:
		v := version.Base
		fmt.Println(v, "— начало")
		for _, c := range inf.Changes {
			v = v.Apply(c.Bump)
			fmt.Printf("%s  %-5s %s\n", v, c.Bump, c.Name)
		}
	default:
		fmt.Println(inf.Version)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "version:", err)
	os.Exit(1)
}
