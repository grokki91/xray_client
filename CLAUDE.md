Инструкции для агентов — [AGENTS.md](AGENTS.md). Главное: репозиторий публичный — данных
установки (IP, домены, UUID, ключи, shortId, пути, порты, URL подписок) в нём не бывает;
перед коммитом `go test ./...` (включает `internal/repocheck`). Каждая правка приложения —
с новым файлом `changes/<ветка>.md` (`patch`/`minor`/`major`): так растёт номер версии без
конфликтов между сессиями ([changes/README.md](changes/README.md)).
Хук `.claude/hooks/commit-guard.sh` не пускает `git commit`/`git push`, пока не зелёный
`go test ./internal/repocheck/` (дерево и текст команды); без `jq`/`go` молча пропускает.
