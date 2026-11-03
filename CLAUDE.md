Инструкции для агентов — [AGENTS.md](AGENTS.md). Главное: репозиторий публичный — данных
установки (IP, домены, UUID, ключи, shortId, пути, порты, URL подписок) в нём не бывает;
перед коммитом `go test ./...` (включает `internal/repocheck`).
Хук `.claude/hooks/commit-guard.sh` не пускает `git commit`/`git push`, пока не зелёный
`go test ./internal/repocheck/` (дерево и текст команды); без `jq`/`go` молча пропускает.
