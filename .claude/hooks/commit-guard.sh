#!/usr/bin/env bash
# PreToolUse(Bash): git commit и git push — только при зелёном go test ./internal/repocheck/
# (данные установки в рабочем дереве и в тексте команды — там сообщение коммита; локальные пути
# /tmp/… и /root/… из текста вырезаются: в них UUID сессии, а не установки). Провал — отказ
# (exit 2, провалы — в stderr, их видит Claude). Нет jq, go или поля command — молча пропускает.
command -v jq >/dev/null 2>&1 || exit 0
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null)
re='(^|[^[:alnum:]_.-])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+(commit|push)([[:space:]]|$)'
[[ $cmd =~ $re ]] || exit 0
verb=${BASH_REMATCH[3]}
command -v go >/dev/null 2>&1 || exit 0
root=${CLAUDE_PROJECT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/../.." && pwd)}
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$cmd" | sed -E "s#/(tmp|root)/[^[:space:]'\"]*##g" >"$tmp"
out=$(cd "$root" && REPOCHECK_EXTRA="$tmp" go test -count=1 ./internal/repocheck/ 2>&1) && exit 0
printf '%s\n' "git $verb остановлен: go test ./internal/repocheck/ не прошёл — исправь и повтори." "$out" >&2
exit 2
