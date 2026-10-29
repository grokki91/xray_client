// Package rules — декларативные данные диагностики: таксономия причин, гипотезы, таблица
// совместимости клиентов и эталонные хосты. Встраиваются в бинарник; движок — internal/rules.
package rules

import "embed"

//go:embed taxonomy.yaml compat.yaml hosts.yaml hypotheses/*.yaml
var FS embed.FS
