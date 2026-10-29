//go:build !windows

package store

import (
	"bytes"
	"errors"
)

// Вне Windows DPAPI нет: данные пишутся открытым текстом с пометкой (только разработка и
// тесты; приложение рассчитано на Windows 11).
const dpapiAvailable = false

var plainMark = []byte("XDIAG-UNPROTECTED\n")

func protect(plain []byte) ([]byte, error) {
	return append(append([]byte(nil), plainMark...), plain...), nil
}

func unprotect(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, plainMark) {
		return nil, errors.New("файл зашифрован DPAPI — открыть можно только в Windows той же учётной записью")
	}
	return sealed[len(plainMark):], nil
}
