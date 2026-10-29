//go:build windows

package store

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiAvailable = true

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// protect — CryptProtectData для текущего пользователя, без UI.
func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	ent := []byte(Entropy)
	if err := windows.CryptProtectData(blob(plain), nil, blob(ent), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	ent := []byte(Entropy)
	if err := windows.CryptUnprotectData(blob(sealed), nil, blob(ent), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
