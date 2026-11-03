//go:build windows

package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func pktmon(args ...string) error {
	cmd := exec.Command("pktmon.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pktmon %s: %v: %s", args[0], err, string(out))
	}
	return nil
}

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// RunElevated запускает `exe capture-helper job` с запросом UAC и ждёт завершения.
func RunElevated(ctx context.Context, exe, jobPath string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(`capture-helper "` + jobPath + `"`)
	info := shellExecuteInfo{fMask: 0x00000040 /* SEE_MASK_NOCLOSEPROCESS */, lpVerb: verb, lpFile: file, lpParameters: params, nShow: windows.SW_HIDE}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return fmt.Errorf("UAC: %v", err)
	}
	if info.hProcess == 0 {
		return fmt.Errorf("UAC: процесс не запущен")
	}
	defer windows.CloseHandle(info.hProcess)
	done := make(chan struct{})
	go func() {
		_, _ = windows.WaitForSingleObject(info.hProcess, windows.INFINITE)
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Не убивать сразу: помощник сам остановит pktmon и снимет фильтр (StopPath); убитый,
		// он оставил бы захват идти до перезагрузки. TerminateProcess — только если не ответил.
		_ = os.WriteFile(StopPath(jobPath), nil, 0o600)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = windows.TerminateProcess(info.hProcess, 1)
		}
		return ctx.Err()
	}
}

// Available — pktmon есть в системе (Windows 10 2004+).
func Available() bool {
	_, err := exec.LookPath("pktmon.exe")
	return err == nil
}
