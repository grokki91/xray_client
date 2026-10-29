//go:build windows

package capture

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func pktmonCapture(j Job, dir string, d time.Duration) Result {
	etl := filepath.Join(dir, "xdiag-capture.etl")
	pcap := filepath.Join(dir, "xdiag-capture.pcapng")
	defer os.Remove(etl)
	defer os.Remove(pcap)
	// Фильтры pktmon — общее состояние системы: свой ставится и снимается, чужие на время
	// захвата снимаются (иначе захват уйдёт по ним), о чём сказано в окне согласия.
	_ = pktmon("filter", "remove")
	defer pktmon("filter", "remove")
	if err := pktmon("filter", "add", "xdiag", "-i", j.IP, "-t", "TCP", "-p", strconv.Itoa(j.Port)); err != nil {
		return Result{Err: err.Error()}
	}
	if err := pktmon("start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", etl); err != nil {
		return Result{Err: err.Error()}
	}
	time.Sleep(d)
	if err := pktmon("stop"); err != nil {
		return Result{Err: err.Error()}
	}
	if err := pktmon("etl2pcap", etl, "--out", pcap); err != nil {
		return Result{Err: err.Error()}
	}
	data, err := os.ReadFile(pcap)
	if err != nil {
		return Result{Err: err.Error()}
	}
	return Analyze(data, net.ParseIP(j.IP), j.Port, j.Salt, j.SNIHash)
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
		_ = windows.TerminateProcess(info.hProcess, 1)
		return ctx.Err()
	}
}

// Available — pktmon есть в системе (Windows 10 2004+).
func Available() bool {
	_, err := exec.LookPath("pktmon.exe")
	return err == nil
}
