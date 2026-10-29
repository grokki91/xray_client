//go:build windows

package osw

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var lastVersions FileVersions

func collect(ctx context.Context, clientPaths []string) Facts {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-")
	cmd.Stdin = strings.NewReader(psScript)
	cmd.Env = append(os.Environ(), "XDIAG_EXE="+strings.Join(clientPaths, "|"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return Facts{Err: "PowerShell: " + err.Error()}
	}
	// Перед JSON PowerShell иногда печатает прогресс — берём с первой «{».
	if i := strings.IndexByte(string(out), '{'); i > 0 {
		out = out[i:]
	}
	f, vers, perr := parsePS(out)
	if perr != nil {
		return Facts{Err: "разбор вывода PowerShell: " + perr.Error()}
	}
	lastVersions = vers
	return f
}

// FileVersion — версия exe из ресурса VERSIONINFO (ProductVersion).
func FileVersion(path string) string {
	if v, ok := lastVersions[strings.ToLower(path)]; ok && v != "" {
		return v
	}
	return fileVersionNative(path)
}

var (
	modVersion                  = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeW = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = modVersion.NewProc("VerQueryValueW")
)

func fileVersionNative(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	n, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(p)), 0)
	if n == 0 {
		return ""
	}
	buf := make([]byte, n)
	if r, _, _ := procGetFileVersionInfoW.Call(uintptr(unsafe.Pointer(p)), 0, n, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return ""
	}
	var fi *windows.VS_FIXEDFILEINFO
	var l uint32
	root, _ := windows.UTF16PtrFromString(`\`)
	if r, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&fi)), uintptr(unsafe.Pointer(&l))); r == 0 || fi == nil {
		return ""
	}
	ms, ls := fi.ProductVersionMS, fi.ProductVersionLS
	return itoa(int(ms>>16)) + "." + itoa(int(ms&0xffff)) + "." + itoa(int(ls>>16))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// BestInterface — индекс интерфейса, через который ОС сейчас отправит пакет на ip.
func BestInterface(ip string) int {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	var idx uint32
	var sa windows.Sockaddr = &windows.SockaddrInet6{Addr: a.As16()}
	if a.Is4() {
		sa = &windows.SockaddrInet4{Addr: a.As4()}
	}
	if windows.GetBestInterfaceEx(sa, &idx) != nil {
		return 0
	}
	return int(idx)
}

// RunHidden запускает консольную программу без окна (версия ядра: xray.exe version).
func RunHidden(ctx context.Context, exe string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd.CombinedOutput()
}

// IsAdmin — процесс запущен с правами администратора.
func IsAdmin() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}
