//go:build windows

package osw

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDAll = 5   // TCP_TABLE_OWNER_PID_ALL
	errInsufficient     = 122 // ERROR_INSUFFICIENT_BUFFER
)

// TCPTable — все TCP-соединения IPv4 и IPv6 с PID владельца. Прав администратора не нужно.
func TCPTable() ([]Conn, error) {
	b, err := tcpTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	out := parseTable4(b)
	if b6, err := tcpTable(windows.AF_INET6); err == nil {
		out = append(out, parseTable6(b6)...)
	}
	return out, nil
}

func tcpTable(af uint32) ([]byte, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return nil, err
	}
	size := uint32(32 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(af), tcpTableOwnerPIDAll, 0)
		switch r {
		case 0:
			return buf, nil
		case errInsufficient:
			size += 4 << 10 // таблица растёт между вызовами
		default:
			return nil, syscall.Errno(r)
		}
	}
	return nil, syscall.Errno(errInsufficient)
}
