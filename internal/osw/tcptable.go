package osw

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Conn — TCP-соединение из таблицы ОС (Windows: GetExtendedTcpTable, класс OWNER_PID_ALL).
// Читается без прав администратора и без единого пакета в сеть: по ней видно, открывает ли
// клиент соединение с сервером и доходит ли оно до SYN-ACK.
type Conn struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  TCPState
	PID    int // 0 — у закрытых сокетов (TIME_WAIT): владелец неизвестен
}

// TCPState — MIB_TCP_STATE.
type TCPState int

const (
	TCPClosed      TCPState = 1
	TCPListen      TCPState = 2
	TCPSynSent     TCPState = 3
	TCPSynRcvd     TCPState = 4
	TCPEstablished TCPState = 5
	TCPFinWait1    TCPState = 6
	TCPFinWait2    TCPState = 7
	TCPCloseWait   TCPState = 8
	TCPClosing     TCPState = 9
	TCPLastAck     TCPState = 10
	TCPTimeWait    TCPState = 11
	TCPDeleteTCB   TCPState = 12
)

// Handshaked — рукопожатие TCP этого соединения прошло (ESTABLISHED или закрытие после него).
func (s TCPState) Handshaked() bool { return s >= TCPEstablished && s <= TCPTimeWait }

// ErrNoTable — таблицы соединений нет (не Windows).
var ErrNoTable = errors.New("таблица TCP-соединений есть только в Windows")

const (
	row4Size = 24 // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
	row6Size = 56 // MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, port, remoteAddr[16], scope, port, state, pid
)

// parseTable4 — MIB_TCPTABLE_OWNER_PID: DWORD числа строк, затем строки. DWORD — в порядке
// байт машины (little-endian), адрес — 4 байта в сетевом порядке, порт — первые 2 байта DWORD в
// сетевом порядке (старшие 16 бит не определены).
func parseTable4(b []byte) []Conn {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	var out []Conn
	for i := 0; i < n && 4+(i+1)*row4Size <= len(b); i++ {
		r := b[4+i*row4Size:]
		out = append(out, Conn{
			State:  TCPState(binary.LittleEndian.Uint32(r)),
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:10])),
			Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:18])),
			PID:    int(binary.LittleEndian.Uint32(r[20:24])),
		})
	}
	return out
}

// parseTable6 — MIB_TCP6TABLE_OWNER_PID; адреса v4-mapped приводятся к IPv4.
func parseTable6(b []byte) []Conn {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	var out []Conn
	for i := 0; i < n && 4+(i+1)*row6Size <= len(b); i++ {
		r := b[4+i*row6Size:]
		out = append(out, Conn{
			Local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])).Unmap(), binary.BigEndian.Uint16(r[20:22])),
			Remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])).Unmap(), binary.BigEndian.Uint16(r[44:46])),
			State:  TCPState(binary.LittleEndian.Uint32(r[48:52])),
			PID:    int(binary.LittleEndian.Uint32(r[52:56])),
		})
	}
	return out
}
