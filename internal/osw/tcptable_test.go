package osw

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Строки — как их кладёт GetExtendedTcpTable (MIB_TCPROW_OWNER_PID и MIB_TCP6ROW_OWNER_PID):
// DWORD — little-endian, адрес — в сетевом порядке, порт — 2 байта в сетевом порядке, мусор в
// старших байтах DWORD порта.
func TestParseTCPTable(t *testing.T) {
	row4 := func(st TCPState, la string, lp uint16, ra string, rp uint16, pid uint32) []byte {
		b := make([]byte, row4Size)
		binary.LittleEndian.PutUint32(b, uint32(st))
		l, r := netip.MustParseAddr(la).As4(), netip.MustParseAddr(ra).As4()
		copy(b[4:8], l[:])
		binary.BigEndian.PutUint16(b[8:10], lp)
		b[10], b[11] = 0xAA, 0x55 // не определено
		copy(b[12:16], r[:])
		binary.BigEndian.PutUint16(b[16:18], rp)
		binary.LittleEndian.PutUint32(b[20:24], pid)
		return b
	}
	tab := []byte{2, 0, 0, 0}
	tab = append(tab, row4(TCPSynSent, "192.0.2.10", 55612, "203.0.113.7", 443, 4321)...)
	tab = append(tab, row4(TCPListen, "127.0.0.1", 12334, "0.0.0.0", 0, 4321)...)
	got := parseTable4(append(tab, 0, 0)) // хвост буфера больше таблицы
	want := []Conn{
		{Local: netip.MustParseAddrPort("192.0.2.10:55612"), Remote: netip.MustParseAddrPort("203.0.113.7:443"), State: TCPSynSent, PID: 4321},
		{Local: netip.MustParseAddrPort("127.0.0.1:12334"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), State: TCPListen, PID: 4321},
	}
	if len(got) != len(want) {
		t.Fatalf("строк %d: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("строка %d: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
	// Число строк больше, чем поместилось в буфер, — лишние не читаются.
	if l := parseTable4(append([]byte{9, 0, 0, 0}, row4(TCPEstablished, "192.0.2.10", 1, "203.0.113.7", 443, 1)...)); len(l) != 1 {
		t.Fatalf("обрезанная таблица: %d строк", len(l))
	}

	r6 := make([]byte, row6Size)
	la, ra := netip.MustParseAddr("2001:db8::10").As16(), netip.MustParseAddr("::ffff:203.0.113.7").As16()
	copy(r6[0:16], la[:])
	binary.BigEndian.PutUint16(r6[20:22], 50001)
	copy(r6[24:40], ra[:])
	binary.BigEndian.PutUint16(r6[44:46], 443)
	binary.LittleEndian.PutUint32(r6[48:52], uint32(TCPEstablished))
	binary.LittleEndian.PutUint32(r6[52:56], 99)
	g6 := parseTable6(append([]byte{1, 0, 0, 0}, r6...))
	if len(g6) != 1 || g6[0].Remote != netip.MustParseAddrPort("203.0.113.7:443") || g6[0].Local.Port() != 50001 ||
		g6[0].State != TCPEstablished || g6[0].PID != 99 {
		t.Fatalf("IPv6: %+v", g6)
	}
	if !TCPTimeWait.Handshaked() || TCPSynSent.Handshaked() || TCPDeleteTCB.Handshaked() {
		t.Fatal("Handshaked")
	}
}
