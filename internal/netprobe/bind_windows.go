//go:build windows

package netprobe

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIF   = 31 // IP_UNICAST_IF
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF
)

// bindInterface: исходящий интерфейс сокета — по индексу, мимо таблицы маршрутов (TUN клиента).
func bindInterface(network string, c syscall.RawConn, idx int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if strings.HasSuffix(network, "6") {
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIF, idx)
			return
		}
		// Для IPv4 индекс — в сетевом порядке байт.
		v := int(uint32(idx)<<24 | (uint32(idx)<<8)&0xff0000 | (uint32(idx)>>8)&0xff00 | uint32(idx)>>24)
		serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIF, v)
		if serr == nil && network != "tcp4" && network != "udp4" {
			// Двойной стек: tcp/udp без суффикса может уйти по IPv6.
			_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIF, idx)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
