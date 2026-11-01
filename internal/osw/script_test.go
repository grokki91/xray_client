package osw

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// Вывод скрипта PowerShell (ConvertTo-Json): одиночные элементы — объектом, а не массивом.
const sample = `{"adapters":[{"Name":"Ethernet","InterfaceDescription":"Intel(R) Ethernet Controller I225-V","ifIndex":12,"Status":"Up"},
{"Name":"HiddifyTunnel","InterfaceDescription":"HiddifyTunnel Tunnel","ifIndex":40,"Status":"Up"},
{"Name":"WireGuard","InterfaceDescription":"WireGuard Tunnel","ifIndex":41,"Status":"Disconnected"}],
"ipif":[{"ifIndex":12,"NlMtu":1500,"InterfaceMetric":25},{"ifIndex":40,"NlMtu":9000,"InterfaceMetric":0}],
"routes":[{"ifIndex":12,"DestinationPrefix":"0.0.0.0/0","RouteMetric":0,"NextHop":"192.168.1.1"},{"ifIndex":40,"DestinationPrefix":"0.0.0.0/1","RouteMetric":0}],
"dns":{"InterfaceIndex":12,"n":2},"doh":null,"smhnr":1,"nrpt":0,
"fw":[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1}],"fwblock":"xray.exe",
"av":[{"displayName":"Windows Defender","productState":397568},{"displayName":"Kaspersky","productState":266240}],
"proxy":{"enable":1,"server":"127.0.0.1:12334","pac":null},"winhttp":"Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).",
"w32tm":"Leap Indicator: 0(no warning)\nSource: time.windows.com,0x9","v6":0,
"listen":{"LocalAddress":"0.0.0.0","LocalPort":12334,"OwningProcess":4242},
"procs":{"Id":4242,"ProcessName":"Hiddify","Path":"C:\\Program Files\\Hiddify\\Hiddify.exe","Ver":"4.1.2"},
"svc":{"Name":"HiddifyTunnelService","Status":"Running"},"vers":[]}`

func TestParsePS(t *testing.T) {
	f, _, err := parsePS([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Adapters) != 3 || f.Adapter(40).Kind != "tun" || f.Adapter(12).Kind != "physical" || f.Adapter(41).Up {
		t.Fatalf("адаптеры: %+v", f.Adapters)
	}
	if f.DefaultIfIndex != 12 || !f.DefaultViaTUN || f.Adapter(12).MTU != 1500 {
		t.Fatalf("маршрут: %d %v", f.DefaultIfIndex, f.DefaultViaTUN)
	}
	if f.DNSServers != 2 || f.DoH || !f.SMHNROff || !f.FirewallOn || len(f.BlockRules) != 1 {
		t.Fatalf("dns/fw: %+v", f)
	}
	if !f.ThirdPartyAV || len(f.AV) != 2 || !f.ProxyEnable || f.ProxyServer != "127.0.0.1:12334" || f.WinHTTP {
		t.Fatalf("av/proxy: %+v", f)
	}
	if !f.TimeSynced || len(f.Listening) != 1 || len(f.ProcessByName("hiddify")) != 1 || f.Services["HiddifyTunnelService"] != "Running" {
		t.Fatalf("прочее: %+v", f)
	}
}

// Скрипт уходит в -EncodedCommand целиком: base64 от UTF-16LE, обратимо, в пределах командной
// строки Windows (32767 символов). Через stdin (-Command -) многострочные блоки PowerShell 5.1
// не выполнял — вывод был пуст.
func TestEncodedCommand(t *testing.T) {
	enc := EncodedCommand(psScript)
	if len(enc) > 30000 {
		t.Fatalf("длина %d", len(enc))
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw)%2 != 0 {
		t.Fatal(err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if string(utf16.Decode(u)) != psScript {
		t.Fatal("скрипт не восстановился")
	}
	if !strings.Contains(psScript, "ConvertTo-Json") || strings.Contains(psScript, `-join "\n"`) {
		t.Fatal("скрипт")
	}
}

func TestParsePSEmpty(t *testing.T) {
	if _, _, err := parsePS([]byte(" \r\n")); err == nil || !strings.Contains(err.Error(), "не вернул") {
		t.Fatalf("%v", err)
	}
}
