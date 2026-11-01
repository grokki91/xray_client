package osw

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

// psScript — сбор фактов одним проходом. Каждый раздел в своём try: отсутствующий командлет
// не роняет остальное. Пути exe клиентов — в переменной окружения XDIAG_EXE (через |), не в
// командной строке. Вывод — один JSON в UTF-8.
//
// Скрипт передаётся через -EncodedCommand (EncodedCommand), а не через stdin (-Command -):
// из stdin PowerShell 5.1 читает построчно, как консоль, и многострочный блок (try { … } на
// нескольких строках) ждёт пустой строки — всё после него, включая ConvertTo-Json, не
// выполняется, вывод пуст («unexpected end of JSON input»).
const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$r = [ordered]@{}
try { $r.adapters = @(Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status) } catch {}
try { $r.ipif = @(Get-NetIPInterface -AddressFamily IPv4 | Select-Object ifIndex, NlMtu, InterfaceMetric, ConnectionState) } catch {}
try { $r.routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object ifIndex, DestinationPrefix, RouteMetric, NextHop) } catch {}
try { $r.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceIndex, @{n='n';e={$_.ServerAddresses.Count}}) } catch {}
try { $r.doh = @(Get-DnsClientDohServerAddress | Select-Object ServerAddress, AutoUpgrade) } catch {}
try { $r.smhnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name DisableSmartNameResolution).DisableSmartNameResolution } catch {}
try { $r.nrpt = @(Get-DnsClientNrptRule).Count } catch {}
try { $r.fw = @(Get-NetFirewallProfile | Select-Object Name, Enabled) } catch {}
try {
  $r.fwblock = @(Get-NetFirewallApplicationFilter -All | Where-Object { $_.Program -match '(?i)hiddify|v2rayn|xray|sing-box|mihomo' } |
    ForEach-Object { $f = $_; $f | Get-NetFirewallRule | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Block' } |
      ForEach-Object { Split-Path $f.Program -Leaf } })
} catch {}
try { $r.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState) } catch {}
try { $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $r.proxy = [ordered]@{ enable = $p.ProxyEnable; server = $p.ProxyServer; pac = $p.AutoConfigURL } } catch {}
try { $r.winhttp = (& netsh.exe winhttp show proxy) -join [char]10 } catch {}
try { $r.w32tm = (& w32tm.exe /query /status) -join [char]10 } catch {}
try { $r.v6 = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.PrefixOrigin -in 'RouterAdvertisement','Dhcp','Manual' -and $_.IPAddress -notlike 'fe80*' -and $_.AddressState -eq 'Preferred' }).Count } catch {}
try { $r.listen = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess) } catch {}
try {
  $r.procs = @(Get-Process | Where-Object { $_.ProcessName -match '^(?i)(hiddify|hiddifycli|hiddify-core|v2rayn|xray|sing-box|mihomo|clash.*)$' } |
    Select-Object Id, ProcessName, Path, @{n='Ver';e={$_.MainModule.FileVersionInfo.ProductVersion}})
} catch {}
try { $r.svc = @(Get-Service -Name 'HiddifyTunnelService','HiddifyService' | Select-Object Name, @{n='Status';e={[string]$_.Status}}) } catch {}
$vers = @()
foreach ($x in ($env:XDIAG_EXE -split '\|')) { if ($x -and (Test-Path -LiteralPath $x)) { $i = (Get-Item -LiteralPath $x).VersionInfo; $vers += [ordered]@{ path = $x; ver = $i.ProductVersion; fver = $i.FileVersion } } }
$r.vers = $vers
$r | ConvertTo-Json -Depth 4 -Compress
`

// EncodedCommand — скрипт для powershell.exe -EncodedCommand: base64 от UTF-16LE. Длина для
// psScript — около 9 КБ при пределе командной строки 32 КБ; секретов в скрипте нет (пути exe —
// в переменной окружения).
func EncodedCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

type psOut struct {
	Adapters json.RawMessage `json:"adapters"`
	IPIf     json.RawMessage `json:"ipif"`
	Routes   json.RawMessage `json:"routes"`
	DNS      json.RawMessage `json:"dns"`
	DoH      json.RawMessage `json:"doh"`
	SMHNR    json.RawMessage `json:"smhnr"`
	NRPT     json.RawMessage `json:"nrpt"`
	FW       json.RawMessage `json:"fw"`
	FWBlock  json.RawMessage `json:"fwblock"`
	AV       json.RawMessage `json:"av"`
	Proxy    *struct {
		Enable json.RawMessage `json:"enable"`
		Server string          `json:"server"`
		PAC    string          `json:"pac"`
	} `json:"proxy"`
	WinHTTP string          `json:"winhttp"`
	W32tm   string          `json:"w32tm"`
	V6      json.RawMessage `json:"v6"`
	Listen  json.RawMessage `json:"listen"`
	Procs   json.RawMessage `json:"procs"`
	Svc     json.RawMessage `json:"svc"`
	Vers    json.RawMessage `json:"vers"`
}

// FileVersions — версии exe из последнего сбора: путь (нижний регистр) → версия.
type FileVersions map[string]string

// parsePS разбирает вывод скрипта.
func parsePS(b []byte) (Facts, FileVersions, error) {
	if strings.TrimSpace(string(b)) == "" {
		return Facts{}, nil, errors.New("PowerShell не вернул данных")
	}
	var o psOut
	if err := json.Unmarshal(b, &o); err != nil {
		return Facts{}, nil, err
	}
	f := Facts{Collected: true, Services: map[string]string{}}
	mtu := map[int]int{}
	metric := map[int]int{}
	for _, r := range asList(o.IPIf) {
		var x struct {
			IfIndex, NlMtu, InterfaceMetric int
		}
		if json.Unmarshal(r, &x) == nil {
			mtu[x.IfIndex] = x.NlMtu
			metric[x.IfIndex] = x.InterfaceMetric
		}
	}
	for _, r := range asList(o.Adapters) {
		var x struct {
			Name, InterfaceDescription string
			IfIndex                    int `json:"ifIndex"`
			Status                     json.RawMessage
		}
		if json.Unmarshal(r, &x) != nil {
			continue
		}
		st := strings.Trim(string(x.Status), `"`)
		up := strings.EqualFold(st, "Up") || st == "1"
		f.Adapters = append(f.Adapters, Adapter{Name: x.Name, Desc: x.InterfaceDescription, IfIndex: x.IfIndex, Up: up,
			Kind: AdapterKind(x.Name, x.InterfaceDescription), MTU: mtu[x.IfIndex]})
	}
	// Маршрут по умолчанию: наименьшая метрика среди физических — для привязки проб; если
	// у TUN/VPN есть 0.0.0.0/0 или половинки /1 — трафик сейчас идёт в тоннель.
	best, bestM := 0, 1<<30
	for _, r := range asList(o.Routes) {
		var x struct {
			IfIndex           int `json:"ifIndex"`
			DestinationPrefix string
			RouteMetric       int
		}
		if json.Unmarshal(r, &x) != nil {
			continue
		}
		a := f.Adapter(x.IfIndex)
		if a == nil {
			continue
		}
		if a.Kind == "tun" || a.Kind == "vpn" {
			f.DefaultViaTUN = true
			continue
		}
		if a.Kind == "physical" && x.DestinationPrefix == "0.0.0.0/0" {
			if m := x.RouteMetric + metric[x.IfIndex]; m < bestM {
				best, bestM = x.IfIndex, m
			}
		}
	}
	f.DefaultIfIndex = best
	for _, r := range asList(o.DNS) {
		var x struct{ N int }
		if json.Unmarshal(r, &x) == nil {
			f.DNSServers += x.N
		}
	}
	f.DoH = len(asList(o.DoH)) > 0
	f.SMHNROff = strings.TrimSpace(string(o.SMHNR)) == "1"
	f.NRPT = atoi(string(o.NRPT))
	for _, r := range asList(o.FW) {
		var x struct {
			Enabled json.RawMessage
		}
		if json.Unmarshal(r, &x) == nil {
			e := strings.Trim(string(x.Enabled), `"`)
			if e == "1" || strings.EqualFold(e, "true") {
				f.FirewallOn = true
			}
		}
	}
	for _, r := range asList(o.FWBlock) {
		var s string
		if json.Unmarshal(r, &s) == nil && s != "" {
			f.BlockRules = append(f.BlockRules, s)
		}
	}
	for _, r := range asList(o.AV) {
		var x struct {
			DisplayName  string `json:"displayName"`
			ProductState int    `json:"productState"`
		}
		if json.Unmarshal(r, &x) != nil || x.DisplayName == "" {
			continue
		}
		// productState: биты 12–13 — включён ли (0x1000).
		if x.ProductState != 0 && x.ProductState&0x1000 == 0 {
			continue
		}
		f.AV = append(f.AV, x.DisplayName)
		if !strings.Contains(strings.ToLower(x.DisplayName), "defender") {
			f.ThirdPartyAV = true
		}
	}
	if o.Proxy != nil {
		e := strings.Trim(string(o.Proxy.Enable), `"`)
		f.ProxyEnable = e == "1" || strings.EqualFold(e, "true")
		f.ProxyServer = o.Proxy.Server
		f.ProxyPAC = o.Proxy.PAC != ""
	}
	w := strings.ToLower(o.WinHTTP)
	f.WinHTTP = strings.Contains(w, "proxy server") && !strings.Contains(w, "direct access")
	f.TimeSynced, f.TimeSource = parseW32tm(o.W32tm)
	f.GlobalV6 = atoi(string(o.V6)) > 0
	for _, r := range asList(o.Listen) {
		var x struct {
			LocalAddress  string
			LocalPort     int
			OwningProcess int
		}
		if json.Unmarshal(r, &x) == nil {
			f.Listening = append(f.Listening, Listen{Addr: x.LocalAddress, Port: x.LocalPort, PID: x.OwningProcess})
		}
	}
	for _, r := range asList(o.Procs) {
		var x struct {
			ID          int `json:"Id"`
			ProcessName string
			Path        string
			Ver         string
		}
		if json.Unmarshal(r, &x) == nil {
			f.Processes = append(f.Processes, Process{PID: x.ID, Name: x.ProcessName, Path: x.Path, Version: x.Ver})
		}
	}
	for _, r := range asList(o.Svc) {
		var x struct{ Name, Status string }
		if json.Unmarshal(r, &x) == nil {
			f.Services[x.Name] = x.Status
		}
	}
	vers := FileVersions{}
	for _, r := range asList(o.Vers) {
		var x struct{ Path, Ver, Fver string }
		if json.Unmarshal(r, &x) == nil {
			v := x.Ver
			if v == "" {
				v = x.Fver
			}
			vers[strings.ToLower(x.Path)] = strings.TrimSpace(v)
		}
	}
	return f, vers, nil
}

// parseW32tm: синхронизировано ли время и с каким источником (вывод локализован — смотрим на
// «Local CMOS Clock»/«Free-running» как на признак отсутствия синхронизации).
func parseW32tm(s string) (bool, string) {
	if strings.TrimSpace(s) == "" {
		return false, ""
	}
	low := strings.ToLower(s)
	if strings.Contains(low, "local cmos clock") || strings.Contains(low, "free-running") {
		return false, "local"
	}
	for _, line := range strings.Split(s, "\n") {
		l := strings.ToLower(line)
		if strings.HasPrefix(strings.TrimSpace(l), "source") || strings.HasPrefix(strings.TrimSpace(l), "источник") {
			return true, "ntp"
		}
	}
	return true, ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.Trim(strings.TrimSpace(s), `"`))
	return n
}
