# Сборка xdiag на Windows из исходников (docs/architecture.md, вопрос 5: сборка владельцем).
# Нужен Go 1.26+:  winget install GoLang.Go   (и git)
# Результат: dist\xdiag-ui.exe (окно) и dist\xdiag.exe (терминал).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$ver = (git describe --tags --always --dirty 2>$null)
if (-not $ver) { $ver = 'dev' }
$ld = "-s -w -X github.com/grokki91/xray_client/internal/engine.Version=$ver"

# Иконка, манифест и версия файла — необязательно: без них exe работает так же.
try {
  go install github.com/tc-hib/go-winres@v0.3.3
  $winres = Join-Path (go env GOPATH) 'bin\go-winres.exe'
  foreach ($d in 'cmd\xdiag-ui', 'cmd\xdiag') {
    Push-Location $d
    & $winres make --in winres\winres.json --out rsrc --arch amd64
    Pop-Location
  }
} catch {
  Write-Warning "go-winres не сработал ($_): exe будут без иконки"
}

New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -ldflags $ld -o dist\xdiag.exe .\cmd\xdiag
go build -trimpath -tags desktop,production -ldflags "$ld -H windowsgui" -o dist\xdiag-ui.exe .\cmd\xdiag-ui
Remove-Item cmd\xdiag-ui\*.syso, cmd\xdiag\*.syso -ErrorAction SilentlyContinue
Get-FileHash dist\*.exe | Format-Table -AutoSize
Write-Host "Готово: dist\xdiag-ui.exe"
