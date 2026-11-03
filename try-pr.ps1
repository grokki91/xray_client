# Проверка ветки или PR на живой Windows одной командой: сборка CI (артефакт
# xdiag-windows-amd64 последнего успешного run build) → %TEMP%\xdiag-<коммит> → xdiag-ui.exe.
#
#   iwr https://raw.githubusercontent.com/grokki91/xray_client/main/try-pr.ps1 -UseBasicParsing -OutFile $env:TEMP\try-pr.ps1; powershell -ep Bypass -f $env:TEMP\try-pr.ps1 <номер PR|ветка>
#
# Запускается из любой папки; локальная копия проекта не нужна.
#
# Скачивание артефакта Actions требует входа в GitHub даже для публичного репозитория:
#   1) gh, если установлен и выполнен gh auth login;
#   2) иначе токен из GH_TOKEN или GITHUB_TOKEN (fine-grained, без прав — чтение публичного);
#   3) иначе сборка из исходников этого коммита через build.ps1 (нужны git и Go 1.26+);
#   -Build — сразу собрать из исходников.
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$Ref,
  [switch]$Build,
  [string]$Repo = 'grokki91/xray_client'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # иначе Invoke-WebRequest в Windows PowerShell качает в разы медленнее
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Artifact = 'xdiag-windows-amd64'
$Workflow = 'build.yml'
$Api = "https://api.github.com/repos/$Repo"

function Fail([string]$msg) { Write-Host $msg -ForegroundColor Red; exit 1 }
function Has([string]$cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# Внешняя команда: stderr не превращается в исключение, результат — код выхода.
function Run([string]$exe, [string[]]$argv, [switch]$Quiet) {
  $ErrorActionPreference = 'Continue'
  if ($Quiet) { & $exe @argv *> $null } else { & $exe @argv 2>&1 | ForEach-Object { Write-Host "  $_" } }
  return $LASTEXITCODE
}

$Token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
function Headers {
  $h = @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'xdiag-try-pr' }
  if ($Token) { $h['Authorization'] = "Bearer $Token" }
  $h
}
function Gh-Api([string]$path) {
  try { Invoke-RestMethod -Uri "$Api/$path" -Headers (Headers) -UseBasicParsing }
  catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 403 -or $code -eq 429) { Fail "GitHub API: лимит запросов без входа исчерпан (60 в час). Задайте GH_TOKEN или подождите." }
    if ($code -eq 404) { return $null }
    throw
  }
}

# 1. Что проверяем: номер PR (21, #21, ссылка на PR) или ветка.
$pr = $null
if ($Ref -match '^(?:#)?(\d+)$' -or $Ref -match '/pull/(\d+)') {
  $pr = Gh-Api "pulls/$($Matches[1])"
  if (-not $pr) { Fail "PR $($Matches[1]) в $Repo не найден." }
  $branch = $pr.head.ref
  $sha = $pr.head.sha
  $fork = $pr.head.repo.full_name -ne $Repo
  Write-Host "PR #$($pr.number): $($pr.title)"
} else {
  $branch = $Ref
  $b = Gh-Api "branches/$([uri]::EscapeDataString($branch))"
  if (-not $b) { Fail "Ветки '$branch' в $Repo нет." }
  $sha = $b.commit.sha
  $fork = $false
}
$short = $sha.Substring(0, 7)
$headShort = $short
Write-Host "Ветка $branch, последний коммит $short"

$dir = Join-Path $env:TEMP "xdiag-$short"
$exe = Join-Path $dir 'xdiag-ui.exe'

function Start-Ui {
  Write-Host "Запуск $exe" -ForegroundColor Green
  Start-Process -FilePath $exe -WorkingDirectory $dir
  exit 0
}
if (Test-Path $exe) { Write-Host "Уже скачано: $dir"; Start-Ui }

# 2. Сборка из исходников этого коммита.
function Build-FromSource {
  foreach ($c in 'git', 'go') {
    if (-not (Has $c)) {
      Fail ("Нет $c. Варианты:`n" +
        "  - войти в GitHub: winget install GitHub.cli; gh auth login — и запустить снова;`n" +
        "  - или токен: `$env:GH_TOKEN='<токен>' — и запустить снова;`n" +
        "  - или для сборки: winget install Git.Git GoLang.Go — и запустить снова;`n" +
        "  - или вручную: $script:runUrl → Artifacts → $Artifact.")
    }
  }
  $src = Join-Path $env:TEMP "xdiag-src-$headShort"
  if (Test-Path $src) { Remove-Item -Recurse -Force $src }
  New-Item -ItemType Directory -Force $src | Out-Null
  $what = if ($pr) { "refs/pull/$($pr.number)/head" } else { "refs/heads/$branch" }
  Write-Host "Сборка из исходников ($what) в $src"
  Push-Location $src
  try {
    if ((Run git @('init', '-q')) -ne 0) { Fail 'git init не удался.' }
    if ((Run git @('fetch', '-q', '--depth', '1', "https://github.com/$Repo.git", $what)) -ne 0) { Fail "git fetch $what не удался." }
    if ((Run git @('checkout', '-q', 'FETCH_HEAD')) -ne 0) { Fail 'git checkout не удался.' }
    $ps = (Get-Process -Id $PID).Path
    if ((Run $ps @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $src 'build.ps1'))) -ne 0) { Fail 'build.ps1 завершился с ошибкой.' }
  } finally { Pop-Location }
  $script:dir = Join-Path $env:TEMP "xdiag-$headShort"
  $script:exe = Join-Path $script:dir 'xdiag-ui.exe'
  New-Item -ItemType Directory -Force $script:dir | Out-Null
  Copy-Item (Join-Path $src 'dist\*.exe') $script:dir
  Start-Ui
}

# 3. Последний успешный run build для этого коммита, иначе — для ветки.
$script:runUrl = "https://github.com/$Repo/actions/workflows/$Workflow"
if ($Build) { Build-FromSource }

$runs = Gh-Api "actions/workflows/$Workflow/runs?head_sha=$sha&per_page=20"
$run = @($runs.workflow_runs | Where-Object { $_.conclusion -eq 'success' }) | Select-Object -First 1
if (-not $run) {
  $active = @($runs.workflow_runs | Where-Object { $_.status -ne 'completed' }) | Select-Object -First 1
  $failed = @($runs.workflow_runs | Where-Object { $_.status -eq 'completed' }) | Select-Object -First 1
  if ($active) { Write-Host "Сборка коммита $short ещё идёт: $($active.html_url)" -ForegroundColor Yellow }
  elseif ($failed) { Write-Host "Сборка коммита $short не прошла ($($failed.conclusion)): $($failed.html_url)" -ForegroundColor Yellow }
  else { Write-Host "Сборки коммита $short нет." -ForegroundColor Yellow }
  if (-not $fork) {
    $older = Gh-Api "actions/workflows/$Workflow/runs?branch=$([uri]::EscapeDataString($branch))&status=success&per_page=1"
    $run = @($older.workflow_runs) | Select-Object -First 1
  }
  if (-not $run) {
    Write-Host 'Готовой сборки нет — собираю из исходников.'
    Build-FromSource
  }
  $short = $run.head_sha.Substring(0, 7)
  Write-Host "Беру последнюю успешную сборку ветки — коммит $short, не последний." -ForegroundColor Yellow
  $dir = Join-Path $env:TEMP "xdiag-$short"
  $exe = Join-Path $dir 'xdiag-ui.exe'
  if (Test-Path $exe) { Write-Host "Уже скачано: $dir"; Start-Ui }
}
$script:runUrl = $run.html_url
Write-Host "Сборка: $($run.html_url)"

# 4. Скачивание артефакта.
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
New-Item -ItemType Directory -Force $dir | Out-Null
$got = $false
if ((Has 'gh') -and ((Run gh @('auth', 'status', '-h', 'github.com') -Quiet) -eq 0)) {
  Write-Host 'Скачивание через gh'
  $got = (Run gh @('run', 'download', "$($run.id)", '-R', $Repo, '-n', $Artifact, '-D', $dir)) -eq 0
} elseif ($Token) {
  Write-Host 'Скачивание по токену из окружения'
  $list = Gh-Api "actions/runs/$($run.id)/artifacts?name=$Artifact"
  $a = @($list.artifacts | Where-Object { -not $_.expired }) | Select-Object -First 1
  if ($a) {
    $zip = Join-Path $env:TEMP "xdiag-$short.zip"
    Invoke-WebRequest -Uri $a.archive_download_url -Headers (Headers) -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    Remove-Item $zip
    $got = $true
  } else { Write-Host "Артефакт $Artifact истёк или не найден." -ForegroundColor Yellow }
} else {
  Write-Host 'Нет gh с входом в GitHub и нет GH_TOKEN: GitHub отдаёт артефакты только после входа.' -ForegroundColor Yellow
}
if (-not $got -or -not (Test-Path $exe)) {
  Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
  Write-Host 'Собираю из исходников.'
  Build-FromSource
}

# 5. Контрольные суммы из сборки.
$sums = Join-Path $dir 'SHA256SUMS.txt'
if (Test-Path $sums) {
  foreach ($line in Get-Content $sums) {
    if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { continue }
    $f = Join-Path $dir $Matches[2].Trim()
    if ((Get-FileHash -Algorithm SHA256 $f).Hash -ne $Matches[1].ToUpper()) { Fail "Контрольная сумма $($Matches[2]) не совпала — файл повреждён." }
  }
  Write-Host 'Контрольные суммы совпали.'
}
Start-Ui
