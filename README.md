# xdiag — почему VPN-клиент пишет «таймаут»

Приложение для Windows 11: одна кнопка «Диагностировать» — и одна причина с уровнем
уверенности, уликами и следующим шагом. Для установки VLESS + REALITY + XHTTP из
[grokki91/xray](https://github.com/grokki91/xray), клиенты — **Hiddify** и **v2rayN**.

«Таймаут» в клиенте рождается минимум в восьми разных ситуациях: клиент не поднял ядро,
профиль испорчен, адрес режется по пути, ClientHello режется, REALITY отверг ClientHello
(например, ядро без X25519MLKEM768), заморозка после рукопожатия, проблема за тоннелем.
xdiag различает их: собирает улики с клиента, Windows, сети, **эталонного ядра Xray-core**
(одна настоящая попытка с вашим профилем) и — по желанию — с сервера через `xm`.

Проект и обоснования — [docs/architecture.md](docs/architecture.md); что сделано и чем
реализация отличается — [docs/implementation.md](docs/implementation.md).

## Пример

Hiddify 4.1.2 и сервер на Xray v26.10.21:

```
Что не работает: Hiddify 4.1.2 не подключается к серверу («таймаут» или «Подключение…»)
Где: L0 — Клиентское приложение
Причина (подтверждено): Hiddify 4.1.2: ядро hiddify-sing-box не шлёт X25519MLKEM768 —
  сервер отдаёт его ClientHello сайту-маске
Улики:
  • [CX] Hiddify 4.1.2: REALITY делает ядро hiddify-sing-box — X25519MLKEM768 не шлёт
  • [P3] тоннель поднят: 204 за 180 мс, скачано 64 КБ без заморозки
  • [P3m] Тот же профиль без X25519MLKEM768 (fp edge): сервер отдал сайт-маску
Что делать:
  1. Сменить клиент на ядро Xray: v2rayN с ядром Xray от v25.7.26 и fp=chrome
  2. Профиль в новый клиент: `sudo xm uri <имя>` или `sudo xm qr <имя>`
Исключено:
  ✓ Сервер, путь до него и профиль: эталонное ядро Xray с этим профилем подключилось
```

## Установка

Сборки — в [Actions](https://github.com/grokki91/xray_client/actions) (артефакт
`xdiag-windows-amd64`) и в Releases по тегу `v*`: `xdiag-ui.exe` (окно) и `xdiag.exe`
(терминал), рядом `SHA256SUMS.txt`. Exe не подписан: SmartScreen при первом запуске покажет
«Подробнее → Выполнить в любом случае». Внутри — ядро Xray-core (для эталонной пробы), поэтому
антивирус может насторожиться.

Собрать самому (Go 1.26+, git):

```powershell
git clone https://github.com/grokki91/xray_client
cd xray_client
.\build.ps1
```

## Что проверяется

| Где | Проверки |
|---|---|
| Клиент | Hiddify/v2rayN: версия и ядро, шлёт ли ядро X25519MLKEM768, профили (синтаксис, fp, транспорт, ключ, shortId), логи, процесс, локальный прокси, TUN |
| Windows | адаптеры и второй VPN, маршрут к серверу, DNS/DoH, брандмауэр, антивирус, системный прокси, часы, IPv6, MTU |
| Сеть | интернет (NCSI, generate_204), белый список (российский эталон ↔ зарубежные), подмена DNS, сайт-маска по своему адресу |
| Сервер снаружи | TCP до порта, TLS с SNI маски, эталонное ядро Xray с вашим профилем (fp chrome) и без X25519MLKEM768 (fp edge), классы заморозки, повтор через 30 с |
| За тоннелем | DNS, URL теста задержки клиента, российский сайт |
| Сервер изнутри (по желанию) | `xm bridge facts/health/doctor` по SSH или импорт `doctor.json`: версия Xray, сверка профиля по хэшам, окно попыток |
| Углублённо (UAC) | захват ClientHello клиента pktmon: был ли SYN, есть ли X25519MLKEM768 |

Приложение ничего не меняет в системе и в клиентах. К серверу — не больше 3 TLS-соединений
за минуту (иначе сама диагностика похожа на шторм); счётчик виден в окне.

## Конфиденциальность

- Профиль, SSH-алиас, папки клиентов и история сеансов хранятся **только на этом ПК** в
  `%LOCALAPPDATA%\xdiag`, зашифрованными Windows DPAPI для вашей учётной записи.
- В окне, отчёте и экспорте адресов, ключей, UUID, shortId, путей и URL нет — только метки
  (`[server]`, `[sni]`, `[uuid:3fa9c1]`, `[ip:A]`). Адрес в экспорт — только по галочке.
- Телеметрии нет. На сервер через мост уходит только случайная соль сессии.
- Посмотреть сохранённое руками:
  - окно: вкладка «Данные» → «Показать сохранённые данные»;
  - терминал: `xdiag data show`, сеанс — `xdiag data show --session <id>`;
  - без xdiag, в Windows PowerShell:

    ```powershell
    Add-Type -AssemblyName System.Security
    $b = [IO.File]::ReadAllBytes("$env:LOCALAPPDATA\xdiag\vault.dpapi")
    $e = [Text.Encoding]::UTF8.GetBytes("xdiag/v1")
    [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b, $e, 'CurrentUser'))
    ```

  Рядом с данными лежит `README.txt` с тем же.

## Терминал

```powershell
xdiag run                                  # диагностика
xdiag run --client v2rayn                  # проверить конкретный клиент
xdiag run --import doctor.json             # с выводом xm doctor с сервера
xdiag run --bridge                         # с мостом (нужен ssh_alias и xm bridge на сервере)
xdiag run --capture                        # + захват ClientHello (UAC)
xdiag run --other-network                  # повтор из другой сети, сравнение с прошлым
xdiag history                              # история; show ID --details; export ID
xdiag settings set ssh_alias xm-ui
Get-Clipboard | xdiag settings set profile_uri -    # профиль — из буфера, не в командной строке
```

## Сервер (по желанию)

Без сервера xdiag работает полностью автономно. С сервером — точнее (окно `xm doctor`
видит, что приходит на сервер в момент попытки):

- **Ручной режим (работает сейчас):** на сервере
  `sudo xm doctor --live 60 --json > doctor.json` — в эти 60 с один раз «Подключить» в
  клиенте; файл скопировать на ПК и «Импорт doctor.json» (или `xdiag run --import doctor.json`).
- **Автоматический мост:** нужна команда `xm bridge` на сервере (этап 0 проекта, отдельный
  PR в `grokki91/xray`, пока не сделан), затем один раз `sudo xm bridge on` и SSH-алиас в
  настройках xdiag. Мост вызывает только `sudo -n xm bridge facts|health|doctor`, ключи SSH
  остаются у Windows (`~/.ssh`), xdiag их не читает.

## Разработка

```bash
go test ./...          # включая сетевой симулятор: настоящий REALITY-сервер Xray-core на петле
go vet ./...
GOOS=windows go build -tags desktop,production -ldflags "-H windowsgui" ./cmd/xdiag-ui
```

Структура: `internal/engine` — фазы и бюджет; `internal/rules` + `rules/*.yaml` — гипотезы;
`internal/clients` — Hiddify и v2rayN; `internal/refcore` — эталонное ядро;
`internal/bridge` — `xm`; `internal/store` — DPAPI; `cmd/` — CLI и окно. Правила для
изменений — [AGENTS.md](AGENTS.md).
