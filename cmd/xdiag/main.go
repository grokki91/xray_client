// Команда xdiag — диагностика подключений Xray на Windows 11 из терминала. То же ядро, что у
// окна xdiag-ui.
//
//	xdiag run [--client auto|hiddify|v2rayn] [--uri-stdin] [--offline] [--no-reference]
//	          [--bridge | --ssh АЛИАС] [--live СЕК] [--import ФАЙЛ]… [--logs ФАЙЛ]
//	          [--capture [--capture-secs СЕК]] [--other-network] [--json] [--yes] [--no-save]
//	xdiag history [list | show ID [--details] | export ID [--include-address] [--text] | delete ID | clear]
//	xdiag data [path | show [--session ID]]
//	xdiag settings [show | set КЛЮЧ ЗНАЧЕНИЕ | unset КЛЮЧ]
//	xdiag bridge-help | hello HEX | version
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/grokki91/xray_client/internal/bridge"
	"github.com/grokki91/xray_client/internal/capture"
	"github.com/grokki91/xray_client/internal/engine"
	"github.com/grokki91/xray_client/internal/hello"
	"github.com/grokki91/xray_client/internal/netprobe"
	"github.com/grokki91/xray_client/internal/report"
	"github.com/grokki91/xray_client/internal/store"
)

func main() {
	consoleUTF8()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "history":
		err = cmdHistory(os.Args[2:])
	case "data":
		err = cmdData(os.Args[2:])
	case "settings":
		err = cmdSettings(os.Args[2:])
	case "bridge-help":
		cmdBridgeHelp()
	case "hello":
		err = cmdHello(os.Args[2:])
	case "capture-helper":
		if len(os.Args) < 3 {
			err = errors.New("capture-helper ФАЙЛ")
		} else {
			err = capture.RunJob(os.Args[2])
		}
	case "version", "--version", "-v":
		fmt.Println("xdiag", engine.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdiag:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `xdiag — диагностика подключений Xray (VLESS+REALITY+XHTTP) на Windows 11

  xdiag run                      диагностика (Hiddify и v2rayN находятся сами)
      --client hiddify|v2rayn    какой клиент проверять (по умолчанию — подключённый)
      --uri-stdin                профиль vless:// из stdin (не из командной строки)
      --offline                  без сети: только клиенты и Windows
      --no-reference             без эталонной пробы Xray-core
      --bridge | --ssh АЛИАС     мост к серверу: ssh АЛИАС sudo -n xm bridge …
      --live СЕК                 окно xm doctor (10–120, по умолчанию 60)
      --import ФАЙЛ              doctor.json / health.json с сервера (ручной режим)
      --logs ФАЙЛ                экспорт логов клиента (Hiddify: «Логи» → «Скопировать»)
      --capture                  захват ClientHello клиента (pktmon, запросит UAC)
      --other-network            повтор из другой сети: сравнить с прошлым сеансом
      --json                     вывод — экспорт сеанса JSON (без секретов)
      --yes                      согласиться на всё без вопросов
  xdiag history                  история; show ID [--details]; export ID [--include-address] [--text]; delete ID; clear
  xdiag data path                где лежат данные
  xdiag data show [--session ID] показать сохранённое (расшифровка DPAPI)
  xdiag settings show | set КЛЮЧ ЗНАЧЕНИЕ | unset КЛЮЧ
      ключи: ssh_alias, profile_uri (значение «-» — из stdin), hiddify_dir, v2rayn_dir,
             client, retention_days, live_seconds, export_include_address, use_bridge, reference
  xdiag bridge-help              команды для сервера (ручной режим)
  xdiag version
`)
}

func openAll() (*store.Store, *engine.Engine, error) {
	st, err := store.Open("")
	if err != nil {
		return nil, nil, err
	}
	e, err := engine.New(st)
	return st, e, err
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	client := fs.String("client", "", "")
	uriStdin := fs.Bool("uri-stdin", false, "")
	offline := fs.Bool("offline", false, "")
	noRef := fs.Bool("no-reference", false, "")
	useBridge := fs.Bool("bridge", false, "")
	ssh := fs.String("ssh", "", "")
	live := fs.Int("live", 0, "")
	var imports multi
	fs.Var(&imports, "import", "")
	logs := fs.String("logs", "", "")
	capt := fs.Bool("capture", false, "")
	captSecs := fs.Int("capture-secs", 60, "")
	other := fs.Bool("other-network", false, "")
	asJSON := fs.Bool("json", false, "")
	yes := fs.Bool("yes", false, "")
	noSave := fs.Bool("no-save", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, e, err := openAll()
	if err != nil {
		return err
	}
	set := st.LoadSettings()
	vault, err := st.LoadVault()
	if err != nil {
		return err
	}
	o := engine.Options{Client: set.Client, ProfileURI: vault.ProfileURI, HiddifyDir: vault.HiddifyDir, V2rayNDir: vault.V2rayNDir,
		Offline: *offline, Reference: set.Reference && !*noRef, LiveSeconds: set.LiveSeconds, Capture: *capt, CaptureSecs: *captSecs,
		OtherNetwork: *other}
	if *client != "" {
		o.Client = *client
	}
	if *uriStdin {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		o.ProfileURI = strings.TrimSpace(string(b))
	}
	if *live > 0 {
		o.LiveSeconds = *live
	}
	if *ssh != "" || *useBridge || set.UseBridge {
		o.Bridge, o.SSHAlias = "ssh", vault.SSHAlias
		if *ssh != "" {
			o.SSHAlias = *ssh
		}
		if o.SSHAlias == "" {
			fmt.Fprintln(os.Stderr, "Мост: SSH-алиас не задан (xdiag settings set ssh_alias xm-ui) — без моста")
			o.Bridge = ""
		}
	}
	for _, f := range imports {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		o.Imports = append(o.Imports, engine.Import{Name: f, Data: b})
	}
	if *logs != "" {
		b, err := os.ReadFile(*logs)
		if err != nil {
			return err
		}
		o.PastedLogs = string(b)
	}
	if exe, err := os.Executable(); err == nil {
		o.SelfExe = exe
	}
	if *other {
		l := st.Sessions()
		if len(l) == 0 {
			return errors.New("--other-network: нет прошлого сеанса для сравнения")
		}
		prev, err := e.Load(l[0].ID)
		if err != nil {
			return err
		}
		o.Prev = prev
		fmt.Fprintf(os.Stderr, "Сравнение с сеансом %s (%s). Убедитесь, что ПК сейчас в другой сети.\n", l[0].ID, l[0].Code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	in := bufio.NewReader(os.Stdin)
	started := map[string]bool{}
	hooks := engine.Hooks{
		Progress: func(s engine.Step) {
			if *asJSON {
				return
			}
			mark := map[string]string{"run": "…", "ok": "✓", "warn": "!", "fail": "✗", "skip": "-"}[s.Status]
			if s.Status == "run" {
				switch {
				case s.Wait > 0:
					fmt.Fprintf(os.Stderr, "  %s %s: %s\n", mark, s.Title, s.Note)
				case !started[s.ID]:
					fmt.Fprintf(os.Stderr, "  %s %s\n", mark, s.Title)
				}
				started[s.ID] = true
				return
			}
			fmt.Fprintf(os.Stderr, "  %s %s%s\n", mark, s.Title, map[bool]string{true: ": " + s.Note, false: ""}[s.Note != ""])
		},
		Confirm: func(ctx context.Context, c engine.Consent) bool {
			if *yes {
				return true
			}
			fmt.Fprintf(os.Stderr, "\n%s [д/Н] ", c.Text)
			line, _ := in.ReadString('\n')
			l := strings.ToLower(strings.TrimSpace(line))
			return l == "д" || l == "да" || l == "y" || l == "yes"
		},
		Window: func(ctx context.Context, what string, secs int) {
			fmt.Fprintf(os.Stderr, "\n>>> %s (%d с)\n", what, secs)
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			left := secs
			for left > 0 {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					left -= 10
					if left > 0 {
						fmt.Fprintf(os.Stderr, "    … осталось %d с\n", left)
					}
				}
			}
		},
		Budget: func(u netprobe.Usage) {
			if !*asJSON {
				fmt.Fprintf(os.Stderr, "    к серверу: %d из %d TLS за минуту\n", u.TLS, u.TLSMax)
			}
		},
	}
	if !*asJSON {
		fmt.Fprintln(os.Stderr, "xdiag: диагностика…")
	}
	sess, err := e.Run(ctx, o, hooks)
	if err != nil {
		return err
	}
	if !*noSave {
		if err := e.Save(sess); err != nil {
			fmt.Fprintln(os.Stderr, "История не сохранена:", err)
		}
	}
	if *asJSON {
		b, err := report.Export(sess, false)
		if err != nil {
			return err
		}
		os.Stdout.Write(append(b, '\n'))
		return nil
	}
	fmt.Println()
	fmt.Print(report.Text(report.Build(sess)))
	fmt.Printf("\nСеанс %s · подробно: xdiag history show %s --details\n", sess.ID, sess.ID)
	return nil
}

func cmdHistory(args []string) error {
	st, e, err := openAll()
	if err != nil {
		return err
	}
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	need := func() (string, error) {
		if len(args) < 2 {
			return "", fmt.Errorf("xdiag history %s ID", sub)
		}
		return args[1], nil
	}
	switch sub {
	case "list":
		l := st.Sessions()
		if len(l) == 0 {
			fmt.Println("История пуста")
		}
		for _, x := range l {
			fmt.Printf("%s  %s  %-22s %-12s %s\n", x.ID, x.At.Local().Format("02.01 15:04"), x.Code, x.Level, x.Short)
		}
	case "show":
		id, err := need()
		if err != nil {
			return err
		}
		s, err := e.Load(id)
		if err != nil {
			return err
		}
		v := report.Build(s)
		fmt.Print(report.Text(v))
		if hasFlag(args, "--details") {
			fmt.Println("\nПодробно:")
			fmt.Print(report.Details(v))
		}
	case "export":
		id, err := need()
		if err != nil {
			return err
		}
		s, err := e.Load(id)
		if err != nil {
			return err
		}
		if hasFlag(args, "--text") {
			fmt.Print(report.ExportText(s))
			return nil
		}
		b, err := report.Export(s, hasFlag(args, "--include-address"))
		if err != nil {
			return err
		}
		os.Stdout.Write(append(b, '\n'))
	case "delete":
		id, err := need()
		if err != nil {
			return err
		}
		return st.DeleteSession(id)
	case "clear":
		if err := st.ClearHistory(); err != nil {
			return err
		}
		fmt.Println("История удалена (на SSD безвозвратность стирания не гарантируется)")
	default:
		return fmt.Errorf("history: неизвестная подкоманда %q", sub)
	}
	return nil
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func cmdData(args []string) error {
	st, err := store.Open("")
	if err != nil {
		return err
	}
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "path":
		fmt.Println(st.Dir)
		if !st.Protected {
			fmt.Println("(вне Windows данные не шифруются — только для разработки)")
		}
	case "show":
		if len(args) >= 3 && args[1] == "--session" {
			var raw json.RawMessage
			if err := st.LoadSession(args[2], &raw); err != nil {
				return err
			}
			var pretty any
			_ = json.Unmarshal(raw, &pretty)
			fmt.Print(pretty2(pretty, ""))
			return nil
		}
		v, err := st.LoadVault()
		if err != nil {
			return err
		}
		fmt.Println("Каталог:", st.Dir)
		fmt.Println("\nНастройки (settings.json):")
		fmt.Print(pretty2(st.LoadSettings(), "  "))
		fmt.Println("\nСекреты (vault.dpapi, расшифровано для вас):")
		fmt.Print(pretty2(v, "  "))
		fmt.Printf("\nСеансов в истории: %d (xdiag data show --session ID)\n", len(st.Sessions()))
	default:
		return fmt.Errorf("data: неизвестная подкоманда %q", sub)
	}
	return nil
}

// pretty2 — JSON без экранирования & < > (URI читается как есть).
func pretty2(v any, prefix string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent(prefix, "  ")
	_ = enc.Encode(v)
	return prefix + b.String()
}

func cmdSettings(args []string) error {
	st, err := store.Open("")
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "show" {
		b, _ := json.MarshalIndent(st.LoadSettings(), "", "  ")
		fmt.Println(string(b))
		v, err := st.LoadVault()
		if err != nil {
			return err
		}
		fmt.Printf("ssh_alias: %s\nprofile_uri: %s\nhiddify_dir: %s\nv2rayn_dir: %s\n", mark(v.SSHAlias), mark(v.ProfileURI), mark(v.HiddifyDir), mark(v.V2rayNDir))
		fmt.Println("(значения секретов: xdiag data show)")
		return nil
	}
	if len(args) < 2 || (args[0] == "set" && len(args) < 3) {
		return errors.New("settings set КЛЮЧ ЗНАЧЕНИЕ | unset КЛЮЧ")
	}
	key, val := args[1], ""
	if args[0] == "set" {
		val = args[2]
		if val == "-" {
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
			val = strings.TrimSpace(string(b))
		}
	} else if args[0] != "unset" {
		return fmt.Errorf("settings: неизвестная подкоманда %q", args[0])
	}
	return applySetting(st, key, val)
}

func mark(s string) string {
	if s == "" {
		return "не задан"
	}
	return "задан"
}

func applySetting(st *store.Store, key, val string) error {
	v, err := st.LoadVault()
	if err != nil {
		return err
	}
	s := st.LoadSettings()
	secret := true
	switch key {
	case "ssh_alias":
		if val != "" {
			if _, err := bridge.Args(val, "facts", 0); err != nil {
				return err
			}
		}
		v.SSHAlias = val
	case "profile_uri":
		v.ProfileURI = val
	case "hiddify_dir":
		v.HiddifyDir = val
	case "v2rayn_dir":
		v.V2rayNDir = val
	default:
		secret = false
	}
	if secret {
		return st.SaveVault(v)
	}
	b := func() (bool, error) { return strconv.ParseBool(val) }
	switch key {
	case "client":
		if val != "auto" && val != "hiddify" && val != "v2rayn" && val != "" {
			return errors.New("client: auto | hiddify | v2rayn")
		}
		s.Client = val
	case "retention_days":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 365 {
			return errors.New("retention_days: 0–365")
		}
		s.RetentionDays = n
	case "live_seconds":
		n, err := strconv.Atoi(val)
		if err != nil || n < 10 || n > 120 {
			return errors.New("live_seconds: 10–120")
		}
		s.LiveSeconds = n
	case "export_include_address":
		x, err := b()
		if err != nil {
			return err
		}
		s.ExportIncludeAddress = x
	case "use_bridge":
		x, err := b()
		if err != nil {
			return err
		}
		s.UseBridge = x
	case "reference":
		x, err := b()
		if err != nil {
			return err
		}
		s.Reference = x
	default:
		return fmt.Errorf("неизвестный ключ %q", key)
	}
	return st.SaveSettings(s)
}

func cmdBridgeHelp() {
	fmt.Println(`Ручной режим (без SSH из приложения). На сервере:

  ` + strings.Join(bridge.ManualCommands(60), "\n  ") + `

Во время первой команды (60 с) один раз нажмите «Подключить» в клиенте на этом ПК.
Скопируйте файлы на ПК и запустите:

  xdiag run --import doctor.json --import health.json

Автоматический мост (когда на сервере появится xm bridge): один раз на сервере
  sudo xm bridge on
и на ПК
  xdiag settings set ssh_alias <алиас из ~/.ssh/config>
  xdiag run --bridge`)
}

func cmdHello(args []string) error {
	if len(args) < 1 {
		return errors.New("hello HEX")
	}
	b, err := hex.DecodeString(strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	h, err := hello.Parse(b)
	if err != nil {
		return err
	}
	out := map[string]any{"sni_set": h.SNI != "", "alpn": h.ALPN, "tls13": h.TLS13(), "shares": h.ShareNames(), "mlkem_rule": h.MLKEMRule(), "size": h.Size}
	j, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(j))
	return nil
}
