package clients

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grokki91/xray_client/internal/osw"
	"github.com/grokki91/xray_client/internal/rules"
)

const (
	tUUID = "00000000-0000-4000-8000-000000000001"
	tPBK  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sqliteExec(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func testEnv(t *testing.T) *Env {
	e, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return &Env{AppData: filepath.Join(root, "Roaming"), LocalAppData: filepath.Join(root, "Local"), ProgramFiles: filepath.Join(root, "PF"),
		UserProfile: filepath.Join(root, "user"), TempDir: t.TempDir(), Compat: e.Compat, Now: time.Now,
		OS: &osw.Facts{Collected: true, Services: map[string]string{}},
		FileVersion: func(p string) string {
			switch filepath.Base(p) {
			case "Hiddify.exe":
				return "4.1.2"
			case "v2rayN.exe":
				return "7.25.6"
			}
			return ""
		},
		RunVersion: func(ctx context.Context, exe string, args ...string) ([]byte, error) {
			return []byte("Xray 26.7.28 (Xray, Penetrates Everything.) 5ca6f4b (go1.26.0 windows/amd64)\nA unified platform"), nil
		},
	}
}

func TestHiddify(t *testing.T) {
	env := testEnv(t)
	write(t, filepath.Join(env.ProgramFiles, "Hiddify", "Hiddify.exe"), "MZ")
	dir := filepath.Join(env.AppData, "Hiddify", "hiddify")
	write(t, filepath.Join(dir, "shared_preferences.json"), `{"flutter.service-mode":"vpn","flutter.mixed-port":12334,"flutter.allow-connection-from-lan":true,"flutter.region":"ru"}`)
	write(t, filepath.Join(dir, "configs", "p1.json"), `{"outbounds":[{"type":"vless","tag":"x","server":"192.0.2.10","server_port":443,"uuid":"`+tUUID+`",
	"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"`+tPBK+`","short_id":"ab"}},
	"transport":{"type":"xhttp","path":"/p","mode":"auto"}}]}`)
	write(t, filepath.Join(dir, "box.log"), "+0300 2026-10-28 ERROR [123 5ms] outbound/vless[x]: reality verification failed\nINFO ok\n")
	sqliteExec(t, filepath.Join(dir, "db.sqlite"),
		`CREATE TABLE profile_entries (id TEXT, type TEXT, active INTEGER, name TEXT, url TEXT, last_update INTEGER)`,
		`INSERT INTO profile_entries VALUES ('p1','remote',1,'Мой сервер','https://sub.example.com/s/abc',0)`)
	env.OS.Listening = []osw.Listen{{Addr: "0.0.0.0", Port: 12334, PID: 7}}
	env.OS.Processes = []osw.Process{{PID: 7, Name: "Hiddify"}}

	h := &Hiddify{}
	d := h.Detect(context.Background(), env)
	if !d.Installed || d.Version != "4.1.2" || d.CoreFamily != "sing-box" || d.CoreMlkem == nil || *d.CoreMlkem || !d.TUN || !d.LAN || d.ProxyPort != 12334 {
		t.Fatalf("%+v", d)
	}
	if d.RUDirect == nil || !*d.RUDirect {
		t.Fatal("регион ru → прямой маршрут для РФ")
	}
	ps, err := h.Profiles(context.Background(), env, d)
	if err != nil || len(ps) != 1 || !ps[0].Active || ps[0].Name != "Мой сервер" || ps[0].SubURL == "" || ps[0].Path != "/p" {
		t.Fatalf("%v %+v", err, ps)
	}
	l := h.Logs(env, d, time.Time{})
	if l.Counts["reality_failed"] != 1 {
		t.Fatalf("%+v", l)
	}
	s := h.State(env, d)
	if !s.Running || !s.CoreListening || len(s.Exposed) != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestV2rayNNewAndOldSchema(t *testing.T) {
	env := testEnv(t)
	dir := filepath.Join(env.UserProfile, "Desktop", "v2rayN-windows-64")
	env.V2rayNDir = ""
	write(t, filepath.Join(dir, "v2rayN.exe"), "MZ")
	write(t, filepath.Join(dir, "bin", "xray", "xray.exe"), "MZ")
	write(t, filepath.Join(dir, "guiConfigs", "guiNConfig.json"), `{"IndexId":"new1","TunModeItem":{"EnableTun":false},
	"Inbound":[{"LocalPort":10808,"AllowLANConn":false}],"CoreTypeItem":[{"ConfigType":5,"CoreType":2}],"SpeedTestItem":{"SpeedPingTestUrl":"https://www.google.com/generate_204"}}`)
	write(t, filepath.Join(dir, "guiLogs", "2026-10-28.txt"), "Failed to build REALITY config: empty fingerprint\n")
	sqliteExec(t, filepath.Join(dir, "guiConfigs", "guiNDB.db"),
		`CREATE TABLE ProfileItem (IndexId TEXT PRIMARY KEY, ConfigType INTEGER, CoreType INTEGER, Remarks TEXT, Address TEXT, Port INTEGER,
		 Password TEXT, Id TEXT, Network TEXT, StreamSecurity TEXT, Sni TEXT, Fingerprint TEXT, PublicKey TEXT, ShortId TEXT, SpiderX TEXT,
		 Path TEXT, RequestHost TEXT, HeaderType TEXT, Flow TEXT, ProtoExtra TEXT, TransportExtra TEXT, Security TEXT)`,
		// Новая схема: UUID в Password, путь и режим — в TransportExtra.
		`INSERT INTO ProfileItem VALUES ('new1',5,NULL,'a','192.0.2.10',443,'`+tUUID+`','', 'xhttp','reality','www.example.com','chrome','`+tPBK+`','ab','/',
		 '','','','','{"Flow":""}','{"Path":"/xh","XhttpMode":"auto"}','')`,
		// Старая схема: UUID в Id, путь в Path, режим в HeaderType; ядро профиля — sing_box.
		`INSERT INTO ProfileItem VALUES ('old1',5,24,'b','198.51.100.4',443,'','`+tUUID+`','xhttp','reality','www.example.com','edge','`+tPBK+`','cd','/',
		 '/old','','packet-up','','','','none')`,
		`INSERT INTO ProfileItem VALUES ('vm',1,NULL,'vmess','203.0.113.1',443,'','','tcp','','','','','','','','','','','','','')`)

	v := &V2rayN{}
	d := v.Detect(context.Background(), env)
	if !d.Installed || d.Version != "7.25.6" || d.CoreFamily != "xray" || d.CoreVersion != "26.7.28" || d.CoreMlkem == nil || !*d.CoreMlkem {
		t.Fatalf("%+v", d)
	}
	ps, err := v.Profiles(context.Background(), env, d)
	if err != nil || len(ps) != 2 {
		t.Fatalf("%v %d", err, len(ps))
	}
	byID := map[string]int{}
	for i, p := range ps {
		byID[p.ID] = i
	}
	n, o := ps[byID["new1"]], ps[byID["old1"]]
	if !n.Active || n.UUID != tUUID || n.Path != "/xh" || n.Mode != "auto" || len(n.Validate()) != 0 {
		t.Fatalf("новая схема: %+v %v", n, n.Validate())
	}
	if o.Active || o.UUID != tUUID || o.Path != "/old" || o.Mode != "packet-up" || o.CoreOverride != "sing_box" || o.Encryption != "none" {
		t.Fatalf("старая схема: %+v", o)
	}
	if l := v.Logs(env, d, time.Time{}); l.Counts["empty_fp"] != 1 {
		t.Fatalf("%+v", l)
	}
}

func TestScanTextPasted(t *testing.T) {
	s := ScanText("ERROR outbound: REALITY: received real certificate (potential MITM or redirection)\nlisten tcp 127.0.0.1:12334: bind: Only one usage of each socket address")
	if !s.Pasted || s.Counts["real_cert"] != 1 || s.Counts["port_busy"] != 1 || len(s.Lines) != 2 {
		t.Fatalf("%+v", s)
	}
	// Прямые проверки Hiddify — отдельно от таймаутов к серверу.
	s = ScanText("WARN monitoring: outbound direct §hide§ URL test failed: (dial tcp 192.0.2.1:80: i/o timeout)\n" +
		"WARN monitoring: outbound direct-fragment §hide§ URL test failed: (dial tcp 192.0.2.1:80: i/o timeout)\n" +
		"ERROR outbound/vless[proxy]: dial tcp 198.51.100.7:443: i/o timeout")
	if s.Counts["direct_failed"] != 2 || s.Counts["timeout"] != 3 {
		t.Fatalf("%+v", s.Counts)
	}
}
