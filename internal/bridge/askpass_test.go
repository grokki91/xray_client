package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Тестовый бинарь сам служит помощником SSH_ASKPASS — как xdiag.exe у ssh.exe.
func TestMain(m *testing.M) {
	if ok, code := AskpassMain(os.Args[1:], os.Stdout); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// Помощник отвечает только на запрос пароля ключа: пароль сервера и PIN не получают ничего.
func TestAskpassMain(t *testing.T) {
	t.Setenv(envAskpass, "1")
	t.Setenv(envPassphrase, "secret-pass")
	var out bytes.Buffer
	if ok, code := AskpassMain([]string{`Enter passphrase for key 'C:\Users\user/.ssh/id_ed25519': `}, &out); !ok || code != 0 || out.String() != "secret-pass\n" {
		t.Fatalf("пароль ключа: %v %d %q", ok, code, out.String())
	}
	for _, prompt := range []string{"root@192.0.2.10's password: ", "Enter PIN for ED25519-SK key: ", ""} {
		out.Reset()
		if ok, code := AskpassMain([]string{prompt}, &out); !ok || code == 0 || out.Len() > 0 {
			t.Errorf("%q: %v %d %q", prompt, ok, code, out.String())
		}
	}
	t.Setenv(envAskpass, "")
	if ok, _ := AskpassMain([]string{"Enter passphrase for key x:"}, &out); ok {
		t.Error("без метки режима — обычный запуск")
	}
}

// С паролем ключа: без BatchMode (он помощника не зовёт), вход по паролю сервера выключен,
// пароль — только в окружении ssh.exe, не в командной строке. Отказы — по строкам `ssh -v`.
func TestSSHPassphrase(t *testing.T) {
	var gotArgs, gotEnv []string
	serr := ""
	s := &SSH{Alias: "xm-ui", Exe: "ssh", Passphrase: "secret-pass", Self: `C:\xdiag\xdiag-ui.exe`,
		Run: func(_ context.Context, _ string, a []string, _ []byte, env []string) ([]byte, []byte, error) {
			gotArgs, gotEnv = a, env
			return nil, []byte(serr), errors.New("exit status 255")
		}}
	accepted := "debug1: Server accepts key: C:\\\\Users\\\\user/.ssh/id_ed25519 ED25519 SHA256:AAAA explicit\n"
	denied := "user@192.0.2.10: Permission denied (publickey).\n"
	for e, want := range map[string]error{
		accepted + "debug1: read_passphrase: requested to askpass\n" + denied: ErrBadPassphrase,
		accepted + denied: ErrAskpass,
		accepted + "debug1: read_passphrase: requested to askpass\nssh_askpass: exec(C:\\\\x): No such file\n" + denied: ErrAskpass,
		"debug1: Authentications that can continue: publickey\n" + denied:                                               ErrAuth,
	} {
		serr = e
		if _, err := s.Facts(context.Background(), "00"); !errors.Is(err, want) {
			t.Errorf("%q → %v, ожидалось %v", e, err, want)
		}
	}
	a := strings.Join(gotArgs, " ")
	if strings.Contains(a, "BatchMode") || !strings.Contains(a, "PasswordAuthentication=no") || !strings.Contains(a, "KbdInteractiveAuthentication=no") ||
		strings.Contains(a, "secret-pass") {
		t.Fatalf("аргументы: %s", a)
	}
	env := strings.Join(gotEnv, "\n")
	for _, w := range []string{`SSH_ASKPASS=C:\xdiag\xdiag-ui.exe`, "SSH_ASKPASS_REQUIRE=force", envAskpass + "=1", envPassphrase + "=secret-pass"} {
		if !strings.Contains(env, w) {
			t.Errorf("окружение без %q", w)
		}
	}
	// Без пароля — как раньше: BatchMode и ничего лишнего в окружении.
	s.Passphrase = ""
	serr = denied
	_, _ = s.Facts(context.Background(), "00")
	if gotEnv != nil || !strings.Contains(strings.Join(gotArgs, " "), "BatchMode=yes") {
		t.Fatalf("без пароля: %v %v", gotArgs, gotEnv)
	}
}

// Настоящий OpenSSH (если есть ssh и sshd): sshd на петле, ключ под паролем. Без пароля —
// ErrPassphrase, с верным — вход, с неверным — ErrBadPassphrase. Проверяет контракт OpenSSH
// (строки -v, SSH_ASKPASS_REQUIRE), на котором стоит classify.
func TestSSHPassphraseOpenSSH(t *testing.T) {
	sshExe, err1 := exec.LookPath("ssh")
	keygen, err2 := exec.LookPath("ssh-keygen")
	sshd := "/usr/sbin/sshd"
	if _, err := os.Stat(sshd); err1 != nil || err2 != nil || err != nil {
		t.Skip("нет OpenSSH (ssh, ssh-keygen, sshd)")
	}
	dir := t.TempDir()
	run := func(name string, a ...string) {
		if out, err := exec.Command(name, a...).CombinedOutput(); err != nil {
			t.Skipf("%s %v: %v %s", name, a, err, out)
		}
	}
	run(keygen, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "hk"))
	run(keygen, "-q", "-t", "ed25519", "-N", "right-pass", "-f", filepath.Join(dir, "key"))
	pub, _ := os.ReadFile(filepath.Join(dir, "key.pub"))
	hk, _ := os.ReadFile(filepath.Join(dir, "hk.pub"))
	os.WriteFile(filepath.Join(dir, "auth"), pub, 0o600)
	port := 22000 + os.Getpid()%2000
	user := os.Getenv("USER")
	if user == "" {
		user = "root"
	}
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s/hk\nPermitRootLogin yes\n"+
		"PasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile %s/auth\nPidFile %s/pid\nStrictModes no\nUsePAM no\n", port, dir, dir, dir)), 0o600)
	os.MkdirAll("/run/sshd", 0o755)
	d := exec.Command(sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	if err := d.Start(); err != nil {
		t.Skipf("sshd: %v", err)
	}
	defer d.Process.Kill()
	os.WriteFile(filepath.Join(dir, "known"), []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, hk)), 0o600)
	cfg := fmt.Sprintf("Host lab\n  HostName 127.0.0.1\n  Port %d\n  User %s\n  IdentityFile %s/key\n  IdentitiesOnly yes\n  UserKnownHostsFile %s/known\n", port, user, dir, dir)
	os.WriteFile(filepath.Join(dir, "cfg"), []byte(cfg), 0o600)
	self, _ := os.Executable()
	t.Setenv("SSH_AUTH_SOCK", "")
	// Вместо `sudo -n xm bridge facts` на «сервере» — cat: stdin (соль) отдаётся как есть, без
	// JSON ответ — ошибка classify; для входа хватает признака «не отказ ssh».
	login := func(pass string) error {
		s := &SSH{Alias: "lab", Exe: sshExe, Passphrase: pass, Self: self, Run: func(ctx context.Context, exe string, a []string, in []byte, env []string) ([]byte, []byte, error) {
			a = append([]string{"-F", filepath.Join(dir, "cfg")}, a...)
			a = append(a[:len(a)-5], "echo", `'{"schema":{"name":"bridge-facts","major":1},"xray":{"version":"t"}}'`)
			cmd := exec.CommandContext(ctx, exe, a...)
			cmd.Env = append(os.Environ(), env...)
			var o, e bytes.Buffer
			cmd.Stdout, cmd.Stderr, cmd.Stdin = &o, &e, bytes.NewReader(in)
			err := cmd.Run()
			return o.Bytes(), e.Bytes(), err
		}}
		_, err := s.Facts(context.Background(), "00")
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := login("right-pass")
		if err == nil {
			break
		}
		if errors.Is(err, ErrUnreachable) && time.Now().After(deadline) {
			t.Skip("sshd на петле не поднялся")
		}
		if !errors.Is(err, ErrUnreachable) {
			t.Fatalf("верный пароль: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := login(""); !errors.Is(err, ErrPassphrase) {
		t.Errorf("без пароля: %v", err)
	}
	if err := login("wrong-pass"); !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("неверный пароль: %v", err)
	}
}
