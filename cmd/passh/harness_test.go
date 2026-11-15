package main

// Black-box test harness: the tests build the passh binary once and run it
// in an isolated environment (IMPLEMENTATION.md: every location passh may
// touch points into a temporary folder), with no terminal at all, or with a
// pseudo-terminal as the controlling terminal so /dev/tty prompts work.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/creack/pty"

	"passh/internal/keys"
	"passh/internal/model"
	"passh/internal/vault"
	"passh/internal/vaultfile"
)

// fixturePass is the passphrase of the fixture vault.
const fixturePass = "plum orbit candle meadow quartz lantern"

// lockedMsg is the message of §5.1 step 3.
const lockedMsg = "vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)"

var (
	// passhBin is the binary under test.
	passhBin string
	// testBase holds everything the tests write. It is short, because the
	// agent's socket path and gpg-agent's sockets live under it.
	testBase string
	// fixtureFile is an empty vault made once with fixturePass (scrypt is
	// slow on purpose); tests copy it. fixtureKey is its vault key, used to
	// prepare entries without another scrypt run.
	fixtureFile string
	fixtureKey  *age.X25519Identity
)

func TestMain(m *testing.M) {
	// The test binary doubles as helper programs passh runs: a fake
	// clipboard command and a fake $EDITOR (helpers_test.go).
	if h := os.Getenv(helperEnv); h != "" {
		os.Exit(runHelper(h))
	}
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	tmp := os.TempDir()
	if len(tmp) > 20 {
		tmp = "/tmp"
	}
	base, err := os.MkdirTemp(tmp, "pcli")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	testBase = base
	defer os.RemoveAll(base)

	passhBin = filepath.Join(base, "passh")
	build := exec.Command(goTool(), "build", "-o", passhBin, "passh/cmd/passh")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building passh:", err)
		return 1
	}

	fixtureFile = filepath.Join(base, "fixture.passh")
	v, err := vault.Create(fixtureFile, []byte(fixturePass), vault.Options{StateDir: filepath.Join(base, "fixture-state")})
	if err != nil {
		fmt.Fprintln(os.Stderr, "making the fixture vault:", err)
		return 1
	}
	fixtureKey = v.Key()
	v.Close()

	code := m.Run()
	// No agent may outlive the tests.
	if pids := agentPIDs(base); len(pids) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: agents left running: %v\n", pids)
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		code = 1
	}
	return code
}

func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

// agentPIDs lists live agent processes whose command line mentions dir.
func agentPIDs(dir string) []int {
	if runtime.GOOS != "linux" {
		return nil
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(cmdline) == 0 {
			continue // gone, or a zombie
		}
		if bytes.Contains(cmdline, []byte("__agent")) && bytes.Contains(cmdline, []byte(dir)) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// env is one test's isolated world.
type env struct {
	t      *testing.T
	root   string
	home   string
	state  string // $XDG_STATE_HOME/passh
	vault  string // the default vault path
	config string // $PASSH_CONFIG
	vars   []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root, err := os.MkdirTemp(testBase, "e")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root}
	vars := []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C.UTF-8",
		"TERM=xterm",
		"USER=tester",
		"GORACE=atexit_sleep_ms=0",
	}
	for k, sub := range map[string]string{
		"HOME":               "h",
		"XDG_CONFIG_HOME":    "h/.config",
		"XDG_DATA_HOME":      "h/.local/share",
		"XDG_STATE_HOME":     "s",
		"XDG_RUNTIME_DIR":    "r",
		"TMPDIR":             "t",
		"PASSWORD_STORE_DIR": "h/.password-store",
		"GNUPGHOME":          "g",
	} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		vars = append(vars, k+"="+dir)
	}
	e.home = filepath.Join(root, "h")
	e.state = filepath.Join(root, "s", "passh")
	e.config = filepath.Join(root, "h", ".config", "passh", "config.toml")
	e.vault = filepath.Join(root, "h", ".local", "share", "passh", "vault.passh")
	e.vars = append(vars, "PASSH_CONFIG="+e.config)
	t.Cleanup(func() {
		for _, pid := range agentPIDs(root) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		os.RemoveAll(root)
	})
	return e
}

// setenv sets an environment variable for the passh runs of this env.
func (e *env) setenv(k, v string) {
	for i, kv := range e.vars {
		if strings.HasPrefix(kv, k+"=") {
			e.vars[i] = k + "=" + v
			return
		}
	}
	e.vars = append(e.vars, k+"="+v)
}

// writeConfig writes the config file: the vault, then extra TOML.
func (e *env) writeConfig(extra string) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.config), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.config, []byte(fmt.Sprintf("vault = %q\n%s", e.vault, extra)), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// withVault installs a copy of the fixture vault and a config file naming it.
func (e *env) withVault() {
	e.t.Helper()
	data, err := os.ReadFile(fixtureFile)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, d := range []string{filepath.Dir(e.vault), filepath.Dir(e.config)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			e.t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.vault, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.config, []byte(fmt.Sprintf("vault = %q\n", e.vault)), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// addEntries stores entries in the vault through the library, with the
// fixture's key (no scrypt).
func (e *env) addEntries(entries ...model.Entry) {
	e.t.Helper()
	v, err := vault.Open(context.Background(), e.vault, keys.FromIdentity(fixtureKey), vault.Options{StateDir: e.state, BackupKeep: 10})
	if err != nil {
		e.t.Fatal(err)
	}
	defer v.Close()
	for _, en := range entries {
		if _, err := v.Add(en, false); err != nil {
			e.t.Fatal(err)
		}
	}
}

// result is a finished passh run.
type result struct {
	code   int
	stdout string
	stderr string
	out    string // everything written to the terminal (sessions only), \r removed
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\n--- stdout ---\n%s\n--- stderr ---\n%s\n--- terminal ---\n%s", r.code, r.stdout, r.stderr, r.out)
}

// run runs passh without a controlling terminal (a new session, stdin from
// /dev/null), as `ssh host passh …` without -t does.
func (e *env) run(args ...string) result {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, passhBin, args...)
	cmd.Env = e.vars
	cmd.Dir = e.root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		e.t.Fatalf("passh %v: %v", args, err)
	}
	return r
}

// ok runs passh without a terminal and requires success.
func (e *env) ok(args ...string) result {
	e.t.Helper()
	r := e.run(args...)
	if r.code != 0 {
		e.t.Fatalf("passh %s: want success, got %s", strings.Join(args, " "), r)
	}
	return r
}

// fail runs passh without a terminal and requires exit status code.
func (e *env) fail(code int, args ...string) result {
	e.t.Helper()
	r := e.run(args...)
	if r.code != code {
		e.t.Fatalf("passh %s: want exit %d, got %s", strings.Join(args, " "), code, r)
	}
	return r
}

// session is passh running with a pseudo-terminal as its controlling
// terminal (stdin and stderr on it; stdout on it too unless piped).
type session struct {
	t    *testing.T
	args []string
	cmd  *exec.Cmd
	ptm  *os.File

	mu  sync.Mutex
	buf bytes.Buffer
	pos int // what expect has consumed

	readDone chan struct{}
	stdout   *bytes.Buffer // when piped
}

type sessOpts struct {
	pipeStdout bool // stdout is a pipe, not the terminal
}

func (e *env) start(o sessOpts, args ...string) *session {
	e.t.Helper()
	ptm, pts, err := pty.Open()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := pty.Setsize(ptm, &pty.Winsize{Rows: 24, Cols: 200}); err != nil {
		e.t.Fatal(err)
	}
	cmd := exec.Command(passhBin, args...)
	cmd.Env = e.vars
	cmd.Dir = e.root
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	s := &session{t: e.t, args: args, cmd: cmd, ptm: ptm, readDone: make(chan struct{})}
	if o.pipeStdout {
		s.stdout = &bytes.Buffer{}
		cmd.Stdout = s.stdout
	}
	// A new session with the pty as controlling terminal: /dev/tty works.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	pts.Close()
	go func() {
		defer close(s.readDone)
		b := make([]byte, 4096)
		for {
			n, err := ptm.Read(b)
			if n > 0 {
				s.mu.Lock()
				s.buf.Write(b[:n])
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	e.t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		ptm.Close()
	})
	return s
}

// output is the terminal output so far, without carriage returns.
func (s *session) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.ReplaceAll(s.buf.String(), "\r", "")
}

// expect waits until the terminal shows want after what was consumed.
func (s *session) expect(want string) {
	s.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		out := s.output()
		if i := strings.Index(out[min(s.pos, len(out)):], want); i >= 0 {
			s.pos += i + len(want)
			return
		}
		select {
		case <-s.readDone:
			s.t.Fatalf("passh %v exited before showing %q; terminal:\n%s", s.args, want, out)
		default:
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("passh %v: timed out waiting for %q; terminal:\n%s", s.args, want, out)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// send types text on the terminal.
func (s *session) send(text string) {
	s.t.Helper()
	if _, err := s.ptm.Write([]byte(text)); err != nil {
		s.t.Fatal(err)
	}
}

// answer waits for a prompt and types a line.
func (s *session) answer(prompt, text string) {
	s.t.Helper()
	s.expect(prompt)
	s.send(text + "\r")
}

// wait waits for passh to exit.
func (s *session) wait() result {
	s.t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		_ = s.cmd.Process.Kill()
		s.t.Fatalf("passh %v didn't exit; terminal:\n%s", s.args, s.output())
	}
	select {
	case <-s.readDone:
	case <-time.After(10 * time.Second):
		s.t.Fatalf("passh %v: the terminal didn't close", s.args)
	}
	r := result{out: s.output()}
	if s.stdout != nil {
		r.stdout = s.stdout.String()
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		s.t.Fatalf("passh %v: %v", s.args, err)
	}
	return r
}

// waitOK waits for passh to exit with success.
func (s *session) waitOK() result {
	s.t.Helper()
	r := s.wait()
	if r.code != 0 {
		s.t.Fatalf("passh %s: want success, got %s", strings.Join(s.args, " "), r)
	}
	return r
}

// unlock runs `passh unlock` on a terminal with pass.
func (e *env) unlock(pass string, args ...string) result {
	e.t.Helper()
	s := e.start(sessOpts{}, append([]string{"unlock"}, args...)...)
	s.answer("Passphrase:", pass)
	r := s.waitOK()
	if !strings.Contains(r.out, "Unlocked") {
		e.t.Fatalf("unlock: %s", r)
	}
	return r
}

// paperKey is the vault's paper recovery key, as the sheet prints it.
func paperKey(t *testing.T, file, pass string) string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.UnwrapKey(f.KeyBlock, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	return keys.FormatRecoveryKey(id)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func mustContain(t *testing.T, what, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s: missing %q in:\n%s", what, w, got)
		}
	}
}

func mustNotContain(t *testing.T, what, got string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(got, b) {
			t.Errorf("%s: unexpected %q in:\n%s", what, b, got)
		}
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}
