// Package acceptance checks the passh binary against the acceptance
// criteria of spec.md §13, as a black box: it builds ./cmd/passh, runs it
// in fully isolated environments (IMPLEMENTATION.md, "Test isolation") and
// looks only at its outputs, its files and its processes. Fixtures are made
// through the binary itself; the vault is read with the age library or the
// stock age CLI, never with passh's own packages.
//
// A test that fails because of a product defect stays in the suite and is
// skipped with t.Skip("BUG: …"), so the suite stays green and the bug is
// tracked.
package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

var (
	repoRoot string // the module root
	testBase string // everything the tests write; short, for socket paths
	binDir   string // holds only the passh binary
	passhBin string // the binary under test
	ageBin   string // the stock age CLI (.tools/bin/age)
	keygenBn string // age-keygen
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	repoRoot = filepath.Clean(filepath.Join(wd, "..", ".."))
	ageBin = filepath.Join(repoRoot, ".tools", "bin", "age")
	keygenBn = filepath.Join(repoRoot, ".tools", "bin", "age-keygen")

	// A short base folder: the agent socket and gpg-agent's sockets live
	// under it, and Unix socket paths are limited to about 104 bytes.
	base, err := os.MkdirTemp("/tmp", "pacc")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	testBase = base
	defer os.RemoveAll(base)

	binDir = filepath.Join(base, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	passhBin = filepath.Join(binDir, "passh")
	build := exec.Command(goTool(), "build", "-o", passhBin, "./cmd/passh")
	build.Dir = repoRoot
	// §10.1: CGO_ENABLED=0, a static binary (G1).
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building passh:", err)
		return 1
	}

	code := m.Run()

	if strays := killStrays(); len(strays) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: passh processes left running after the tests: %v\n", strays)
		code = 1
	}
	return code
}

// goTool is the go command that runs the tests: `go test` puts its own
// GOROOT/bin first in $PATH.
func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "go", "bin", "go")
}

// killStrays kills every live process of the binary under test and returns
// their pids.
func killStrays() []int {
	var pids []int
	for _, p := range passhProcs("") {
		_ = syscall.Kill(p.pid, syscall.SIGKILL)
		pids = append(pids, p.pid)
	}
	return pids
}

// ---------------------------------------------------------------------------
// Output log: every output of every passh run, for the S9 scan (§13.2.10).

var (
	outMu  sync.Mutex
	outLog []string
)

func logOutput(s ...string) {
	outMu.Lock()
	defer outMu.Unlock()
	outLog = append(outLog, s...)
}

func allOutputs() []string {
	outMu.Lock()
	defer outMu.Unlock()
	return append([]string(nil), outLog...)
}

// ---------------------------------------------------------------------------
// Environments.

// env is one isolated world: every variable of IMPLEMENTATION.md points
// into its own folder.
type env struct {
	t       *testing.T
	root    string
	home    string
	cfgHome string
	data    string // $XDG_DATA_HOME
	stateH  string // $XDG_STATE_HOME
	state   string // $XDG_STATE_HOME/passh
	runtime string // $XDG_RUNTIME_DIR
	tmp     string // $TMPDIR
	gnupg   string // $GNUPGHOME
	pstore  string // $PASSWORD_STORE_DIR
	vault   string // default vault path
	config  string // $PASSH_CONFIG
	path    string // $PATH
	extra   []string
}

var envSeq struct {
	sync.Mutex
	n int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	envSeq.Lock()
	envSeq.n++
	n := envSeq.n
	envSeq.Unlock()
	root := filepath.Join(testBase, "e"+strconv.Itoa(n))
	e := &env{
		t:       t,
		root:    root,
		home:    filepath.Join(root, "h"),
		cfgHome: filepath.Join(root, "h", ".config"),
		data:    filepath.Join(root, "h", ".local", "share"),
		stateH:  filepath.Join(root, "s"),
		runtime: filepath.Join(root, "r"),
		tmp:     filepath.Join(root, "t"),
		gnupg:   filepath.Join(root, "g"),
		pstore:  filepath.Join(root, "h", ".password-store"),
		path:    binDir + ":/usr/bin:/bin",
	}
	e.state = filepath.Join(e.stateH, "passh")
	e.vault = filepath.Join(e.data, "passh", "vault.passh")
	e.config = filepath.Join(e.cfgHome, "passh", "config.toml")
	for _, d := range []string{e.home, e.cfgHome, e.data, e.stateH, e.runtime, e.tmp, e.gnupg} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range passhProcs(root) {
			_ = syscall.Kill(p.pid, syscall.SIGKILL)
		}
		_ = os.RemoveAll(root)
	})
	return e
}

func (e *env) vars() []string {
	v := []string{
		"PATH=" + e.path,
		"LANG=C.UTF-8",
		"TERM=xterm-256color",
		"USER=tester",
		"HOME=" + e.home,
		"XDG_CONFIG_HOME=" + e.cfgHome,
		"XDG_DATA_HOME=" + e.data,
		"XDG_STATE_HOME=" + e.stateH,
		"XDG_RUNTIME_DIR=" + e.runtime,
		"TMPDIR=" + e.tmp,
		"PASSH_CONFIG=" + e.config,
		"PASSWORD_STORE_DIR=" + e.pstore,
		"GNUPGHOME=" + e.gnupg,
	}
	return append(v, e.extra...)
}

// with returns a copy of e bound to t (for subtests).
func (e *env) with(t *testing.T) *env {
	c := *e
	c.t = t
	return &c
}

// writeConfig writes the config file naming the default vault, with extra
// TOML appended.
func (e *env) writeConfig(extra string) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.config), 0o700); err != nil {
		e.t.Fatal(err)
	}
	body := fmt.Sprintf("vault = %q\n%s", e.vault, extra)
	if err := os.WriteFile(e.config, []byte(body), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// installVault copies src to the default vault path and writes a config.
func (e *env) installVault(src string, extraConfig string) {
	e.t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(e.vault), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.vault, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
	e.writeConfig(extraConfig)
}

// result is one finished passh run.
type result struct {
	code   int
	stdout string
	stderr string
	term   string // terminal output (pty sessions), CR removed
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\n--- stdout ---\n%s\n--- stderr ---\n%s\n--- terminal ---\n%s", r.code, r.stdout, r.stderr, r.term)
}

// all is everything the run printed.
func (r result) all() string { return r.stdout + r.stderr + r.term }

// run runs passh with no controlling terminal (a new session, stdin from
// /dev/null), as `ssh host passh …` without -t.
func (e *env) run(args ...string) result {
	e.t.Helper()
	return e.runStdin(nil, args...)
}

func (e *env) runStdin(stdin []byte, args ...string) result {
	e.t.Helper()
	return e.runCmd(passhBin, stdin, args...)
}

func (e *env) runCmd(bin string, stdin []byte, args ...string) result {
	e.t.Helper()
	r, err := e.exec(bin, stdin, args...)
	if err != nil {
		e.t.Fatalf("%s %v: %v", bin, args, err)
	}
	return r
}

// exec runs a program without a terminal; safe to call from goroutines.
func (e *env) exec(bin string, stdin []byte, args ...string) (result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = e.vars()
	cmd.Dir = e.root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	logOutput(r.stdout, r.stderr)
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		return r, err
	}
	return r, nil
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

// ---------------------------------------------------------------------------
// Terminal sessions.

// session is a process with a pseudo-terminal as its controlling terminal.
type session struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	ptm  *os.File

	mu  sync.Mutex
	buf bytes.Buffer
	pos int

	readDone chan struct{}
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	waited   bool
	res      result

	rows, cols uint16
	vt         *vt // screen emulator, built on first use
	fed        int // bytes of buf fed to vt
}

type sessOpts struct {
	pipeStdout bool   // stdout to a pipe instead of the terminal
	pipeStderr bool   // stderr to a pipe instead of the terminal
	bin        string // program; default passh
	cols       uint16
	rows       uint16
}

func (e *env) start(o sessOpts, args ...string) *session {
	e.t.Helper()
	ptm, pts, err := pty.Open()
	if err != nil {
		e.t.Fatal(err)
	}
	cols, rows := o.cols, o.rows
	if cols == 0 {
		cols = 220
	}
	if rows == 0 {
		rows = 40
	}
	if err := pty.Setsize(ptm, &pty.Winsize{Rows: rows, Cols: cols}); err != nil {
		e.t.Fatal(err)
	}
	bin := o.bin
	if bin == "" {
		bin = passhBin
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = e.vars()
	cmd.Dir = e.root
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	s := &session{t: e.t, name: filepath.Base(bin) + " " + strings.Join(args, " "), cmd: cmd, ptm: ptm, readDone: make(chan struct{}), rows: rows, cols: cols}
	if o.pipeStdout {
		s.stdout = &bytes.Buffer{}
		cmd.Stdout = s.stdout
	}
	if o.pipeStderr {
		s.stderr = &bytes.Buffer{}
		cmd.Stderr = s.stderr
	}
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
		if !s.waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		ptm.Close()
	})
	return s
}

// raw is the terminal output so far, exactly as written (CR included).
func (s *session) raw() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

func (s *session) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.ReplaceAll(s.buf.String(), "\r", "")
}

// expect waits until the terminal shows want after what was consumed.
func (s *session) expect(want string) {
	s.t.Helper()
	if !s.expectWithin(want, 60*time.Second) {
		s.t.Fatalf("%s: timed out waiting for %q; terminal:\n%s", s.name, want, s.output())
	}
}

// expectWithin is expect with a timeout; false if want didn't appear
// (or the process exited first).
func (s *session) expectWithin(want string, d time.Duration) bool {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for {
		out := s.output()
		if i := strings.Index(out[min(s.pos, len(out)):], want); i >= 0 {
			s.pos += i + len(want)
			return true
		}
		select {
		case <-s.readDone:
			out = s.output()
			if i := strings.Index(out[min(s.pos, len(out)):], want); i >= 0 {
				s.pos += i + len(want)
				return true
			}
			return false
		default:
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond) // polling, with a deadline
	}
}

// expectAny waits for the first of wants to appear and returns it ("" on
// exit or timeout).
func (s *session) expectAny(d time.Duration, wants ...string) string {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for {
		out := s.output()
		rest := out[min(s.pos, len(out)):]
		best, bestAt := "", -1
		for _, w := range wants {
			if i := strings.Index(rest, w); i >= 0 && (bestAt < 0 || i < bestAt) {
				best, bestAt = w, i
			}
		}
		if bestAt >= 0 {
			s.pos += bestAt + len(best)
			return best
		}
		select {
		case <-s.readDone:
			return ""
		default:
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(5 * time.Millisecond) // polling, with a deadline
	}
}

func (s *session) send(text string) {
	s.t.Helper()
	if _, err := s.ptm.Write([]byte(text)); err != nil {
		s.t.Fatal(err)
	}
}

// answer waits for prompt and types a line. At a passphrase or password
// prompt it first waits for the terminal's echo to go off (raw mode), so
// the secret is never echoed; other prompts read in the terminal's normal
// mode, where what is typed early waits in the line buffer.
func (s *session) answer(prompt, text string) {
	s.t.Helper()
	s.expect(prompt)
	if secretPrompt(prompt) {
		s.waitEchoOff()
	}
	s.send(text + "\r")
}

func (s *session) wait() result {
	s.t.Helper()
	if s.waited {
		return s.res
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(90 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
		s.waited = true
		s.t.Fatalf("%s didn't exit; terminal:\n%s", s.name, s.output())
	}
	s.waited = true
	select {
	case <-s.readDone:
	case <-time.After(10 * time.Second):
		// A child (the agent) may hold the terminal open; that is fine.
	}
	r := result{term: s.output()}
	if s.stdout != nil {
		r.stdout = s.stdout.String()
	}
	if s.stderr != nil {
		r.stderr = s.stderr.String()
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	case err != nil:
		s.t.Fatalf("%s: %v", s.name, err)
	}
	logOutput(r.stdout, r.stderr, r.term)
	s.res = r
	return r
}

func (s *session) waitOK() result {
	s.t.Helper()
	r := s.wait()
	if r.code != 0 {
		s.t.Fatalf("%s: want success, got %s", s.name, r)
	}
	return r
}

// ---------------------------------------------------------------------------
// Common flows.

var agentPIDRe = regexp.MustCompile(`agent \(pid (\d+)\)`)

// unlock runs `passh unlock` on a terminal and returns the agent's pid.
func (e *env) unlock(pass string, args ...string) int {
	e.t.Helper()
	s := e.start(sessOpts{}, append([]string{"unlock"}, args...)...)
	s.answer("Passphrase:", pass)
	r := s.waitOK()
	m := agentPIDRe.FindStringSubmatch(r.all())
	if m == nil {
		e.t.Fatalf("unlock: no agent pid in the output: %s", r)
	}
	pid, _ := strconv.Atoi(m[1])
	return pid
}

// initVault runs `passh init` on a terminal with pass, declining the offer
// to print the recovery key (§5.4).
func (e *env) initVault(pass string, args ...string) result {
	e.t.Helper()
	s := e.start(sessOpts{}, append([]string{"init"}, args...)...)
	s.answer("New passphrase:", pass)
	s.answer("Repeat passphrase:", pass)
	if s.expectWithin("recovery key now?", 30*time.Second) {
		s.send("n\r") // a line prompt: typing early is fine
	}
	return s.wait()
}

// lock runs `passh lock`.
func (e *env) lock() {
	e.t.Helper()
	e.ok("lock")
}

// addEntry runs `passh add` on a terminal (the agent, if running, gives the
// key; else pass is typed). notes may hold several lines.
type newEntry struct {
	path, password, username, url, tags, notes string
}

func (e *env) add(pass string, ne newEntry, extraArgs ...string) result {
	e.t.Helper()
	s := e.start(sessOpts{}, append([]string{"add", ne.path}, extraArgs...)...)
	e.typeEntry(s, pass, ne)
	return s.waitOK()
}

func (e *env) typeEntry(s *session, pass string, ne newEntry) {
	e.t.Helper()
	if pass != "" {
		s.answer("Passphrase:", pass)
	}
	s.answer("Password (empty to generate):", ne.password)
	if ne.password != "" {
		s.answer("Repeat password:", ne.password)
	}
	s.answer("Username:", ne.username)
	s.answer("URL:", ne.url)
	s.answer("Tags (comma-separated):", ne.tags)
	s.expect("Notes (end with an empty line):") // line prompts from here on
	if ne.notes != "" {
		for _, l := range strings.Split(ne.notes, "\n") {
			s.send(l + "\r")
		}
	}
	s.send("\r")
}

// ---------------------------------------------------------------------------
// Processes.

type procInfo struct {
	pid     int
	cmdline []byte
	environ []byte
}

// passhProcs lists live processes of the binary under test whose
// environment mentions root (all of them if root is empty).
func passhProcs(root string) []procInfo {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procInfo
	for _, de := range ents {
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || !strings.HasPrefix(exe, passhBin) {
			continue
		}
		st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if i := bytes.LastIndexByte(st, ')'); i >= 0 && len(st) > i+2 && st[i+2] == 'Z' {
			continue // zombie
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		environ, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if root != "" && !bytes.Contains(environ, []byte(root)) && !bytes.Contains(cmdline, []byte(root)) {
			continue
		}
		out = append(out, procInfo{pid: pid, cmdline: cmdline, environ: environ})
	}
	return out
}

// agentProcs are the live agents of an environment.
func agentProcs(root string) []procInfo {
	var out []procInfo
	for _, p := range passhProcs(root) {
		if bytes.Contains(p.cmdline, []byte("__agent")) {
			out = append(out, p)
		}
	}
	return out
}

// alive reports whether pid is a live, non-zombie process.
func alive(pid int) bool {
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := bytes.LastIndexByte(st, ')')
	return !(i >= 0 && len(st) > i+2 && st[i+2] == 'Z')
}

// waitGone waits up to d for pid to exit.
func waitGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond) // polling, with a deadline
	}
	return !alive(pid)
}

// ---------------------------------------------------------------------------
// Small helpers.

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	writeFile(t, dst, readFile(t, src), 0o600)
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

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// walkFiles lists every regular file under root with its content.
func walkFiles(root string) map[string][]byte {
	out := map[string][]byte{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip what can't be read; the walk goes on
		}
		if info.Mode().IsRegular() {
			if b, err := os.ReadFile(p); err == nil {
				out[p] = b
			}
		}
		return nil
	})
	return out
}

// readAllLimited reads r fully (helper for io).
func readAllLimited(r io.Reader) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, 64<<20))
	return b
}
