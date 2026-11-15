package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestStartDetachedAgent is safety test 6 against a real agent process:
// started from the test binary, detached, handed the key on stdin.
func TestStartDetachedAgent(t *testing.T) {
	e := isolate(t)
	ctx := context.Background()
	st := startAgent(t, e, Options{IdleTTL: time.Minute, MaxTTL: 2 * time.Minute})
	real, _ := realPath(e.vault)
	if st.Vault != real || st.Socket != e.socket(t) || st.PID == os.Getpid() {
		t.Errorf("status = %+v", st)
	}
	if st.IdleLeft <= 50*time.Second || st.MaxLeft <= 110*time.Second {
		t.Errorf("time left: idle %s, max %s", st.IdleLeft, st.MaxLeft)
	}

	// S2: the key is in neither the arguments nor the environment of the
	// agent. The arguments are what Start documents.
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", st.PID))
	if err != nil {
		t.Fatal(err)
	}
	environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", st.PID))
	if err != nil {
		t.Fatal(err)
	}
	if len(environ) == 0 || !bytes.Contains(environ, []byte("XDG_STATE_HOME=")) {
		t.Fatalf("couldn't read the agent's environment: %q", environ)
	}
	secret := e.key.String()
	body := secret[len(keyPrefix):]
	for name, b := range map[string][]byte{"cmdline": cmdline, "environ": environ} {
		for _, s := range []string{secret, body, strings.ToLower(body), body[:20]} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("the key appears in /proc/%d/%s", st.PID, name)
			}
		}
	}
	args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")[1:]
	want := []string{ChildCommand, "--vault=" + real, "--idle-ttl=1m0s", "--max-ttl=2m0s"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Errorf("agent arguments %q, want %q", args, want)
	}

	// Detached: its own session, so the end of ours doesn't reach it.
	sid, err := unix.Getsid(st.PID)
	if err != nil || sid != st.PID {
		t.Errorf("agent session = %d, %v; want its own (%d)", sid, err, st.PID)
	}
	if mySid, _ := unix.Getsid(0); sid == mySid {
		t.Error("agent shares the test's session")
	}
	// S7: no core dumps.
	limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", st.PID))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(limits), "\n") {
		if rest, ok := strings.CutPrefix(line, "Max core file size"); ok {
			if f := strings.Fields(rest); len(f) < 2 || f[0] != "0" || f[1] != "0" {
				t.Errorf("core dumps not disabled: %q", line)
			}
		}
	}

	// Folder 0700, socket 0600.
	fi, err := os.Lstat(filepath.Dir(st.Socket))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("agent folder: %v, %v", fi, err)
	}
	fi, err = os.Lstat(st.Socket)
	if err != nil || fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket: %v, %v", fi, err)
	}

	c := e.client(t)
	id, err := c.KeyFor(ctx, e.keyBlock)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != secret {
		t.Error("the agent returned another key")
	}
	// The key block's digest reached the agent through stdin: it serves
	// the key for that key block only.
	ks := KeySource{Vault: e.vault}
	if id, err := ks.VaultKey(ctx, e.keyBlock); err != nil || id.String() != secret {
		t.Fatalf("KeySource with the unlocked key block: %v", err)
	}
	if _, err := ks.VaultKey(ctx, append([]byte("x"), e.keyBlock...)); !errors.Is(err, ErrKeyBlockChanged) || !errors.Is(err, ErrNoAgent) {
		t.Fatalf("KeySource with another key block: %v", err)
	}

	// A second start reports the running agent and its time left.
	_, err = Start(ctx, e.vault, e.key, Options{KeyBlock: e.keyBlock, IdleTTL: time.Minute, MaxTTL: time.Minute})
	var running *AlreadyRunningError
	if !errors.As(err, &running) || !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start: %v, want AlreadyRunningError", err)
	}
	if running.Status.PID != st.PID || running.Status.Left() <= 0 || running.Status.MaxLeft > 2*time.Minute {
		t.Errorf("second Start status = %+v", running.Status)
	}
	if !strings.Contains(err.Error(), "already running") || !strings.Contains(err.Error(), "at the latest") {
		t.Errorf("message %q", err)
	}
	if pids := agentPIDs(t, real); len(pids) != 1 {
		t.Errorf("agents running: %v", pids)
	}

	// SIGHUP (the SSH session ending) doesn't stop it: once the signal has
	// been delivered (it is no longer pending), the agent still runs.
	if err := syscall.Kill(st.PID, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, st.PID, syscall.SIGHUP)
	if !agentProcess(st.PID, real) {
		t.Fatal("agent died on SIGHUP")
	}
	if _, err := c.KeyFor(ctx, e.keyBlock); err != nil {
		t.Errorf("KeyFor after SIGHUP: %v", err)
	}

	// `passh lock`.
	stopped, err := c.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.PID != st.PID {
		t.Errorf("Stop status pid %d, want %d", stopped.PID, st.PID)
	}
	waitExited(t, e, st.PID, 5*time.Second)
}

// TestDetachedAgentExits: the agent process exits at each exit condition.
func TestDetachedAgentExits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  Options
		byTTL bool // exits at a TTL, not before
		do    func(t *testing.T, e *env, st Status)
	}{
		{"idle TTL", Options{IdleTTL: 300 * time.Millisecond, MaxTTL: time.Minute}, true, nil},
		{"max TTL", Options{IdleTTL: time.Minute, MaxTTL: 400 * time.Millisecond}, true, func(t *testing.T, e *env, st Status) {
			// Use doesn't extend the max TTL.
			c := e.client(t)
			for {
				if _, err := c.KeyFor(context.Background(), e.keyBlock); err != nil {
					if !errors.Is(err, ErrNoAgent) {
						t.Errorf("KeyFor: %v", err)
					}
					return
				}
				time.Sleep(20 * time.Millisecond) // time passing under test: the max TTL of a real agent
			}
		}},
		{"SIGTERM", Options{IdleTTL: time.Minute, MaxTTL: time.Minute}, false, func(t *testing.T, e *env, st Status) {
			if err := syscall.Kill(st.PID, syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
		}},
		{"SIGINT", Options{IdleTTL: time.Minute, MaxTTL: time.Minute}, false, func(t *testing.T, e *env, st Status) {
			if err := syscall.Kill(st.PID, syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
		}},
		{"socket removed", Options{IdleTTL: time.Minute, MaxTTL: time.Minute}, false, func(t *testing.T, e *env, st Status) {
			if err := os.Remove(st.Socket); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := isolate(t)
			start := time.Now()
			st := startAgent(t, e, tc.opts)
			if tc.do != nil {
				tc.do(t, e, st)
			}
			// The socket watch runs every second in a real agent.
			waitExited(t, e, st.PID, 5*time.Second)
			ttl := min(tc.opts.IdleTTL, tc.opts.MaxTTL)
			if d := time.Since(start); tc.byTTL && d < ttl {
				t.Errorf("exited after %s, before its TTL", d)
			} else if !tc.byTTL && d > 10*time.Second {
				t.Errorf("exited only after %s", d)
			}
		})
	}
}

// TestStartRemovesStaleSocket: a crashed agent's socket doesn't block a new
// one.
func TestStartRemovesStaleSocket(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	sock, err := ensureSocketPath(real)
	if err != nil {
		t.Fatal(err)
	}
	makeStaleSocket(t, sock)
	st := startAgent(t, e, Options{IdleTTL: time.Minute, MaxTTL: time.Minute})
	if st.Socket != sock {
		t.Errorf("socket %s, want %s", st.Socket, sock)
	}
	if _, err := e.client(t).KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Errorf("KeyFor: %v", err)
	}
	if _, err := e.client(t).Stop(context.Background()); err != nil {
		t.Error(err)
	}
	waitExited(t, e, st.PID, 5*time.Second)
}

// TestStartFailures: errors before and inside the child reach the caller,
// and no agent is left running.
func TestStartFailures(t *testing.T) {
	needProc(t)
	ctx := context.Background()
	e := isolate(t)
	opts := Options{KeyBlock: e.keyBlock, IdleTTL: time.Minute, MaxTTL: time.Minute}
	for name, f := range map[string]func() error{
		"no key": func() error { _, err := Start(ctx, e.vault, nil, opts); return err },
		"no key block": func() error {
			_, err := Start(ctx, e.vault, e.key, Options{IdleTTL: time.Minute, MaxTTL: time.Minute})
			if err != nil && !strings.Contains(err.Error(), "no key block") {
				t.Errorf("no key block: %v", err)
			}
			return err
		},
		"zero idle": func() error {
			_, err := Start(ctx, e.vault, e.key, Options{KeyBlock: e.keyBlock, MaxTTL: time.Minute})
			return err
		},
		"zero max": func() error {
			_, err := Start(ctx, e.vault, e.key, Options{KeyBlock: e.keyBlock, IdleTTL: time.Minute})
			return err
		},
		"no vault": func() error {
			_, err := Start(ctx, filepath.Join(e.root, "missing"), e.key, opts)
			return err
		},
	} {
		if err := f(); err == nil {
			t.Errorf("%s: Start succeeded", name)
		}
	}

	// A refused agent folder: refused before anything is started.
	dir := filepath.Join(e.root, "s", "passh", "agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(ctx, e.vault, e.key, opts); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("Start with a 0755 folder: %v", err)
	}

	// The child can't create the agent folder: its error comes back.
	e = isolate(t)
	opts.KeyBlock = e.keyBlock
	state := filepath.Join(e.root, "s")
	if err := os.Chmod(state, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(state, 0o700)
	_, err := Start(ctx, e.vault, e.key, opts)
	if err == nil || !strings.Contains(err.Error(), "creating the state folder") {
		t.Errorf("Start with a read-only state folder: %v", err)
	}
	real, _ := realPath(e.vault)
	if pids := agentPIDs(t, real); len(pids) != 0 {
		t.Errorf("agents left running: %v", pids)
	}
}

// TestOnlyStartStartsAgent: the client and the KeySource never start an
// agent, whatever they are asked.
func TestOnlyStartStartsAgent(t *testing.T) {
	needProc(t)
	e := isolate(t)
	ctx := context.Background()
	c := e.client(t)
	ks := KeySource{Vault: e.vault}
	for i := 0; i < 3; i++ {
		if _, err := ks.VaultKey(ctx, nil); !errors.Is(err, ErrNoAgent) {
			t.Errorf("KeySource: %v", err)
		}
		if _, err := c.KeyFor(ctx, e.keyBlock); !errors.Is(err, ErrNoAgent) {
			t.Errorf("KeyFor: %v", err)
		}
		if _, err := c.Status(ctx); !errors.Is(err, ErrNoAgent) {
			t.Errorf("Status: %v", err)
		}
		if _, err := c.Stop(ctx); !errors.Is(err, ErrNoAgent) {
			t.Errorf("Stop: %v", err)
		}
	}
	// No wait needed: every call above has returned, and a process started
	// by one of them would exist by now (Start itself waits for the agent).
	real, _ := realPath(e.vault)
	if pids := agentPIDs(t, real); len(pids) != 0 {
		t.Errorf("agent processes appeared: %v", pids)
	}
	if exists(filepath.Join(e.root, "s", "passh")) {
		t.Error("the client created the state folder")
	}
	if children := childProcesses(t, e.root); len(children) != 0 {
		t.Errorf("the client started processes: %v", children)
	}
}

// childProcesses lists the live child processes of the test process that
// mention the agent's subcommand or root (a vault path inside it).
func childProcesses(t *testing.T, root string) []string {
	t.Helper()
	files, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil || len(files) == 0 {
		t.Skipf("can't list child processes: %v", err)
	}
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, pid := range strings.Fields(string(b)) {
			cmd, err := os.ReadFile("/proc/" + pid + "/cmdline")
			if err == nil && (bytes.Contains(cmd, []byte(ChildCommand)) || bytes.Contains(cmd, []byte(root))) {
				out = append(out, pid+": "+strings.ReplaceAll(string(cmd), "\x00", " "))
			}
		}
	}
	return out
}

// TestChildMainByHand: `passh __agent` run without Start's readiness pipe
// refuses to run.
func TestChildMainByHand(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	cmd := osexec.Command(os.Args[0], ChildCommand, "--vault="+real, "--idle-ttl=1m", "--max-ttl=1m")
	cmd.Stdin = strings.NewReader(e.key.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *osexec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Errorf("exit = %v, want status 2", err)
	}
	if !strings.Contains(stderr.String(), "passh unlock") {
		t.Errorf("stderr %q", stderr.String())
	}
	if exists(e.socket(t)) {
		t.Error("an agent was started")
	}
}

// TestRunChild runs the agent's main function inside the test process (so
// coverage sees it), with the signals sent to the test process itself.
func TestRunChild(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	defer unix.Umask(unix.Umask(0o022))

	run := func(args []string, key string) (ready string, done <-chan int) {
		t.Helper()
		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readyR, readyW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan int, 1)
		go func() { ch <- runChild(args, inR, readyW) }()
		_, _ = io.WriteString(inW, key)
		inW.Close()
		_ = readyR.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(readyR)
		readyR.Close()
		return string(b), ch
	}
	args := []string{"--vault=" + e.vault, "--idle-ttl=1m", "--max-ttl=1m"}

	for _, tc := range []struct {
		name string
		args []string
		key  string
		want string
	}{
		{"bad flag", []string{"--nope"}, e.key.String(), "error: agent: flag provided but not defined"},
		{"extra argument", append(args[:3:3], "x"), e.key.String(), `unexpected argument "x"`},
		{"relative vault", []string{"--vault=v", "--idle-ttl=1m", "--max-ttl=1m"}, e.key.String(), "absolute path"},
		{"no TTL", []string{"--vault=" + e.vault}, e.key.String(), "must be positive"},
		{"missing vault", []string{"--vault=" + e.root + "/missing", "--idle-ttl=1m", "--max-ttl=1m"}, e.key.String(), "resolving the vault path"},
		{"no key", args, "", "the key on stdin"},
		{"bad key", args, "AGE-SECRET-KEY-1QQQ", "the key on stdin"},
		{"no digest", args, e.key.String(), "digest is missing"},
		{"long key", args, strings.Repeat("A", 600), "too long"},
	} {
		ready, done := run(tc.args, tc.key)
		if !strings.HasPrefix(ready, readyError) || !strings.Contains(ready, tc.want) {
			t.Errorf("%s: ready = %q, want an error with %q", tc.name, ready, tc.want)
		}
		if code := <-done; code != 1 {
			t.Errorf("%s: exit %d", tc.name, code)
		}
	}

	for name, in := range map[string]string{
		"bad digest":  e.key.String() + "\nnot-a-digest\n",
		"extra lines": e.key.String() + "\n" + keyBlockSum(e.keyBlock) + "\nmore\n",
	} {
		ready, done := run(args, in)
		if !strings.HasPrefix(ready, readyError) || <-done != 1 {
			t.Errorf("%s: ready = %q", name, ready)
		}
	}

	ready, done := run(args, "\n "+e.key.String()+"\n"+keyBlockSum(e.keyBlock)+"\n")
	if ready != readyOK+"\n" {
		t.Fatalf("ready = %q", ready)
	}
	c := e.client(t)
	if id, err := c.KeyFor(context.Background(), e.keyBlock); err != nil || id.String() != e.key.String() {
		t.Fatalf("KeyFor: %v", err)
	}
	if _, err := c.KeyFor(context.Background(), []byte("another key block")); !errors.Is(err, ErrKeyBlockChanged) {
		t.Fatalf("KeyFor another key block: %v", err)
	}
	if st, err := c.Status(context.Background()); err != nil || st.Vault != real || st.PID != os.Getpid() {
		t.Errorf("Status = %+v, %v", st, err)
	}

	// A second agent for the same vault reports "running".
	ready2, done2 := run(args, e.key.String()+"\n"+keyBlockSum(e.keyBlock))
	if ready2 != readyRunning+"\n" || <-done2 != 1 {
		t.Errorf("second agent: ready = %q", ready2)
	}

	// SIGHUP is ignored; SIGTERM stops the agent.
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, os.Getpid(), syscall.SIGHUP)
	if _, err := c.KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Fatalf("KeyFor after SIGHUP: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent still running after SIGTERM")
	}
	if exists(e.socket(t)) {
		t.Error("socket left behind")
	}
}

func TestReadInput(t *testing.T) {
	e := isolate(t)
	good := e.key.String()
	sum := keyBlockSum(e.keyBlock)
	got, gotSum, err := readInput(strings.NewReader(" \n" + good + "\r\n" + sum + "\n"))
	if err != nil || string(got) != good || gotSum != sum {
		t.Errorf("readInput = %q, %q, %v", got, gotSum, err)
	}
	if _, _, err := readInput(strings.NewReader(good + "\n" + strings.ToUpper(sum))); err == nil {
		t.Error("an upper-case digest was accepted")
	}
	if _, _, err := readInput(strings.NewReader(good + "\n")); err == nil || !strings.Contains(err.Error(), "digest is missing") {
		t.Errorf("no digest: %v", err)
	}
	boom := errors.New("boom")
	if _, _, err := readInput(io.MultiReader(strings.NewReader("AGE"), errReader{boom})); !errors.Is(err, boom) {
		t.Errorf("read error: %v", err)
	}
	for _, bad := range []string{"", good[:30], strings.ToLower(good), good + " " + good, strings.Repeat("A", 512)} {
		if _, _, err := readInput(strings.NewReader(bad + "\n" + sum)); err == nil {
			t.Errorf("readInput(%.20q…) accepted", bad)
		}
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseChildArgs(t *testing.T) {
	e := isolate(t)
	link := filepath.Join(e.root, "link")
	if err := os.Symlink(e.vault, link); err != nil {
		t.Fatal(err)
	}
	real, opts, err := parseChildArgs([]string{"--vault=" + link, "--idle-ttl=15m", "--max-ttl=2h"})
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := realPath(e.vault); real != want || opts.IdleTTL != 15*time.Minute || opts.MaxTTL != 2*time.Hour {
		t.Errorf("parseChildArgs = %q, %+v", real, opts)
	}
	// Start's arguments parse back to the same values.
	in := Options{IdleTTL: 1500 * time.Millisecond, MaxTTL: 90 * time.Minute}
	if got, opts, err := parseChildArgs(childArgs(real, in)[1:]); err != nil || got != real || opts.IdleTTL != in.IdleTTL || opts.MaxTTL != in.MaxTTL {
		t.Errorf("round trip = %q, %+v, %v", got, opts, err)
	}
	if _, _, err := parseChildArgs([]string{"--vault=" + real, "--idle-ttl=-1s", "--max-ttl=1m"}); err == nil {
		t.Error("negative TTL accepted")
	}
}

func TestWaitReady(t *testing.T) {
	pipe := func(t *testing.T, write string, closeW bool) *os.File {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(); w.Close() })
		_, _ = io.WriteString(w, write)
		if closeW {
			w.Close()
		}
		return r
	}
	ctx := context.Background()
	if line, err := waitReady(ctx, pipe(t, "ok\n", false)); err != nil || line != readyOK {
		t.Errorf("ok: %q, %v", line, err)
	}
	for _, tc := range []struct {
		write string
		want  string
	}{
		{"", "exited before it was ready"},
		{"o", "exited before it was ready"},
	} {
		if _, err := waitReady(ctx, pipe(t, tc.write, true)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.write, err, tc.want)
		}
	}

	old := startTimeout
	startTimeout = 50 * time.Millisecond
	defer func() { startTimeout = old }()
	if _, err := waitReady(ctx, pipe(t, "", false)); err == nil || !strings.Contains(err.Error(), "didn't report ready within") {
		t.Errorf("timeout: %v", err)
	}
	startTimeout = 10 * time.Second
	cctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(30*time.Millisecond, cancel)
	if _, err := waitReady(cctx, pipe(t, "", false)); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
	dctx, cancel2 := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel2()
	if _, err := waitReady(dctx, pipe(t, "", false)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ctx deadline: %v", err)
	}
	if _, err := waitReady(ctx, pipe(t, strings.Repeat("x", 2000), false)); err == nil {
		t.Error("an endless line accepted")
	}
}
