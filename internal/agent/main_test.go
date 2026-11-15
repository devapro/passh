package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
)

// The test binary doubles as the agent: Start re-executes exec.Self() (this
// binary) with ChildCommand, and TestMain hands such a run to ChildMain, as
// passh's hidden subcommand does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildCommand {
		os.Exit(ChildMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// env is one test's isolated world.
type env struct {
	root     string
	vault    string // a vault file (its contents don't matter to the agent)
	key      *age.X25519Identity
	keyBlock []byte // the key block the key was "unlocked" from
}

// isolate points every location passh may touch at a temporary folder
// (IMPLEMENTATION.md) and creates a vault file there.
func isolate(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for envVar, sub := range map[string]string{
		"HOME":               "h",
		"XDG_CONFIG_HOME":    "h/.config",
		"XDG_DATA_HOME":      "h/.local/share",
		"XDG_STATE_HOME":     "s",
		"XDG_RUNTIME_DIR":    "r",
		"TMPDIR":             "t",
		"PASSWORD_STORE_DIR": "h/.password-store",
		"GNUPGHOME":          "h/.gnupg",
	} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envVar, dir)
	}
	t.Setenv("PASSH_CONFIG", filepath.Join(root, "h", "config.toml"))
	// A race-enabled agent would otherwise sleep 1 s before exiting.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	vault := filepath.Join(root, "vault.passh")
	if err := os.WriteFile(vault, []byte("not opened by the agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{root: root, vault: vault, key: key, keyBlock: []byte("key block of " + root)}
	// Never the real /tmp or state folder.
	if sock := e.socket(t); !strings.HasPrefix(sock, root+"/") {
		t.Fatalf("socket %s is outside the test folder %s", sock, root)
	}
	return e
}

func (e *env) socket(t *testing.T) string {
	t.Helper()
	p, err := SocketPath(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) keyText() []byte { return []byte(e.key.String()) }

// waitFor polls cond every few milliseconds until it holds or timeout
// passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// agentProcess reports whether pid is a live (not zombie) agent process
// serving vault, by its /proc entries.
func agentProcess(pid int, vault string) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(cmdline) == 0 {
		return false // gone, or a zombie (empty cmdline)
	}
	return bytes.Contains(cmdline, []byte(ChildCommand)) && bytes.Contains(cmdline, []byte(vault))
}

// agentPIDs lists the live agent processes serving vault.
func agentPIDs(t *testing.T, vault string) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && agentProcess(pid, vault) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func needProc(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
}

// startAgent starts a real detached agent for e and makes sure it is gone
// at the end of the test.
func startAgent(t *testing.T, e *env, opts Options) Status {
	t.Helper()
	needProc(t)
	if opts.KeyBlock == nil {
		opts.KeyBlock = e.keyBlock
	}
	st, err := Start(context.Background(), e.vault, e.key, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	real, _ := realPath(e.vault)
	t.Cleanup(func() {
		for _, pid := range agentPIDs(t, real) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	if st.PID <= 0 || !agentProcess(st.PID, real) {
		t.Fatalf("status pid %d is not a running agent for %s", st.PID, real)
	}
	return st
}

// waitExited waits until the agent process pid has exited and its socket is
// gone.
func waitExited(t *testing.T, e *env, pid int, timeout time.Duration) {
	t.Helper()
	real, _ := realPath(e.vault)
	sock := e.socket(t)
	waitFor(t, timeout, "agent exit", func() bool {
		return !agentProcess(pid, real) && !exists(sock)
	})
	if _, err := e.client(t).Status(context.Background()); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Status after exit: %v, want ErrNoAgent", err)
	}
}
