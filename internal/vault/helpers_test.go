package vault

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// isolatedVars are pointed at a temporary tree for the whole test binary, so
// no test or child process can touch the user's files (IMPLEMENTATION.md).
var isolatedVars = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
	"TMPDIR", "PASSWORD_STORE_DIR", "GNUPGHOME",
}

// Child processes (fault injection, concurrent saves) are this test binary,
// started with childEnv set. They get the vault and state paths through the
// environment and the vault key through stdin (S2).
const (
	childEnv      = "PASSH_VAULT_TEST_CHILD"
	childPathEnv  = "PASSH_VAULT_TEST_PATH"
	childStateEnv = "PASSH_VAULT_TEST_STATE"
	childCrashEnv = "PASSH_VAULT_TEST_CRASH"
	childEntryEnv = "PASSH_VAULT_TEST_ENTRY"
	// childPlainRename makes the child replace the vault with a plain
	// rename, as on file systems without an exchanging rename.
	childPlainRename = "PASSH_VAULT_TEST_PLAIN_RENAME"
)

// noExchange makes saves use the plain-rename fallback until the test ends.
func noExchange(t *testing.T) {
	old := exchangeFiles
	exchangeFiles = func(a, b string) error { return errNoAtomicRename }
	t.Cleanup(func() { exchangeFiles = old })
}

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		os.Exit(runChild(mode))
	}
	root, err := os.MkdirTemp("", "passh-vault-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, v := range isolatedVars {
		dir := filepath.Join(root, strings.ToLower(v))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv(v, dir)
	}
	os.Setenv("PASSH_CONFIG", filepath.Join(root, "passh-config.toml"))
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

// runChild is the child side of the multi-process tests.
//
//	crash:      open, arm testHook to SIGKILL at $PASSH_VAULT_TEST_CRASH, add an entry
//	concurrent: open, print "opened", wait for "go" on stdin, add an entry, print the result
func runChild(mode string) int {
	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadString('\n')
	if err != nil {
		fmt.Println("error: reading the key:", err)
		return 2
	}
	key, err := age.ParseX25519Identity(strings.TrimSpace(line))
	if err != nil {
		fmt.Println("error: bad key")
		return 2
	}
	if os.Getenv(childPlainRename) != "" {
		exchangeFiles = func(a, b string) error { return errNoAtomicRename }
	}
	opts := Options{StateDir: os.Getenv(childStateEnv), BackupKeep: 3, RollbackWarn: true}
	v, err := Open(context.Background(), os.Getenv(childPathEnv), keys.FromIdentity(key), opts)
	if err != nil {
		fmt.Println("error: open:", err)
		return 2
	}
	e := testEntry(os.Getenv(childEntryEnv), "child-password")
	switch mode {
	case "crash":
		point := os.Getenv(childCrashEnv)
		testHook = func(p, _ string) {
			if p == point {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
				select {} // never returns
			}
		}
		_, err := v.Add(e, false)
		fmt.Println("hook not reached; save:", err)
		return 3
	case "concurrent":
		fmt.Println("opened")
		if l, err := in.ReadString('\n'); err != nil || strings.TrimSpace(l) != "go" {
			fmt.Println("error: no go")
			return 2
		}
		_, err := v.Add(e, false)
		switch {
		case err == nil:
			fmt.Println("ok")
		case errors.Is(err, ErrChanged):
			fmt.Println("changed")
		default:
			fmt.Println("error:", err)
		}
		return 0
	}
	return 2
}

const testPass = "orbit velvet cactus lumen harbor quill"

// testWorkFactor: key blocks of most fixtures use a tiny scrypt work factor
// so that tests that unlock with a passphrase stay fast. passh itself
// always writes 2^18 (keys.WrapKey); the tests of Create, Passwd, Rekey and
// recover use that real path.
const testWorkFactor = 4

// lowKeyBlock builds a key block like keys.WrapKey, with testWorkFactor.
func lowKeyBlock(t testing.TB, id *age.X25519Identity, pass string) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(testWorkFactor)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(id.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// passSource is a keys.PassphraseSource that answers pass and counts the
// questions.
func passSource(pass string, asked *atomic.Int32) keys.KeySource {
	return &keys.PassphraseSource{Read: func(string) ([]byte, error) {
		if asked != nil {
			asked.Add(1)
		}
		return []byte(pass), nil
	}}
}

// clock is a fake clock that moves one minute per reading, so every save
// and backup has its own time.
type clock struct{ n atomic.Int64 }

var clockStart = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func (c *clock) Now() time.Time {
	return clockStart.Add(time.Duration(c.n.Add(1)) * time.Minute)
}

// env is one test vault: its folder, a state folder, the key and the
// collected warnings and prompts.
type env struct {
	t        *testing.T
	dir      string // the vault's folder
	state    string
	path     string
	key      *age.X25519Identity
	keyBlock []byte
	clock    clock

	mu       sync.Mutex
	warnings []string
	prompts  []string
	answer   bool // the prompt's answer
	noPrompt bool // Options.Prompt = nil (no terminal)
	keep     int
}

// newEnv creates a vault (revision 1, no entries) with a fresh key.
func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t:     t,
		dir:   filepath.Join(root, "data"),
		state: filepath.Join(root, "state"),
		keep:  10,
	}
	e.path = filepath.Join(e.dir, "vault.passh")
	var err error
	if e.key, err = keys.NewVaultKey(); err != nil {
		t.Fatal(err)
	}
	e.keyBlock = lowKeyBlock(t, e.key, testPass)
	v, err := newVault(e.path, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.create(e.key, e.keyBlock); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) opts() Options {
	o := Options{
		StateDir:     e.state,
		BackupKeep:   e.keep,
		RollbackWarn: true,
		Now:          e.clock.Now,
		Warn: func(msg string) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.warnings = append(e.warnings, msg)
		},
	}
	if !e.noPrompt {
		o.Prompt = func(w string) (bool, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.prompts = append(e.prompts, w)
			return e.answer, nil
		}
	}
	return o
}

// takeWarnings returns and clears the collected warnings and prompts.
func (e *env) take() (warnings, prompts []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	warnings, prompts = e.warnings, e.prompts
	e.warnings, e.prompts = nil, nil
	return
}

// open opens the vault with the vault key, as with the agent or a paper key.
func (e *env) open() *Vault {
	e.t.Helper()
	return e.openFile(e.path)
}

func (e *env) openFile(path string) *Vault {
	e.t.Helper()
	v, err := Open(context.Background(), path, keys.FromIdentity(e.key), e.opts())
	if err != nil {
		e.t.Fatalf("open %s: %v", path, err)
	}
	return v
}

func (e *env) read() []byte {
	e.t.Helper()
	b, err := os.ReadFile(e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) write(b []byte) {
	e.t.Helper()
	if err := os.WriteFile(e.path, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// temps lists the temporary files in dir.
func temps(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func testEntry(path, password string) model.Entry {
	return model.Entry{
		Path:     paths.MustParse(path),
		Password: password,
		Username: "user-" + password,
		URL:      "https://example.com/" + password,
		Tags:     []string{"t-" + password},
		Fields:   []model.Field{{Key: "pin", Value: "pin-" + password}},
		Notes:    "notes-" + password,
	}
}

func entryPaths(list []model.Entry) []string {
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.Path.String())
	}
	return out
}

func mustAdd(t testing.TB, v *Vault, path, password string) model.Entry {
	t.Helper()
	e, err := v.Add(testEntry(path, password), false)
	if err != nil {
		t.Fatalf("add %s: %v", path, err)
	}
	return e
}

// filesUnder returns every regular file below the given folders.
func filesUnder(t testing.TB, dirs ...string) []string {
	t.Helper()
	var out []string
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.Type().IsRegular() {
				out = append(out, p)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	slices.Sort(out)
	return out
}

func mode(t testing.TB, path string) fs.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}
