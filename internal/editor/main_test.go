package editor

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

// The test binary doubles as a fake editor: symlinked under the names vim,
// nvim, nano, emacs…, and run with helperEnv set, it records what it was
// given (editorRun) and then edits the file as editorAction says.
const (
	helperEnv  = "PASSH_EDITOR_HELPER"  // "1" in the fake editor
	logEnv     = "PASSH_EDITOR_LOG"     // JSON lines of editorRun
	actionEnv  = "PASSH_EDITOR_ACTION"  // keep, write, fail, sleep, litter
	textEnv    = "PASSH_EDITOR_TEXT"    // what "write" puts in the file
	text2Env   = "PASSH_EDITOR_TEXT2"   // … on the second run, if set
	linkDirEnv = "PASSH_EDITOR_LINKDIR" // hard-link the file here first
)

// editorRun is what the fake editor saw.
type editorRun struct {
	Name     string   // base name it was started as
	Args     []string // its arguments
	File     string   // the last argument
	Before   string   // the file's content when it started
	FileMode uint32
	DirMode  uint32
	OnTmpfs  bool
	TTY      bool // stdin, stdout and stderr are terminals
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(fakeEditor())
	}
	os.Exit(isolated(m))
}

// isolated runs the tests with every user folder pointing into a temporary
// directory (IMPLEMENTATION.md, test isolation).
func isolated(m *testing.M) int {
	root, err := os.MkdirTemp("", "passh-editor-test-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
		"XDG_RUNTIME_DIR", "TMPDIR", "PASSH_CONFIG", "PASSWORD_STORE_DIR", "GNUPGHOME"} {
		d := filepath.Join(root, strings.ToLower(v))
		if err := os.Mkdir(d, 0o700); err != nil {
			panic(err)
		}
		os.Setenv(v, d)
	}
	os.Unsetenv("EDITOR")
	os.Unsetenv("VISUAL")
	return m.Run()
}

func fakeEditor() int {
	args := os.Args[1:]
	if len(args) == 0 {
		return 90
	}
	r := editorRun{Name: filepath.Base(os.Args[0]), Args: args, File: args[len(args)-1]}
	b, err := os.ReadFile(r.File)
	if err != nil {
		return 91
	}
	r.Before = string(b)
	if fi, err := os.Stat(r.File); err == nil {
		r.FileMode = uint32(fi.Mode().Perm())
	}
	dir := filepath.Dir(r.File)
	if fi, err := os.Stat(dir); err == nil {
		r.DirMode = uint32(fi.Mode().Perm())
	}
	r.OnTmpfs = onTmpfs(dir)
	r.TTY = term.IsTerminal(0) && term.IsTerminal(1) && term.IsTerminal(2)

	log := os.Getenv(logEnv)
	runs := 0
	if f, err := os.Open(log); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			runs++
		}
		f.Close()
	}
	line, _ := json.Marshal(r)
	f, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return 92
	}
	_, _ = f.Write(append(line, '\n'))
	f.Close()

	if d := os.Getenv(linkDirEnv); d != "" {
		if err := os.Link(r.File, filepath.Join(d, "linked.txt")); err != nil {
			return 93
		}
	}
	text := os.Getenv(textEnv)
	if t2, ok := os.LookupEnv(text2Env); ok && runs >= 1 {
		text = t2
	}
	write := func() int {
		// In place, like an editor with nowritebackup: same inode.
		f, err := os.OpenFile(r.File, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return 94
		}
		defer f.Close()
		if _, err := f.WriteString(text); err != nil {
			return 95
		}
		return 0
	}
	switch os.Getenv(actionEnv) {
	case "keep":
		return 0
	case "write":
		return write()
	case "fail":
		write()
		return 2
	case "litter":
		_ = os.WriteFile(r.File+"~", b, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "."+filepath.Base(r.File)+".swp"), b, 0o600)
		return write()
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	}
	return 99
}

// readRuns returns what the fake editor recorded.
func readRuns(t *testing.T) []editorRun {
	t.Helper()
	f, err := os.Open(os.Getenv(logEnv))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var runs []editorRun
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r editorRun
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
	}
	return runs
}
