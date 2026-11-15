package editor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/devapro/passh/internal/entrytext"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/tty"
)

// tmpfsDir makes a folder of the test's own on /dev/shm, or skips.
func tmpfsDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/dev/shm", "passh-editor-test-")
	if err != nil {
		t.Skip("no /dev/shm:", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if !onTmpfs(d) {
		t.Skip("/dev/shm is not tmpfs here")
	}
	return d
}

// diskDir is a folder that is not on tmpfs, or skips.
func diskDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if onTmpfs(d) {
		t.Skip("the temporary folder is on tmpfs here")
	}
	return d
}

// withShm points the /dev/shm fallback at dir for one test.
func withShm(t *testing.T, dir string) {
	t.Helper()
	old := shmDir
	shmDir = dir
	t.Cleanup(func() { shmDir = old })
}

// setup prepares a tmpfs runtime folder, no /dev/shm fallback, a $PATH
// with fake editors and the fake editor's environment. It returns the
// runtime folder.
func setup(t *testing.T, action, text string) string {
	t.Helper()
	rt := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	withShm(t, diskDir(t))
	fakeEditors(t)
	t.Setenv(helperEnv, "1")
	t.Setenv(logEnv, filepath.Join(t.TempDir(), "runs.jsonl"))
	t.Setenv(actionEnv, action)
	t.Setenv(textEnv, text)
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a -race child would wait 1 s on exit
	return rt
}

// fakeEditors puts symlinks to the test binary named like editors into a
// new folder and makes it the whole $PATH.
func fakeEditors(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	for _, n := range []string{"vim", "nvim", "nano", "emacs", "vi"} {
		if err := os.Symlink(exe, filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	return bin
}

// ptyTerm returns the terminal side of a new pseudo-terminal.
func ptyTerm(t *testing.T) *os.File {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(io.Discard, master)
	}()
	t.Cleanup(func() {
		slave.Close()
		master.Close()
		select { // the reader ends when the pty is closed
		case <-copied:
		case <-time.After(10 * time.Second):
			t.Error("the pty reader didn't end")
		}
	})
	return slave
}

func sampleEntry(t *testing.T) model.Entry {
	t.Helper()
	var e model.Entry
	// Unknown keys at entry and field level must survive.
	js := `{"id":"0f6c0000-0000-4000-8000-000000000001","path":"work/github","password":"s3cr3t-P@ss",
		"username":"arsenii","url":"https://github.com","tags":["work","dev"],
		"fields":[{"key":"recovery-email","value":"me@example.com","x-note":1},{"key":"pin","value":"1234"}],
		"notes":"Recovery codes.\nline two","created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z",
		"x-future":"kept"}`
	if err := json.Unmarshal([]byte(js), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func jsonOf(t *testing.T, e model.Entry) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTempBase(t *testing.T) {
	shm := tmpfsDir(t)
	rt := tmpfsDir(t)
	disk := diskDir(t)

	t.Setenv("XDG_RUNTIME_DIR", rt)
	withShm(t, shm)
	if got, err := TempBase(); err != nil || got != rt {
		t.Errorf("tmpfs $XDG_RUNTIME_DIR: TempBase = %q, %v; want %q", got, err, rt)
	}

	t.Setenv("XDG_RUNTIME_DIR", disk)
	if got, err := TempBase(); err != nil || got != shm {
		t.Errorf("$XDG_RUNTIME_DIR on disk: TempBase = %q, %v; want the /dev/shm fallback %q", got, err, shm)
	}
	t.Setenv("XDG_RUNTIME_DIR", "relative/dir")
	if got, err := TempBase(); err != nil || got != shm {
		t.Errorf("relative $XDG_RUNTIME_DIR: TempBase = %q, %v; want %q", got, err, shm)
	}

	withShm(t, diskDir(t))
	t.Setenv("XDG_RUNTIME_DIR", disk)
	if _, err := TempBase(); !errors.Is(err, ErrNoTmpfs) {
		t.Errorf("no tmpfs anywhere: TempBase error = %v, want ErrNoTmpfs", err)
	}
	os.Unsetenv("XDG_RUNTIME_DIR")
	if _, err := TempBase(); !errors.Is(err, ErrNoTmpfs) || !strings.Contains(err.Error(), "built-in form") {
		t.Errorf("no $XDG_RUNTIME_DIR: TempBase error = %v, want ErrNoTmpfs with advice", err)
	}
	withShm(t, filepath.Join(disk, "missing"))
	if _, err := TempBase(); !errors.Is(err, ErrNoTmpfs) {
		t.Errorf("missing /dev/shm: TempBase error = %v", err)
	}
}

func TestNewEditorKinds(t *testing.T) {
	bin := fakeEditors(t)
	const file = "/run/user/1/passh-edit-x/entry.txt"
	for _, tc := range []struct {
		cmdline string
		kind    Kind
		argv    []string
	}{
		{"vim", KindVim, []string{"-n", "-u", "NONE", "-i", "NONE", "-c", "set nobackup nowritebackup noundofile noswapfile", "--", file}},
		{"nvim -p", KindNeovim, []string{"-p", "-n", "--clean", "-i", "NONE", "-c", "set nobackup nowritebackup noundofile noswapfile", "--", file}},
		{"nano", KindNano, []string{"--ignorercfiles", "--nohelp", "--", file}},
		{`'emacs' -nw "-f" x`, KindOther, []string{"-nw", "-f", "x", file}},
		{filepath.Join(bin, "vim"), KindVim, []string{"-n", "-u", "NONE", "-i", "NONE", "-c", "set nobackup nowritebackup noundofile noswapfile", "--", file}},
		{"vi", KindOther, []string{file}}, // vi → the test binary: not known to be vim
	} {
		ed, err := NewEditor(tc.cmdline)
		if err != nil {
			t.Fatalf("%s: %v", tc.cmdline, err)
		}
		if ed.Kind != tc.kind {
			t.Errorf("%s: kind %v, want %v", tc.cmdline, ed.Kind, tc.kind)
		}
		if got := ed.Argv(file); !slices.Equal(got, tc.argv) {
			t.Errorf("%s: argv %q, want %q", tc.cmdline, got, tc.argv)
		}
		if (ed.Warning != "") != (tc.kind == KindOther) {
			t.Errorf("%s: warning %q", tc.cmdline, ed.Warning)
		}
	}
	for _, k := range []Kind{KindOther, KindVim, KindNeovim, KindNano} {
		if k.String() == "" {
			t.Error("empty kind name")
		}
	}

	for _, bad := range []string{"", `vim "unterminated`, "passh-no-such-editor", `""`} {
		if _, err := NewEditor(bad); err == nil {
			t.Errorf("NewEditor(%q) succeeded", bad)
		}
	}
}

func TestEditorKindFromSymlinkTarget(t *testing.T) {
	bin := fakeEditors(t)
	// /usr/bin/vi → /etc/alternatives/vi → vim.basic: vim, by the target's
	// name. A copy is needed so that the final name is vim.basic.
	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(t.TempDir(), "vim.basic")
	if err := os.WriteFile(real, data, 0o700); err != nil {
		t.Fatal(err)
	}
	alt := filepath.Join(t.TempDir(), "vi")
	if err := os.Symlink(real, alt); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(bin, "vi"))
	if err := os.Symlink(alt, filepath.Join(bin, "vi")); err != nil {
		t.Fatal(err)
	}
	ed, err := NewEditor("vi")
	if err != nil {
		t.Fatal(err)
	}
	if ed.Kind != KindVim || ed.Warning != "" {
		t.Fatalf("vi → vim.basic: kind %v, warning %q", ed.Kind, ed.Warning)
	}
}

func TestFindEditor(t *testing.T) {
	fakeEditors(t)
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", "")
	if ed, err := FindEditor(); err != nil || ed.Name != "vi" {
		t.Errorf("no $EDITOR or $VISUAL: %+v, %v; want vi", ed, err)
	}
	t.Setenv("VISUAL", "nano")
	if ed, err := FindEditor(); err != nil || ed.Kind != KindNano {
		t.Errorf("$VISUAL=nano: %+v, %v", ed, err)
	}
	t.Setenv("EDITOR", "nvim")
	if ed, err := FindEditor(); err != nil || ed.Kind != KindNeovim {
		t.Errorf("$EDITOR=nvim wins over $VISUAL: %+v, %v", ed, err)
	}
	t.Setenv("EDITOR", "passh-no-such-editor")
	if _, err := FindEditor(); err == nil || !strings.Contains(err.Error(), "$EDITOR") {
		t.Errorf("missing $EDITOR program: %v", err)
	}
}

func TestEditVim(t *testing.T) {
	e := sampleEntry(t)
	edited := strings.Replace(entrytext.Format(e), "username: arsenii", "username: bob", 1)
	rt := setup(t, "write", edited)
	ed, err := NewEditor("vim")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ed.Edit(context.Background(), ptyTerm(t), e, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := e.Clone()
	want.Username = "bob"
	if !got.Equal(want) || jsonOf(t, got) != jsonOf(t, want) {
		t.Fatalf("result\n%s\nwant\n%s", jsonOf(t, got), jsonOf(t, want))
	}

	runs := readRuns(t)
	if len(runs) != 1 {
		t.Fatalf("%d editor runs, want 1", len(runs))
	}
	r := runs[0]
	if r.Name != "vim" || !r.TTY {
		t.Errorf("editor %q, terminal %v", r.Name, r.TTY)
	}
	wantArgs := append(slices.Clone(leakSafeFlags[KindVim]), "--", r.File)
	if !slices.Equal(r.Args, wantArgs) {
		t.Errorf("args %q, want %q", r.Args, wantArgs)
	}
	if !strings.HasPrefix(r.File, rt+"/"+tempPrefix) || !r.OnTmpfs {
		t.Errorf("file %s (tmpfs %v), want it in a %s folder in %s", r.File, r.OnTmpfs, tempPrefix, rt)
	}
	if r.FileMode != 0o600 || r.DirMode != 0o700 {
		t.Errorf("modes: file %o, folder %o; want 600 and 700", r.FileMode, r.DirMode)
	}
	if r.Before != entrytext.Format(e) {
		t.Errorf("the editor got %q, want the text form", r.Before)
	}
	if _, err := os.Stat(filepath.Dir(r.File)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary folder still there: %v", err)
	}
	if l := Leftovers(); len(l) != 0 {
		t.Errorf("leftovers: %q", l)
	}
}

func TestEditFlagsPerEditor(t *testing.T) {
	for _, name := range []string{"vim", "nvim", "nano", "emacs"} {
		t.Run(name, func(t *testing.T) {
			setup(t, "keep", "")
			ed, err := NewEditor(name)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil)
			if !errors.Is(err, ErrNoChange) {
				t.Fatalf("Edit = %v, want ErrNoChange", err)
			}
			r := readRuns(t)[0]
			want := ed.Argv(r.File)
			if !slices.Equal(r.Args, want) {
				t.Errorf("args %q, want %q", r.Args, want)
			}
			hasDashes := slices.Contains(r.Args, "--")
			if hasDashes != (name != "emacs") {
				t.Errorf("-- in args: %v", hasDashes)
			}
		})
	}
}

func TestEditNoChange(t *testing.T) {
	e := sampleEntry(t)
	// Different bytes, same content: CRLF line endings.
	crlf := strings.ReplaceAll(entrytext.Format(e), "\n", "\r\n")
	setup(t, "write", crlf)
	ed, _ := NewEditor("nano")
	if _, err := ed.Edit(context.Background(), ptyTerm(t), e, nil); !errors.Is(err, ErrNoChange) {
		t.Fatalf("Edit = %v, want ErrNoChange", err)
	}
}

func TestEditParseError(t *testing.T) {
	bad := "pw\nusername: a\nusername: b\n"
	setup(t, "write", bad)
	ed, _ := NewEditor("vim")
	_, err := ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 3 || !errors.Is(err, entrytext.ErrDuplicate) {
		t.Fatalf("Edit = %v, want a ParseError on line 3", err)
	}
	if !strings.HasPrefix(err.Error(), "line 3: ") {
		t.Errorf("message %q", err)
	}
	if l := Leftovers(); len(l) != 0 {
		t.Errorf("leftovers: %q", l)
	}
}

func TestEditParseErrorRetry(t *testing.T) {
	bad := "pw\nusername: a\ntags: ok\nurl: x\nurl: y\n"
	good := "new-pw\nusername: a\n"
	setup(t, "write", bad)
	t.Setenv(text2Env, good)
	ed, _ := NewEditor("vim")
	e := sampleEntry(t)
	asked := 0
	got, err := ed.Edit(context.Background(), ptyTerm(t), e, func(pe *ParseError) bool {
		asked++
		if pe.Line != 5 {
			t.Errorf("retry got line %d, want 5", pe.Line)
		}
		if l := Leftovers(); len(l) != 0 {
			t.Errorf("the temporary file is still there while asking: %q", l)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Errorf("retry asked %d times, want 1", asked)
	}
	runs := readRuns(t)
	if len(runs) != 2 || runs[1].Before != bad {
		t.Fatalf("second run started from %q, want the user's text", runs[len(runs)-1].Before)
	}
	if got.Password != "new-pw" || got.Username != "a" || got.URL != "" || len(got.Tags) != 0 || len(got.Fields) != 0 || got.Notes != "" {
		t.Errorf("result %+v", got)
	}
	if got.ID != e.ID || got.Path != e.Path || !got.CreatedAt.Equal(e.CreatedAt) {
		t.Error("id, path or times changed")
	}

	// Declining the retry returns the error.
	t.Setenv(logEnv, filepath.Join(t.TempDir(), "runs2.jsonl"))
	_, err = ed.Edit(context.Background(), ptyTerm(t), e, func(*ParseError) bool { return false })
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("Edit = %v, want a ParseError", err)
	}
}

func TestEditInvalidUTF8(t *testing.T) {
	setup(t, "write", "pw\nusername: a\nnotes \xff here\n")
	ed, _ := NewEditor("vim")
	_, err := ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 3 || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("Edit = %v, want a UTF-8 ParseError on line 3", err)
	}
}

func TestEditKeepsCustomFieldExtras(t *testing.T) {
	e := sampleEntry(t)
	text := entrytext.Format(e)
	// Change the pin, move recovery-email after it, and edit the notes.
	text = strings.Replace(text, "recovery-email: me@example.com\npin: 1234\n", "pin: 4321\nrecovery-email: me@example.com\n", 1)
	text = strings.Replace(text, "line two", "line 2", 1)
	setup(t, "write", text)
	ed, _ := NewEditor("vim")
	got, err := ed.Edit(context.Background(), ptyTerm(t), e, nil)
	if err != nil {
		t.Fatal(err)
	}
	js := jsonOf(t, got)
	if !strings.Contains(js, `{"key":"pin","value":"4321"}`) ||
		!strings.Contains(js, `{"key":"recovery-email","value":"me@example.com","x-note":1}`) ||
		!strings.Contains(js, `"x-future":"kept"`) || got.Notes != "Recovery codes.\nline 2" {
		t.Fatalf("result %s", js)
	}
}

func TestEditorFailureCleansUp(t *testing.T) {
	setup(t, "fail", "changed\n")
	ed, _ := NewEditor("vim")
	_, err := ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil)
	if err == nil || errors.Is(err, ErrNoChange) || !strings.Contains(err.Error(), "editor failed") {
		t.Fatalf("Edit = %v, want the editor's failure", err)
	}
	r := readRuns(t)[0]
	if _, err := os.Stat(filepath.Dir(r.File)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary folder still there after a failure: %v", err)
	}
}

func TestCleanupZeroesFiles(t *testing.T) {
	e := sampleEntry(t)
	rt := setup(t, "litter", "new\nusername: x\n")
	link := tmpfsDir(t) // same tmpfs as rt, so a hard link works
	t.Setenv(linkDirEnv, link)
	ed, _ := NewEditor("vim")
	if _, err := ed.Edit(context.Background(), ptyTerm(t), e, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(link, "linked.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("the file wasn't overwritten with zeros before removal: %q", b)
	}
	matches, _ := filepath.Glob(filepath.Join(rt, tempPrefix+"*"))
	if len(matches) != 0 {
		t.Fatalf("left behind: %q", matches)
	}
}

func TestEditInterrupted(t *testing.T) {
	for _, how := range []string{"signal", "context"} {
		t.Run(how, func(t *testing.T) {
			setup(t, "sleep", "")
			ed, _ := NewEditor("vim")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					if fi, err := os.Stat(os.Getenv(logEnv)); err == nil && fi.Size() > 0 {
						break // the editor runs
					}
					time.Sleep(10 * time.Millisecond)
				}
				if how == "signal" {
					_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
				} else {
					cancel()
				}
			}()
			start := time.Now()
			_, err := ed.Edit(ctx, ptyTerm(t), sampleEntry(t), nil)
			if !errors.Is(err, ErrInterrupted) {
				t.Fatalf("Edit = %v, want ErrInterrupted", err)
			}
			if how == "context" && !errors.Is(err, context.Canceled) {
				t.Errorf("Edit = %v, want it to wrap context.Canceled", err)
			}
			if time.Since(start) > 30*time.Second {
				t.Error("the editor wasn't stopped")
			}
			r := readRuns(t)[0]
			if _, err := os.Stat(filepath.Dir(r.File)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("temporary folder still there after an interrupt: %v", err)
			}
		})
	}
}

// A signal that arrives once the plaintext file exists, before the editor
// runs, is caught too: Edit returns ErrInterrupted and the folder is gone,
// instead of passh dying with the file on tmpfs (CONC-6, S1; review
// TUI-005). Without the handler in place, SIGHUP would kill the test.
func TestEditSignalBeforeEditor(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			setup(t, "write", "changed\n")
			var file string
			testHookWritten = func(f string) {
				file = f
				if err := syscall.Kill(os.Getpid(), sig); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { testHookWritten = nil })
			ed, _ := NewEditor("vim")
			_, err := ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil)
			if !errors.Is(err, ErrInterrupted) {
				t.Fatalf("Edit = %v, want ErrInterrupted", err)
			}
			if file == "" {
				t.Fatal("the hook didn't run")
			}
			if _, err := os.Stat(filepath.Dir(file)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("temporary folder still there after the signal: %v", err)
			}
		})
	}
}

func TestEditNeedsTerminalAndTmpfs(t *testing.T) {
	setup(t, "keep", "")
	ed, _ := NewEditor("vim")
	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ed.Edit(context.Background(), f, sampleEntry(t), nil); !errors.Is(err, tty.ErrNoTerminal) {
		t.Errorf("Edit on a file = %v, want ErrNoTerminal", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", diskDir(t))
	if _, err := ed.Edit(context.Background(), ptyTerm(t), sampleEntry(t), nil); !errors.Is(err, ErrNoTmpfs) {
		t.Errorf("Edit without tmpfs = %v, want ErrNoTmpfs", err)
	}
	if runs := readRuns(t); len(runs) != 0 {
		t.Errorf("the editor ran %d times", len(runs))
	}
}

func TestLeftovers(t *testing.T) {
	rt := tmpfsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	withShm(t, diskDir(t))
	if l := Leftovers(); len(l) != 0 {
		t.Fatalf("leftovers in a new folder: %q", l)
	}
	d := filepath.Join(rt, tempPrefix+"123")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if l := Leftovers(); !slices.Equal(l, []string{d}) {
		t.Fatalf("Leftovers = %q, want %q", l, d)
	}
}

func TestWithContentAndParseHelpers(t *testing.T) {
	e := sampleEntry(t)
	p, err := entrytext.Parse(entrytext.Format(e))
	if err != nil {
		t.Fatal(err)
	}
	if r := withContent(e, p); !r.Equal(e) {
		t.Fatal("re-parsing the text form changed the entry")
	}
	if _, err := parseText("pw\ntags: a\x01b\n"); err == nil {
		t.Fatal("a control character in a tag parsed")
	}
}
