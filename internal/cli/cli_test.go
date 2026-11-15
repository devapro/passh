package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passh/internal/importpass"
	"passh/internal/model"
	"passh/internal/paths"
)

func TestRenderTree(t *testing.T) {
	got := renderTree([]string{"bank/my bank", "work", "work/github", "work/atlassian/jira", "top", "evil\u202egnp/x"})
	want := "" +
		"├── bank/\n" +
		"│   └── my bank\n" +
		"├── evil\\u202egnp/\n" +
		"│   └── x\n" +
		"├── top\n" +
		"├── work/\n" +
		"│   ├── atlassian/\n" +
		"│   │   └── jira\n" +
		"│   └── github\n" +
		"└── work\n"
	if got != want {
		t.Errorf("renderTree:\n%s\nwant:\n%s", got, want)
	}
	if renderTree(nil) != "" {
		t.Error("empty tree")
	}
}

func TestFmtDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Hour:    "2h",
		90 * time.Minute: "1h30m",
		time.Hour + 59*time.Minute + 59*time.Second: "1h59m",
		15 * time.Minute:                      "15m",
		14*time.Minute + 59*time.Second:       "14m59s",
		45*time.Second + 400*time.Millisecond: "45s",
		-time.Second:                          "0s",
	} {
		if got := fmtDuration(d); got != want {
			t.Errorf("fmtDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestFindEntries(t *testing.T) {
	entries := []model.Entry{
		{Path: paths.MustParse("work/github"), Tags: []string{"dev"}},
		{Path: paths.MustParse("work/gitlab"), Tags: []string{"dev", "2fa"}},
		{Path: paths.MustParse("bank/card"), Tags: []string{"money"}},
	}
	hits := findEntries(entries, "GTHB")
	if len(hits) != 1 || hits[0].path != "work/github" || hits[0].tag != "" {
		t.Errorf("GTHB: %+v", hits)
	}
	hits = findEntries(entries, "2fa")
	if len(hits) != 1 || hits[0].path != "work/gitlab" || hits[0].tag != "2fa" {
		t.Errorf("2fa: %+v", hits)
	}
	hits = findEntries(entries, "mny")
	if len(hits) != 1 || hits[0].path != "bank/card" {
		t.Errorf("mny: %+v", hits)
	}
	if hits = findEntries(entries, "zzz"); len(hits) != 0 {
		t.Errorf("zzz: %+v", hits)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"work/github":   "work/github",
		"bank/My Bank":  "'bank/My Bank'",
		"it's":          `'it'\''s'`,
		"a/\x1b[2Jb":    `'a/\x1b[2Jb'`,
		"x@host:1,2=3+": "x@host:1,2=3+",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackupDest(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	got, err := backupDest(dir, "/x/vault.passh", now)
	if err != nil || got != filepath.Join(dir, "vault-20261115-120000.passh") {
		t.Errorf("folder: %q, %v", got, err)
	}
	got, err = backupDest(filepath.Join(dir, "copy.passh"), "/x/vault.passh", now)
	if err != nil || got != filepath.Join(dir, "copy.passh") {
		t.Errorf("file: %q, %v", got, err)
	}
	if _, err := backupDest(filepath.Join(dir, "nope")+"/", "/x/vault.passh", now); err == nil {
		t.Error("a missing folder with a trailing / was accepted")
	}
}

func TestWriteChecked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.passh")
	sum, err := writeChecked(p, []byte("content"))
	if err != nil || sum != "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73" {
		t.Fatalf("writeChecked: %q, %v", sum, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if _, err := writeChecked(p, []byte("other")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("overwrite: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "content" {
		t.Errorf("file changed: %q", b)
	}
}

func TestImportReportEscapes(t *testing.T) {
	res := &importpass.Result{
		Dir:    "/store\x1b]0;x\a",
		DryRun: true,
		Items:  []importpass.Item{{File: "a\u202e.gpg", Path: paths.MustParse("a\u202e"), Replace: true}},
		Skipped: []importpass.Skip{
			{File: "evil\x1b[2J.gpg", Reason: importpass.InvalidPath, Detail: "it contains a control character"},
			{File: "dup.gpg", Reason: importpass.DuplicatePath, Detail: "same path as \x1b[1m"},
		},
	}
	out := importReport(res, 1)
	for _, bad := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("report holds %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{
		`a\u202e  (replaces the entry in the vault)`,
		`evil\x1b[2J.gpg — invalid path: it contains a control character`,
		"Would skip 2: 1 invalid path, 1 duplicate path.",
		"Would import 1 entry (1 replacing entries already in the vault).",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestUsageErrorExitStatus(t *testing.T) {
	a := &app{stderr: devNull(t)}
	if got := a.exitStatus(nil); got != exitOK {
		t.Errorf("nil: %d", got)
	}
	if got := a.exitStatus(errors.New("x")); got != exitError {
		t.Errorf("error: %d", got)
	}
	if got := a.exitStatus(usagef("bad %s", "flag")); got != exitUsage {
		t.Errorf("usage: %d", got)
	}
	if got := a.exitStatus(errReported); got != exitError {
		t.Errorf("reported: %d", got)
	}
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
