package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	return fmt.Sprintf("%x", sha256.Sum256(readFile(t, p)))
}

// §13.2.1: paths with . or .. segments, empty segments, a leading - in any
// segment, or control characters are rejected (add, generate, mv); paths
// are NFC-normalized and at most 1024 bytes.
func TestS1_PathValidation(t *testing.T) {
	e, _ := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	before := fileSHA(t, e.vault)

	bad := []string{
		"", ".", "..", "a/./b", "a/../b", "./a", "../a", "a/.", "a/..",
		"a//b", "/a", "a/", "/", "//",
		"-a", "a/-b", "a/b/-c",
		"a\x01b", "a/\x1b[31mred", "a\x7fb", "a\tb", "a\nb", "a\rb",
		"a\u0085b", "a\u009bb", // C1 controls (NEL, CSI)
		strings.Repeat("x", 1025),
	}
	for _, p := range bad {
		q := fmt.Sprintf("%q", p)
		if len(q) > 40 {
			q = q[:40] + "…"
		}
		if r := e.run("generate", "--", p); r.code == 0 {
			t.Errorf("generate %s accepted", q)
		} else if bytes.ContainsAny([]byte(r.stderr), "\x1b\x07\x01\x7f") {
			t.Errorf("generate %s: the error echoes control characters: %q", q, r.stderr)
		}
		// `mv src folder/` moves into folder/ (documented), so a trailing
		// slash is no invalid destination for mv.
		if p != "a/" {
			if r := e.run("mv", "--", "csv/plus", p); r.code == 0 {
				t.Errorf("mv csv/plus %s accepted", q)
			}
		}
		if r := e.run("tag", "--add", "x", "--", p); r.code == 0 {
			t.Errorf("tag %s accepted", q)
		}
		s := e.start(sessOpts{}, "add", "--", p)
		if s.expectWithin("Password", 3*time.Second) {
			t.Errorf("add %s reached the password prompt", q)
		}
		if r := s.wait(); r.code == 0 {
			t.Errorf("add %s succeeded", q)
		}
	}
	if fileSHA(t, e.vault) != before {
		t.Fatalf("a rejected path changed the vault")
	}

	// mv from a bad source path.
	if r := e.run("mv", "--", "csv/../csv/plus", "csv/x"); r.code == 0 {
		t.Errorf("mv from csv/../csv/plus accepted")
	}

	// §4.4: tags are trimmed and non-empty, without commas or control
	// characters.
	for _, tag := range []string{"", "   ", "a\x1bb", "a\tb", "a\u0085b"} {
		if r := e.run("tag", "work/github", "--add", tag); r.code == 0 {
			t.Errorf("tag %q accepted", tag)
		}
	}
	if r := e.run("tag", "work/github", "--add", "a,b"); r.code == 0 {
		// --add a,b may mean two tags; then neither may hold a comma.
		d := mustDecrypt(t, e.vault, fixtures(t).key)
		gh, _ := d.entry("work/github")
		for _, tg := range gh.Tags {
			if strings.Contains(tg, ",") {
				t.Errorf("a tag with a comma was stored: %q", tg)
			}
		}
	}
	e.ok("tag", "work/github", "--add", "  padded  ")
	d0 := mustDecrypt(t, e.vault, fixtures(t).key)
	gh, _ := d0.entry("work/github")
	if !slicesContains(gh.Tags, "padded") {
		t.Errorf("tag not trimmed: %q", gh.Tags)
	}

	// Accepted: 1024 bytes, Unicode normalized to NFC, case-sensitive.
	long := "a/" + strings.Repeat("y", 1022)
	e.ok("generate", long)
	e.ok("generate", "café/x") // NFD é
	e.ok("generate", "Case/X")
	e.ok("generate", "case/X")
	r := e.ok("export", "--format", "json", "--confirm-plaintext")
	var d vData
	if err := json.Unmarshal([]byte(r.stdout), &d); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{long, "café/x", "Case/X", "case/X"} {
		if _, ok := d.entry(p); !ok {
			t.Errorf("entry %.30q missing (NFC/case-sensitivity)", p)
		}
	}
	if _, ok := d.entry("café/x"); ok {
		t.Errorf("path stored in NFD, not NFC")
	}
	if r := e.run("show", "café/x", "--field", "password"); r.code != 0 || len(r.stdout) != 24 {
		t.Errorf("show of the NFC path: %s", r)
	}
	if r := e.run("show", "café/x", "--field", "password"); r.code != 0 {
		t.Errorf("show of the NFD spelling should find the NFC entry: %s", r)
	}
}

// evilEntry holds escape sequences in every value (§13.2.3, S4).
const evilEntry = "pw\x1b]52;c;SGVsbG8=\x07tail\n" +
	"username: user\x1b[2J\x1b[Hname\n" +
	"url: https://x.example/\x1b]8;;http://evil.example\x1b\\link\x1b]8;;\x1b\\\n" +
	"tags: t1, t2\n" +
	"field: val\u009b31mC1\x07bell\n" +
	"---\n" +
	"notes\x1b]0;pwned title\x07 and \x1b[31mred\x1b[0m\rcarriage\x1bP+q\x1b\\"

// liveControls reports control bytes in terminal output that could act:
// ESC, BEL, C1 controls (as UTF-8 or raw), and a CR that isn't part of CRLF.
func liveControls(out []byte) []string {
	var bad []string
	s := string(out)
	for i, r := range s {
		switch {
		case r == 0x1b:
			bad = append(bad, fmt.Sprintf("ESC at %d", i))
		case r == 0x07:
			bad = append(bad, fmt.Sprintf("BEL at %d", i))
		case r >= 0x80 && r <= 0x9f:
			bad = append(bad, fmt.Sprintf("C1 %#x at %d", r, i))
		case r == '\r' && (i+1 >= len(s) || s[i+1] != '\n'):
			bad = append(bad, fmt.Sprintf("bare CR at %d", i))
		case r == 0xfffd && strings.Contains(s[i:min(i+3, len(s))], "\x9b"):
			bad = append(bad, fmt.Sprintf("raw 0x9b at %d", i))
		}
	}
	for i := 0; i < len(out); i++ {
		if out[i] == 0x9b && (i == 0 || out[i-1] != 0xc2) {
			bad = append(bad, fmt.Sprintf("raw byte 0x9b at %d", i))
		}
	}
	return bad
}

func TestS3_EscapesInert(t *testing.T) {
	g := makeGPGStoreWith(t, map[string]string{
		"evil/osc52":             evilEntry,
		"evil/c1\u009b":          "c1 path\n",
		"evil/bidi\u202egnp.exe": "bidi path\n",
	}, false)
	f := fixtures(t)
	e := newEnv(t)
	e.installVault(f.empty, "")
	e.gnupg = g.home
	e.path = binDir + ":/usr/bin:/bin"
	e.unlock(fixPass)
	defer e.lock()
	r := e.ok("import", "pass", g.store)
	mustContain(t, "import of the evil store", r.stdout, "Imported 2 entries")
	e.path = binDir

	check := func(what string, out []byte) {
		t.Helper()
		if bad := liveControls(out); len(bad) > 0 {
			t.Errorf("%s: live control characters %v in output:\n%q", what, bad, out)
		}
	}
	onTerm := func(args ...string) []byte {
		t.Helper()
		s := e.start(sessOpts{}, args...)
		s.wait()
		return s.raw()
	}

	// show, show --field, ls, find, tags: on a terminal and piped.
	for _, args := range [][]string{
		{"show", "evil/osc52"},
		{"show", "evil/osc52", "--field", "username"},
		{"show", "evil/osc52", "--field", "url"},
		{"show", "evil/osc52", "--field", "notes"},
		{"show", "evil/osc52", "--field", "field"},
		{"show", "evil/osc52", "--field", "password"},
		{"ls"},
		{"ls", "evil"},
		{"find", "evil"},
		{"find", "t1"},
		{"tags"},
		// Error messages that repeat user input or vault content.
		{"show", "evil/nope\x1b]52;c;QUFB\x07"},
		{"show", "evil/osc52", "--field", "x\x1b]52;c;QUFB\x07"},
		{"ls", "nope\x1b]52;c;QUFB\x07"},
		{"find", "zz\x1b]52;c;QUFB\x07zz"},
		{"mv", "evil/osc52", "evil/\x1b[2J"},
	} {
		name := fmt.Sprintf("%q", args)
		check(name+" on a terminal", onTerm(args...))
		if args[0] == "show" && len(args) == 4 && args[2] == "--field" && !strings.Contains(args[3], "\x1b") {
			continue // piped --field prints the exact value by design (§6.4)
		}
		r := e.run(args...)
		check(name+" piped (stdout)", []byte(r.stdout))
		check(name+" piped (stderr)", []byte(r.stderr))
	}

	// show --raw prints the exact bytes (S4).
	r = e.ok("show", "evil/osc52", "--raw")
	for _, want := range []string{
		"pw\x1b]52;c;SGVsbG8=\x07tail\n",
		"user\x1b[2J\x1b[Hname",
		"https://x.example/\x1b]8;;http://evil.example\x1b\\link\x1b]8;;\x1b\\",
		"val\u009b31mC1\x07bell",
		"notes\x1b]0;pwned title\x07 and \x1b[31mred\x1b[0m\rcarriage\x1bP+q\x1b\\",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("show --raw lacks the exact bytes %q in %q", want, r.stdout)
		}
	}
	if !strings.HasPrefix(r.stdout, "pw\x1b]52;c;SGVsbG8=\x07tail\n") {
		t.Errorf("show --raw: line 1 isn't the exact password: %q", r.stdout)
	}
	if r := e.ok("show", "evil/osc52", "--field", "password", "--raw"); r.stdout != "pw\x1b]52;c;SGVsbG8=\x07tail" {
		t.Errorf("show --field password --raw = %q", r.stdout)
	}
}

func slicesContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
