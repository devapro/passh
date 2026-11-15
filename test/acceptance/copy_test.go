package acceptance

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// fakeClipboard writes a clipboard command that logs each value it gets on
// stdin (base64) with the time in ms, one line per call.
func fakeClipboard(t *testing.T, dir string) (cmd, log string) {
	t.Helper()
	cmd = filepath.Join(dir, "fakeclip")
	log = filepath.Join(dir, "clip.log")
	script := "#!/bin/sh\nv=$(base64 -w0)\nprintf '%s %s\\n' \"$(date +%s%3N)\" \"$v\" >> " + log + "\n"
	writeFile(t, cmd, []byte(script), 0o755)
	return cmd, log
}

type clipCall struct {
	at    time.Time
	value string
}

func readClipLog(t *testing.T, log string) []clipCall {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	var out []clipCall
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		ms, enc, _ := strings.Cut(l, " ")
		n, _ := strconv.ParseInt(ms, 10, 64)
		v, _ := base64.StdEncoding.DecodeString(enc)
		out = append(out, clipCall{time.UnixMilli(n), string(v)})
	}
	return out
}

// §13.1.5: copy through OSC 52 on a terminal: the exact bytes, then an
// empty value after clipboard.clear_after; the value is never printed.
func TestF5_CopyOSC52(t *testing.T) {
	e, _ := popEnv(t, "[clipboard]\nclear_after = \"2s\"\n")
	e.unlock(fixPass)
	defer e.lock()
	for _, c := range []struct{ field, value string }{
		{"", "s3cr3t-P@ss"},
		{"username", "arsenii"},
		{"notes", "Recovery codes: 1111-2222\nsecond line of notes"},
	} {
		args := []string{"copy", "work/github"}
		if c.field != "" {
			args = append(args, "--field", c.field)
		}
		s := e.start(sessOpts{}, args...)
		want := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(c.value)) + "\x07"
		if !s.expectWithin(want, 10*time.Second) {
			t.Fatalf("copy %v: no OSC 52 with the exact bytes; terminal:\n%q", args, s.raw())
		}
		copied := time.Now()
		if !s.expectWithin("\x1b]52;c;\x07", 8*time.Second) {
			t.Errorf("copy %v: not cleared within 8 s (clear_after 2s)", args)
		}
		if d := time.Since(copied); d < 1500*time.Millisecond {
			t.Errorf("copy %v: cleared after %v, before clear_after", args, d)
		}
		r := s.waitOK()
		mustContain(t, "copy", r.term, "cleared")
		raw := strings.ReplaceAll(string(s.raw()), want, "")
		if strings.Contains(raw, c.value) || strings.Contains(raw, strings.Split(c.value, "\n")[0]) {
			t.Errorf("copy %v printed the value", args)
		}
	}
}

// §13.1.5: copy through clipboard.command (stdin), cleared after
// clear_after; Ctrl-C clears at once; without any clipboard, a hint and no
// secret.
func TestF5_CopyCommand(t *testing.T) {
	f := fixtures(t)
	e := newEnv(t)
	cmd, log := fakeClipboard(t, filepath.Join(e.root, "clip"))
	e.installVault(f.pop, "[clipboard]\nclear_after = \"2s\"\ncommand = [\""+cmd+"\"]\n")
	e.unlock(fixPass)
	defer e.lock()

	start := time.Now()
	r := e.ok("copy", "work/github") // no terminal: the command needs none
	calls := readClipLog(t, log)
	if len(calls) != 2 || calls[0].value != "s3cr3t-P@ss" || calls[1].value != "" {
		t.Fatalf("clipboard command calls = %+v, want the password then an empty value", calls)
	}
	if d := calls[1].at.Sub(calls[0].at); d < 1500*time.Millisecond || d > 6*time.Second {
		t.Errorf("cleared %v after the copy, clear_after 2s", d)
	}
	if time.Since(start) < 1500*time.Millisecond {
		t.Errorf("copy returned before the clear (§6.3: non-TUI copy waits)")
	}
	mustNotContain(t, "copy output", r.all(), "s3cr3t-P@ss")

	// Ctrl-C on a terminal clears at once.
	_ = os.Remove(log)
	e.writeConfig("[clipboard]\nclear_after = \"30s\"\ncommand = [\"" + cmd + "\"]\n")
	s := e.start(sessOpts{}, "copy", "work/github")
	s.mustScreen(10*time.Second, "clears in 30s")
	time.Sleep(200 * time.Millisecond)
	sent := time.Now()
	s.send("\x03")
	s.wait()
	calls = readClipLog(t, log)
	if len(calls) != 2 || calls[1].value != "" || calls[1].at.Sub(sent) > 3*time.Second {
		t.Errorf("Ctrl-C: clipboard calls = %+v, want the clear at once", calls)
	}

	// Neither OSC 52 (no terminal) nor a command: a hint, no secret.
	e.writeConfig("")
	r = e.run("copy", "work/github")
	if r.code == 0 || !strings.Contains(r.stderr, "passh show work/github --field password |") {
		t.Errorf("copy without a clipboard: want the §6.3 hint, got %s", r)
	}
	mustNotContain(t, "copy without a clipboard", r.all(), "s3cr3t-P@ss")
}

// §3.3, §13.1.5: the config written by init clears the clipboard after 30 s
// (explicitly or by default).
func TestF5_DefaultClearAfter(t *testing.T) {
	e := newEnv(t)
	if r := e.initVault(fixPass); r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	var cfg map[string]any
	if _, err := toml.DecodeFile(e.config, &cfg); err != nil {
		t.Fatalf("the config written by init isn't TOML: %v", err)
	}
	if cb, ok := cfg["clipboard"].(map[string]any); ok {
		if v, ok := cb["clear_after"]; ok && v != "30s" {
			t.Errorf("init wrote clipboard.clear_after = %v, want 30s", v)
		}
	}
	// The effective value, as copy reports it.
	cmd, _ := fakeClipboard(t, filepath.Join(e.root, "clip"))
	cfgText := string(readFile(t, e.config))
	if !strings.Contains(cfgText, "[clipboard]") {
		cfgText += "\n[clipboard]\ncommand = [\"" + cmd + "\"]\n"
	} else {
		cfgText = strings.Replace(cfgText, "[clipboard]", "[clipboard]\ncommand = [\""+cmd+"\"]", 1)
		cfgText = removeKeyLine(cfgText, "command", 1)
	}
	writeFile(t, e.config, []byte(cfgText), 0o600)
	e.unlock(fixPass)
	defer e.lock()
	e.ok("generate", "x/y")
	s := e.start(sessOpts{}, "copy", "x/y")
	if !s.waitScreen(10*time.Second, "clears in 30s") {
		t.Errorf("default clear_after isn't 30s:\n%s", s.screen())
	}
	s.send("\x03")
	s.wait()
}

// removeKeyLine drops the second and later lines that set key (so an
// inserted line wins over a commented or empty default).
func removeKeyLine(text, key string, keep int) string {
	var out []string
	seen := 0
	for _, l := range strings.Split(text, "\n") {
		tl := strings.TrimSpace(l)
		if strings.HasPrefix(tl, key+" ") || strings.HasPrefix(tl, key+"=") {
			seen++
			if seen > keep {
				continue
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
