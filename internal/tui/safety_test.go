package tui

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vaultfile"
)

// sgr matches the styling sequences the TUI itself emits (lipgloss: bold,
// faint, reverse, the basic colours): the frame's allow-list. Nothing else
// may start with ESC.
var sgr = sgrSeq

// checkInert fails if the view holds anything a terminal would interpret
// other than the TUI's own SGR styling: ESC, BEL, CR, other C0 controls,
// C1 controls (U+0080–U+009F, the 8-bit CSI among them, and a raw 0x9b
// byte) or bidi overrides.
func (h *harness) checkInert(what string) {
	h.t.Helper()
	v := sgr.ReplaceAllString(h.view(), "")
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == 0x9b {
			h.t.Fatalf("%s: raw 0x9b byte at %d", what, i)
		}
		if c < 0x20 && c != '\n' || c == 0x7f {
			h.t.Fatalf("%s: control byte %#x at %d: %q", what, c, i, v[max(i-20, 0):min(i+20, len(v))])
		}
	}
	for _, r := range v {
		if r >= 0x80 && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			h.t.Fatalf("%s: dangerous rune %U in the view", what, r)
		}
	}
}

const (
	osc52    = "\x1b]52;c;ZXZpbA==\x07"
	csi      = "\x1b[2J\x1b[31m"
	csi8     = "\u009b31m"
	title    = "\x1b]0;pwned\x07"
	bidiPath = "evil\u202eplh/\u2066x\u2069"
)

// Safety test 3 (TUI part): escape sequences in entry content, OSC 52
// included, render inert (S4).
func TestEscapeSequencesInert(t *testing.T) {
	evil := model.Entry{
		Path:     paths.MustParse(bidiPath + "/" + "]52;c;name"),
		Password: "pw" + osc52 + csi8,
		Username: "user" + osc52 + csi + csi8,
		URL:      "https://x" + title + csi8,
		Tags:     []string{"tag\u202e", "]52;c;"},
		Fields: []model.Field{
			{Key: "info", Value: "v" + osc52 + csi + "\u0085" + csi8},
			{Key: "otp", Value: "otpauth://" + osc52},
		},
		Notes: "line1" + osc52 + "\n\tline2" + csi + "\rover\n" + csi8 + title + "\x00\x7f",
	}
	h := newHarness(t, append(sampleEntries(), evil))
	h.checkInert("unlocked")
	h.selectPath(evil.Path.String())
	h.checkInert("selected")
	// The sequences show as text.
	h.contains(`user\x1b]52;c;ZXZpbA==\x07\x1b[2J\x1b[31m\u009b31m`, `\x1b]0;pwned\x07`, "\\u202e")
	h.press("r")
	h.checkInert("revealed")
	h.contains(`pw\x1b]52;c;ZXZpbA==\x07\u009b31m`, `otpauth://\x1b]52`)
	h.press("enter")
	h.checkInert("detail")
	h.contains(`line1\x1b]52;c;`, `\x1b[2J\x1b[31m\rover`, `\x00\x7f`, `\u0085`)
	h.press("down", "down", "down", "esc")
	for _, size := range [][2]int{{40, 20}, {80, 24}, {120, 40}} {
		h.resize(size[0], size[1])
		h.checkInert("resized")
		h.press("enter")
		h.checkInert("resized detail")
		h.press("esc")
	}
	h.resize(100, 30)

	// Every place a value can show up: tags view, search, prompts, the
	// form, the status line.
	h.press("tab")
	h.checkInert("tags view")
	h.press("space", "down")
	h.checkInert("tag selected")
	h.press("tab", "/")
	h.typeText("52")
	h.checkInert("search")
	h.press("esc")
	h.selectPath(evil.Path.String())
	h.press("m")
	h.checkInert("move prompt")
	h.press("esc", "t")
	h.checkInert("tags prompt")
	h.press("esc", "e")
	h.checkInert("form")
	h.press("esc")
	h.press("u")
	h.checkInert("copied")
	h.press("d")
	h.checkInert("delete question")
	h.press("y")
	h.checkInert("deleted")
	h.contains("Deleted evil")

	// Typed or pasted control characters are inert too.
	h.press("/")
	h.send(pasteMsg(osc52 + csi8))
	h.checkInert("pasted search")
	h.press("esc", "L")
	h.send(pasteMsg(osc52))
	h.checkInert("lock screen")
}

// An error message carrying entry content is escaped as well.
func TestStatusInert(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.m.setStatus("boom "+osc52+csi8, true)
	h.checkInert("status")
	if !strings.Contains(h.plain(), `boom \x1b]52;c;`) {
		t.Fatalf("status:\n%s", h.plain())
	}
	h.run(h.m.lock(0))
	h.m.lk.setMsg("bad "+title, true)
	h.checkInert("lock message")
}

// The frame is the choke point of S4: View escapes everything in it but the
// TUI's own styling, so a value that missed its sanitize call can't drive
// the terminal (review rule notes, INV-5). inertStyled is checked on a
// frame built from unescaped values; the screens below are checked through
// View with escape sequences in every field a screen shows.
func TestFrameInert(t *testing.T) {
	raw := osc52 + csi + csi8 + title + "\r\x00\u202e" +
		"\x1b[8mhidden\x1b[m" + "\x1b[5mblink" + "\x1b[38;2;1;2;3mrgb" + "\x1b]8;;https://x\x07link" + "\x1bPdcs\x1b\\"
	frame := styleTitle.Render("title "+raw) + "\n" + styleError.Render(raw) + "\n" + raw
	got := inertStyled(frame)
	if rest := sgr.ReplaceAllString(got, ""); strings.ContainsAny(rest, "\x1b\x07\r\x00\u009b\u202e") {
		t.Fatalf("inertStyled left a control sequence: %q", rest)
	}
	for _, want := range []string{"\x1b[1m", "\x1b[31m", `\x1b]52;c;`, `\x1b[8mhidden`, `\x1b[5mblink`, `\x1b[38;2;1;2;3m`, `\x1b]8;;`, `\u202e`} {
		if !strings.Contains(got, want) {
			t.Errorf("inertStyled(frame) lacks %q: %q", want, got)
		}
	}
	if again := inertStyled(got); again != got {
		t.Errorf("inertStyled isn't idempotent: %q", again)
	}

	evil := model.Entry{
		Path:     paths.MustParse("evil" + "\u202e" + "/x" + "]52;c;"),
		Password: "pw" + osc52,
		Username: "user" + csi,
		URL:      "u" + title,
		Tags:     []string{"t" + "\u202e"},
		Fields:   []model.Field{{Key: "k", Value: "v" + osc52}},
		Notes:    "n" + csi8 + "\r" + osc52,
	}
	h := newHarness(t, append(sampleEntries(), evil), func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true })
	h.selectPath(evil.Path.String())
	screens := []struct {
		name string
		open func()
	}{
		{"list and pane", func() {}},
		{"revealed detail", func() { h.press("r", "enter") }},
		{"help", func() { h.press("esc", "?") }},
		{"narrow", func() { h.press("x"); h.resize(40, 20) }},
		{"narrow detail", func() { h.selectPath(evil.Path.String()); h.press("enter") }},
		{"wide again", func() { h.press("esc"); h.resize(100, 30) }},
		{"print setup", func() { h.selectPath(evil.Path.String()); h.press("P") }},
		{"tags prompt", func() { h.press("esc"); h.selectPath(evil.Path.String()); h.press("t") }},
		{"form", func() { h.press("esc", "e") }},
		{"status", func() { h.press("esc"); h.m.setStatus("boom "+raw, true) }},
		{"delete question", func() { h.selectPath(evil.Path.String()); h.press("d") }},
		{"rollback question", func() { h.press("n"); h.m.confirm = &confirm{kind: confirmRollback, text: raw} }},
		{"lock screen", func() { h.m.confirm = nil; h.press("L"); h.m.lk.setMsg(raw, true) }},
		{"lock screen question", func() { h.m.lk.ask = raw }},
		{"lock screen busy", func() { h.m.lk.ask, h.m.lk.busy, h.m.lk.busyText = "", true, raw }},
	}
	for _, s := range screens {
		s.open()
		h.checkInert(s.name)
	}
}

// A key block that asks for more scrypt work than passh uses is refused
// before scrypt runs, with a message that says a passphrase can't help.
func TestWorkFactorOnLockScreen(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	// The stanza's work factor is checked before the header's MAC.
	kb := regexp.MustCompile(`(-> scrypt \S+) 4\n`).ReplaceAll(f.KeyBlock, []byte("$1 30\n"))
	if bytes.Equal(kb, f.KeyBlock) {
		t.Fatal("no scrypt stanza with work factor 4 in the key block")
	}
	file, err := vaultfile.Encode(kb, f.DataBlock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	h.typeText(testPass)
	h.press("enter")
	if h.m.screen != screenLock || h.quit {
		t.Fatal("opened, or quit")
	}
	h.contains("asks for more scrypt work than passh ever uses", "Restore a backup")
	h.lacks("Wrong passphrase")
}
