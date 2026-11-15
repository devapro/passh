package tui

import (
	"regexp"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// sgr matches the styling sequences the TUI itself emits (lipgloss: bold,
// faint, reverse, colours). Nothing else may start with ESC.
var sgr = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

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
	h.m.lock(0)
	h.m.lk.setMsg("bad "+title, true)
	h.checkInert("lock message")
}
