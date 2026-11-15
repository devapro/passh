package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/model"
)

// checkFits fails if a line of the view is wider than w or there are more
// than h lines.
func (h *harness) checkFits(w, hh int, what string) {
	h.t.Helper()
	lines := strings.Split(h.view(), "\n")
	if len(lines) > hh {
		h.t.Fatalf("%s at %dx%d: %d lines:\n%s", what, w, hh, len(lines), h.plain())
	}
	for i, l := range lines {
		if lw := ansi.StringWidth(l); lw > w {
			h.t.Fatalf("%s at %dx%d: line %d is %d cells wide:\n%s", what, w, hh, i+1, lw, h.plain())
		}
	}
}

func (h *harness) resize(w, hh int) { h.send(tea.WindowSizeMsg{Width: w, Height: hh}) }

func longEntries() []model.Entry {
	es := sampleEntries()
	long := strings.Repeat("very-long-segment-", 8)
	es = append(es,
		entry("deep/"+long+"/x/"+long, func(e *model.Entry) {
			e.Username = strings.Repeat("u", 200)
			e.URL = "https://" + strings.Repeat("x", 150) + ".example"
			e.Tags = []string{strings.Repeat("t", 90), "short"}
			e.Notes = strings.Repeat("word ", 80) + "\n\tindented\n" + strings.Repeat("Ж", 120)
			e.Fields = []model.Field{{Key: strings.Repeat("k", 40), Value: strings.Repeat("v", 100)}}
		}),
		entry("wide/日本語のパス/絵文字🔑", func(e *model.Entry) { e.Username = "名前" }),
	)
	for i := range 40 {
		es = append(es, entry(fmt.Sprintf("many/entry-%02d", i), nil))
	}
	return es
}

// Every screen fits 80×24, as the mockup of §6.2.
func TestLayout80x24(t *testing.T) {
	h := newHarness(t, longEntries())
	h.resize(80, 24)
	check := func(what string) {
		t.Helper()
		h.checkFits(80, 24, what)
	}
	check("main")
	if n := len(strings.Split(h.view(), "\n")); n != 24 {
		t.Fatalf("the main view has %d lines, want 24", n)
	}
	h.contains("┌ passh ── unlocked · locks in 5:00", "VIEW: [Folders]  Tags", "/ search",
		"c copy pw · u copy user · r reveal · e edit · a add · t tags",
		"Tab folders/tags · / search · P print", "L lock · ? help · q quit", "└")
	for _, p := range []string{"work/github", "deep/" + strings.Repeat("very-long-segment-", 8) + "/x/" + strings.Repeat("very-long-segment-", 8), "wide/日本語のパス/絵文字🔑", "many/entry-39"} {
		h.selectPath(p)
		check("entry " + p)
		h.press("r")
		check("revealed " + p)
		h.press("r", "enter")
		check("detail " + p)
		h.press("down", "down", "pgdown", "esc")
	}
	h.press("?")
	check("help")
	h.press("x", "tab", "space", "down", "space")
	check("tags")
	h.press("/")
	h.typeText("entry")
	check("search")
	h.press("esc")
	h.selectPath("work/github")
	h.press("d")
	check("confirm")
	h.press("n", "m")
	check("prompt")
	h.press("esc", "e")
	check("form")
	h.press("esc")
	h.m.changedOnDisk = true
	check("changed on disk")
	h.m.changedOnDisk = false
	h.press("L")
	check("lock screen")
}

// At about 40 columns (a phone over SSH) the TUI uses one pane:
// list → Enter → detail → Esc (§6.2).
func TestNarrowLayout(t *testing.T) {
	h := newHarness(t, longEntries())
	h.resize(40, 20)
	h.checkFits(40, 20, "list")
	h.lacks("│ username") // no detail pane beside the list
	h.contains("[Folders]", "↵ open")
	h.selectPath("work/github")
	h.press("enter")
	if !h.m.detail {
		t.Fatal("Enter didn't open the detail")
	}
	h.checkFits(40, 20, "detail")
	h.contains("work/github", "username", "arsenii", "••••••••", "Esc back")
	h.press("c")
	if h.clip.copies[0].value != "s3cr3t-P@ss" {
		t.Fatal("c in the detail")
	}
	h.press("r")
	h.contains("s3cr3t-P@ss")
	h.checkFits(40, 20, "revealed")
	h.press("down", "down", "down", "down", "down", "down", "down", "down", "down", "down")
	h.checkFits(40, 20, "scrolled")
	h.press("esc")
	if h.m.detail {
		t.Fatal("Esc didn't go back to the list")
	}
	h.lacks("s3cr3t-P@ss")
	h.checkFits(40, 20, "back")

	// r on the list opens the detail with the password shown.
	h.press("r")
	if !h.m.detail || !h.m.revealed(h.m.detailID) {
		t.Fatal("r on the narrow list should open the detail revealed")
	}
	h.press("esc", "?")
	h.checkFits(40, 20, "help")
	h.press("x", "e")
	h.checkFits(40, 20, "form")
	h.press("esc", "/")
	h.typeText("many")
	h.checkFits(40, 20, "search")
	h.press("esc", "t")
	h.checkFits(40, 20, "tags prompt")
	h.press("esc")
	h.selectPath("deep/" + strings.Repeat("very-long-segment-", 8) + "/x/" + strings.Repeat("very-long-segment-", 8))
	h.press("enter")
	h.checkFits(40, 20, "long entry")
}

// No size breaks the layout or panics, down to tiny windows.
func TestLayoutSweep(t *testing.T) {
	h := newHarness(t, longEntries())
	h.selectPath("deep/" + strings.Repeat("very-long-segment-", 8) + "/x/" + strings.Repeat("very-long-segment-", 8))
	for _, w := range []int{1, 10, 19, 20, 25, 30, 39, 40, 41, 60, 79, 80, 81, 100, 160} {
		for _, hh := range []int{1, 3, 5, 6, 8, 10, 12, 16, 24, 50} {
			h.resize(w, hh)
			h.checkFits(w, hh, "main")
			h.press("enter")
			h.checkFits(w, hh, "detail")
			h.press("esc", "?")
			h.checkFits(w, hh, "help")
			h.press("x", "e")
			h.checkFits(w, hh, "form")
			h.press("esc")
		}
	}
	h.press("L")
	for _, w := range []int{1, 20, 40, 80} {
		for _, hh := range []int{1, 5, 24} {
			h.resize(w, hh)
			h.checkFits(w, hh, "lock")
		}
	}
}
