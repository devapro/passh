package editor

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

func TestLineInputEditing(t *testing.T) {
	in := NewLineInput("hello world", false)
	k := func(names ...string) {
		t.Helper()
		for _, n := range names {
			if !in.Update(key(t, n)) {
				t.Fatalf("%s not handled", n)
			}
		}
	}
	want := func(s string, pos int) {
		t.Helper()
		if in.String() != s || in.Cursor() != pos {
			t.Fatalf("got %q at %d, want %q at %d", in.String(), in.Cursor(), s, pos)
		}
	}
	want("hello world", 11)
	k("alt+b")
	want("hello world", 6)
	k("ctrl+w")
	want("world", 0)
	k("alt+f")
	want("world", 5)
	k("home", "right", "delete")
	want("wrld", 1)
	k("ctrl+k")
	want("w", 1)
	k("left", "end", "backspace")
	want("", 0)
	if !in.Empty() {
		t.Fatal("not empty")
	}
	in.Update(tea.KeyPressMsg{Code: 'x', Text: "x\ny"}) // typed line breaks are dropped
	want("xy", 2)
	if in.Update(key(t, "ctrl+s")) || in.Update(key(t, "enter")) {
		t.Fatal("ctrl+s and enter are not editing keys")
	}
	k("ctrl+u")
	if !in.Paste("pasted\n") || in.String() != "pasted" {
		t.Fatalf("paste: %q", in.String())
	}
	if in.Paste("two\nlines") || in.Paste("bad \xff") || in.String() != "pasted" {
		t.Fatal("a multi-line or invalid paste was accepted")
	}
	if string(in.Bytes()) != "pasted" {
		t.Fatal("Bytes")
	}
	in.Wipe()
	if !in.Empty() || in.Cursor() != 0 {
		t.Fatal("Wipe")
	}
	var zero LineInput
	if zero.String() != "" || !zero.Update(tea.KeyPressMsg{Code: 'a', Text: "a"}) || zero.String() != "a" {
		t.Fatal("the zero LineInput isn't usable")
	}
}

func TestLineInputView(t *testing.T) {
	long := NewLineInput(strings.Repeat("abcdefghij", 10), false)
	for _, w := range []int{0, 1, 5, 20} {
		if vw := ansi.StringWidth(long.View(w, true)); vw > max(w, 1) {
			t.Fatalf("view %d cells wide in %d", vw, w)
		}
	}
	if got := ansi.Strip(long.View(20, true)); !strings.HasSuffix(got, "hij ") {
		t.Fatalf("the cursor end isn't visible: %q", got)
	}
	long.Update(key(t, "home"))
	if got := ansi.Strip(long.View(20, true)); !strings.HasPrefix(got, "abc") {
		t.Fatalf("home: %q", got)
	}
	if got := ansi.Strip(long.View(20, false)); !strings.HasSuffix(got, "…") {
		t.Fatalf("unfocused long value: %q", got)
	}
	// S4: a control character shows as text.
	ctl := NewLineInput("a\x1b]52;c;x\x07b", false)
	if got := ansi.Strip(ctl.View(40, false)); got != `a\x1b]52;c;x\x07b` {
		t.Fatalf("control characters shown as %q", got)
	}
}

func TestLineInputMasked(t *testing.T) {
	in := NewLineInput("", true)
	if got := ansi.Strip(in.View(20, true)); got != " " {
		t.Fatalf("empty masked view %q", got)
	}
	in.Update(tea.KeyPressMsg{Code: 's', Text: "secret"})
	if in.View(20, false) != Mask {
		t.Fatalf("masked view %q", in.View(20, false))
	}
	// Movement does nothing; editing happens at the end.
	in.Update(key(t, "home"))
	in.Update(key(t, "left"))
	in.Update(tea.KeyPressMsg{Code: '!', Text: "!"})
	in.Update(key(t, "backspace"))
	in.Update(key(t, "backspace"))
	if in.String() != "secre" {
		t.Fatalf("masked editing: %q", in.String())
	}
	if !in.Paste("X") || in.String() != "secreX" {
		t.Fatalf("masked paste: %q", in.String())
	}
	in.Update(key(t, "ctrl+w"))
	if !in.Empty() {
		t.Fatal("ctrl+w should clear a masked input")
	}
}

func TestFormResume(t *testing.T) {
	e := model.Entry{Path: paths.MustParse("work/x"), Password: "old", Username: "u"}
	f := NewForm(e, FormOptions{Title: "edit work/x"})
	f.SetSize(80, 24)
	f.Resume("ignored") // still open: nothing happens
	press(t, f, "tab", "ctrl+u")
	typeText(f, "bob")
	press(t, f, "ctrl+s")
	first := saved(t, f)
	if first.Username != "bob" {
		t.Fatalf("result %+v", first)
	}
	f.Resume("Not saved: the vault changed on disk.")
	if f.Done() {
		t.Fatal("Resume didn't reopen the form")
	}
	if _, err := f.Result(); err == nil {
		t.Fatal("an open form has a result")
	}
	if !strings.Contains(plain(f), "Not saved: the vault changed on disk.") || !strings.Contains(plain(f), "bob") {
		t.Fatalf("view after Resume:\n%s", plain(f))
	}
	if !f.Changed() {
		t.Fatal("Changed must still compare with the starting values")
	}
	// Esc asks, because the input differs from the start.
	press(t, f, "esc")
	if f.Done() || !strings.Contains(plain(f), "Discard the changes?") {
		t.Fatalf("esc after Resume:\n%s", plain(f))
	}
	press(t, f, "x") // keep editing
	typeText(f, "2")
	press(t, f, "ctrl+s")
	if got := saved(t, f); got.Username != "bob2" || got.Password != "old" {
		t.Fatalf("second result %+v", got)
	}

	// A cancelled form stays cancelled.
	c := NewForm(e, FormOptions{})
	press(t, c, "esc")
	c.Resume("x")
	if !c.Done() {
		t.Fatal("Resume reopened a cancelled form")
	}
}
