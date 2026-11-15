package editor

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/gen"
	"github.com/devapro/passh/internal/model"
)

// key builds the key press that Bubble Tea reports for a name such as
// "tab", "shift+tab", "ctrl+s" or "a".
func key(t *testing.T, name string) tea.KeyPressMsg {
	t.Helper()
	parts := strings.Split(name, "+")
	var k tea.KeyPressMsg
	for _, m := range parts[:len(parts)-1] {
		switch m {
		case "ctrl":
			k.Mod |= tea.ModCtrl
		case "alt":
			k.Mod |= tea.ModAlt
		case "shift":
			k.Mod |= tea.ModShift
		}
	}
	codes := map[string]rune{
		"tab": tea.KeyTab, "enter": tea.KeyEnter, "esc": tea.KeyEscape, "backspace": tea.KeyBackspace,
		"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
		"home": tea.KeyHome, "end": tea.KeyEnd, "delete": tea.KeyDelete,
		"pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown, "space": tea.KeySpace,
	}
	last := parts[len(parts)-1]
	if c, ok := codes[last]; ok {
		k.Code = c
	} else {
		k.Code = []rune(last)[0]
		if k.Mod == 0 {
			k.Text = last
		}
	}
	if k.String() != name {
		t.Fatalf("key %q reports itself as %q", name, k.String())
	}
	return k
}

func press(t *testing.T, f *Form, names ...string) tea.Cmd {
	t.Helper()
	var cmd tea.Cmd
	for _, n := range names {
		_, cmd = f.Update(key(t, n))
	}
	return cmd
}

func typeText(f *Form, s string) {
	for _, r := range s {
		f.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
}

func paste(f *Form, s string) { f.Update(tea.PasteMsg{Content: s}) }

func plain(f *Form) string { return ansi.Strip(f.View()) }

func saved(t *testing.T, f *Form) model.Entry {
	t.Helper()
	if !f.Done() {
		t.Fatalf("the form is still open:\n%s", plain(f))
	}
	e, err := f.Result()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestFormEditsEveryField(t *testing.T) {
	e := sampleEntry(t)
	f := NewForm(e, FormOptions{Title: "edit work/github"})
	f.SetSize(80, 24)
	if f.Init() != nil {
		t.Error("Init returned a command")
	}
	if f.focus != fieldPassword {
		t.Fatalf("focus starts on %d", f.focus)
	}
	press(t, f, "ctrl+u")
	typeText(f, "new pw")
	press(t, f, "tab", "ctrl+u")
	typeText(f, "bob")
	press(t, f, "enter", "tab", "ctrl+u") // url unchanged, then tags
	typeText(f, "home, Work ,home")
	press(t, f, "tab")
	typeText(f, "X") // notes, at the start
	press(t, f, "ctrl+s")
	got := saved(t, f)

	want := e.Clone()
	want.Password, want.Username, want.Tags, want.Notes = "new pw", "bob", []string{"home", "Work"}, "XRecovery codes.\nline two"
	if !got.Equal(want) || jsonOf(t, got) != jsonOf(t, want) {
		t.Fatalf("result\n%s\nwant\n%s", jsonOf(t, got), jsonOf(t, want))
	}
	// Done: further input is ignored.
	typeText(f, "zzz")
	if again := saved(t, f); !again.Equal(got) {
		t.Fatal("input after saving changed the result")
	}
}

func TestFormUnchangedKeepsExactValues(t *testing.T) {
	e := sampleEntry(t)
	e.Password = "\tp\x01w\u202e"         // control and bidi characters, as an import may bring
	e.Notes = "a\r\nb\x1b[2J\n\tindented" // CR, escape sequence, tab
	f := NewForm(e, FormOptions{})
	if f.Changed() {
		t.Fatal("a new form reports changes")
	}
	press(t, f, "tab", "tab", "tab", "tab", "ctrl+s")
	got := saved(t, f)
	if !got.Equal(e) {
		t.Fatalf("saving untouched values changed them: %q %q", got.Password, got.Notes)
	}
}

func TestFormNewEntry(t *testing.T) {
	f := NewForm(model.Entry{}, FormOptions{Title: "add work/gitlab"})
	if !strings.Contains(plain(f), "(empty)") {
		t.Errorf("empty password not shown as such:\n%s", plain(f))
	}
	typeText(f, "pw")
	press(t, f, "alt+enter")
	if got := saved(t, f); got.Password != "pw" || got.Tags != nil || got.Notes != "" {
		t.Fatalf("result %+v", got)
	}
	if _, err := NewForm(model.Entry{}, FormOptions{}).Result(); err == nil {
		t.Error("Result of an open form succeeded")
	}
}

func TestFormCancel(t *testing.T) {
	f := NewForm(sampleEntry(t), FormOptions{})
	press(t, f, "esc")
	if _, err := f.Result(); !errors.Is(err, ErrCancelled) {
		t.Fatalf("esc without changes: %v, want ErrCancelled", err)
	}

	f = NewForm(sampleEntry(t), FormOptions{})
	press(t, f, "tab")
	typeText(f, "x")
	press(t, f, "esc")
	if f.Done() || !strings.Contains(plain(f), "Discard the changes?") {
		t.Fatalf("esc with changes didn't ask:\n%s", plain(f))
	}
	typeText(f, "y") // any other key keeps editing, and is not typed
	if f.Done() || strings.Contains(plain(f), "Discard") || f.in[fieldUsername].String() != "arseniix" {
		t.Fatalf("after keeping: done %v, username %q", f.Done(), f.in[fieldUsername].String())
	}
	press(t, f, "esc")
	paste(f, "pasted") // closes the question too, and is dropped
	if f.Done() || f.confirming || strings.Contains(f.in[fieldUsername].String(), "pasted") {
		t.Fatal("a paste during the question was taken")
	}
	press(t, f, "ctrl+c", "ctrl+c")
	if _, err := f.Result(); !errors.Is(err, ErrCancelled) {
		t.Fatalf("ctrl+c twice: %v, want ErrCancelled", err)
	}
}

func TestFormPasswordMasking(t *testing.T) {
	const secret = "correct-horse-battery"
	e := sampleEntry(t)
	e.Password = secret
	f := NewForm(e, FormOptions{})
	v := f.View()
	if strings.Contains(v, secret) || strings.Contains(v, "correct") || !strings.Contains(v, Mask) {
		t.Fatalf("hidden password view:\n%s", plain(f))
	}
	// The mask has a fixed length.
	short := NewForm(model.Entry{Password: "ab"}, FormOptions{})
	if !strings.Contains(plain(short), "› password  "+Mask+" ") {
		t.Errorf("short password: %q", strings.Split(plain(short), "\n")[0])
	}

	// Hidden: no cursor movement, appending and erasing at the end only.
	press(t, f, "home", "left")
	typeText(f, "!")
	press(t, f, "backspace", "backspace")
	if got := f.in[fieldPassword].String(); got != secret[:len(secret)-1] {
		t.Fatalf("masked editing: %q", got)
	}
	if !strings.Contains(plain(f), "changed") {
		t.Error("no change marker")
	}
	press(t, f, "ctrl+w")
	if f.in[fieldPassword].String() != "" {
		t.Fatal("ctrl+w didn't clear the hidden password")
	}
	typeText(f, secret)

	cmd := press(t, f, "ctrl+r")
	if cmd == nil {
		t.Fatal("reveal returned no timer")
	}
	if !strings.Contains(plain(f), secret) || !strings.Contains(plain(f), "hides again in 10 s") {
		t.Fatalf("revealed view:\n%s", plain(f))
	}
	firstSeq := f.revealSeq
	f.Update(hideMsg{form: f.id, seq: firstSeq})
	if strings.Contains(plain(f), secret) {
		t.Fatal("still shown after the timer")
	}

	// A stale timer doesn't hide a newer reveal; another form's doesn't either.
	press(t, f, "ctrl+r")
	f.Update(hideMsg{form: f.id, seq: firstSeq})
	other := NewForm(model.Entry{}, FormOptions{})
	f.Update(hideMsg{form: other.id, seq: f.revealSeq})
	if !strings.Contains(plain(f), secret) {
		t.Fatal("a stale timer hid the password")
	}
	if cmd := press(t, f, "ctrl+r"); cmd != nil || strings.Contains(plain(f), secret) {
		t.Fatal("ctrl+r didn't hide it again")
	}
	press(t, f, "ctrl+s")
	if got := saved(t, f); got.Password != secret {
		t.Fatalf("password %q", got.Password)
	}
}

func TestFormRevealedEditing(t *testing.T) {
	f := NewForm(model.Entry{Password: "abcdef"}, FormOptions{})
	press(t, f, "ctrl+r", "home", "right", "delete")
	typeText(f, "X")
	if got := f.in[fieldPassword].String(); got != "aXcdef" {
		t.Fatalf("password %q", got)
	}
	press(t, f, "end", "ctrl+w")
	typeText(f, "pass word")
	press(t, f, "alt+b", "ctrl+k", "ctrl+a", "alt+f", "alt+d")
	if got := f.in[fieldPassword].String(); got != "pass" {
		t.Fatalf("password %q", got)
	}
}

func TestFormGenerate(t *testing.T) {
	rnd := bytes.NewReader(bytes.Repeat([]byte{0, 1, 2, 3}, 16))
	f := NewForm(sampleEntry(t), FormOptions{Gen: gen.Options{Length: 12, Rand: rnd}})
	press(t, f, "tab", "ctrl+g") // works from any field
	pw := f.in[fieldPassword].String()
	if pw != "ABCDABCDABCD" {
		t.Fatalf("generated %q", pw)
	}
	if v := plain(f); strings.Contains(v, pw) || !strings.Contains(v, "Generated a new password (12 characters)") {
		t.Fatalf("view after generating:\n%s", v)
	}
	press(t, f, "ctrl+s")
	if got := saved(t, f); got.Password != pw {
		t.Fatalf("saved %q", got.Password)
	}

	f = NewForm(model.Entry{}, FormOptions{Gen: gen.Options{Alphabet: "a"}})
	press(t, f, "ctrl+g")
	if !strings.Contains(plain(f), "Generating a password failed") || f.in[fieldPassword].String() != "" {
		t.Fatalf("bad alphabet:\n%s", plain(f))
	}
}

func TestFormLineBreaks(t *testing.T) {
	f := NewForm(model.Entry{}, FormOptions{})
	paste(f, "p@ss\r\n") // into the hidden password: the trailing break goes
	press(t, f, "tab")
	paste(f, "bob\n")
	paste(f, "by\nmistake")
	if v := plain(f); !strings.Contains(v, "paste refused: username is a single line") {
		t.Fatalf("multi-line paste not refused:\n%s", v)
	}
	typeText(f, "!") // typing clears the message
	if strings.Contains(plain(f), "paste refused") {
		t.Error("the message stayed")
	}
	paste(f, "\xff")
	if !strings.Contains(plain(f), "not valid UTF-8") {
		t.Error("invalid UTF-8 paste not refused")
	}
	f.Update(tea.KeyPressMsg{Code: 'x', Text: "x\ny"}) // never inserts a line break
	press(t, f, "shift+tab", "shift+tab")              // to the notes
	paste(f, "one\r\ntwo\rthree")
	press(t, f, "enter")
	typeText(f, "four")
	paste(f, "\xfe")
	press(t, f, "ctrl+s")
	got := saved(t, f)
	if got.Password != "p@ss" || got.Username != "bob!xy" || got.Notes != "one\ntwo\nthree\nfour" {
		t.Fatalf("result %q %q %q", got.Password, got.Username, got.Notes)
	}
}

func TestFormTagErrorInline(t *testing.T) {
	f := NewForm(model.Entry{}, FormOptions{})
	press(t, f, "tab", "tab", "tab")
	paste(f, "ok, bad\ttag")
	press(t, f, "tab", "ctrl+s")
	if f.Done() {
		t.Fatal("saved with an invalid tag")
	}
	if f.focus != fieldTags {
		t.Error("focus didn't go to the tags")
	}
	lines := strings.Split(plain(f), "\n")
	i := slicesIndexFunc(lines, func(l string) bool { return strings.Contains(l, "tags") })
	if i < 0 || i+1 >= len(lines) || !strings.Contains(lines[i+1], `invalid tag "bad\ttag"`) {
		t.Fatalf("no inline error under the tags:\n%s", plain(f))
	}
	press(t, f, "ctrl+u")
	typeText(f, "ok, good")
	press(t, f, "ctrl+s")
	if got := saved(t, f); strings.Join(got.Tags, "|") != "ok|good" {
		t.Fatalf("tags %q", got.Tags)
	}
}

func slicesIndexFunc(s []string, f func(string) bool) int {
	for i, v := range s {
		if f(v) {
			return i
		}
	}
	return -1
}

func TestFormEscapesContent(t *testing.T) {
	e := sampleEntry(t)
	e.Username = "evil\x1b]52;c;aGk=\a"
	e.URL = "\u202egro.elgoog"
	e.Notes = "clear\x1b[2Jscreen\u009b31m"
	e.Fields = append(e.Fields, model.Field{Key: "k", Value: "v"})
	f := NewForm(e, FormOptions{Title: "edit \x1b]0;title\a"})
	f.SetSize(100, 30)
	raw := f.View()
	for _, bad := range []string{"\x1b]", "\a", "\x1b[2J", "\u202e", "\u009b"} {
		if strings.Contains(raw, bad) {
			t.Errorf("view contains %q", bad)
		}
	}
	v := plain(f)
	for _, want := range []string{`evil\x1b]52;c;aGk=\x07`, `\u202egro.elgoog`, `clear\x1b[2Jscreen\u009b31m`, `edit \x1b]0;title\x07`,
		"recovery-email, pin, k (kept as they are"} {
		if !strings.Contains(v, want) {
			t.Errorf("view lacks %q:\n%s", want, v)
		}
	}
}

func TestFormLayoutFits(t *testing.T) {
	e := sampleEntry(t)
	e.URL = "https://example.com/a/very/long/url/that/does/not/fit/in/forty/columns/at/all?with=query&and=more"
	e.Notes = strings.Repeat("A long line of notes that has to wrap on a narrow terminal. ", 6) + "\nshort\n\n" + strings.Repeat("line\n", 30)
	for _, size := range [][2]int{{80, 24}, {40, 24}, {40, 16}, {120, 40}, {30, 12}} {
		w, h := size[0], size[1]
		f := NewForm(e, FormOptions{Title: "edit work/github"})
		f.SetSize(w, h)
		for _, focus := range []int{fieldPassword, fieldURL, fieldNotes} {
			f.focus = focus
			f.scroll()
			v := plain(f)
			lines := strings.Split(v, "\n")
			if len(lines) > h {
				t.Errorf("%dx%d focus %d: %d lines", w, h, focus, len(lines))
			}
			for _, l := range lines {
				if ansi.StringWidth(l) > w {
					t.Errorf("%dx%d: line wider than the terminal: %q", w, h, l)
				}
			}
			if !strings.Contains(v, "ctrl+s save") || !strings.Contains(v, "notes") {
				t.Errorf("%dx%d: missing parts:\n%s", w, h, v)
			}
		}
		if w == 40 || w == 80 {
			f.focus = fieldPassword
			t.Logf("%dx%d:\n%s", w, h, plain(f))
		}
	}
}

func TestFormFocusMovement(t *testing.T) {
	f := NewForm(sampleEntry(t), FormOptions{})
	steps := []struct {
		key  string
		want int
	}{
		{"tab", fieldUsername}, {"enter", fieldURL}, {"down", fieldTags}, {"up", fieldURL},
		{"ctrl+n", fieldTags}, {"ctrl+p", fieldURL}, {"tab", fieldTags}, {"tab", fieldNotes},
		{"tab", fieldPassword}, {"shift+tab", fieldNotes}, {"shift+tab", fieldTags},
	}
	for _, s := range steps {
		press(t, f, s.key)
		if f.focus != s.want {
			t.Fatalf("after %s: focus %d, want %d", s.key, f.focus, s.want)
		}
	}
	// Up on the first row of the notes leaves them.
	press(t, f, "tab", "down", "up", "up")
	if f.focus != fieldTags {
		t.Fatalf("up from the notes' first row: focus %d", f.focus)
	}
}

func TestFormNotesEditing(t *testing.T) {
	f := NewForm(model.Entry{Notes: "ab\ncd"}, FormOptions{})
	f.SetSize(40, 20)
	press(t, f, "shift+tab")    // notes, at 0,0
	press(t, f, "end", "enter") // split after "ab"
	typeText(f, "x")
	press(t, f, "down", "end", "backspace", "home", "backspace") // "c" joins "x"
	if got := f.notes.String(); got != "ab\nxc" {
		t.Fatalf("notes %q", got)
	}
	press(t, f, "ctrl+a", "delete", "ctrl+e", "delete") // remove "x"; delete at the end of the last line does nothing
	press(t, f, "up", "ctrl+e", "delete")               // join
	if got := f.notes.String(); got != "abc" {
		t.Fatalf("notes %q", got)
	}
	typeText(f, " word")
	press(t, f, "ctrl+w", "alt+b", "ctrl+k")
	if got := f.notes.String(); got != "" {
		t.Fatalf("notes %q", got)
	}
	typeText(f, "one two")
	press(t, f, "alt+b", "alt+d", "ctrl+u", "left", "right", "alt+f")
	if got := f.notes.String(); got != "" || f.notes.col != 0 {
		t.Fatalf("notes %q col %d", got, f.notes.col)
	}
	typeText(f, "x")
	press(t, f, "enter")
	typeText(f, "y")
	press(t, f, "ctrl+a", "ctrl+w", "left", "right", "alt+left", "alt+right", "ctrl+k")
	if got := f.notes.String(); got != "xy" {
		t.Fatalf("notes %q", got)
	}
}

func TestFormNotesWrapAndScroll(t *testing.T) {
	long := strings.Repeat("0123456789", 10) // 100 cells
	var lines []string
	for range 40 {
		lines = append(lines, "row")
	}
	f := NewForm(model.Entry{Notes: long + "\n" + strings.Join(lines, "\n")}, FormOptions{})
	f.SetSize(40, 16)
	press(t, f, "shift+tab") // notes at 0,0
	w := f.notesWidth()
	rows := f.notes.layout(w)
	if rows[0].end-rows[0].start != w-1 || rows[1].line != 0 {
		t.Fatalf("wrapping: %+v (width %d)", rows[:3], w)
	}
	press(t, f, "right", "right", "down")
	if f.notes.row != 0 || f.notes.col != w-1+2 {
		t.Fatalf("down within a wrapped line: row %d col %d", f.notes.row, f.notes.col)
	}
	press(t, f, "down", "down", "down")
	if f.notes.row != 1 || f.notes.col != 2 {
		t.Fatalf("down past the wrapped line: row %d col %d", f.notes.row, f.notes.col)
	}
	press(t, f, "pgdown", "pgdown", "pgdown", "pgdown", "pgdown", "pgdown", "pgdown", "pgdown")
	if f.notes.row != 40 {
		t.Fatalf("pgdown to the end: row %d", f.notes.row)
	}
	if v := plain(f); !strings.Contains(v, "row") || strings.Contains(v, "0123456789") {
		t.Fatalf("not scrolled to the end:\n%s", v)
	}
	press(t, f, "down") // at the last row: stays
	press(t, f, "pgup", "pgup", "pgup", "pgup", "pgup", "pgup", "pgup", "pgup")
	if f.notes.row != 0 {
		t.Fatalf("pgup to the start: row %d", f.notes.row)
	}
	if v := plain(f); !strings.Contains(v, "0123456789") {
		t.Fatalf("not scrolled back:\n%s", v)
	}
	// The end of a wrapped row is the start of the next one, except at the
	// end of the line, where the reserved cell holds the cursor.
	tw := w - 1
	f.notes.col = tw
	if got := f.notes.cursorRow(f.notes.layout(w)); got != 1 {
		t.Fatalf("cursor at the end of row 0 shows on row %d, want 1", got)
	}
	f.notes.col = len(f.notes.lines[0])
	last := (100+tw-1)/tw - 1
	if got := f.notes.cursorRow(f.notes.layout(w)); got != last {
		t.Fatalf("cursor at the end of the line shows on row %d, want %d", got, last)
	}
}

func TestLineInputScrolling(t *testing.T) {
	in := newLineInput(strings.Repeat("abcdefghij", 5)) // 50 cells
	const w = 20
	in.scroll(w)
	if got := ansi.StringWidth(ansi.Strip(in.view(w, true))); got > w {
		t.Fatalf("view width %d", got)
	}
	if !strings.HasSuffix(ansi.Strip(in.view(w, true)), "hij ") {
		t.Fatalf("end not visible: %q", ansi.Strip(in.view(w, true)))
	}
	in.key("home", false)
	in.scroll(w)
	if v := ansi.Strip(in.view(w, true)); !strings.HasPrefix(v, "abcdefghij") || ansi.StringWidth(v) != w {
		t.Fatalf("start not visible: %q", v)
	}
	// Wide characters and escaped control characters count by their cells.
	in = newLineInput("日本語\x1b")
	if v := ansi.Strip(in.view(w, false)); v != `日本語\x1b` {
		t.Fatalf("view %q", v)
	}
	// 語 (2 cells) + \x1b (4) + the cursor (1) don't fit in 6 cells.
	if got := fitOffset(in.value, len(in.value), 0, 6); got != 3 {
		t.Fatalf("offset for a narrow window: %d", got)
	}
	if got := fitOffset(in.value, len(in.value), 0, 7); got != 2 {
		t.Fatalf("offset for a narrow window: %d", got)
	}
}

func TestFormNoWindowSizeHandling(t *testing.T) {
	f := NewForm(model.Entry{}, FormOptions{})
	f.SetSize(50, 20)
	f.Update(tea.WindowSizeMsg{Width: 200, Height: 100})
	if f.width != 50 || f.height != 20 {
		t.Fatal("the form took the window size; the host sets it")
	}
}
