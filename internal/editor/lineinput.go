package editor

import (
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// LineInput is a one-line text input for hosts outside this package (the
// TUI's passphrase, search, path and tag prompts). It is the form's own
// single-line widget: values are kept exactly, every rune is shown through
// sanitize.Line (S4), and nothing reads the system clipboard (S8).
//
// A Masked input shows Mask instead of its text and edits only at its end,
// so nothing about the hidden value shows through cursor movement. Wipe
// overwrites the value; Bytes returns it without making a string, so a
// passphrase can be wiped afterwards.
//
// The zero value is an empty, unmasked input.
type LineInput struct {
	in lineInput
	// Masked hides the value (a passphrase).
	Masked bool
}

// NewLineInput returns an input holding s, with the cursor at its end.
func NewLineInput(s string, masked bool) LineInput {
	return LineInput{in: newLineInput(s), Masked: masked}
}

// String returns the value.
func (l *LineInput) String() string { return l.in.String() }

// Empty reports whether the value is empty.
func (l *LineInput) Empty() bool { return len(l.in.value) == 0 }

// Cursor returns the cursor position, in runes from the start.
func (l *LineInput) Cursor() int { return l.in.pos }

// Bytes returns the value as UTF-8 in a new slice, without making a string.
func (l *LineInput) Bytes() []byte {
	b := make([]byte, 0, len(l.in.value)*utf8.UTFMax)
	for _, r := range l.in.value {
		b = utf8.AppendRune(b, r)
	}
	return b
}

// Wipe overwrites the value with zeros and empties the input.
func (l *LineInput) Wipe() {
	clear(l.in.value[:cap(l.in.value)])
	l.in = lineInput{}
}

// Update applies an editing key (readline style: ctrl+a, ctrl+e, ctrl+u,
// ctrl+k, ctrl+w, alt+b, alt+f, …) or typed text, and reports whether msg
// was one. Line breaks in typed text are dropped.
func (l *LineInput) Update(msg tea.KeyPressMsg) bool {
	if l.in.key(msg.String(), l.Masked) {
		return true
	}
	if !typed(msg) {
		return false
	}
	l.insert([]rune(strings.Map(dropLineBreak, msg.Text)))
	return true
}

// Paste inserts pasted text, less one trailing line break (copying a line
// usually copies its line break too). Text with a line break inside, or
// that isn't valid UTF-8, is refused: Paste returns false and changes
// nothing.
func (l *LineInput) Paste(s string) bool {
	for _, suffix := range []string{"\r\n", "\n", "\r"} {
		if t, ok := strings.CutSuffix(s, suffix); ok {
			s = t
			break
		}
	}
	if strings.ContainsAny(s, "\r\n") || !utf8.ValidString(s) {
		return false
	}
	l.insert([]rune(s))
	return true
}

func (l *LineInput) insert(rs []rune) {
	if l.Masked {
		l.in.pos = len(l.in.value)
	}
	old := l.in.value
	l.in.insert(rs)
	if l.Masked {
		clear(old[:cap(old)]) // no stale copy of a passphrase
	}
}

// View renders the input in at most width cells, with a cursor when
// focused: the visible part of the value, scrolled to show the cursor, or
// Mask when the input is masked and not empty.
func (l *LineInput) View(width int, focused bool) string {
	width = max(width, 1)
	if l.Masked {
		s := ""
		if len(l.in.value) > 0 {
			s = Mask
		}
		if focused {
			s += styleCursor.Render(" ")
		}
		return ansi.Truncate(s, width, "")
	}
	l.in.scroll(width)
	return l.in.view(width, focused)
}
