package editor

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/gen"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/sanitize"
)

// RevealDuration is how long a revealed password stays visible (S5).
const RevealDuration = 10 * time.Second

// Mask is what a hidden password looks like: always the same length, so it
// doesn't tell the password's length (S5).
const Mask = "••••••••"

// ErrCancelled is returned when the user cancels the form.
var ErrCancelled = errors.New("cancelled")

// FormOptions configure a Form.
type FormOptions struct {
	// Title is the first line, e.g. "add work/gitlab". It is shown through
	// S4 escaping.
	Title string
	// Gen configures the generate key. The zero value makes 24 letters and
	// digits from crypto/rand.
	Gen gen.Options
}

// The fields in focus order.
const (
	fieldPassword = iota
	fieldUsername
	fieldURL
	fieldTags
	fieldNotes
	numFields
	numLines = fieldNotes // single-line fields come first
)

var fieldNames = [numFields]string{"password", "username", "url", "tags", "notes"}

const (
	labelWidth  = 8                  // the longest name, "password"
	prefixWidth = 2 + labelWidth + 2 // focus marker, label, gap
	minValue    = 8                  // the value column never gets narrower
)

var (
	styleTitle = lipgloss.NewStyle().Bold(true)
	styleFocus = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Cyan)
	styleFaint = lipgloss.NewStyle().Faint(true)
	styleError = lipgloss.NewStyle().Foreground(lipgloss.Red)
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Yellow)
)

type formState int

const (
	editing formState = iota
	submitted
	cancelled
)

var formIDs atomic.Uint64

// hideMsg hides a revealed password once RevealDuration has passed.
type hideMsg struct {
	form uint64
	seq  int
}

// Form is the built-in entry form (§5.6): single-line inputs for
// password, username, url and tags, and a text area for the notes.
//
// Embedding it in a Bubble Tea program:
//
//	f := editor.NewForm(entry, editor.FormOptions{Title: "edit " + path})
//	f.SetSize(w, h)            // the area the host gives it; again on resize
//	cmd := f.Init()
//	…
//	// in the host's Update, for every message the host doesn't handle
//	// itself, including the form's own timer messages:
//	f, cmd = f.Update(msg)
//	if f.Done() {
//		e, err := f.Result() // err is ErrCancelled when cancelled
//		…
//	}
//	// in the host's View:
//	content := f.View()
//
// The form doesn't act on tea.WindowSizeMsg itself: the host decides its
// size with SetSize. Values are rendered through S4 escaping; the password
// shows as Mask unless revealed.
//
// Keys: tab / shift+tab (or enter, up and down in single-line fields) move
// between fields; ctrl+s or alt+enter saves; esc or ctrl+c cancels, asking
// first when something changed; ctrl+r reveals the password for
// RevealDuration (again hides it); ctrl+g generates a password. In the
// notes, enter starts a new line. Editing keys are the usual readline
// ones (ctrl+a, ctrl+e, ctrl+u, ctrl+k, ctrl+w, alt+b, alt+f, …).
//
// Line breaks: a single-line field never holds one. A paste into it loses
// one trailing line break (copying a line usually includes it); a paste
// with a line break inside is refused with a message. Pasted CRLF and CR in
// the notes become LF.
//
// Custom fields (model.Entry.Fields) aren't edited here; they are listed by
// key and kept exactly, as are the entry's id, path, times and unknown
// keys. A field the user didn't change keeps its exact original value.
type Form struct {
	id   uint64
	opts FormOptions
	orig model.Entry

	in     [numLines]lineInput
	loaded [numLines]string // each input's starting text
	notes  textArea
	notes0 string // the notes' starting text

	focus     int
	revealed  bool
	revealSeq int

	width, height int

	errs       [numFields]string // inline errors per field
	status     string            // message above the key help
	statusErr  bool
	confirming bool // "discard changes?" is showing

	state  formState
	result model.Entry
}

// NewForm returns a form filled with e's content. For a new entry, pass an
// entry with only its path set (or nothing at all).
func NewForm(e model.Entry, opts FormOptions) *Form {
	f := &Form{
		id:     formIDs.Add(1),
		opts:   opts,
		orig:   e.Clone(),
		width:  80,
		height: 24,
	}
	vals := [numLines]string{e.Password, e.Username, e.URL, strings.Join(e.Tags, ", ")}
	for i, v := range vals {
		f.in[i] = newLineInput(v)
		f.loaded[i] = f.in[i].String()
	}
	f.notes = newTextArea(e.Notes)
	f.notes0 = f.notes.String()
	return f
}

// Init returns no command: the form needs none to start.
func (f *Form) Init() tea.Cmd { return nil }

// SetSize sets the area the form is drawn in, in terminal cells.
func (f *Form) SetSize(width, height int) {
	f.width, f.height = max(width, 1), max(height, 1)
	f.scroll()
}

// Done reports whether the user saved or cancelled.
func (f *Form) Done() bool { return f.state != editing }

// Result returns the edited entry after the user saved: the original entry
// (id, path, times, custom fields, unknown keys) with password, username,
// url, tags and notes from the form, validated and normalized by
// model.Entry.NormalizeContent. After a cancel it returns ErrCancelled.
func (f *Form) Result() (model.Entry, error) {
	switch f.state {
	case submitted:
		return f.result.Clone(), nil
	case cancelled:
		return model.Entry{}, ErrCancelled
	}
	return model.Entry{}, errors.New("the form is still open")
}

// Changed reports whether any value differs from what the form started
// with.
func (f *Form) Changed() bool {
	for i := range f.in {
		if f.in[i].String() != f.loaded[i] {
			return true
		}
	}
	return f.notes.String() != f.notes0
}

// Resume puts a saved form back into editing with every value as the user
// left it, e.g. after the host's save was refused. msg, if not empty, shows
// in the status line as an error. Changed still compares with the values
// the form started with, so esc asks before dropping the input. A form
// that is still open or was cancelled is left as it is.
func (f *Form) Resume(msg string) {
	if f.state != submitted {
		return
	}
	f.state = editing
	f.result = model.Entry{}
	f.confirming = false
	f.setStatus(msg, msg != "")
	f.scroll()
}

// Update handles a message and returns the form and a command to run.
func (f *Form) Update(msg tea.Msg) (*Form, tea.Cmd) {
	if f.state != editing {
		return f, nil
	}
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case hideMsg:
		if msg.form == f.id && msg.seq == f.revealSeq {
			f.hide()
		}
	case tea.PasteMsg:
		if f.confirming { // like any key: keep editing, drop the input
			f.confirming = false
			f.status = ""
			break
		}
		f.paste(msg.Content)
	case tea.KeyPressMsg:
		cmd = f.key(msg)
	}
	f.scroll()
	return f, cmd
}

func (f *Form) key(msg tea.KeyPressMsg) tea.Cmd {
	k := msg.String()
	if f.confirming {
		f.confirming = false
		f.status = ""
		if k == "esc" || k == "ctrl+c" {
			f.state = cancelled
		}
		return nil // any other key just closes the question
	}
	switch k {
	case "ctrl+s", "alt+enter":
		f.submit()
		return nil
	case "esc", "ctrl+c":
		if !f.Changed() {
			f.state = cancelled
			return nil
		}
		f.confirming = true
		f.setStatus("Discard the changes? esc: discard · any other key: keep editing", false)
		return nil
	case "ctrl+r":
		return f.toggleReveal()
	case "ctrl+g":
		f.generate()
		return nil
	case "tab":
		f.move(1)
		return nil
	case "shift+tab":
		f.move(-1)
		return nil
	}

	if f.focus == fieldNotes {
		before := f.notes.String()
		switch k {
		case "up", "ctrl+p":
			if !f.notes.vertical(-1, f.notesWidth()) {
				f.move(-1)
			}
		case "down", "ctrl+n":
			f.notes.vertical(1, f.notesWidth())
		default:
			if !f.notes.key(k, f.notesWidth(), f.notesHeight()) && typed(msg) {
				f.notes.insert([]rune(msg.Text))
			}
		}
		if f.notes.String() != before {
			f.errs[fieldNotes] = ""
		}
		return nil
	}

	switch k {
	case "enter", "down", "ctrl+n":
		f.move(1)
		return nil
	case "up", "ctrl+p":
		f.move(-1)
		return nil
	}
	in := &f.in[f.focus]
	before := in.String()
	if !in.key(k, f.masked()) && typed(msg) {
		if f.masked() {
			in.pos = len(in.value)
		}
		in.insert([]rune(strings.Map(dropLineBreak, msg.Text)))
	}
	if in.String() != before {
		f.errs[f.focus] = ""
	}
	return nil
}

// typed reports whether msg is text to insert rather than a command key.
func typed(msg tea.KeyPressMsg) bool {
	return msg.Text != "" && !msg.Mod.Contains(tea.ModCtrl) && !msg.Mod.Contains(tea.ModAlt)
}

func dropLineBreak(r rune) rune {
	if r == '\n' || r == '\r' {
		return -1
	}
	return r
}

// masked reports whether the password input is focused and hidden.
func (f *Form) masked() bool { return f.focus == fieldPassword && !f.revealed }

func (f *Form) move(delta int) {
	f.focus = (f.focus + delta + numFields) % numFields
	if f.focus == fieldPassword && !f.revealed {
		f.in[fieldPassword].pos = len(f.in[fieldPassword].value)
	}
	f.notes.goalX = -1
}

func (f *Form) paste(s string) {
	if !utf8.ValidString(s) {
		f.errs[f.focus] = "paste refused: the text is not valid UTF-8"
		return
	}
	if f.focus == fieldNotes {
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
		f.notes.insert([]rune(s))
		f.errs[fieldNotes] = ""
		return
	}
	// Copying a line usually copies its line break too.
	for _, suffix := range []string{"\r\n", "\n", "\r"} {
		if t, ok := strings.CutSuffix(s, suffix); ok {
			s = t
			break
		}
	}
	if strings.ContainsAny(s, "\r\n") {
		f.errs[f.focus] = "paste refused: " + fieldNames[f.focus] + " is a single line and the text has line breaks"
		return
	}
	in := &f.in[f.focus]
	if f.masked() {
		in.pos = len(in.value)
	}
	in.insert([]rune(s))
	f.errs[f.focus] = ""
}

func (f *Form) toggleReveal() tea.Cmd {
	if f.revealed {
		f.hide()
		return nil
	}
	f.revealed = true
	f.revealSeq++
	f.setStatus(fmt.Sprintf("Password shown; it hides again in %d s (ctrl+r hides it now).", int(RevealDuration/time.Second)), false)
	id, seq := f.id, f.revealSeq
	return tea.Tick(RevealDuration, func(time.Time) tea.Msg { return hideMsg{form: id, seq: seq} })
}

func (f *Form) hide() {
	if !f.revealed {
		return
	}
	f.revealed = false
	f.revealSeq++ // a pending timer no longer applies
	f.in[fieldPassword].pos = len(f.in[fieldPassword].value)
	if !f.confirming && !f.statusErr {
		f.status = ""
	}
}

func (f *Form) generate() {
	pw, err := gen.Generate(f.opts.Gen)
	if err != nil {
		f.setStatus("Generating a password failed: "+err.Error(), true)
		return
	}
	f.in[fieldPassword] = newLineInput(pw)
	f.errs[fieldPassword] = ""
	show := "ctrl+r shows it"
	if f.revealed {
		show = "it is shown"
	}
	f.setStatus(fmt.Sprintf("Generated a new password (%d characters); %s.", utf8.RuneCountInString(pw), show), false)
}

func (f *Form) setStatus(s string, isErr bool) {
	f.status, f.statusErr = s, isErr
}

// value returns input i's text, or the original value exactly when the
// input wasn't changed.
func (f *Form) value(i int, orig string) string {
	if v := f.in[i].String(); v != f.loaded[i] {
		return v
	}
	return orig
}

func (f *Form) submit() {
	f.errs = [numFields]string{}
	f.setStatus("", false)

	e := f.orig.Clone()
	e.Password = f.value(fieldPassword, f.orig.Password)
	e.Username = f.value(fieldUsername, f.orig.Username)
	e.URL = f.value(fieldURL, f.orig.URL)
	if v := f.in[fieldTags].String(); v != f.loaded[fieldTags] {
		tags, err := model.ParseTagList(v)
		if err != nil {
			f.errs[fieldTags] = err.Error()
			f.focus = fieldTags
			return
		}
		e.Tags = tags
	}
	if v := f.notes.String(); v != f.notes0 {
		e.Notes = v
	}
	if err := e.NormalizeContent(); err != nil {
		f.setStatus(err.Error(), true)
		return
	}
	f.result = e
	f.state = submitted
}

// Layout.

func (f *Form) valueWidth() int { return max(f.width-prefixWidth, minValue) }

// notesWidth is the text width inside the notes' "│ " gutter.
func (f *Form) notesWidth() int { return max(f.valueWidth()-2, 4) }

// spacious reports whether there is room for blank separator lines.
func (f *Form) spacious() bool { return f.height >= 16 }

// notesHeight is what is left for the notes after everything else.
func (f *Form) notesHeight() int {
	used := numLines + len(f.helpLines()) + len(f.statusLines())
	if f.opts.Title != "" {
		used++
		if f.spacious() {
			used++
		}
	}
	for _, e := range f.errs {
		if e != "" {
			used++
		}
	}
	if len(f.orig.Fields) > 0 {
		used++
	}
	if f.spacious() {
		used++ // blank line before the help
	}
	return max(f.height-used, 1)
}

func (f *Form) scroll() {
	for i := range f.in {
		f.in[i].scroll(f.valueWidth())
	}
	f.notes.scroll(f.notesWidth(), f.notesHeight())
}

func (f *Form) label(i int) string {
	marker := " "
	name := fmt.Sprintf("%*s", labelWidth, fieldNames[i])
	switch {
	case f.errs[i] != "":
		name = styleError.Render(name)
		if i == f.focus {
			marker = styleError.Render("›")
		}
	case i == f.focus:
		marker = styleFocus.Render("›")
		name = styleFocus.Render(name)
	}
	return marker + " " + name + "  "
}

func (f *Form) passwordView() string {
	in := &f.in[fieldPassword]
	focused := f.focus == fieldPassword
	if f.revealed {
		return in.view(f.valueWidth(), focused)
	}
	var s string
	if focused {
		s = styleCursor.Render(" ")
	}
	if len(in.value) > 0 {
		s = Mask + s
	} else {
		s += styleFaint.Render("(empty)")
	}
	if in.String() != f.loaded[fieldPassword] {
		s += styleFaint.Render(" changed")
	}
	return s
}

func (f *Form) statusLines() []string {
	if f.status == "" {
		return nil
	}
	return strings.Split(ansi.Wrap(sanitize.Line(f.status), f.width, ""), "\n")
}

// helpLines lists the keys, wrapped between items.
func (f *Form) helpLines() []string {
	items := []string{"ctrl+s save", "esc cancel", "tab next"}
	if f.focus == fieldNotes {
		items = append(items, "enter new line")
	}
	if f.revealed {
		items = append(items, "ctrl+r hide password")
	} else {
		items = append(items, "ctrl+r show password")
	}
	items = append(items, "ctrl+g generate")

	const sep = " · "
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case ansi.StringWidth(cur+sep+it) <= f.width:
			cur += sep + it
		default:
			lines = append(lines, cur)
			cur = it
		}
	}
	return append(lines, cur)
}

// View renders the form: at most the size given to SetSize when it fits.
func (f *Form) View() string {
	var lines []string
	add := func(s string) { lines = append(lines, ansi.Truncate(s, f.width, "")) }
	errLine := func(i int) {
		if f.errs[i] != "" {
			add(strings.Repeat(" ", prefixWidth) + styleError.Render(sanitize.Line(f.errs[i])))
		}
	}

	if f.opts.Title != "" {
		add(styleTitle.Render(sanitize.Line(f.opts.Title)))
		if f.spacious() {
			add("")
		}
	}

	add(f.label(fieldPassword) + f.passwordView())
	errLine(fieldPassword)
	for i := fieldUsername; i < numLines; i++ {
		add(f.label(i) + f.in[i].view(f.valueWidth(), f.focus == i))
		errLine(i)
	}

	gutter := styleFaint.Render("│") + " "
	for j, row := range f.notes.view(f.notesWidth(), f.notesHeight(), f.focus == fieldNotes) {
		prefix := strings.Repeat(" ", prefixWidth)
		if j == 0 {
			prefix = f.label(fieldNotes)
		}
		add(prefix + gutter + row)
	}
	errLine(fieldNotes)

	if len(f.orig.Fields) > 0 {
		keys := make([]string, len(f.orig.Fields))
		for i, fl := range f.orig.Fields {
			keys[i] = sanitize.Line(fl.Key)
		}
		text := strings.Join(keys, ", ") + " (kept as they are; edit them with --editor)"
		add(fmt.Sprintf("  %*s  ", labelWidth, "fields") + styleFaint.Render(ansi.Truncate(text, f.valueWidth(), "…")))
	}

	style := styleFaint
	if f.statusErr {
		style = styleError
	} else if f.confirming {
		style = styleWarn
	}
	if f.spacious() {
		add("")
	}
	for _, l := range f.statusLines() {
		add(style.Render(l))
	}
	for _, l := range f.helpLines() {
		add(styleFaint.Render(l))
	}
	return strings.Join(lines, "\n")
}
