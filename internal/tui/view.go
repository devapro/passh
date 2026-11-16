package tui

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/sanitize"
)

var (
	styleTitle = lipgloss.NewStyle().Bold(true)
	styleFaint = lipgloss.NewStyle().Faint(true)
	styleError = lipgloss.NewStyle().Foreground(lipgloss.Red)
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Yellow)
	styleKey   = lipgloss.NewStyle().Bold(true)
	styleSel   = lipgloss.NewStyle().Reverse(true)
	styleLabel = lipgloss.NewStyle().Foreground(lipgloss.Cyan)
)

// Layout.
const (
	wideMin   = 80 // narrower terminals get a single pane (§6.2)
	minWidth  = 20
	minHeight = 6
	labelW    = 10 // "password" and two spaces
	// maxStatusLines caps the status message (an error with a list of
	// backups can be long).
	maxStatusLines = 6
)

func (m *app) narrow() bool { return m.w < wideMin }

// View renders the screen. Every value from the vault goes through
// sanitize where it is rendered (S4), and the whole frame goes through
// inertStyled once more: the choke point that keeps a missed call from
// reaching the terminal. Lines never exceed the terminal's width.
func (m *app) View() tea.View {
	var s string
	switch m.screen {
	case screenLock:
		s = m.viewLock()
	case screenMain:
		s = m.viewMain()
	}
	v := tea.NewView(inertStyled(s))
	// The alternate screen: nothing shown, a revealed password included,
	// stays in the scrollback after passh exits.
	v.AltScreen = true
	return v
}

// pad truncates s to w cells and fills it up with spaces.
func pad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "")
	if n := w - ansi.StringWidth(s); n > 0 {
		s += strings.Repeat(" ", n)
	}
	return s
}

// fitLines joins at most h lines, each cut to w cells.
func fitLines(lines []string, w, h int) string {
	if len(lines) > h {
		lines = lines[:h]
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = ansi.Truncate(l, w, "")
	}
	return strings.Join(out, "\n")
}

// wrapItems joins items with " · ", breaking lines between items.
func wrapItems(items []string, w int) []string {
	const sep = " · "
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case ansi.StringWidth(cur+sep+it) <= w:
			cur += sep + it
		default:
			lines = append(lines, cur)
			cur = it
		}
	}
	return append(lines, cur)
}

// wrapText wraps already escaped text to w cells.
func wrapText(s string, w int) []string {
	if s == "" {
		return []string{""}
	}
	return strings.Split(ansi.Wrap(s, max(w, 1), ""), "\n")
}

func fmtCountdown(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

func (m *app) lockText() string {
	if m.job != nil && m.job.kind == "reload" {
		return m.d.p.T("reloading…")
	}
	if m.sess.Deadline().IsZero() {
		return m.d.p.T("unlocked")
	}
	return m.d.p.T("unlocked · locks in %s", fmtCountdown(m.sess.Remaining()))
}

// shortLockText is lockText for a title that has no room for it: the
// countdown without "unlocked".
func (m *app) shortLockText() string {
	if (m.job != nil && m.job.kind == "reload") || m.sess.Deadline().IsZero() {
		return m.lockText()
	}
	return m.d.p.T("locks in %s", fmtCountdown(m.sess.Remaining()))
}

// titleLine is the one-line title of the narrow view, the form and the
// print dialog: "passh · extra · unlocked · locks in 4:12". When it is wider
// than w, the extras go first, then "unlocked", so the countdown stays.
func (m *app) titleLine(w int, extra ...string) string {
	line := func(parts []string, lock string) string {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(" · " + p)
		}
		return b.String() + " · " + lock
	}
	rest := line(extra, m.lockText())
	if ansi.StringWidth("passh"+rest) > w && len(extra) > 0 {
		rest = line(nil, m.lockText())
	}
	if ansi.StringWidth("passh"+rest) > w {
		rest = line(nil, m.shortLockText())
	}
	return styleTitle.Render("passh") + styleFaint.Render(rest)
}

func (m *app) viewMain() string {
	if m.w < minWidth || m.h < minHeight {
		return fitLines([]string{m.d.p.T("passh: window too small")}, m.w, m.h)
	}
	switch {
	case m.form != nil:
		return m.viewForm()
	case m.printDlg != nil:
		return m.viewPrint()
	case m.narrow():
		return m.viewNarrow()
	}
	return m.viewWide()
}

// fullBody reports whether the body is one full-width block (help or an
// entry's detail) instead of the list and the detail pane.
func (m *app) fullBody() bool { return m.help || m.detail || m.printSetup != nil }

// bodyHeight is the height of the list or detail area.
func (m *app) bodyHeight() int {
	inner := m.w
	chrome := 4 // header, tabs, two rules
	if !m.narrow() {
		inner = m.w - 2
		chrome = 5 // top, tabs, two rules, bottom
	}
	return max(m.h-chrome-len(m.statusLines(inner-1))-len(m.footerLines(inner-1)), 1)
}

func (m *app) tabsLine(w int) string {
	tab := func(name string, on bool) string {
		if on {
			return styleKey.Render("[" + name + "]")
		}
		return " " + name + " "
	}
	left := tab(m.d.p.T("Folders"), m.view == viewFolders) + " " + tab(m.d.p.T("Tags"), m.view == viewTags)
	if !m.narrow() {
		left = m.d.p.T("VIEW:") + " " + left
	}
	var right string
	switch {
	case m.search.typing:
		right = "/ " + m.search.in.View(max(min(30, w-ansi.StringWidth(left)-4), 4), true)
	case m.search.active:
		right = "/ " + sanitize.Line(m.search.in.String())
	case !m.narrow():
		right = styleFaint.Render("/ " + m.d.p.T("search"))
	}
	if right == "" {
		return left
	}
	gap := w - ansi.StringWidth(left) - ansi.StringWidth(right)
	if gap < 2 {
		return left + "  " + right
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m *app) viewWide() string {
	w := m.w
	inner := w - 2
	lw := min(max(inner*35/100, 24), 40)
	rw := inner - lw - 1
	status := m.statusLines(inner - 1)
	footer := m.footerLines(inner - 1)
	bodyH := m.bodyHeight()
	b := func(s string) string { return styleFaint.Render(s) }
	boxed := func(s string) string { return b("│") + pad(" "+s, inner) + b("│") }

	var lines []string
	title := " passh ── " + m.lockText() + " "
	title = ansi.Truncate(title, inner, "")
	lines = append(lines, b("┌")+styleTitle.Render(title)+b(strings.Repeat("─", max(inner-ansi.StringWidth(title), 0))+"┐"))
	lines = append(lines, boxed(m.tabsLine(inner-2)))
	if m.fullBody() {
		lines = append(lines, b("├"+strings.Repeat("─", inner)+"┤"))
		for _, l := range m.fullBodyLines(inner-2, bodyH) {
			lines = append(lines, boxed(l))
		}
		lines = append(lines, b("├"+strings.Repeat("─", inner)+"┤"))
	} else {
		lines = append(lines, b("├"+strings.Repeat("─", lw)+"┬"+strings.Repeat("─", rw)+"┤"))
		left := m.listLines(lw, bodyH)
		right := m.paneLines(rw-2, bodyH)
		for i := range bodyH {
			lines = append(lines, b("│")+pad(left[i], lw)+b("│")+pad(" "+right[i], rw)+b("│"))
		}
		lines = append(lines, b("├"+strings.Repeat("─", lw)+"┴"+strings.Repeat("─", rw)+"┤"))
	}
	for _, s := range status {
		lines = append(lines, boxed(s))
	}
	for _, s := range footer {
		lines = append(lines, boxed(styleFaint.Render(s)))
	}
	lines = append(lines, b("└"+strings.Repeat("─", inner)+"┘"))
	return fitLines(lines, w, m.h)
}

func (m *app) viewNarrow() string {
	w := m.w
	status := m.statusLines(w - 1)
	footer := m.footerLines(w - 1)
	bodyH := m.bodyHeight()
	rule := styleFaint.Render(strings.Repeat("─", w))

	var lines []string
	lines = append(lines, m.titleLine(w))
	lines = append(lines, m.tabsLine(w))
	lines = append(lines, rule)
	var body []string
	if m.fullBody() {
		body = m.fullBodyLines(w-1, bodyH)
		for i := range body {
			body[i] = " " + body[i]
		}
	} else {
		body = m.listLines(w, bodyH)
	}
	lines = append(lines, body...)
	lines = append(lines, rule)
	for _, s := range status {
		lines = append(lines, " "+s)
	}
	for _, s := range footer {
		lines = append(lines, " "+styleFaint.Render(s))
	}
	return fitLines(lines, w, m.h)
}

// listLines renders exactly h rows of the list, w cells wide, scrolled
// to show the cursor.
func (m *app) listLines(w, h int) []string {
	rows, idx := m.rowsAndCursor()
	c := &m.cur[m.list()]
	if idx >= 0 {
		if idx < c.off {
			c.off = idx
		}
		if idx >= c.off+h {
			c.off = idx - h + 1
		}
	}
	c.off = max(min(c.off, len(rows)-h), 0)
	out := make([]string, 0, h)
	for i := c.off; i < len(rows) && len(out) < h; i++ {
		out = append(out, m.rowLine(rows[i], w, i == idx))
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out
}

func (m *app) rowLine(r row, w int, selected bool) string {
	indent := strings.Repeat("  ", r.depth)
	var text, right string
	switch r.kind {
	case rowFolder:
		mark := "▸ "
		if r.open {
			mark = "▾ "
		}
		text = indent + mark + sanitize.Line(r.label)
		right = fmt.Sprintf("(%d)", r.count)
	case rowEntry:
		text = indent + "  " + sanitize.Line(r.label)
		if r.note != "" {
			right = "#" + sanitize.Line(r.note)
		}
	case rowTag:
		mark := "[ ] "
		if r.open {
			mark = "[x] "
		}
		text = mark + sanitize.Line(r.label)
		right = fmt.Sprintf("(%d)", r.count)
	case rowNote:
		return styleFaint.Render(ansi.Truncate(" "+sanitize.Line(r.label), w, "…"))
	}
	text = " " + text
	inner := w - 1 // one space on the right
	if right != "" {
		rw := ansi.StringWidth(right)
		avail := inner - rw - 1
		if avail < 6 {
			right, rw, avail = "", 0, inner
		}
		text = pad(ansi.Truncate(text, avail, "…"), avail)
		if rw > 0 {
			text += " " + right
		}
	} else {
		text = ansi.Truncate(text, inner, "…")
	}
	text = pad(text, w)
	if selected {
		return styleSel.Render(text)
	}
	return text
}

// paneLines is the right pane: the detail of the selected row.
func (m *app) paneLines(w, h int) []string {
	var lines []string
	r, ok := m.selectedRow()
	switch {
	case !ok:
		lines = []string{styleFaint.Render(m.d.p.T("Nothing selected."))}
	case r.kind == rowEntry:
		if e, ok := m.entryByID(strings.TrimPrefix(r.key, "e:")); ok {
			lines = m.detailLines(e, w)
		}
	case r.kind == rowFolder:
		lines = []string{
			styleTitle.Render(sanitize.Line(strings.TrimPrefix(r.key, "f:")) + "/"),
			styleFaint.Render(countText(m.d.p, r.count)),
			"",
			styleFaint.Render(m.d.p.T("Enter opens it, ← closes it.")),
		}
	case r.kind == rowTag:
		lines = []string{
			styleTitle.Render(m.d.p.T("tag %s", sanitize.Line(r.label))),
			styleFaint.Render(countText(m.d.p, r.count)),
			"",
			styleFaint.Render(m.d.p.T("Space selects it; entries with all selected tags are listed.")),
		}
	}
	var out []string
	for _, l := range lines {
		out = append(out, wrapText(l, w)...)
	}
	if len(out) > h {
		out = out[:h]
		out[h-1] = styleFaint.Render(m.d.p.T("… Enter shows all"))
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out
}

// countText is "1 entry", "5 entries" in p's language.
func countText(p i18n.Printer, n int) string {
	return p.N(n, "%d entry", "%d entries", n)
}

// fullBodyLines renders the help or the open entry, scrolled.
func (m *app) fullBodyLines(w, h int) []string {
	var lines []string
	off := &m.detailOff
	if m.printSetup != nil {
		lines = m.printSetupLines(w)
		zero := 0
		off = &zero
	} else if m.help {
		lines = helpLines(m.d.p, w)
		off = &m.helpOff
	} else if e, ok := m.entryByID(m.detailID); ok {
		lines = m.detailLines(e, w)
	}
	*off = max(min(*off, len(lines)-h), 0)
	out := make([]string, 0, h)
	for i := *off; i < len(lines) && len(out) < h; i++ {
		out = append(out, lines[i])
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out
}

// detailLines renders an entry, w cells wide: secrets masked unless
// revealed (S5), every value escaped (S4).
func (m *app) detailLines(e model.Entry, w int) []string {
	w = max(w, 8)
	revealed := m.revealed(e.ID)
	var out []string
	for _, l := range wrapText(sanitize.Line(e.Path.String()), w) {
		out = append(out, styleTitle.Render(l))
	}
	stacked := w < 30
	field := func(label, value string, faint bool) {
		style := func(s string) string { return s }
		if faint {
			style = fn(styleFaint)
		}
		if stacked || ansi.StringWidth(label) > labelW-2 {
			out = append(out, styleLabel.Render(ansi.Truncate(label, w, "…")))
			for _, l := range wrapText(value, w-2) {
				out = append(out, "  "+style(l))
			}
			return
		}
		for i, l := range wrapText(value, w-labelW) {
			prefix := strings.Repeat(" ", labelW)
			if i == 0 {
				prefix = styleLabel.Render(pad(label, labelW))
			}
			out = append(out, prefix+style(l))
		}
	}
	secret := func(label, value string) {
		switch {
		case value == "":
			field(label, m.d.p.T("(none)"), true)
		case revealed:
			field(label, sanitize.Line(value), false)
		default:
			field(label, editor.Mask, false)
		}
	}

	if e.Username != "" {
		field("username", sanitize.Line(e.Username), false)
	}
	secret("password", e.Password)
	if e.Password != "" && !stacked {
		hint := m.d.p.T("[c]opy [r]eveal")
		if revealed {
			hint = m.d.p.T("[c]opy [r] hide")
		}
		last := len(out) - 1
		if ansi.StringWidth(out[last])+3+ansi.StringWidth(hint) <= w {
			out[last] += "   " + styleFaint.Render(hint)
		}
	}
	if e.URL != "" {
		field("url", sanitize.Line(e.URL), false)
	}
	if len(e.Tags) > 0 {
		tags := make([]string, len(e.Tags))
		for i, t := range e.Tags {
			tags[i] = sanitize.Line(t)
		}
		field("tags", strings.Join(tags, " · "), false)
	}
	for _, f := range e.Fields {
		if f.IsSecret() {
			secret(sanitize.Line(f.Key), f.Value)
		} else {
			field(sanitize.Line(f.Key), sanitize.Line(f.Value), false)
		}
	}
	if e.Notes != "" {
		var notes []string
		for l := range strings.SplitSeq(e.Notes, "\n") {
			notes = append(notes, sanitize.Line(strings.ReplaceAll(l, "\t", "    ")))
		}
		if stacked {
			out = append(out, styleLabel.Render("notes"))
			for _, n := range notes {
				for _, l := range wrapText(n, w-2) {
					out = append(out, "  "+l)
				}
			}
		} else {
			first := true
			for _, n := range notes {
				for _, l := range wrapText(n, w-labelW) {
					prefix := strings.Repeat(" ", labelW)
					if first {
						prefix, first = styleLabel.Render(pad("notes", labelW)), false
					}
					out = append(out, prefix+l)
				}
			}
		}
	}
	if !e.UpdatedAt.IsZero() {
		out = append(out, styleFaint.Render(ansi.Truncate(m.d.p.T("updated %s", e.UpdatedAt.Local().Format("2006-01-02 15:04")), w, "")))
	}
	if revealed {
		left := m.reveal.until.Sub(m.now())
		out = append(out, styleWarn.Render(ansi.Truncate(m.d.p.T("shown for %d s more (r hides)", int((left+time.Second-1)/time.Second)), w, "")))
	}
	return out
}

// keyHelp is a key and what it does: the key is the same in every
// language, the help is a catalog key (i18n.Mark) translated where it is
// drawn. A key of "" shows the help alone ("any other key closes").
type keyHelp struct{ key, help string }

// text is the item as a hint bar shows it: "c copy pw".
func (k keyHelp) text(p i18n.Printer) string {
	help := p.T(k.help) // i18n:dynamic: keyHelp tables hold i18n.Mark keys
	if k.key == "" {
		return help
	}
	return k.key + " " + help
}

// hintItems renders a hint bar's items in p's language.
func hintItems(p i18n.Printer, ks []keyHelp) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.text(p)
	}
	return out
}

// helpKeys are the keys of the help screen.
var helpKeys = []keyHelp{
	{"↑ ↓  k j", i18n.Mark("move")},
	{"Enter  →", i18n.Mark("open a folder or an entry")},
	{"←  Esc", i18n.Mark("close a folder; back")},
	{"Tab", i18n.Mark("Folders / Tags view")},
	{"Space", i18n.Mark("select a tag (Tags view: AND)")},
	{"/", i18n.Mark("fuzzy search, paths and tags")},
	{"c  u", i18n.Mark("copy password / username")},
	{"r", i18n.Mark("reveal secrets for 10 s")},
	{"e  a", i18n.Mark("edit / add an entry")},
	{"t", i18n.Mark("edit tags")},
	{"m", i18n.Mark("move (rename) an entry")},
	{"d", i18n.Mark("delete an entry (asks first)")},
	{"R", i18n.Mark("reload the vault from disk")},
	{"P", i18n.Mark("print page")},
	{"L", i18n.Mark("lock now (in a text field L is a letter)")},
	{"?", i18n.Mark("this help")},
	{"q", i18n.Mark("quit (locks)")},
}

// helpNotesW is the width the notes under the keys wrap to at most.
const helpNotesW = 44

// helpLines lists the keys, w cells wide, in p's language.
func helpLines(p i18n.Printer, w int) []string {
	out := []string{styleTitle.Render(p.T("Keys"))}
	for _, k := range helpKeys {
		for i, l := range wrapText(p.T(k.help), max(w-10, 8)) { // i18n:dynamic: helpKeys holds i18n.Mark keys
			key := ""
			if i == 0 {
				key = k.key
			}
			out = append(out, styleKey.Render(pad(key, 10))+l)
		}
	}
	out = append(out, "")
	for _, n := range []string{
		p.T("In the form: ctrl+s saves, esc cancels, ctrl+r shows the password, ctrl+g generates."),
		p.T("Text fields (form, search, prompts): Esc first, then L. The idle lock and signals lock from anywhere."),
	} {
		for _, l := range wrapText(n, max(min(w, helpNotesW), 1)) {
			out = append(out, styleFaint.Render(l))
		}
	}
	return out
}

// statusLines is the status area: the "changed on disk" banner, then a
// prompt, a question or the last message.
func (m *app) statusLines(w int) []string {
	var out []string
	if m.changedOnDisk {
		for _, l := range wrapText(m.d.p.T("Vault changed on disk — R to reload. Saving is blocked until then."), w) {
			out = append(out, styleWarn.Render(l))
		}
	}
	switch {
	case m.prompt != nil:
		p := m.prompt
		label := sanitize.Line(p.label)
		if ansi.StringWidth(label) > w/2 {
			out = append(out, styleKey.Render(ansi.Truncate(label, w, "…")))
			label = ""
		}
		out = append(out, styleKey.Render(label)+p.in.View(max(w-ansi.StringWidth(label), 4), true))
		if p.err != "" {
			for _, l := range wrapText(sanitize.Line(p.err), w) {
				out = append(out, styleError.Render(l))
			}
		}
	case m.confirm != nil:
		text := m.confirm.text
		if m.confirm.kind == confirmRollback {
			text = m.d.p.T("Warning: %s", text) + " " + m.d.p.T("Continue with this copy?")
		}
		lines := wrapText(sanitize.Line(text)+" [y/N]", w)
		for _, l := range lines {
			out = append(out, styleWarn.Render(l))
		}
	default:
		text, isErr := m.statusText()
		if text == "" {
			if len(out) == 0 {
				out = append(out, "")
			}
			break
		}
		var lines []string
		for part := range strings.SplitSeq(text, "\n") { // e.g. a list of backups
			lines = append(lines, wrapText(sanitize.Line(part), w)...)
		}
		if len(lines) > maxStatusLines {
			lines = append(lines[:maxStatusLines-1], "…")
		}
		for _, l := range lines {
			if isErr {
				l = styleError.Render(l)
			}
			out = append(out, l)
		}
	}
	return out
}

func (m *app) statusText() (string, bool) {
	if !m.st.copied {
		return m.st.text, m.st.err
	}
	return m.clearText()
}

// capitalize upper-cases the first letter of s, whatever its script.
func capitalize(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 || r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// The hint bars of the footer (footerLines).
var (
	hintsPrompt     = []keyHelp{{"Enter", i18n.Mark("ok")}, {"Esc", i18n.Mark("cancel")}}
	hintsPrintSetup = []keyHelp{{"↑↓", i18n.Mark("move")}, {"space", i18n.Mark("choose")}, {"Enter", i18n.Mark("continue")}, {"Esc", i18n.Mark("cancel")}, {"L", i18n.Mark("lock")}}
	hintsConfirm    = []keyHelp{{"y", i18n.Mark("yes")}, {"", i18n.Mark("any other key: no")}}
	hintsHelp       = []keyHelp{{"↑↓", i18n.Mark("scroll")}, {"", i18n.Mark("any other key closes")}}
	hintsSearch     = []keyHelp{{"", i18n.Mark("type to search")}, {"↑↓", i18n.Mark("move")}, {"Enter", i18n.Mark("done")}, {"Esc", i18n.Mark("close")}}
	hintsNarrowDet  = []keyHelp{{"Esc", i18n.Mark("back")}, {"c", i18n.Mark("copy")}, {"u", i18n.Mark("user")}, {"r", i18n.Mark("reveal")}, {"e", i18n.Mark("edit")}, {"?", i18n.Mark("help")}}
	hintsNarrow     = []keyHelp{{"↵", i18n.Mark("open")}, {"c", i18n.Mark("copy")}, {"/", i18n.Mark("search")}, {"Tab", i18n.Mark("view")}, {"?", i18n.Mark("help")}, {"q", i18n.Mark("quit")}}
	hintsDetail     = []keyHelp{{"Esc", i18n.Mark("back")}, {"↑↓", i18n.Mark("scroll")}, {"c", i18n.Mark("copy pw")}, {"u", i18n.Mark("copy user")}, {"r", i18n.Mark("reveal")}, {"e", i18n.Mark("edit")}, {"t", i18n.Mark("tags")}, {"d", i18n.Mark("delete")}, {"?", i18n.Mark("help")}}
	hintsMainEntry  = []keyHelp{{"c", i18n.Mark("copy pw")}, {"u", i18n.Mark("copy user")}, {"r", i18n.Mark("reveal")}, {"e", i18n.Mark("edit")}, {"a", i18n.Mark("add")}, {"t", i18n.Mark("tags")}, {"d", i18n.Mark("delete")}}
	hintsMainApp    = []keyHelp{{"Tab", i18n.Mark("folders/tags")}, {"/", i18n.Mark("search")}, {"P", i18n.Mark("print")}, {"R", i18n.Mark("reload")}, {"L", i18n.Mark("lock")}, {"?", i18n.Mark("help")}, {"q", i18n.Mark("quit")}}
)

// footerLines lists the keys that apply now.
func (m *app) footerLines(w int) []string {
	var hints []keyHelp
	switch {
	case m.prompt != nil:
		hints = hintsPrompt
	case m.printSetup != nil:
		hints = hintsPrintSetup
	case m.confirm != nil:
		hints = hintsConfirm
	case m.help:
		hints = hintsHelp
	case m.search.typing:
		hints = hintsSearch
	case m.narrow() && m.detail:
		hints = hintsNarrowDet
	case m.narrow():
		hints = hintsNarrow
	case m.detail:
		hints = hintsDetail
	default:
		// Two bars, the entry's keys and the app's, each on its own line
		// when it fits; translations that are too wide for that flow as one
		// list, which takes fewer lines.
		i1, i2 := hintItems(m.d.p, hintsMainEntry), hintItems(m.d.p, hintsMainApp)
		l1, l2 := wrapItems(i1, w), wrapItems(i2, w)
		if len(l1)+len(l2) > 2 {
			if all := wrapItems(append(i1, i2...), w); len(all) < len(l1)+len(l2) {
				return all
			}
		}
		return append(l1, l2...)
	}
	lines := wrapItems(hintItems(m.d.p, hints), w)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	return lines
}

// formStatus is shown under the form: the banner and the TUI's message,
// wrapped to the window's width.
func (m *app) formStatus() []string {
	var out []string
	if m.changedOnDisk {
		for _, l := range wrapText(m.d.p.T("Vault changed on disk: saving is refused; your input is kept for after R."), m.w) {
			out = append(out, styleWarn.Render(l))
		}
	}
	if text, isErr := m.statusText(); text != "" {
		var lines []string
		for part := range strings.SplitSeq(text, "\n") {
			lines = append(lines, wrapText(sanitize.Line(part), m.w)...)
		}
		if len(lines) > maxStatusLines {
			lines = append(lines[:maxStatusLines-1], "…")
		}
		for _, l := range lines {
			if isErr {
				l = styleError.Render(l)
			}
			out = append(out, l)
		}
	}
	return out
}

func (m *app) viewForm() string {
	status := m.formStatus()
	m.form.SetSize(m.w, max(m.h-1-len(status), 1))
	lines := []string{m.titleLine(m.w)}
	lines = append(lines, strings.Split(m.form.View(), "\n")...)
	if extra := m.h - len(lines) - len(status); extra > 0 {
		lines = append(lines, make([]string, extra)...)
	}
	lines = append(lines, status...)
	return fitLines(lines, m.w, m.h)
}

func (m *app) viewPrint() string {
	lines := []string{m.titleLine(m.w, m.d.p.T("print page"))}
	// The dialog may be another package's (PrintPage); View's inertStyled
	// makes its frame safe like everything else.
	lines = append(lines, strings.Split(m.printDlg.View(m.w, max(m.h-1, 1)), "\n")...)
	return fitLines(lines, m.w, m.h)
}

// sgrSeq matches SGR styling with the attributes passh's styles use (here
// and in internal/editor): reset, bold, faint, reverse, the basic colours
// and their resets. Nothing else may start with ESC in a frame; SGR that
// hides text (8), blinks or sets other colours is shown as text like any
// other sequence.
var sgrSeq = regexp.MustCompile(`\x1b\[(?:` + sgrParam + `(?:;` + sgrParam + `)*)?m`)

const sgrParam = `(?:0|1|2|7|22|27|39|3[0-7]|9[0-7])`

// inertStyled escapes everything in a frame except the TUI's own SGR
// styling (S4); View applies it to every frame.
func inertStyled(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range sgrSeq.FindAllStringIndex(s, -1) {
		b.WriteString(sanitize.Text(s[last:loc[0]]))
		b.WriteString(s[loc[0]:loc[1]])
		last = loc[1]
	}
	b.WriteString(sanitize.Text(s[last:]))
	return strings.ReplaceAll(b.String(), "\t", " ")
}

// fn turns a style into a function of one string.
func fn(st lipgloss.Style) func(string) string {
	return func(s string) string { return st.Render(s) }
}
