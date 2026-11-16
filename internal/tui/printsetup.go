package tui

import (
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/tty"
)

// The step between P and the PRINT confirmation (EXAMPLES.md §9.2): which
// entries the sheet holds (all, the folder under the cursor, or the
// entries with all the selected tags) and which fields.

type scopeKind int

const (
	scopeAll scopeKind = iota
	scopeFolder
	scopeTags
)

type printScope struct {
	kind   scopeKind
	folder paths.Path
	tags   []string
	count  int
}

// label describes the scope in p's language: "folder work/ (2 entries)".
func (s printScope) label(p i18n.Printer) string {
	switch s.kind {
	case scopeFolder:
		return p.T("folder %s/ (%s)", s.folder.String(), countText(p, s.count))
	case scopeTags:
		return p.T("tags %s (%s)", strings.Join(s.tags, " + "), countText(p, s.count))
	}
	return p.T("all entries (%s)", countText(p, s.count))
}

// printFields are the field toggles, as print.ParseFields names them. The
// labels of the entry fields are their names, the same in every language
// (§3.3); "custom fields" is a description, translated (i18n.Mark).
var printFields = []struct{ name, label string }{
	{print.FieldPassword, "password"},
	{print.FieldUsername, "username"},
	{print.FieldURL, "url"},
	{print.FieldCustom, i18n.Mark("custom fields")},
}

type printSetup struct {
	scopes []printScope
	scope  int // the chosen scope
	fields []bool
	cur    int // the row under the cursor: scopes, then fields
	err    string
}

func (p *printSetup) rows() int { return len(p.scopes) + len(p.fields) }

// options returns the sheet options chosen.
func (p *printSetup) options() print.Options {
	s := p.scopes[p.scope]
	var o print.Options
	switch s.kind {
	case scopeFolder:
		o.Folder = s.folder
	case scopeTags:
		o.Tags = append([]string(nil), s.tags...)
	}
	for i, on := range p.fields {
		if on {
			o.Fields = append(o.Fields, printFields[i].name)
		}
	}
	return o
}

// startPrintSetup is P: it opens the setup step, with the current view's
// context as the default scope.
func (m *app) startPrintSetup() {
	switch {
	case !m.d.cfg.PrintWeb.Enabled:
		m.setStatus(m.d.p.T("The print page is off: set enabled = true in the [print_web] table of the config file (print_web.enabled)."), true)
		return
	case m.v == nil:
		return
	case m.busy() || m.printStarting:
		m.setBusyStatus()
		return
	}
	ps := &printSetup{
		scopes: []printScope{{kind: scopeAll, count: len(m.entries)}},
		fields: make([]bool, len(printFields)),
	}
	defaults := print.DefaultFieldList()
	for i, f := range printFields {
		ps.fields[i] = slices.Contains(defaults, f.name)
	}
	if f := m.folderOfCursor(); f != "" {
		if folder, err := paths.ParseFolder(f); err == nil {
			ps.scopes = append(ps.scopes, printScope{kind: scopeFolder, folder: folder, count: len(m.data.ListFolder(folder))})
			if m.list() == viewFolders {
				ps.scope = len(ps.scopes) - 1
			}
		}
	}
	if sel := m.selectedTags(); len(sel) > 0 && m.view == viewTags {
		ps.scopes = append(ps.scopes, printScope{kind: scopeTags, tags: sel, count: len(m.taggedEntries(sel))})
		if m.list() == viewTags {
			ps.scope = len(ps.scopes) - 1
		}
	}
	ps.cur = ps.scope
	m.printSetup = ps
}

func (m *app) printSetupKey(msg tea.KeyPressMsg) tea.Cmd {
	ps := m.printSetup
	switch msg.String() {
	case "esc", "ctrl+c":
		m.printSetup = nil
		m.setStatus(m.d.p.T("Print page cancelled."), false)
	case "up", "k":
		ps.cur = max(ps.cur-1, 0)
	case "down", "j", "tab":
		ps.cur = min(ps.cur+1, ps.rows()-1)
	case "home", "g":
		ps.cur = 0
	case "end", "G":
		ps.cur = ps.rows() - 1
	case "space", "x":
		ps.err = ""
		if ps.cur < len(ps.scopes) {
			ps.scope = ps.cur
		} else {
			i := ps.cur - len(ps.scopes)
			ps.fields[i] = !ps.fields[i]
		}
	case "enter":
		o := ps.options()
		switch {
		case len(o.Fields) == 0:
			ps.err = m.d.p.T("Choose at least one field.")
		case ps.scopes[ps.scope].count == 0:
			ps.err = m.d.p.T("No entries to print there: choose another.")
		default:
			m.printSetup = nil
			m.prompt = &prompt{
				kind:  promptPrint,
				label: m.d.p.T("Type %s to start the print page: ", tty.PhrasePrint),
				in:    editor.NewLineInput("", false),
				print: &o,
			}
		}
	}
	return nil
}

// printSetupLines renders the setup step, w cells wide.
func (m *app) printSetupLines(w int) []string {
	ps, p := m.printSetup, m.d.p
	out := []string{styleTitle.Render(p.T("Print page: what to print"))}
	row := func(i int, mark, label string) {
		text := mark + " " + sanitize.Line(label)
		prefix := "  "
		if i == ps.cur {
			prefix = "› "
		}
		text = ansi.Truncate(prefix+text, w, "…")
		if i == ps.cur {
			text = styleSel.Render(pad(text, w))
		}
		out = append(out, text)
	}
	out = append(out, styleLabel.Render(p.T("Entries")))
	for i, s := range ps.scopes {
		mark := "( )"
		if i == ps.scope {
			mark = "(•)"
		}
		row(i, mark, s.label(p))
	}
	out = append(out, styleLabel.Render(p.T("Fields")))
	for i, f := range printFields {
		mark := "[ ]"
		if ps.fields[i] {
			mark = "[x]"
		}
		label := f.label
		if f.name == print.FieldCustom {
			label = p.T(f.label) // i18n:dynamic: marked in printFields
		}
		row(len(ps.scopes)+i, mark, label)
	}
	if ps.err != "" {
		out = append(out, "")
		for _, l := range wrapText(ps.err, max(w, 1)) {
			out = append(out, styleError.Render(l))
		}
	}
	return out
}
