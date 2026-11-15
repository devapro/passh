package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/tty"
)

// formCtx is what the TUI knows about the open form.
type formCtx struct {
	add  bool
	id   string      // edit: the entry's id
	orig model.Entry // edit: the entry when the form opened
	// resumed: the form holds input that wasn't saved yet (a refused save),
	// so Esc asks before dropping it even if nothing changed since.
	resumed        bool
	confirmDiscard bool
}

type promptKind int

const (
	promptAdd promptKind = iota
	promptMove
	promptTags
	promptPrint
)

// prompt is a one-line question in the status area.
type prompt struct {
	kind  promptKind
	label string
	in    editor.LineInput
	err   string
	id    string         // move, tags: the entry
	print *print.Options // print: what the setup step chose
}

type confirmKind int

const (
	confirmDelete confirmKind = iota
	confirmRollback
)

// confirm is a yes/no question in the status area.
type confirm struct {
	kind confirmKind
	text string
	id   string
	path paths.Path
}

// kept is input a save refused because the vault changed on disk (§4.6
// step 2: "the TUI form keeps its values"). R reloads, then reopens it.
type kept struct {
	reopen func(m *app)
}

const changedText = "The vault changed on disk: R reloads it."

// typing reports whether a text field has the keys: the form, a prompt
// (path, tags, PRINT) or the search query. There L is a letter, so it
// doesn't lock; the idle lock and signals still do (§5.2).
func (m *app) typing() bool {
	return (m.form != nil && !m.fctx.confirmDiscard) || m.prompt != nil || m.search.typing
}

func (m *app) mainKey(msg tea.KeyPressMsg) tea.Cmd {
	// L locks from every screen but a text field: lists, the detail, help,
	// questions, the print setup and the print dialog (§5.2; the lock also
	// stops the print page, §7.4).
	if msg.String() == "L" && !m.typing() {
		return m.lock(session.ReasonKey)
	}
	switch {
	case m.form != nil:
		return m.formKey(msg)
	case m.printDlg != nil:
		return m.printUpdate(msg)
	case m.confirm != nil:
		return m.confirmKey(msg)
	case m.prompt != nil:
		return m.promptKey(msg)
	case m.printSetup != nil:
		return m.printSetupKey(msg)
	}
	k := msg.String()
	if m.help {
		switch k {
		case "up", "k":
			m.helpOff = max(m.helpOff-1, 0)
		case "down", "j":
			m.helpOff++
		case "ctrl+c":
			return m.userQuit()
		default:
			m.help, m.helpOff = false, 0
		}
		return nil
	}
	if m.search.typing {
		return m.searchKey(msg)
	}

	switch k {
	case "q", "ctrl+c":
		return m.userQuit()
	case "?":
		m.help, m.helpOff = true, 0
		return nil
	case "R":
		return m.reload()
	case "/":
		m.detail = false
		if !m.search.active {
			m.search = searchState{active: true, in: editor.NewLineInput("", false)}
			m.search.run(m.entries)
			m.cur[viewSearch] = cursor{}
		}
		m.search.typing = true
		return nil
	case "tab":
		m.detail = false
		if m.search.active {
			m.search.wipe()
		}
		if m.view == viewFolders {
			m.view = viewTags
		} else {
			m.view = viewFolders
		}
		return nil
	case "P":
		m.startPrintSetup()
		return nil
	case "a":
		m.startAdd()
		return nil
	case "c":
		return m.copyField(model.FieldPassword)
	case "u":
		return m.copyField(model.FieldUsername)
	case "r":
		return m.toggleReveal()
	case "e":
		m.startEdit()
		return nil
	case "t":
		m.startTags()
		return nil
	case "m":
		m.startMove()
		return nil
	case "d":
		m.startDelete()
		return nil
	}

	if m.detail {
		switch k {
		case "esc", "left", "h", "backspace":
			m.detail = false
			m.reveal.id = "" // leaving the entry hides it
			m.selectEntry(m.detailID)
		case "up", "k":
			m.detailOff = max(m.detailOff-1, 0)
		case "down", "j":
			m.detailOff++
		case "pgup":
			m.detailOff = max(m.detailOff-m.bodyHeight(), 0)
		case "pgdown", "space":
			m.detailOff += m.bodyHeight()
		case "home", "g":
			m.detailOff = 0
		}
		return nil
	}

	switch k {
	case "up", "k", "ctrl+p":
		m.move(-1)
	case "down", "j", "ctrl+n":
		m.move(1)
	case "pgup":
		m.move(-max(m.bodyHeight()-1, 1))
	case "pgdown":
		m.move(max(m.bodyHeight()-1, 1))
	case "home", "g":
		m.moveTo(false)
	case "end", "G":
		m.moveTo(true)
	case "enter":
		m.activate(true)
	case "right", "l":
		m.activate(false)
	case "space":
		if r, ok := m.selectedRow(); ok && r.kind != rowEntry {
			m.activate(true)
		}
	case "left", "h":
		m.back()
	case "esc":
		switch {
		case m.search.active:
			m.search.wipe()
		case m.view == viewTags && len(m.tagSel) > 0:
			clear(m.tagSel)
		}
	}
	return nil
}

func (m *app) mainPaste(msg tea.PasteMsg) tea.Cmd {
	switch {
	case m.form != nil:
		return m.formUpdate(msg)
	case m.printDlg != nil:
		return m.printUpdate(msg)
	case m.prompt != nil:
		if !m.prompt.in.Paste(msg.Content) {
			m.prompt.err = "Paste refused: one line only."
		}
	case m.search.typing:
		if m.search.in.Paste(msg.Content) {
			m.search.run(m.entries)
			m.cur[viewSearch] = cursor{}
		}
	}
	return nil
}

func (m *app) searchKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.search.wipe()
	case "enter":
		m.search.typing = false
		if len(m.search.results) == 0 {
			m.search.wipe()
		}
	case "up", "ctrl+p":
		m.move(-1)
	case "down", "ctrl+n":
		m.move(1)
	case "ctrl+c":
		return m.userQuit()
	case "tab":
		m.search.wipe()
		return m.mainKey(msg)
	default:
		before := m.search.in.String()
		m.search.in.Update(msg)
		if m.search.in.String() != before {
			m.search.run(m.entries)
			m.cur[viewSearch] = cursor{}
		}
	}
	return nil
}

// refuse reports whether changes are refused now: busy (a reload or a
// save runs), or the vault changed on disk. It sets the status.
func (m *app) refuse() bool {
	switch {
	case m.v == nil:
		return true
	case m.busy():
		m.setBusyStatus()
		return true
	case m.changedOnDisk:
		m.setStatusSticky(changedText+" Changes are blocked until then.", true)
		return true
	}
	return false
}

func (m *app) needEntry() (model.Entry, bool) {
	e, ok := m.selectedEntry()
	if !ok {
		m.setStatus("Select an entry first.", false)
	}
	return e, ok
}

// copyField copies the password or the username (§6.3), in a command.
func (m *app) copyField(field string) tea.Cmd {
	e, ok := m.needEntry()
	if !ok {
		return nil
	}
	value, _ := e.Field(field)
	if value == "" {
		m.setStatus(fmt.Sprintf("%s has no %s.", e.Path, field), false)
		return nil
	}
	if m.clip.c == nil {
		err := m.clip.err
		if err == nil {
			err = &clipboard.NoClipboardError{Reason: "no clipboard is configured"}
		}
		m.setStatusSticky(clipboard.WithHint(err, e.Path.String(), field).Error(), true)
		return nil
	}
	return m.copyValue(value, field, e.Path.String())
}

func (m *app) toggleReveal() tea.Cmd {
	e, ok := m.needEntry()
	if !ok {
		return nil
	}
	if m.revealed(e.ID) {
		m.reveal = reveal{seq: m.reveal.seq + 1}
		return nil
	}
	seq := m.reveal.seq + 1
	m.reveal = reveal{id: e.ID, until: m.now().Add(editor.RevealDuration), seq: seq}
	if m.narrow() && !m.detail {
		m.openDetail(e.ID)
		m.reveal.id = e.ID
	}
	return m.after(editor.RevealDuration, hideMsg{seq: seq})
}

func (m *app) revealed(id string) bool {
	return id != "" && m.reveal.id == id && m.now().Before(m.reveal.until)
}

// Forms.

func (m *app) startEdit() {
	e, ok := m.needEntry()
	if !ok || m.refuse() {
		return
	}
	m.openForm(e, formCtx{id: e.ID, orig: e})
}

func (m *app) startAdd() {
	if m.refuse() {
		return
	}
	pre := m.folderOfCursor()
	if pre != "" {
		pre += "/"
	}
	m.prompt = &prompt{kind: promptAdd, label: "New entry's path: ", in: editor.NewLineInput(pre, false)}
}

func (m *app) openForm(e model.Entry, fc formCtx) {
	title := "edit " + e.Path.String()
	if fc.add {
		title = "add " + e.Path.String()
	}
	if fc.resumed {
		title += " (not saved yet)"
	}
	m.form = editor.NewForm(e, editor.FormOptions{Title: title})
	m.fctx = fc
	if !fc.resumed {
		m.st = status{}
	}
	m.reveal = reveal{seq: m.reveal.seq + 1}
	m.sizeForm()
}

func (m *app) sizeForm() {
	if m.form != nil {
		m.form.SetSize(m.w, max(m.h-1-len(m.formStatus()), 1))
	}
}

func (m *app) closeForm() {
	m.form, m.fctx = nil, formCtx{}
}

func (m *app) formKey(msg tea.KeyPressMsg) tea.Cmd {
	k := msg.String()
	if m.fctx.confirmDiscard {
		m.fctx.confirmDiscard = false
		m.st = status{}
		if k == "esc" || k == "ctrl+c" {
			m.closeForm()
			m.setStatus("Changes discarded.", false)
		}
		return nil
	}
	if m.fctx.resumed && (k == "esc" || k == "ctrl+c") && !m.form.Changed() {
		m.fctx.confirmDiscard = true
		m.setStatusSticky("Discard the changes that weren't saved? esc: discard · any other key: keep editing", false)
		return nil
	}
	return m.formUpdate(msg)
}

func (m *app) formUpdate(msg tea.Msg) tea.Cmd {
	_, cmd := m.form.Update(msg)
	if !m.form.Done() {
		return cmd
	}
	f, fc := m.form, m.fctx
	e, err := f.Result()
	m.closeForm()
	if err != nil {
		m.setStatus("Cancelled.", false)
		return nil
	}
	return m.saveForm(f, e, fc)
}

// saveForm saves the form's result (§4.6) in a command. A refused save
// keeps the values: the form comes back at once (Resume), or after R when
// the vault changed on disk.
func (m *app) saveForm(f *editor.Form, e model.Entry, fc formCtx) tea.Cmd {
	resume := func(m *app, msg string) {
		m.form, m.fctx = f, fc
		f.Resume(msg)
		m.sizeForm()
	}
	switch {
	case m.v == nil:
		return nil
	case m.saving != nil: // not reached: forms don't open while a save runs
		resume(m, "Not saved yet: the previous change is still being saved; ctrl+s again.")
		return nil
	case m.job != nil || m.changedOnDisk:
		m.keepForm(f, e, fc)
		return nil
	}
	id := e.ID
	return m.save(&saveOp{
		what: e.Path.String(),
		run: func(ctx context.Context, v Vault) (string, error) {
			if fc.add {
				stored, err := v.AddContext(ctx, e, false)
				id = stored.ID
				return "Added " + e.Path.String() + ".", err
			}
			changed, err := v.UpdateContext(ctx, e)
			if !changed {
				return "No changes.", err
			}
			return "Saved " + e.Path.String() + ".", err
		},
		refused: func(m *app) { m.keepForm(f, e, fc) },
		done: func(m *app, text string, err error) {
			if err != nil {
				resume(m, "Not saved: "+err.Error())
				return
			}
			m.selectEntry(id)
			m.setStatus(text, false)
		},
	})
}

// keepForm keeps a form whose save was refused because the vault changed
// on disk; R reloads, then reopens it.
func (m *app) keepForm(f *editor.Form, e model.Entry, fc formCtx) {
	m.kept = &kept{reopen: func(m *app) {
		const back = "Reloaded: your input is back; ctrl+s saves it."
		cur, found := m.entryByID(fc.id)
		switch {
		case fc.add || (found && cur.Equal(fc.orig)):
			// Nothing changed under the form: it comes back as it was.
			m.form, m.fctx = f, fc
			f.Resume(back)
			m.sizeForm()
			m.st = status{}
		case !found:
			fc.add, fc.id, fc.resumed = true, "", true
			e.ID = ""
			m.openForm(e, fc)
			m.setStatusSticky(e.Path.String()+" was deleted on disk: saving adds it again.", false)
		default:
			// The entry changed on disk: the user's changes go on top of
			// the reloaded entry, so the reload undoes nothing.
			orig := fc.orig
			fc.orig, fc.resumed = cur, true
			m.openForm(rebase(cur, orig, e), fc)
			m.setStatusSticky(back+" It changed on disk too; the other values are the new ones.", false)
		}
	}}
	m.setStatusSticky("Not saved: the vault changed on disk. R reloads it; your input is kept.", true)
}

// rebase applies the values the user changed (edited differs from orig)
// to cur, the entry as reloaded, so a reload doesn't undo changes made on
// disk to the other values.
func rebase(cur, orig, edited model.Entry) model.Entry {
	out := cur.Clone()
	if edited.Password != orig.Password {
		out.Password = edited.Password
	}
	if edited.Username != orig.Username {
		out.Username = edited.Username
	}
	if edited.URL != orig.URL {
		out.URL = edited.URL
	}
	if !slices.Equal(edited.Tags, orig.Tags) {
		out.Tags = slices.Clone(edited.Tags)
	}
	if edited.Notes != orig.Notes {
		out.Notes = edited.Notes
	}
	return out
}

// Prompts.

func (m *app) startMove() {
	e, ok := m.needEntry()
	if !ok || m.refuse() {
		return
	}
	m.prompt = &prompt{kind: promptMove, label: "Move to: ", in: editor.NewLineInput(e.Path.String(), false), id: e.ID}
}

func (m *app) startTags() {
	e, ok := m.needEntry()
	if !ok || m.refuse() {
		return
	}
	m.prompt = &prompt{kind: promptTags, label: "Tags (comma-separated): ", in: editor.NewLineInput(strings.Join(e.Tags, ", "), false), id: e.ID}
}

func (m *app) promptKey(msg tea.KeyPressMsg) tea.Cmd {
	p := m.prompt
	switch msg.String() {
	case "esc", "ctrl+c":
		p.in.Wipe()
		m.prompt = nil
		return nil
	case "enter":
		return m.submitPrompt(p)
	}
	before := p.in.String()
	p.in.Update(msg)
	if p.in.String() != before {
		p.err = ""
	}
	return nil
}

func (m *app) closePrompt() {
	m.prompt = nil
}

// keepPrompt closes a prompt whose save was refused and keeps its input
// for after the reload.
func (m *app) keepPrompt(p *prompt) {
	m.closePrompt()
	p.err = ""
	m.kept = &kept{reopen: func(m *app) { m.prompt = p }}
	m.setStatusSticky("Not saved: the vault changed on disk. R reloads it; your input is kept.", true)
}

func (m *app) submitPrompt(p *prompt) tea.Cmd {
	text := p.in.String()
	switch p.kind {
	case promptPrint:
		m.closePrompt()
		if text != tty.PhrasePrint {
			m.setStatus("Not confirmed: the print page wasn't started.", false)
			return nil
		}
		var o print.Options
		if p.print != nil {
			o = *p.print
		}
		return m.startPrint(o)
	case promptAdd:
		dst, err := paths.Parse(text)
		if err != nil {
			p.err = err.Error()
			return nil
		}
		if m.pathTaken(dst) {
			p.err = dst.String() + " already exists: e edits it."
			return nil
		}
		m.closePrompt()
		m.openForm(model.Entry{Path: dst}, formCtx{add: true})
		return nil
	}

	e, ok := m.entryByID(p.id)
	if !ok {
		m.closePrompt()
		m.setStatus("The entry no longer exists.", true)
		return nil
	}
	switch p.kind {
	case promptMove:
		dst, err := paths.Parse(text)
		if err != nil {
			p.err = err.Error()
			return nil
		}
		if dst == e.Path {
			m.closePrompt()
			return nil
		}
		return m.savePrompt(p, &saveOp{
			what: e.Path.String(),
			run: func(ctx context.Context, v Vault) (string, error) {
				return fmt.Sprintf("Moved %s to %s.", e.Path, dst), v.MoveContext(ctx, e.Path, dst)
			},
			done: func(m *app, text string, err error) {
				if err == nil {
					m.selectEntry(e.ID)
				}
			},
		})
	case promptTags:
		tags, err := model.ParseTagList(text)
		if err != nil {
			p.err = err.Error()
			return nil
		}
		var add, remove []string
		for _, t := range tags {
			if !slices.Contains(e.Tags, t) {
				add = append(add, t)
			}
		}
		for _, t := range e.Tags {
			if !slices.Contains(tags, t) {
				remove = append(remove, t)
			}
		}
		if len(add) == 0 && len(remove) == 0 {
			m.closePrompt()
			m.setStatus("No changes.", false)
			return nil
		}
		return m.savePrompt(p, &saveOp{
			what: e.Path.String(),
			run: func(ctx context.Context, v Vault) (string, error) {
				_, _, err := v.EditTagsContext(ctx, e.Path, add, remove)
				return "Tags of " + e.Path.String() + " saved.", err
			},
		})
	}
	return nil
}

// savePrompt closes the prompt p and saves its change in a command; a
// failed save reopens it with the error, a refused one keeps it for after
// the reload. op.done, if set, runs after the prompt's own handling.
func (m *app) savePrompt(p *prompt, op *saveOp) tea.Cmd {
	if m.busy() || m.changedOnDisk {
		m.keepPrompt(p)
		return nil
	}
	m.closePrompt()
	extra := op.done
	op.refused = func(m *app) { m.keepPrompt(p) }
	op.done = func(m *app, text string, err error) {
		if err != nil {
			p.err = err.Error()
			m.prompt = p
		} else {
			m.setStatus(text, false)
		}
		if extra != nil {
			extra(m, text, err)
		}
	}
	return m.save(op)
}

// Delete.

func (m *app) startDelete() {
	e, ok := m.needEntry()
	if !ok || m.refuse() {
		return
	}
	m.confirm = &confirm{kind: confirmDelete, text: "Delete " + e.Path.String() + "?", id: e.ID, path: e.Path}
}

func (m *app) confirmKey(msg tea.KeyPressMsg) tea.Cmd {
	c := m.confirm
	m.confirm = nil
	k := msg.String()
	yes := k == "y" || k == "Y"
	switch c.kind {
	case confirmRollback:
		if k == "ctrl+c" {
			return m.userQuit() // ends the job: the question gets no answer
		}
		return m.answerAsk(yes)
	case confirmDelete:
		if !yes {
			m.setStatus("Not deleted.", false)
			return nil
		}
		const changed = "Not deleted: the vault changed on disk. R reloads it; then delete again."
		if m.busy() || m.changedOnDisk {
			m.setStatusSticky(changed, true)
			return nil
		}
		return m.save(&saveOp{
			what: c.path.String(),
			run: func(ctx context.Context, v Vault) (string, error) {
				return "Deleted " + c.path.String() + ".", v.RemoveContext(ctx, c.path)
			},
			refused: func(m *app) { m.setStatusSticky(changed, true) },
			done: func(m *app, text string, err error) {
				if err != nil {
					m.setStatusSticky("Not deleted: "+err.Error(), true)
					return
				}
				if m.detailID == c.id {
					m.detail = false
				}
				m.setStatus(text, false)
			},
		})
	}
	return nil
}

// Print page.

func (m *app) printUpdate(msg tea.Msg) tea.Cmd {
	cmd := m.printDlg.Update(msg)
	if m.printDlg.Done() {
		m.printDlg.Stop()
		text := "Print page stopped."
		if o, ok := m.printDlg.(interface{ Outcome() string }); ok && o.Outcome() != "" {
			text = "Print page: " + o.Outcome()
		}
		m.printDlg = nil
		m.setStatus(text, false)
	}
	return cmd
}
