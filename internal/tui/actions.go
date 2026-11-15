package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/session"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vault"
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
		m.lock(session.ReasonKey)
		return nil
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
		m.copyField(model.FieldPassword)
		return nil
	case "u":
		m.copyField(model.FieldUsername)
		return nil
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

// refuse reports whether changes are refused now: busy, or the vault
// changed on disk. It sets the status.
func (m *app) refuse() bool {
	switch {
	case m.v == nil:
		return true
	case m.job != nil:
		m.setStatus("Busy: wait for the reload to finish.", true)
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

// copyField copies the password or the username (§6.3).
func (m *app) copyField(field string) {
	e, ok := m.needEntry()
	if !ok {
		return
	}
	value, _ := e.Field(field)
	if value == "" {
		m.setStatus(fmt.Sprintf("%s has no %s.", e.Path, field), false)
		return
	}
	if m.clip.c == nil {
		err := m.clip.err
		if err == nil {
			err = &clipboard.NoClipboardError{Reason: "no clipboard is configured"}
		}
		m.setStatusSticky(clipboard.WithHint(err, e.Path.String(), field).Error(), true)
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()
	if err := m.clip.copy(ctx, value, field, m.d.cfg.Clipboard.ClearAfter); err != nil {
		m.setStatusSticky("Not copied: "+clipboard.WithHint(err, e.Path.String(), field).Error(), true)
		return
	}
	m.st = status{copied: true}
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
	m.saveForm(f, e, fc)
	return nil
}

// saveForm saves the form's result (§4.6). A refused save keeps the
// values: the form comes back at once (Resume), or after R when the vault
// changed on disk.
func (m *app) saveForm(f *editor.Form, e model.Entry, fc formCtx) {
	if m.v == nil {
		return
	}
	if m.job != nil || m.blocked() {
		m.keepForm(f, e, fc)
		return
	}
	var (
		err     error
		changed = true
		id      = e.ID
	)
	if fc.add {
		var stored model.Entry
		stored, err = m.v.Add(e, false)
		id = stored.ID
	} else {
		changed, err = m.v.Update(e)
	}
	switch {
	case errors.Is(err, vault.ErrChanged):
		m.changedOnDisk = true
		m.keepForm(f, e, fc)
	case err != nil:
		m.form, m.fctx = f, fc
		f.Resume("Not saved: " + err.Error())
		m.sizeForm()
	default:
		m.refresh()
		m.selectEntry(id)
		switch {
		case fc.add:
			m.setStatus("Added "+e.Path.String()+".", false)
		case changed:
			m.setStatus("Saved "+e.Path.String()+".", false)
		default:
			m.setStatus("No changes.", false)
		}
	}
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
		if m.job != nil || m.blocked() {
			m.keepPrompt(p)
			return nil
		}
		err = m.v.Move(e.Path, dst)
		switch {
		case errors.Is(err, vault.ErrChanged):
			m.changedOnDisk = true
			m.keepPrompt(p)
		case err != nil:
			p.err = err.Error()
		default:
			m.closePrompt()
			m.refresh()
			m.selectEntry(e.ID)
			m.setStatus(fmt.Sprintf("Moved %s to %s.", e.Path, dst), false)
		}
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
		if m.job != nil || m.blocked() {
			m.keepPrompt(p)
			return nil
		}
		_, _, err = m.v.EditTags(e.Path, add, remove)
		switch {
		case errors.Is(err, vault.ErrChanged):
			m.changedOnDisk = true
			m.keepPrompt(p)
		case err != nil:
			p.err = err.Error()
		default:
			m.closePrompt()
			m.refresh()
			m.setStatus("Tags of "+e.Path.String()+" saved.", false)
		}
	}
	return nil
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
			m.br.answer(false)
			return m.userQuit()
		}
		return m.answerAsk(yes)
	case confirmDelete:
		if !yes {
			m.setStatus("Not deleted.", false)
			return nil
		}
		if m.job != nil || m.blocked() {
			m.setStatusSticky("Not deleted: the vault changed on disk. R reloads it; then delete again.", true)
			return nil
		}
		err := m.v.Remove(c.path)
		switch {
		case errors.Is(err, vault.ErrChanged):
			m.changedOnDisk = true
			m.setStatusSticky("Not deleted: the vault changed on disk. R reloads it; then delete again.", true)
		case err != nil:
			m.setStatusSticky("Not deleted: "+err.Error(), true)
		default:
			if m.detailID == c.id {
				m.detail = false
			}
			m.refresh()
			m.setStatus("Deleted "+c.path.String()+".", false)
		}
	}
	return nil
}

// Reload.

func (m *app) reload() tea.Cmd {
	if m.v == nil || m.job != nil {
		return nil
	}
	v := m.v
	m.setStatusSticky("Reloading…", false)
	return m.startJob("reload", func(ctx context.Context, gen int) tea.Msg {
		return reloadedMsg{gen: gen, err: v.Reload(ctx)}
	})
}

func (m *app) onReloaded(msg reloadedMsg) tea.Cmd {
	if m.job == nil || msg.gen != m.job.gen {
		return nil
	}
	m.job = nil
	if m.confirm != nil && m.confirm.kind == confirmRollback {
		m.confirm = nil
	}
	if m.screen != screenMain || m.v == nil {
		return nil
	}
	if err := msg.err; err != nil {
		if !errors.Is(err, context.Canceled) {
			m.setStatusSticky("Reload failed: "+err.Error(), true)
		}
		return nil
	}
	m.changedOnDisk = false
	m.refresh()
	info := m.v.Info()
	m.setStatus(fmt.Sprintf("Reloaded: revision %d, %d entries.", info.Revision, info.Entries), false)
	if k := m.kept; k != nil {
		m.kept = nil
		k.reopen(m)
	}
	return nil
}

// Print page.

func (m *app) startPrint(sheet print.Options) tea.Cmd {
	if m.v == nil {
		return nil
	}
	data := m.v.Snapshot()
	if data == nil {
		return nil
	}
	clearAfter := m.d.cfg.Clipboard.ClearAfter
	dlg, err := m.d.print(m.ctx, PrintRequest{
		Data:  data,
		Sheet: sheet,
		Copy: func(value string) error {
			if m.clip.c == nil {
				if m.clip.err != nil {
					return m.clip.err
				}
				return clipboard.ErrNoClipboard
			}
			return m.clip.copy(m.ctx, value, "URL", clearAfter)
		},
	})
	if err != nil {
		m.setStatusSticky("Print page: "+err.Error(), true)
		return nil
	}
	m.printDlg = dlg
	m.sess.OnLock(dlg.Stop)
	return dlg.Init()
}

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
