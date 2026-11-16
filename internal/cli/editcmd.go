package cli

import (
	"context"
	"errors"
	"io"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vault"
)

// changedAttempts bounds how often a save is retried after "vault changed
// on disk".
const changedAttempts = 3

func (a *app) cmdEdit() *cobra.Command {
	var useEditor bool
	c := &cobra.Command{
		Use:   "edit <path> [--editor]",
		Short: a.T("Edit an entry in the built-in form, or in $EDITOR"),
		Long: a.T("Edit an entry in the built-in form: password, username, url, tags and notes\n" +
			"(ctrl+s saves, esc cancels, ctrl+r reveals the password, ctrl+g generates one).\n\n" +
			"--editor opens the entry's text form in $EDITOR instead, in a temporary file on\n" +
			"tmpfs that is wiped afterwards. vim, neovim and nano get flags that keep them\n" +
			"from writing swap, backup or history files. Where there is no tmpfs (macOS),\n" +
			"the built-in form is used."),
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			t, err := a.needTTY("passh edit")
			if err != nil {
				return err
			}
			var ed *editor.Editor
			if useEditor {
				if ed, err = a.findEditor(); err != nil {
					return err
				}
			}
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			e, ok := v.Get(p)
			if !ok {
				return notFound(v, p)
			}

			var edited model.Entry
			if ed != nil {
				if ed.Warning != "" {
					a.termf(t, "warning: %s\n", ed.WarningMsg)
				}
				edited, err = ed.Edit(ctx, t.File(), e, func(pe *editor.ParseError) bool {
					a.termf(t, "The entry isn't valid: %s\n", line(a.p.Error(pe)))
					// A failed prompt (EOF, a signal) means no: the edit is
					// not saved, and the editor's file is removed.
					again, err := t.YesNoContext(ctx, a.T("Edit it again?"), true)
					return err == nil && again
				})
			} else {
				edited, err = editor.Run(ctx, t.File(), e, editor.FormOptions{Title: a.T("edit %s", p.String()), Printer: a.p})
			}
			switch {
			case errors.Is(err, editor.ErrNoChange):
				a.statusf("No change.")
				return nil
			case errors.Is(err, editor.ErrCancelled):
				return i18n.NewError("cancelled; nothing was saved")
			case err != nil:
				return i18n.Errorf("nothing was saved: %w", err)
			}
			changed, err := a.saveEdit(ctx, t, v, edited)
			if err != nil {
				return err
			}
			if !changed {
				a.statusf("No change.")
				return nil
			}
			a.statusf("Saved %s.", line(edited.Path.String()))
			return nil
		},
	}
	c.Flags().BoolVar(&useEditor, "editor", false, a.T("edit the text form in $EDITOR (temporary file on tmpfs)"))
	return c
}

// findEditor is the external editor for `edit --editor`, or nil when there
// is no tmpfs for its temporary file: then the form is used (S1).
func (a *app) findEditor() (*editor.Editor, error) {
	if _, err := editor.TempBase(); errors.Is(err, editor.ErrNoTmpfs) {
		a.notef("%v; using the built-in form instead", err)
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return editor.FindEditor()
}

// saveEdit saves the edited entry. If the vault changed on disk since it
// was opened (§4.6), it asks whether to reload and apply the edit again to
// the same entry (by id). The edited text is never written anywhere else.
func (a *app) saveEdit(ctx context.Context, t *tty.TTY, v *vault.Vault, edited model.Entry) (bool, error) {
	for attempt := 1; ; attempt++ {
		changed, err := v.UpdateContext(ctx, edited)
		if !errors.Is(err, vault.ErrChanged) {
			return changed, err
		}
		if attempt == changedAttempts {
			return false, err
		}
		again, aerr := t.YesNoContext(ctx, a.T("The vault changed on disk since it was opened; reload and apply your edit again?"), false)
		if aerr != nil && !errors.Is(aerr, io.EOF) {
			return false, i18n.Errorf("not saved: %w", aerr)
		}
		if !again {
			return false, i18n.NewError("not saved: the vault changed on disk since it was opened")
		}
		if err := v.Reload(ctx); err != nil {
			return false, i18n.Errorf("not saved: reloading the vault: %w", err)
		}
		cur, ok := v.GetByID(edited.ID)
		if !ok {
			return false, i18n.Errorf("not saved: %s was deleted or replaced in the vault on disk", edited.Path)
		}
		edited = withEditedContent(cur, edited)
	}
}

// withEditedContent is cur (as reloaded: its path, times and unknown keys)
// with the values the user edited.
func withEditedContent(cur, edited model.Entry) model.Entry {
	r := cur.Clone()
	r.Password, r.Username, r.URL, r.Notes = edited.Password, edited.Username, edited.URL, edited.Notes
	r.Tags = append([]string(nil), edited.Tags...)
	r.Fields = edited.Clone().Fields
	return r
}
