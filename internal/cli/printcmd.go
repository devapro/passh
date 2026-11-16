package cli

import (
	"bytes"
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/export"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/tty"
)

// errPDFRemoved answers the --format flag of older versions: passh writes
// no PDF (owner decision, 2026-11-16).
var errPDFRemoved = usagef("PDF output was removed; use --web to print from a browser (it can save as PDF), or omit --format for the text sheet")

// render lays out doc as the text sheet. The caller wipes the result.
func render(doc print.Document) ([]byte, error) {
	var buf bytes.Buffer
	if err := print.WriteTXT(&buf, doc); err != nil {
		clear(buf.Bytes()[:buf.Cap()])
		return nil, err
	}
	return buf.Bytes(), nil
}

// printFlags are the output flags shared by print and recovery-key print.
type printFlags struct {
	out string
	web bool
	// format is the removed --format option, hidden: using it says why it
	// is gone instead of "unknown flag".
	format string
}

func (pf *printFlags) register(c *cobra.Command) {
	c.Flags().StringVarP(&pf.out, "output", "o", "", "write to this new file (mode 0600) instead of stdout")
	c.Flags().BoolVar(&pf.web, "web", false, "show the sheet on the one-shot print page (§7.4), with a QR code; a browser can print it or save it as PDF")
	c.Flags().StringVar(&pf.format, "format", "", "removed: the sheet is plain text")
	_ = c.Flags().MarkHidden("format") // the flag was just defined: can't fail
}

// parse checks the flags: no removed PDF option, and no -o with --web.
func (pf *printFlags) parse(c *cobra.Command) error {
	if c.Flags().Changed("format") {
		return errPDFRemoved
	}
	if pf.web && c.Flags().Changed("output") {
		return usagef("--output can't be used with --web")
	}
	return nil
}

func (a *app) cmdPrint() *cobra.Command {
	var (
		pf      printFlags
		folder  string
		tags    []string
		fields  string
		confirm bool
	)
	c := &cobra.Command{
		Use:   "print [--tag t] [--folder f] [--fields password,username,url] [-o file] [--confirm-plaintext] [--web]",
		Short: "Print a password sheet (text), or show it on the print page (--web)",
		Long: "Lay out the chosen entries as a text password sheet, grouped by folder, with\n" +
			"the chosen fields (default password,username,url; also tags, notes, fields, or\n" +
			"a custom field's key). Ambiguous characters are marked.\n\n" +
			"The sheet is plaintext: it is never written to a terminal, and it needs\n" +
			"confirmation as a plaintext export does (type EXPORT PLAINTEXT, or\n" +
			"--confirm-plaintext without a terminal). Use -o file (mode 0600) or redirect\n" +
			"stdout; print it, then delete the file.\n\n" +
			"--web shows it on the one-shot print page instead (print_web.enabled; needs a\n" +
			"terminal and typing PRINT); the browser prints it, or saves it as PDF.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := pf.parse(cmd); err != nil {
				return err
			}
			var err error
			if pf.web && confirm {
				return usagef("--confirm-plaintext can't be used with --web: the print page needs a terminal")
			}
			opts := print.Options{}
			if folder != "" {
				if opts.Folder, err = paths.ParseFolder(folder); err != nil {
					return err
				}
			}
			for _, t := range tags {
				n, err := model.NormalizeTag(t)
				if err != nil {
					return err
				}
				opts.Tags = append(opts.Tags, n)
			}
			if opts.Fields, err = print.ParseFields(fields); err != nil {
				return usageErr(err)
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}

			var out output
			if pf.web {
				t, err := a.webPrelude(ctx, cfg, tty.PhrasePrint)
				if err != nil {
					return err
				}
				sheet, err := a.passwordSheet(ctx, opts)
				if err != nil {
					return err
				}
				return a.servePrintPage(ctx, t, cfg, sheet)
			}
			if out, err = a.prepareOutput(pf.out, "the sheet"); err != nil {
				return err
			}
			// The same confirmation as a plaintext export (§7.2, §7.1).
			t, terr := a.tty()
			prompt, err := export.ConfirmPlaintext(export.Options{}, terr == nil, confirm)
			if err != nil {
				return errors.New("printing needs confirmation: without a terminal, add --confirm-plaintext")
			}
			if prompt {
				termf(t, "The sheet holds your passwords unencrypted.\n")
				if err := t.ConfirmContext(ctx, tty.PhraseExportPlaintext); err != nil {
					return err
				}
			}
			sheet, err := a.passwordSheet(ctx, opts)
			if err != nil {
				return err
			}
			data, err := render(sheet)
			if err != nil {
				return err
			}
			defer clear(data)
			dest, err := a.write(out, data, true)
			if err != nil {
				return err
			}
			a.notef("printed %s (text sheet) to %s; print it, then delete the file", plural(sheet.Len(), "entry", "entries"), dest)
			return nil
		},
	}
	pf.register(c)
	c.Flags().StringSliceVar(&tags, "tag", nil, "only entries with this tag (repeat for several: all must match)")
	c.Flags().StringVar(&folder, "folder", "", "only entries in this folder")
	c.Flags().StringVar(&fields, "fields", "", "fields to print, comma-separated (default password,username,url)")
	c.Flags().BoolVar(&confirm, "confirm-plaintext", false, "confirm a plaintext sheet when there is no terminal")
	return c
}

// passwordSheet unlocks the vault and lays out the sheet; the vault is
// closed again before the sheet is written or served.
func (a *app) passwordSheet(ctx context.Context, opts print.Options) (*print.Sheet, error) {
	v, err := a.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	return print.NewSheet(v.Entries(), opts)
}

// webPrelude checks what the print page needs before anything is
// unlocked: print_web.enabled, a terminal, and the confirmation phrase.
func (a *app) webPrelude(ctx context.Context, cfg *config.Config, phrase string) (*tty.TTY, error) {
	if !cfg.PrintWeb.Enabled {
		return nil, printweb.ErrDisabled
	}
	t, err := a.needTTY("the print page")
	if err != nil {
		return nil, err
	}
	if err := t.ConfirmContext(ctx, phrase); err != nil {
		return nil, err
	}
	return t, nil
}
