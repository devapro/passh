package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/export"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/printweb"
	"github.com/devapro/passh/internal/tty"
)

// docFormat is the format of a printed sheet.
type docFormat string

const (
	formatPDF docFormat = "pdf"
	formatTXT docFormat = "txt"
)

func parseDocFormat(s string) (docFormat, error) {
	switch f := docFormat(strings.ToLower(s)); f {
	case formatPDF, formatTXT:
		return f, nil
	}
	return "", usagef("--format %q: use pdf or txt", s)
}

// render lays out doc as PDF or text.
func render(doc print.Document, f docFormat, paper print.PaperSize) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if f == formatTXT {
		err = print.WriteTXT(&buf, doc)
	} else {
		err = print.WritePDF(&buf, doc, paper)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// printFlags are the output flags shared by print and recovery-key print.
type printFlags struct {
	format string
	paper  string
	out    string
	web    bool
}

func (pf *printFlags) register(c *cobra.Command) {
	c.Flags().StringVar(&pf.format, "format", "pdf", "pdf or txt")
	c.Flags().StringVar(&pf.paper, "paper", "a4", "PDF paper size: a4 or letter")
	c.Flags().StringVarP(&pf.out, "output", "o", "", "write to this new file (mode 0600) instead of stdout")
	c.Flags().BoolVar(&pf.web, "web", false, "show the sheet on the one-shot print page (§7.4) instead")
}

// parse checks the flags: the format and paper size, and that --web isn't
// combined with file options.
func (pf *printFlags) parse(c *cobra.Command) (docFormat, print.PaperSize, error) {
	if pf.web {
		for _, f := range []string{"format", "paper", "output"} {
			if c.Flags().Changed(f) {
				return "", 0, usagef("--%s can't be used with --web", f)
			}
		}
	}
	f, err := parseDocFormat(pf.format)
	if err != nil {
		return "", 0, err
	}
	paper, err := print.ParsePaperSize(pf.paper)
	if err != nil {
		return "", 0, usageErr(err)
	}
	return f, paper, nil
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
		Use:   "print [--tag t] [--folder f] [--fields password,username,url] [--format pdf|txt] [-o file]",
		Short: "Print a password sheet (PDF or text), or show it on the print page (--web)",
		Long: "Lay out the chosen entries as a password sheet, grouped by folder, with the\n" +
			"chosen fields (default password,username,url; also tags, notes, fields, or a\n" +
			"custom field's key). Ambiguous characters are marked.\n\n" +
			"The sheet is plaintext: it is never written to a terminal, and it needs\n" +
			"confirmation as a plaintext export does (type EXPORT PLAINTEXT, or\n" +
			"--confirm-plaintext without a terminal). Print it, then delete the file.\n\n" +
			"--web shows it on the one-shot print page instead (print_web.enabled; needs a\n" +
			"terminal and typing PRINT).",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			f, paper, err := pf.parse(cmd)
			if err != nil {
				return err
			}
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
			data, err := render(sheet, f, paper)
			if err != nil {
				return err
			}
			defer clear(data)
			dest, err := a.write(out, data, true)
			if err != nil {
				return err
			}
			a.notef("printed %s (%s) to %s; print it, then delete the file", plural(sheet.Len(), "entry", "entries"), f, dest)
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
