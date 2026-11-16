package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/importpass"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/tty"
)

func (a *app) cmdImport() *cobra.Command {
	c := &cobra.Command{
		Use:   "import",
		Short: a.T("Import entries from another password manager"),
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usagef("say what to import from, e.g. `passh import pass`")
		},
	}
	c.AddCommand(a.cmdImportPass())
	return c
}

func (a *app) cmdImportPass() *cobra.Command {
	var overwrite, dryRun bool
	c := &cobra.Command{
		Use:   "pass [dir]",
		Short: a.T("One-way import from a pass store (needs gpg)"),
		Long: a.T("Import a pass store (password-store.org) into the vault, in one save. The store\n" +
			"is only read. dir defaults to $PASSWORD_STORE_DIR, then ~/.password-store.\n" +
			"Each entry is decrypted with gpg, as pass does. Paths already in the vault are\n" +
			"skipped unless --overwrite is given. --dry-run lists what would be imported\n" +
			"and the conflicts without decrypting anything."),
		Args: rangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dir := ""
			if len(args) == 1 {
				dir = args[0]
			}
			v, err := a.unlock(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			opts := importpass.Options{
				Dir:       dir,
				Overwrite: overwrite,
				DryRun:    dryRun,
				Exists:    func(p paths.Path) bool { _, ok := v.Get(p); return ok },
			}
			opts.GPG.TTY = a.gpgTTY()
			if tty.IsTerminal(a.stderr) {
				opts.Progress = func(n, total int, file string) {
					fmt.Fprintf(a.stderr, "\r%s\x1b[K", a.T("Decrypting %d/%d…", n, total))
					if n == total {
						fmt.Fprint(a.stderr, "\r\x1b[K")
					}
				}
			}
			res, err := importpass.Run(ctx, opts)
			if err != nil {
				return err
			}
			replaced := 0
			for _, it := range res.Items {
				if it.Replace {
					replaced++
				}
			}
			if !dryRun && len(res.Items) > 0 {
				err := v.ApplyContext(ctx, func(d *model.Data, now time.Time) (bool, error) {
					for _, e := range res.Entries() {
						if _, err := d.Add(e, now, overwrite); err != nil {
							return false, fmt.Errorf("%s: %w", e.Path, err)
						}
					}
					return true, nil
				})
				if err != nil {
					return i18n.Errorf("nothing was imported: %w", err)
				}
			}
			return writeAll(a.stdout, importReportIn(a.p, res, replaced))
		},
	}
	c.Flags().BoolVar(&overwrite, "overwrite", false, a.T("replace entries whose path is already in the vault"))
	c.Flags().BoolVar(&dryRun, "dry-run", false, a.T("list what would be imported and the conflicts; decrypt nothing"))
	return c
}

// gpgTTY is GPG_TTY for gpg's pinentry (§4.9): "" when $GPG_TTY is set
// (gpg inherits it), else the device of passh's terminal, such as
// /dev/pts/3: /dev/tty when there is one (also with every standard stream
// redirected), else a standard stream that is a terminal.
func (a *app) gpgTTY() string {
	if os.Getenv("GPG_TTY") != "" {
		return ""
	}
	if t, err := a.tty(); err == nil {
		if n := t.DeviceName(); n != "" {
			return n
		}
	}
	for _, f := range []*os.File{a.stdin, a.stderr, a.stdout} {
		if n := tty.DeviceName(f); n != "" {
			return n
		}
	}
	return ""
}

// importReport is the summary of an import (§4.9), in English: what was
// (or would be) imported, what was skipped and why. See importReportIn.
func importReport(res *importpass.Result, replaced int) string {
	return importReportIn(i18n.Printer{}, res, replaced)
}

// importReportIn is the import report in p's language: it is a report for
// people, translated except the names in it (paths, file names). Every name
// from the store is escaped (S4): file names in a pass store can hold any
// bytes.
func importReportIn(p i18n.Printer, res *importpass.Result, replaced int) string {
	var b strings.Builder
	n := len(res.Items)
	if res.DryRun {
		b.WriteString(p.T("Dry run: nothing was decrypted or saved. Store: %s", line(res.Dir)) + "\n")
		if n > 0 {
			b.WriteString(p.N(n, "Would import %d entry:", "Would import %d entries:", n) + "\n")
			for _, it := range res.Items {
				if it.Replace {
					b.WriteString("  " + p.T("%s  (replaces the entry in the vault)", line(it.Path.String())) + "\n")
				} else {
					b.WriteString("  " + line(it.Path.String()) + "\n")
				}
			}
		}
	}
	// "(n replacing entries already in the vault)": English uses one form
	// for every n, Russian and Serbian don't.
	replacing := ""
	if replaced > 0 {
		replacing = p.N(replaced, " (%d replacing entries already in the vault)", " (%d replacing entries already in the vault)", replaced)
	}
	if res.DryRun {
		b.WriteString(p.N(n, "Would import %d entry%s.", "Would import %d entries%s.", n, replacing) + "\n")
	} else {
		b.WriteString(p.N(n, "Imported %d entry%s from %s.", "Imported %d entries%s from %s.", n, replacing, line(res.Dir)) + "\n")
	}
	if len(res.Skipped) == 0 {
		return b.String()
	}
	by := res.SkippedBy()
	reasons := make([]importpass.Reason, 0, len(by))
	for r := range by {
		reasons = append(reasons, r)
	}
	slices.Sort(reasons)
	counts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		counts = append(counts, reasonCount(p, by[r], r))
	}
	// One form in English; Russian and Serbian agree with the count.
	skipped := len(res.Skipped)
	if res.DryRun {
		b.WriteString(p.N(skipped, "Would skip %d: %s.", "Would skip %d: %s.", skipped, strings.Join(counts, ", ")) + "\n")
	} else {
		b.WriteString(p.N(skipped, "Skipped %d: %s.", "Skipped %d: %s.", skipped, strings.Join(counts, ", ")) + "\n")
	}
	for _, s := range res.Skipped {
		detail := ""
		if s.Detail != "" {
			detail = ": " + line(s.LocalizeDetail(p))
		}
		fmt.Fprintf(&b, "  %s — %s%s\n", line(s.File), localized(p, s.Reason), detail)
	}
	return b.String()
}

// reasonCount is one item of the import report's count of skipped files:
// "2 invalid path" in English. Russian and Serbian put the count after the
// reason ("недопустимый путь — 2"): before it, the reason would have to
// agree with the number, and it is one text for every count.
func reasonCount(p i18n.Printer, n int, r importpass.Reason) string {
	if p.Lang() == i18n.En {
		return fmt.Sprintf("%d %s", n, localized(p, r))
	}
	return fmt.Sprintf("%s — %d", localized(p, r), n)
}

// localized renders v for people in p's language: a value that implements
// i18n.Localizer translates itself, anything else is printed with %v.
func localized(p i18n.Printer, v any) string {
	if l, ok := v.(i18n.Localizer); ok {
		return l.Localize(p)
	}
	return fmt.Sprint(v)
}
