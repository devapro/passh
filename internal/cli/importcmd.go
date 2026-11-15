package cli

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"passh/internal/importpass"
	"passh/internal/model"
	"passh/internal/paths"
	"passh/internal/tty"
)

func (a *app) cmdImport() *cobra.Command {
	c := &cobra.Command{
		Use:   "import",
		Short: "Import entries from another password manager",
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
		Short: "One-way import from a pass store (needs gpg)",
		Long: "Import a pass store (password-store.org) into the vault, in one save. The store\n" +
			"is only read. dir defaults to $PASSWORD_STORE_DIR, then ~/.password-store.\n" +
			"Each entry is decrypted with gpg, as pass does. Paths already in the vault are\n" +
			"skipped unless --overwrite is given. --dry-run lists what would be imported\n" +
			"and the conflicts without decrypting anything.",
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
			if tty.IsTerminal(a.stderr) {
				opts.Progress = func(n, total int, file string) {
					fmt.Fprintf(a.stderr, "\rDecrypting %d/%d…\x1b[K", n, total)
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
				err := v.Apply(func(d *model.Data, now time.Time) (bool, error) {
					for _, e := range res.Entries() {
						if _, err := d.Add(e, now, overwrite); err != nil {
							return false, fmt.Errorf("%s: %w", e.Path, err)
						}
					}
					return true, nil
				})
				if err != nil {
					return fmt.Errorf("nothing was imported: %w", err)
				}
			}
			return writeAll(a.stdout, importReport(res, replaced))
		},
	}
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace entries whose path is already in the vault")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "list what would be imported and the conflicts; decrypt nothing")
	return c
}

// importReport is the summary of an import (§4.9): what was (or would be)
// imported, what was skipped and why. Every name from the store is escaped
// (S4): file names in a pass store can hold any bytes.
func importReport(res *importpass.Result, replaced int) string {
	var b strings.Builder
	if res.DryRun {
		fmt.Fprintf(&b, "Dry run: nothing was decrypted or saved. Store: %s\n", line(res.Dir))
		if len(res.Items) > 0 {
			fmt.Fprintf(&b, "Would import %s:\n", plural(len(res.Items), "entry", "entries"))
			for _, it := range res.Items {
				note := ""
				if it.Replace {
					note = "  (replaces the entry in the vault)"
				}
				fmt.Fprintf(&b, "  %s%s\n", line(it.Path.String()), note)
			}
		}
	}
	verb := "Imported"
	if res.DryRun {
		verb = "Would import"
	}
	fmt.Fprintf(&b, "%s %s", verb, plural(len(res.Items), "entry", "entries"))
	if replaced > 0 {
		fmt.Fprintf(&b, " (%d replacing entries already in the vault)", replaced)
	}
	if !res.DryRun {
		fmt.Fprintf(&b, " from %s", line(res.Dir))
	}
	b.WriteString(".\n")
	if len(res.Skipped) == 0 {
		return b.String()
	}
	by := res.SkippedBy()
	reasons := make([]importpass.Reason, 0, len(by))
	for r := range by {
		reasons = append(reasons, r)
	}
	slices.Sort(reasons)
	var counts []string
	for _, r := range reasons {
		counts = append(counts, fmt.Sprintf("%d %s", by[r], r))
	}
	skipVerb := "Skipped"
	if res.DryRun {
		skipVerb = "Would skip"
	}
	fmt.Fprintf(&b, "%s %d: %s.\n", skipVerb, len(res.Skipped), strings.Join(counts, ", "))
	for _, s := range res.Skipped {
		detail := ""
		if s.Detail != "" {
			detail = ": " + line(s.Detail)
		}
		fmt.Fprintf(&b, "  %s — %s%s\n", line(s.File), s.Reason, detail)
	}
	return b.String()
}
