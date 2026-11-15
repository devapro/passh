package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"passh/internal/config"
	"passh/internal/export"
	"passh/internal/tty"
)

func (a *app) cmdExport() *cobra.Command {
	var (
		format, folder, outFlag, recipient string
		tags                               []string
		confirm, spreadsheetSafe           bool
	)
	c := &cobra.Command{
		Use:   "export --format <csv|json|bitwarden-json>",
		Short: "Export entries for other tools (plaintext unless --age)",
		Long: "Export entries as csv, json (the vault's data format) or bitwarden-json.\n\n" +
			"Export data is never written to a terminal: use -o file or redirect stdout.\n" +
			"A plaintext export needs confirmation: with a terminal you type EXPORT PLAINTEXT;\n" +
			"without one (e.g. over ssh without -t) add --confirm-plaintext. --age <recipient>\n" +
			"encrypts the export to an age public key instead. -o creates a new file with\n" +
			"mode 0600 and never overwrites one.\n\n" +
			"For a backup, don't export: copy the vault file (passh backup).",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format == "" {
				return usagef("--format is required: csv, json or bitwarden-json")
			}
			f, err := export.ParseFormat(format)
			if err != nil {
				return usageErr(err)
			}
			filter, err := export.ParseFilter(folder, tags)
			if err != nil {
				return err
			}
			opts := export.Options{Format: f, Filter: filter, SpreadsheetSafe: spreadsheetSafe, Recipient: recipient}
			if recipient != "" && confirm {
				return usageErr(export.ErrAgeAndConfirm)
			}
			if spreadsheetSafe && f != export.FormatCSV {
				return usageErr(export.ErrSpreadsheetSafe)
			}
			if recipient != "" {
				if _, err := export.ParseRecipient(recipient); err != nil {
					return err
				}
			}

			// Where the data goes: never a terminal.
			out, err := a.prepareOutput(outFlag, "export data")
			if err != nil {
				return err
			}

			// Confirmation of a plaintext export (§7.1).
			t, terr := a.tty()
			prompt, err := export.ConfirmPlaintext(opts, terr == nil, confirm)
			if err != nil {
				if errors.Is(err, export.ErrAgeAndConfirm) {
					return usageErr(err)
				}
				return err
			}
			if prompt {
				t.Printf("This writes your passwords unencrypted.\n")
				if err := t.Confirm(tty.PhraseExportPlaintext); err != nil {
					return err
				}
			}

			v, err := a.unlock(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			var buf bytes.Buffer
			defer func() { b := buf.Bytes(); clear(b[:cap(b)]) }()
			sum, err := export.Export(&buf, v.Snapshot(), opts)
			if err != nil {
				return err
			}
			dest, err := a.write(out, buf.Bytes(), opts.Plaintext())
			if err != nil {
				return err
			}
			kind := "plaintext"
			if sum.Encrypted {
				kind = "encrypted with age"
			}
			a.notef("exported %s (%s, %s) to %s", plural(sum.Entries, "entry", "entries"), f, kind, dest)
			if sum.OmittedFields > 0 {
				a.warnf("CSV has no column for custom fields: %s left out (otp fields included); use --format json or bitwarden-json to keep them",
					plural(sum.OmittedFields, "field was", "fields were"))
			}
			return nil
		},
	}
	fl := c.Flags()
	fl.StringVar(&format, "format", "", "csv, json or bitwarden-json")
	fl.StringSliceVar(&tags, "tag", nil, "only entries with this tag (repeat for several: all must match)")
	fl.StringVar(&folder, "folder", "", "only entries in this folder")
	fl.StringVarP(&outFlag, "output", "o", "", "write to this new file (mode 0600) instead of stdout")
	fl.StringVar(&recipient, "age", "", "encrypt to this age public key (age1…)")
	fl.BoolVar(&confirm, "confirm-plaintext", false, "confirm a plaintext export when there is no terminal")
	fl.BoolVar(&spreadsheetSafe, "spreadsheet-safe", false, "CSV: prefix ' to cells starting with = + - @ (changes values; not for password managers)")
	return c
}

// writeNewFile creates path (never overwriting, never through a symlink)
// with mode 0600, writes data and fsyncs it. A terminal device is refused.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; passh doesn't overwrite files", config.ContractHome(path))
	}
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", config.ContractHome(path), err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("writing %s: %w", config.ContractHome(path), err)
	}
	return nil
}
