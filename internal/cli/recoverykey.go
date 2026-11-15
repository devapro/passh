package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/print"
	"github.com/devapro/passh/internal/tty"
)

// recoverySheetHint tells the user to print the paper recovery key.
const recoverySheetHint = "Print the paper recovery key now and keep the sheet offline:\n" +
	"  passh recovery-key print\n" +
	"Without it, a forgotten passphrase means the data is lost."

func (a *app) cmdRecoveryKey() *cobra.Command {
	c := &cobra.Command{
		Use:   "recovery-key",
		Short: "The paper recovery key",
		Args:  noArgs(),
		RunE: func(*cobra.Command, []string) error {
			return usagef("say what to do, e.g. `passh recovery-key print`")
		},
	}
	var pf printFlags
	p := &cobra.Command{
		Use:   "print [--format pdf|txt] [-o file] [--web]",
		Short: "Print the paper recovery key (needs a terminal and typing PRINT RECOVERY KEY)",
		Long: "Print the paper recovery key: the vault key in groups of four characters and\n" +
			"as a QR code, the vault_id, the print date, a warning and the manual recovery\n" +
			"steps. Whoever has the sheet and a copy of the vault can read everything: keep\n" +
			"it offline, and print a new one after `passh rekey`.\n\n" +
			"It needs a terminal and typing PRINT RECOVERY KEY. The sheet is never written\n" +
			"to a terminal: use -o file (mode 0600) or redirect stdout, print it, then delete\n" +
			"the file. --web shows it on the one-shot print page instead.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			f, paper, err := pf.parse(cmd)
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			var out output
			var t *tty.TTY
			if pf.web {
				if t, err = a.webPrelude(ctx, cfg, tty.PhrasePrintRecoveryKey); err != nil {
					return err
				}
			} else {
				if out, err = a.prepareOutput(pf.out, "the recovery key"); err != nil {
					return err
				}
				if t, err = a.needTTY("passh recovery-key print"); err != nil {
					return err
				}
				if err := t.ConfirmContext(ctx, tty.PhrasePrintRecoveryKey); err != nil {
					return err
				}
			}
			sheet, err := a.recoverySheet(ctx)
			if err != nil {
				return err
			}
			if pf.web {
				return a.servePrintPage(ctx, t, cfg, sheet)
			}
			dest, err := a.writeRecoverySheet(out, sheet, f, paper)
			if err != nil {
				return err
			}
			// stderr: with stdout redirected, stdout is the sheet (CLI-001).
			a.statusf("Wrote the paper recovery key to %s.", dest)
			return nil
		},
	}
	pf.register(p)
	c.AddCommand(p)
	return c
}

// recoverySheet unlocks the vault (the usual key chain) and makes the
// sheet for its key.
func (a *app) recoverySheet(ctx context.Context) (*print.RecoverySheet, error) {
	v, err := a.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	return print.NewRecoverySheet(v.Key(), v.Info().VaultID, time.Now())
}

// writeRecoverySheet renders and writes the sheet.
func (a *app) writeRecoverySheet(out output, sheet *print.RecoverySheet, f docFormat, paper print.PaperSize) (string, error) {
	data, err := render(sheet, f, paper)
	if err != nil {
		return "", err
	}
	defer clear(data)
	dest, err := a.write(out, data, true)
	if err != nil {
		return "", err
	}
	if out.path != "" {
		a.notef("print it, keep the sheet offline, then delete the file: rm %s", shellQuote(out.path))
	}
	return dest, nil
}

// offerRecoverySheet is `passh init`'s offer to print the recovery key
// (§5.4): a sheet written to a file the user picks (PDF, or text for a
// .txt name), after typing PRINT RECOVERY KEY.
func (a *app) offerRecoverySheet(ctx context.Context, t *tty.TTY, key *age.X25519Identity, vaultID string) error {
	ok, err := t.YesNoContext(ctx, "Print the recovery key now?", true)
	var se *tty.SignalError
	switch {
	case errors.As(err, &se):
		return err // a signal ends passh
	case err != nil:
		// The vault is created; a failed prompt (no answer, EOF) only skips
		// the offer, and the hint says how to print the sheet later.
		a.statusf("%s", recoverySheetHint)
		return nil //nolint:nilerr // see the comment above (CLI-010)
	case !ok:
		a.statusf("%s", recoverySheetHint)
		return nil
	}
	def := defaultSheetPath()
	var out output
	for i := 0; ; i++ {
		ans, err := t.ReadLineContext(ctx, fmt.Sprintf("Write the sheet (PDF; .txt for text) to [%s]: ", displayPath(def)))
		if err != nil {
			return err
		}
		if strings.TrimSpace(ans) == "" {
			ans = def
		}
		if out, err = a.prepareOutput(ans, "the recovery key"); err == nil && out.path != "" {
			break
		}
		if i == promptAttempts-1 {
			return err
		}
		termf(t, "%v\n", err)
	}
	if err := t.ConfirmContext(ctx, tty.PhrasePrintRecoveryKey); err != nil {
		return err
	}
	sheet, err := print.NewRecoverySheet(key, vaultID, time.Now())
	if err != nil {
		return err
	}
	f := formatPDF
	if strings.EqualFold(filepath.Ext(out.path), ".txt") {
		f = formatTXT
	}
	dest, err := a.writeRecoverySheet(out, sheet, f, print.A4)
	if err != nil {
		return err
	}
	a.statusf("Wrote the paper recovery key to %s.", dest)
	return nil
}

// defaultSheetPath proposes where init writes the recovery sheet: on
// tmpfs if there is one (/dev/shm), else in the home folder.
func defaultSheetPath() string {
	if onTmpfs("/dev/shm") {
		return "/dev/shm/passh-recovery.pdf"
	}
	if home, err := config.HomeDir(); err == nil {
		return filepath.Join(home, "passh-recovery.pdf")
	}
	return "passh-recovery.pdf"
}
