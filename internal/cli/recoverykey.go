package cli

import (
	"context"
	"errors"
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
	"  passh recovery-key print -o <file>   (or --web, with the key as a QR code)\n" +
	"Without it, a forgotten passphrase means the data is lost."

func (a *app) cmdRecoveryKey() *cobra.Command {
	c := &cobra.Command{
		Use:   "recovery-key",
		Short: a.T("The paper recovery key"),
		Args:  noArgs(),
		RunE: func(*cobra.Command, []string) error {
			return usagef("say what to do, e.g. `passh recovery-key print`")
		},
	}
	var pf printFlags
	p := &cobra.Command{
		Use:   "print [-o file] [--web]",
		Short: a.T("Print the paper recovery key (needs a terminal and typing PRINT RECOVERY KEY)"),
		Long: a.T("Print the paper recovery key as a text sheet: the vault key in groups of four\n" +
			"characters, the vault_id, the print date, a warning and the manual recovery\n" +
			"steps. Whoever has the sheet and a copy of the vault can read everything: keep\n" +
			"it offline, and print a new one after `passh rekey`.\n\n" +
			"It needs a terminal and typing PRINT RECOVERY KEY. The sheet is never written\n" +
			"to a terminal: use -o file (mode 0600) or redirect stdout, print it, then delete\n" +
			"the file. --web shows it on the one-shot print page instead, with the key as a\n" +
			"QR code; the browser prints it, or saves it as PDF."),
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := pf.parse(cmd); err != nil {
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
				if out, err = a.prepareOutput(pf.out, errRecoveryKeyToTerminal); err != nil {
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
			dest, err := a.writeRecoverySheet(out, sheet)
			if err != nil {
				return err
			}
			// stderr: with stdout redirected, stdout is the sheet (CLI-001).
			a.statusf("Wrote the paper recovery key to %s.", dest)
			a.sheetFileNote(out)
			return nil
		},
	}
	pf.register(p, a.p)
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
	return print.NewRecoverySheet(v.Key(), v.Info().VaultID, time.Now(), a.p)
}

// writeRecoverySheet renders and writes the text sheet. The caller says
// where it went, then calls sheetFileNote.
func (a *app) writeRecoverySheet(out output, sheet *print.RecoverySheet) (string, error) {
	data, err := render(sheet)
	if err != nil {
		return "", err
	}
	defer clear(data)
	return a.write(out, data, true)
}

// sheetFileNote tells what to do with a recovery sheet written to a file:
// after "Wrote the paper recovery key to …", which "print it" refers to.
func (a *app) sheetFileNote(out output) {
	if out.path != "" {
		a.notef("print it, keep the sheet offline, then delete the file: rm %s", shellQuote(out.path))
	}
}

// offerRecoverySheet is `passh init`'s offer to print the recovery key
// (§5.4): the text sheet, written to a file the user picks after typing
// PRINT RECOVERY KEY. The version with a QR code is on the print page.
func (a *app) offerRecoverySheet(ctx context.Context, t *tty.TTY, key *age.X25519Identity, vaultID string) error {
	ok, err := t.YesNoContext(ctx, a.T("Print the recovery key now?"), true)
	var se *tty.SignalError
	switch {
	case errors.As(err, &se):
		return err // a signal ends passh
	case err != nil:
		// The vault is created; a failed prompt (no answer, EOF) only skips
		// the offer, and the hint says how to print the sheet later.
		a.statusf(recoverySheetHint)
		return nil //nolint:nilerr // see the comment above (CLI-010)
	case !ok:
		a.statusf(recoverySheetHint)
		return nil
	}
	def := defaultSheetPath()
	var out output
	for i := 0; ; i++ {
		ans, err := t.ReadLineContext(ctx, a.T("Write the text sheet to [%s]: ", displayPath(def)))
		if err != nil {
			return err
		}
		if strings.TrimSpace(ans) == "" {
			ans = def
		}
		if out, err = a.prepareOutput(ans, errRecoveryKeyToTerminal); err == nil && out.path != "" {
			break
		}
		if i == promptAttempts-1 {
			return err
		}
		a.termf(t, "%v\n", err)
	}
	if err := t.ConfirmContext(ctx, tty.PhrasePrintRecoveryKey); err != nil {
		return err
	}
	sheet, err := print.NewRecoverySheet(key, vaultID, time.Now(), a.p)
	if err != nil {
		return err
	}
	dest, err := a.writeRecoverySheet(out, sheet)
	if err != nil {
		return err
	}
	a.statusf("Wrote the paper recovery key to %s.", dest)
	a.sheetFileNote(out)
	a.statusf("For a version with the key as a QR code: passh recovery-key print --web")
	return nil
}

// defaultSheetPath proposes where init writes the recovery sheet: on
// tmpfs if there is one (/dev/shm), else in the home folder.
func defaultSheetPath() string {
	if onTmpfs("/dev/shm") {
		return "/dev/shm/passh-recovery.txt"
	}
	if home, err := config.HomeDir(); err == nil {
		return filepath.Join(home, "passh-recovery.txt")
	}
	return "passh-recovery.txt"
}
