package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vault"
)

func (a *app) cmdPasswd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the passphrase (the paper recovery key stays valid)",
		Long: "Change the passphrase: only the key block is rewritten, and the paper recovery\n" +
			"key stays valid. It asks for the current passphrase on the terminal, also while\n" +
			"the agent runs: the agent's key isn't enough to change it. A running agent is\n" +
			"stopped afterwards.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			t, path, v, err := a.openWithCurrentPassphrase(ctx, "passwd")
			if err != nil {
				return err
			}
			defer v.Close()
			termf(t, "Choose the new passphrase.\n")
			pass, err := newPassphrase(ctx, t)
			if err != nil {
				return err
			}
			err = v.PasswdContext(ctx, pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.statusf("Passphrase changed. The paper recovery key stays valid.\n" +
				"Copies and backups made before still open with the old passphrase.")
			a.stopStaleAgent(ctx, path, "was unlocked with the old key block")
			return nil
		},
	}
}

func (a *app) cmdRekey() *cobra.Command {
	return &cobra.Command{
		Use:   "rekey",
		Short: "Make a new vault key (the old passphrase and paper key stop working on new versions)",
		Long: "Make a new vault key and re-encrypt the data to it, with a passphrase (the same or\n" +
			"a new one). The old passphrase and paper recovery key don't open new versions of\n" +
			"the file. It asks for the current passphrase on the terminal, also while the\n" +
			"agent runs: the agent's key isn't enough to replace the vault key. A running\n" +
			"agent is stopped afterwards.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			t, path, v, err := a.openWithCurrentPassphrase(ctx, "rekey")
			if err != nil {
				return err
			}
			defer v.Close()
			termf(t, "Choose the passphrase for the new vault key (it may be the same as before).\n")
			pass, err := newPassphrase(ctx, t)
			if err != nil {
				return err
			}
			_, err = v.RekeyContext(ctx, pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.statusf("The vault has a new key. The old passphrase and the old paper recovery key\n" +
				"no longer open new versions of it; copies made before still open with them.\n" +
				"Print a new paper recovery key now: passh recovery-key print")
			a.stopStaleAgent(ctx, path, "held the old key")
			return nil
		},
	}
}

// openWithCurrentPassphrase opens the vault for passwd and rekey (named by
// command) with the current passphrase, checked by unwrapping the vault's
// key block, and never with the agent's key (CLI-018, owner decision): a
// process that can reach the agent must not be able to change the
// passphrase or replace the vault key. Without a terminal it fails, also
// when an agent runs. A wrong passphrase is asked again, then fails with
// the §4.5 error.
func (a *app) openWithCurrentPassphrase(ctx context.Context, command string) (*tty.TTY, string, *vault.Vault, error) {
	t, err := a.tty()
	if err != nil {
		return nil, "", nil, fmt.Errorf("passh %s needs the current passphrase, typed on a terminal; the agent's key isn't enough "+
			"to change the passphrase or the vault key (over SSH: `ssh -t host passh %s`)", command, command)
	}
	cfg, path, err := a.vaultFile()
	if err != nil {
		return nil, "", nil, err
	}
	v, err := a.openVault(ctx, cfg, path, openOpts{noAgent: true, prompt: "Current passphrase: "})
	if err != nil {
		return nil, "", nil, err
	}
	return t, path, v, nil
}

func (a *app) cmdRecover() *cobra.Command {
	return &cobra.Command{
		Use:   "recover [--vault file]",
		Short: "Open the vault with the paper recovery key and set a new passphrase",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			t, err := a.needTTY("passh recover")
			if err != nil {
				return err
			}
			cfg, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			id, err := readRecoveryKey(ctx, t)
			if err != nil {
				return err
			}
			// Recovery: a key block too damaged to parse is tolerated; the
			// new passphrase writes a new one.
			vopts := a.vaultOptions(ctx, cfg, false)
			vopts.Recovery = true
			v, err := vault.Open(ctx, path, keys.FromIdentity(id), vopts)
			if errors.Is(err, keys.ErrKeyMismatch) {
				return fmt.Errorf("this recovery key doesn't open %s: it belongs to another vault, or the vault was rekeyed after the sheet was printed", config.ContractHome(path))
			}
			if err != nil {
				return err
			}
			defer v.Close()
			termf(t, "The recovery key opens the vault. Choose a new passphrase.\n")
			pass, err := newPassphrase(ctx, t)
			if err != nil {
				return err
			}
			err = v.PasswdContext(ctx, pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.statusf("New passphrase set for %s. The paper recovery key stays valid.", displayPath(path))
			a.stopStaleAgent(ctx, path, "was unlocked with the old key block")
			return nil
		},
	}
}

// readRecoveryKey reads the paper key from the terminal: typed or pasted
// on one or several lines, ended by an empty line. Spaces, line breaks,
// hyphens and letter case don't matter (keys.ParseRecoveryKeyBytes), and
// the bech32 checksum catches typos. The key is the one secret that stays
// valid until `passh rekey` (CLI-005, SEC-1): each character shows as *,
// so it never reaches the screen or the scrollback, and the typed bytes are
// wiped once parsed.
func readRecoveryKey(ctx context.Context, t *tty.TTY) (*age.X25519Identity, error) {
	termf(t, "Type the recovery key from the paper sheet (AGE-SECRET-KEY-1…); it shows as *.\n"+
		"Spaces, line breaks and letter case don't matter. End with an empty line.\n")
	for attempt := 1; ; attempt++ {
		typed, err := t.ReadMaskedLinesContext(ctx, "> ")
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		id, err := keys.ParseRecoveryKeyBytes(typed)
		empty := len(typed) == 0
		clear(typed)
		if err == nil {
			return id, nil
		}
		if attempt == promptAttempts || empty {
			return nil, err
		}
		termf(t, "%v. Type it again.\n", err)
	}
}
