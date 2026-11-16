package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vault"
)

func (a *app) cmdInit() *cobra.Command {
	return &cobra.Command{
		Use:   "init [--vault file]",
		Short: a.T("Create a new vault, and the config file if it doesn't exist"),
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			loc, err := config.Locate(a.configFlag)
			if err != nil {
				return err
			}
			cfg, err := config.Load(loc.Path)
			haveConfig := err == nil
			switch {
			case haveConfig:
			case errors.Is(err, config.ErrNoConfig):
				cfg = config.Default()
			default:
				return err
			}
			path := cfg.Vault
			if a.vaultFlag != "" {
				if path, err = config.ExpandPath(a.vaultFlag); err != nil {
					return fmt.Errorf("--vault: %w", err)
				}
			}
			if path == "" {
				if path, err = config.DefaultVaultPath(); err != nil {
					return err
				}
			}
			if _, err := os.Lstat(path); err == nil {
				return i18n.Errorf("%s already exists; passh init doesn't overwrite a vault", config.ContractHome(path))
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			t, err := a.needTTY("passh init")
			if err != nil {
				return err
			}
			a.termf(t, "Creating the vault %s.\nChoose a passphrase: 6 or more random words are best.\n", displayPath(path))
			pass, err := a.newPassphrase(ctx, t)
			if err != nil {
				return err
			}
			v, err := vault.CreateContext(ctx, path, pass, a.vaultOptions(ctx, cfg, false))
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			defer v.Close()
			a.statusf("Created the vault %s.", displayPath(path))
			switch {
			case !haveConfig:
				if err := config.WriteInitial(loc.Path, path); err != nil {
					return i18n.Errorf("the vault was created, but the config file wasn't: %w", err)
				}
				a.statusf("Wrote the config file %s.", displayPath(loc.Path))
			case !sameFile(cfg.Vault, path):
				a.statusf("The config file %s exists and wasn't changed; it names the vault %s.\n"+
					"Use --vault %s with each command, or change vault in the config file.",
					displayPath(loc.Path), displayPath(cfg.Vault), displayPath(path))
			}
			if err := a.offerRecoverySheet(ctx, t, v.Key(), v.Info().VaultID); err != nil {
				return i18n.Errorf("the vault was created, but the recovery sheet wasn't written: %w; run `passh recovery-key print` later", err)
			}
			return nil
		},
	}
}
