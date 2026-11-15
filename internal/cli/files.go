package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/vault"
	"github.com/devapro/passh/internal/vaultfile"
)

// maxVaultSize bounds what passh reads as a vault file, as the vault
// package does: a wrong path (a disk image, a device) fails fast.
const maxVaultSize = 64 << 20

// readVaultBytes reads a vault file: a regular file of at most
// maxVaultSize bytes.
func readVaultBytes(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", config.ContractHome(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxVaultSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxVaultSize {
		return nil, fmt.Errorf("%s is larger than 64 MiB: not a passh vault", config.ContractHome(path))
	}
	return data, nil
}

func (a *app) cmdVerify() *cobra.Command {
	var full bool
	c := &cobra.Command{
		Use:   "verify [file] [--full]",
		Short: "Check the vault or a copy of it",
		Long: "Check a vault file without the passphrase: the passh-vault line, both blocks\n" +
			"complete, base64 and age headers valid. It prints the file's SHA-256 and size;\n" +
			"a byte-exact copy has the same SHA-256 as the original.\n\n" +
			"--full also decrypts the file (through the agent, or by asking for the\n" +
			"passphrase) and prints its vault_id, revision, saved_at and entry count, and\n" +
			"how it compares with the newest revision seen on this machine.",
		Args: rangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, agents, err := a.verifyTarget(args)
			if err != nil {
				return err
			}
			data, err := readVaultBytes(path)
			if err != nil {
				return err
			}
			info, cerr := vaultfile.Check(data)
			status := "OK"
			if cerr != nil {
				status = "FAILED"
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s: %s\n", displayPath(path), status)
			fmt.Fprintf(&b, "  SHA-256   %s\n", info.SHA256)
			fmt.Fprintf(&b, "  size      %d bytes\n", info.Size)
			if err := writeAll(a.stdout, b.String()); err != nil {
				return err
			}
			if cerr != nil {
				return fmt.Errorf("%s: %w", config.ContractHome(path), cerr)
			}
			for _, w := range info.Warnings {
				a.notef("note: %s", w)
			}
			if !info.Canonical {
				a.notef("note: the file isn't in passh's canonical form (line endings or line wrapping changed in copying); it opens, and `passh backup` writes a canonical copy")
			}
			if !full {
				return nil
			}
			v, err := a.openVault(cmd.Context(), cfg, path, openOpts{agents: agents, reportOnly: true})
			if err != nil {
				return err
			}
			defer v.Close()
			vi := v.Info()
			rb := v.Rollback()
			b.Reset()
			fmt.Fprintf(&b, "  vault_id  %s\n", line(vi.VaultID))
			fmt.Fprintf(&b, "  revision  %d\n", vi.Revision)
			fmt.Fprintf(&b, "  saved_at  %s\n", vi.SavedAt.UTC().Format(time.DateTime+" UTC"))
			fmt.Fprintf(&b, "  entries   %d\n", vi.Entries)
			fmt.Fprintf(&b, "  rollback  %s\n", rollbackReport(rb))
			if err := writeAll(a.stdout, b.String()); err != nil {
				return err
			}
			if rb.Older() {
				a.warnf("%s", rb.Message())
			}
			return nil
		},
	}
	c.Flags().BoolVar(&full, "full", false, "also decrypt the file and check its data")
	return c
}

// verifyTarget is the file `verify` checks: the argument, or the config's
// vault. A file argument needs no config file. agents are the vaults whose
// agents may hold the key for --full: the file's own, then the config's
// vault's (a copy of it opens with the same key).
func (a *app) verifyTarget(args []string) (*config.Config, string, []string, error) {
	if len(args) == 0 {
		cfg, path, err := a.vaultFile()
		return cfg, path, nil, err
	}
	path, err := config.ExpandPath(args[0])
	if err != nil {
		return nil, "", nil, err
	}
	cfg, err := config.Resolve(a.configFlag, a.vaultFlag)
	switch {
	case err == nil:
	case errors.Is(err, config.ErrNoConfig) && a.configFlag == "":
		cfg = config.Default()
	default:
		return nil, "", nil, err
	}
	agents := []string{path}
	if cfg.Vault != "" && !sameFile(cfg.Vault, path) {
		if _, err := os.Stat(cfg.Vault); err == nil {
			agents = append(agents, cfg.Vault)
		}
	}
	return cfg, path, agents, nil
}

// rollbackReport describes the comparison with the rollback record
// (§4.10), for `verify --full`.
func rollbackReport(rb vault.RollbackStatus) string {
	switch {
	case !rb.Seen:
		return "this machine hasn't seen this vault before"
	case rb.Older():
		return fmt.Sprintf("OLDER than seen before on this machine (seen r%d of %s)",
			rb.SeenRevision, rb.SeenSavedAt.UTC().Format(time.DateOnly))
	case rb.Revision == rb.SeenRevision:
		return fmt.Sprintf("OK: the newest revision seen on this machine (r%d)", rb.SeenRevision)
	default:
		return fmt.Sprintf("OK: newer than seen before on this machine (r%d)", rb.SeenRevision)
	}
}

// backupTimeFormat is the time in a backup's default name:
// vault-20261115-120000.passh.
const backupTimeFormat = "20060102-150405"

func (a *app) cmdBackup() *cobra.Command {
	return &cobra.Command{
		Use:   "backup <dest>",
		Short: "Make a checked copy of the vault in a file or folder",
		Long: "Copy the vault to a file, or into a folder as <name>-<UTC time>.passh, with\n" +
			"mode 0600. The copy is flushed to disk, read back and compared by SHA-256.\n" +
			"An existing file is never overwritten. A vault that isn't in canonical form\n" +
			"(e.g. after an email or a paste) is written in canonical form. No passphrase\n" +
			"is needed.",
		Args: exactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, src, err := a.vaultFile()
			if err != nil {
				return err
			}
			data, err := readVaultBytes(src)
			if err != nil {
				return err
			}
			f, err := vaultfile.Parse(data)
			if err != nil {
				return fmt.Errorf("%s doesn't pass the structure check, so it isn't copied: %w", config.ContractHome(src), err)
			}
			content := data
			if !f.Canonical {
				if content, err = vaultfile.Encode(f.KeyBlock, f.DataBlock); err != nil {
					return err
				}
			}
			dest, err := backupDest(args[0], src, time.Now())
			if err != nil {
				return err
			}
			// exception FILE-2 (CLI-003, deferred): the copy is written under
			// its final name, not through a temporary file and a rename; that
			// moves behind a vault helper with the backup rework.
			sum, err := writeNew(dest, content, true)
			if err != nil {
				return err
			}
			// The report is data, as verify's is (OUT-1); the confirmation
			// and the hint are status.
			a.statusf("Backed up %s to %s.", displayPath(src), displayPath(dest))
			var b strings.Builder
			fmt.Fprintf(&b, "%s: OK\n", displayPath(dest))
			fmt.Fprintf(&b, "  SHA-256   %s\n", hex.EncodeToString(sum[:]))
			fmt.Fprintf(&b, "  size      %d bytes\n", len(content))
			if err := writeAll(a.stdout, b.String()); err != nil {
				return err
			}
			if f.Canonical {
				a.statusf("The copy is byte for byte the vault; `passh verify` shows the same SHA-256 for both.")
			} else {
				a.statusf("The vault isn't in canonical form, so the copy was written in canonical form;\n" +
					"its SHA-256 differs from the vault's, and the stock age tool reads its blocks (§8).")
			}
			return nil
		},
	}
}

// backupDest is the file `backup` writes: dest itself, or, if dest is a
// folder (or ends in /), <vault name>-<UTC time>.passh in it.
func backupDest(dest, src string, now time.Time) (string, error) {
	p, err := config.ExpandPath(dest)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(p)
	isDir := err == nil && st.IsDir()
	if !isDir && strings.HasSuffix(dest, "/") {
		return "", fmt.Errorf("%s: no such folder", config.ContractHome(p))
	}
	if !isDir {
		return p, nil
	}
	name := strings.TrimSuffix(filepath.Base(src), ".passh")
	return filepath.Join(p, name+"-"+now.UTC().Format(backupTimeFormat)+".passh"), nil
}

// syncDirBestEffort fsyncs a folder so a new file in it is durable; file
// systems that can't (FAT, network) are tolerated.
func syncDirBestEffort(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

func (a *app) cmdBackups() *cobra.Command {
	return &cobra.Command{
		Use:   "backups",
		Short: "List the automatic backups of the vault",
		Long: "List the automatic backups passh made before each save (§4.7), newest first,\n" +
			"with time and revision. To restore one, copy it over the vault file and run\n" +
			"`passh verify --full`. No passphrase is needed.",
		Args: noArgs(),
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			state, err := config.StateDir()
			if err != nil {
				return err
			}
			list, matched, err := vault.FindBackups(state, cfg.Vault)
			if err != nil {
				// No readable vault: that is when backups matter most.
				a.notef("note: %s can't be read (%v); listing every automatic backup on this machine", displayPath(cfg.Vault), err)
				if list, err = vault.ListBackups(state, ""); err != nil {
					return err
				}
				matched = true
			}
			if len(list) == 0 {
				a.statusf("No automatic backups yet. passh makes one before each save (backup.keep = %d).", cfg.Backup.Keep)
				return nil
			}
			if !matched {
				a.notef("note: no backup has this vault's current key block (it was changed by passwd or rekey and not saved since, or the file is damaged); listing every automatic backup on this machine")
			}
			var b strings.Builder
			for _, bk := range list {
				fmt.Fprintf(&b, "%s  r%d  %s\n", bk.Time.UTC().Format(time.DateTime), bk.Revision, displayPath(bk.Path))
			}
			return writeAll(a.stdout, b.String())
		},
	}
}
