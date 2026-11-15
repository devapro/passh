package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"passh/internal/agent"
	"passh/internal/config"
	"passh/internal/keys"
	"passh/internal/tty"
	"passh/internal/vault"
	"passh/internal/vaultfile"
)

// recoverySheetHint tells the user to print the paper recovery key.
const recoverySheetHint = "Print the paper recovery key now and keep the sheet offline:\n" +
	"  passh recovery-key print\n" +
	"Without it, a forgotten passphrase means the data is lost."

func (a *app) cmdInit() *cobra.Command {
	return &cobra.Command{
		Use:   "init [--vault file]",
		Short: "Create a new vault, and the config file if it doesn't exist",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
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
				return fmt.Errorf("%s already exists; passh init doesn't overwrite a vault", config.ContractHome(path))
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			t, err := a.needTTY("passh init")
			if err != nil {
				return err
			}
			t.Printf("Creating the vault %s.\nChoose a passphrase: 6 or more random words are best.\n", displayPath(path))
			pass, err := newPassphrase(t)
			if err != nil {
				return err
			}
			v, err := vault.Create(path, pass, a.vaultOptions(cfg, false))
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			defer v.Close()
			a.printf("Created the vault %s.\n", displayPath(path))
			switch {
			case !haveConfig:
				if err := config.WriteInitial(loc.Path, path); err != nil {
					return fmt.Errorf("the vault was created, but the config file wasn't: %w", err)
				}
				a.printf("Wrote the config file %s.\n", displayPath(loc.Path))
			case !sameFile(cfg.Vault, path):
				a.printf("The config file %s exists and wasn't changed; it names the vault %s.\n"+
					"Use --vault %s with each command, or change vault in the config file.\n",
					displayPath(loc.Path), displayPath(cfg.Vault), displayPath(path))
			}
			if err := a.offerRecoverySheet(t, v.Key(), v.Info().VaultID); err != nil {
				return fmt.Errorf("the vault was created, but the recovery sheet wasn't written: %w; run `passh recovery-key print` later", err)
			}
			return nil
		},
	}
}

func (a *app) cmdUnlock() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "unlock [--ttl d]",
		Short: "Start the agent: no passphrase prompts for a while, also without a terminal",
		Long: "Ask for the passphrase and start the agent, which keeps the vault key in memory\n" +
			"so later commands, including ones without a terminal (ssh host passh show …),\n" +
			"don't ask for it. The agent exits after agent.idle_ttl without use, after\n" +
			"agent.max_ttl (or --ttl) in any case, and on `passh lock`.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("ttl") && ttl <= 0 {
				return usagef("--ttl must be more than zero")
			}
			ctx := cmd.Context()
			cfg, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			c, err := agent.NewClient(path)
			if err != nil {
				return err
			}
			if st, err := c.Status(ctx); err == nil {
				if !a.agentStale(ctx, c, path) {
					a.printf("Already unlocked: %s.\n", agentTimes(st))
					return nil
				}
				a.notef("the running agent was unlocked with another key block (passwd elsewhere?); replacing it")
				if _, err := c.Stop(ctx); err != nil && !errors.Is(err, agent.ErrNoAgent) {
					return err
				}
			} else if !errors.Is(err, agent.ErrNoAgent) {
				return err
			}
			if _, err := a.tty(); err != nil {
				return errors.New("passh unlock needs a terminal to ask for the passphrase (over SSH: `ssh -t host passh unlock`)")
			}
			// The passphrase is checked by opening the vault with it.
			v, err := a.openVault(ctx, cfg, path, openOpts{noAgent: true})
			if err != nil {
				return err
			}
			defer v.Close()
			maxTTL := cfg.Agent.MaxTTL
			if ttl > 0 {
				maxTTL = ttl
			}
			st, err := agent.Start(ctx, path, v.Key(), agentOptions(cfg.Agent.IdleTTL, maxTTL, v.KeyBlock()))
			var running *agent.AlreadyRunningError
			if errors.As(err, &running) {
				a.printf("Already unlocked: %s.\n", agentTimes(running.Status))
				return nil
			}
			if err != nil {
				return err
			}
			a.printf("Unlocked %s: %s.\nRun `passh lock` to stop the agent now.\n", displayPath(path), agentTimes(st))
			return nil
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", 0, "stop the agent after this long in any case (overrides agent.max_ttl), e.g. 30m")
	return c
}

// agentStale reports whether the running agent of path serves another key
// block than the vault file has now, so it would never hand out its key.
func (a *app) agentStale(ctx context.Context, c *agent.Client, path string) bool {
	data, err := readVaultBytes(path)
	if err != nil {
		return false
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		return false
	}
	_, err = c.KeyFor(ctx, f.KeyBlock)
	return errors.Is(err, agent.ErrKeyBlockChanged)
}

// agentOptions are the new agent's settings: its TTLs, and the key block
// the passphrase just decrypted, so the agent can tell when the vault's key
// block changes (a passwd elsewhere) and stop handing out its key.
func agentOptions(idle, maxTTL time.Duration, keyBlock []byte) agent.Options {
	return agent.Options{IdleTTL: idle, MaxTTL: maxTTL, KeyBlock: keyBlock}
}

// agentTimes describes when an agent exits.
func agentTimes(st agent.Status) string {
	if st.IdleLeft >= st.MaxLeft {
		return fmt.Sprintf("the agent (pid %d) exits in %s", st.PID, fmtDuration(st.MaxLeft))
	}
	return fmt.Sprintf("the agent (pid %d) exits in %s if unused, in %s at the latest",
		st.PID, fmtDuration(st.IdleLeft), fmtDuration(st.MaxLeft))
}

// fmtDuration writes d for people: "2h", "1h30m", "15m", "14m59s", "45s".
func fmtDuration(d time.Duration) string {
	d = max(d.Round(time.Second), 0)
	h, m, s := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	var b strings.Builder
	switch {
	case h > 0:
		fmt.Fprintf(&b, "%dh", h)
		if m > 0 {
			fmt.Fprintf(&b, "%dm", m)
		}
	case m > 0:
		fmt.Fprintf(&b, "%dm", m)
		if s > 0 {
			fmt.Fprintf(&b, "%ds", s)
		}
	default:
		fmt.Fprintf(&b, "%ds", s)
	}
	return b.String()
}

func (a *app) cmdLock() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Stop the agent",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			stopped, st, err := stopAgent(cmd.Context(), path)
			if err != nil {
				return err
			}
			if !stopped {
				a.printf("No agent is running for %s.\n", displayPath(path))
				return nil
			}
			a.printf("Locked: the agent (pid %d) stopped.\n", st.PID)
			return nil
		},
	}
}

// stopStaleAgent stops the agent of path after passwd, rekey or recover
// wrote a new key block: the agent serves its key only for the key block it
// unlocked, so it is of no use any more.
func (a *app) stopStaleAgent(ctx context.Context, path, why string) {
	stopped, _, err := stopAgent(ctx, path)
	switch {
	case err != nil:
		a.warnf("the agent couldn't be stopped: %v; stop it with `passh lock`", err)
	case stopped:
		a.printf("The agent %s and was stopped; run `passh unlock` again if you need it.\n", why)
	}
}

// stopAgent stops the agent of path, if one runs.
func stopAgent(ctx context.Context, path string) (bool, agent.Status, error) {
	c, err := agent.NewClient(path)
	if err != nil {
		return false, agent.Status{}, err
	}
	st, err := c.Stop(ctx)
	if errors.Is(err, agent.ErrNoAgent) {
		return false, agent.Status{}, nil
	}
	if err != nil {
		return false, agent.Status{}, err
	}
	return true, st, nil
}

func (a *app) cmdPasswd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the passphrase (the paper recovery key stays valid)",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := a.needTTY("passh passwd")
			if err != nil {
				return err
			}
			cfg, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			v, err := a.openVault(cmd.Context(), cfg, path, openOpts{prompt: "Current passphrase: "})
			if err != nil {
				return err
			}
			defer v.Close()
			t.Printf("Choose the new passphrase.\n")
			pass, err := newPassphrase(t)
			if err != nil {
				return err
			}
			err = v.Passwd(pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.printf("Passphrase changed. The paper recovery key stays valid.\n" +
				"Copies and backups made before still open with the old passphrase.\n")
			a.stopStaleAgent(cmd.Context(), path, "was unlocked with the old key block")
			return nil
		},
	}
}

func (a *app) cmdRekey() *cobra.Command {
	return &cobra.Command{
		Use:   "rekey",
		Short: "Make a new vault key (the old passphrase and paper key stop working on new versions)",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			t, err := a.needTTY("passh rekey")
			if err != nil {
				return err
			}
			cfg, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			v, err := a.openVault(ctx, cfg, path, openOpts{prompt: "Current passphrase: "})
			if err != nil {
				return err
			}
			defer v.Close()
			t.Printf("Choose the passphrase for the new vault key (it may be the same as before).\n")
			pass, err := newPassphrase(t)
			if err != nil {
				return err
			}
			_, err = v.Rekey(pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.printf("The vault has a new key. The old passphrase and the old paper recovery key\n" +
				"no longer open new versions of it; copies made before still open with them.\n" +
				"Print a new paper recovery key now: passh recovery-key print\n")
			a.stopStaleAgent(ctx, path, "held the old key")
			return nil
		},
	}
}

func (a *app) cmdRecover() *cobra.Command {
	return &cobra.Command{
		Use:   "recover [--vault file]",
		Short: "Open the vault with the paper recovery key and set a new passphrase",
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := a.needTTY("passh recover")
			if err != nil {
				return err
			}
			cfg, path, err := a.vaultFile()
			if err != nil {
				return err
			}
			id, err := readRecoveryKey(t)
			if err != nil {
				return err
			}
			// Recovery: a key block too damaged to parse is tolerated; the
			// new passphrase writes a new one.
			vopts := a.vaultOptions(cfg, false)
			vopts.Recovery = true
			v, err := vault.Open(cmd.Context(), path, keys.FromIdentity(id), vopts)
			if errors.Is(err, keys.ErrKeyMismatch) {
				return fmt.Errorf("this recovery key doesn't open %s: it belongs to another vault, or the vault was rekeyed after the sheet was printed", config.ContractHome(path))
			}
			if err != nil {
				return err
			}
			defer v.Close()
			t.Printf("The recovery key opens the vault. Choose a new passphrase.\n")
			pass, err := newPassphrase(t)
			if err != nil {
				return err
			}
			err = v.Passwd(pass)
			tty.Wipe(pass)
			if err != nil {
				return err
			}
			a.printf("New passphrase set for %s. The paper recovery key stays valid.\n", displayPath(path))
			a.stopStaleAgent(cmd.Context(), path, "was unlocked with the old key block")
			return nil
		},
	}
}

// readRecoveryKey reads the paper key from the terminal: typed on one or
// several lines, ended by an empty line. Spaces, line breaks, hyphens and
// letter case don't matter (keys.ParseRecoveryKey). The key is typed from
// paper, so it is shown while typed, which makes typos easy to spot; the
// bech32 checksum catches the ones that slip through.
func readRecoveryKey(t *tty.TTY) (*age.X25519Identity, error) {
	t.Printf("Type the recovery key from the paper sheet (AGE-SECRET-KEY-1…).\n" +
		"Spaces, line breaks and letter case don't matter. End with an empty line.\n")
	for attempt := 1; ; attempt++ {
		var b strings.Builder
		for {
			l, err := t.ReadLine("> ")
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(l) == "" {
				if b.Len() > 0 {
					break
				}
				continue
			}
			b.WriteString(l)
			b.WriteByte('\n')
		}
		id, err := keys.ParseRecoveryKey(b.String())
		if err == nil {
			return id, nil
		}
		if attempt == promptAttempts || b.Len() == 0 {
			return nil, err
		}
		t.Printf("%v. Type it again.\n", err)
	}
}
