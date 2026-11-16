package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/vaultfile"
)

func (a *app) cmdUnlock() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "unlock [--ttl d]",
		Short: a.T("Start the agent: no passphrase prompts for a while, also without a terminal"),
		Long: a.T("Ask for the passphrase and start the agent, which keeps the vault key in memory\n" +
			"so later commands, including ones without a terminal (ssh host passh show …),\n" +
			"don't ask for it. The agent exits after agent.idle_ttl without use, after\n" +
			"agent.max_ttl (or --ttl) in any case, and on `passh lock`.\n\n" +
			"With an agent already running for the vault, unlock restarts its idle time and\n" +
			"says how long it has left. --ttl only applies to a new agent: passh says when it\n" +
			"wasn't applied (run `passh lock` first)."),
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ttlSet := cmd.Flags().Changed("ttl")
			if ttlSet && ttl <= 0 {
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
			if _, err := c.Status(ctx); err == nil {
				current, err := a.touchAgent(ctx, c, path)
				if err != nil {
					return err
				}
				if current {
					return a.reportRunning(ctx, c, ttlSet)
				}
				a.notef("the running agent was unlocked with another key block (passwd elsewhere?); replacing it")
				if _, err := c.Stop(ctx); err != nil && !errors.Is(err, agent.ErrNoAgent) {
					return err
				}
			} else if !errors.Is(err, agent.ErrNoAgent) {
				return err
			}
			if _, err := a.tty(); err != nil {
				return i18n.NewError("passh unlock needs a terminal to ask for the passphrase (over SSH: `ssh -t host passh unlock`)")
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
			if errors.Is(err, agent.ErrAlreadyRunning) {
				// Another unlock won the race: restart its idle time too.
				if _, err := c.KeyFor(ctx, v.KeyBlock()); err != nil {
					return err
				}
				return a.reportRunning(ctx, c, ttlSet)
			}
			if err != nil {
				return err
			}
			a.statusf("Unlocked %s: %s.\nRun `passh lock` to stop the agent now.", displayPath(path), a.agentTimes(st))
			return nil
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", 0, a.T("stop a new agent after this long in any case (overrides agent.max_ttl), e.g. 30m"))
	return c
}

// touchAgent asks the running agent of path for the key of the vault's
// current key block. That key request restarts the agent's idle time
// (§5.3). It reports whether the agent serves this key block; false means
// it was unlocked with another one (a passwd elsewhere) and is of no use.
func (a *app) touchAgent(ctx context.Context, c *agent.Client, path string) (bool, error) {
	data, err := readVaultBytes(path)
	if err != nil {
		return false, i18n.Errorf("an agent is running, but the vault can't be checked against it: %w", err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		return false, i18n.Errorf("an agent is running, but the vault can't be checked against it: %s: %w", config.ContractHome(path), err)
	}
	_, err = c.KeyFor(ctx, f.KeyBlock)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, agent.ErrKeyBlockChanged), errors.Is(err, agent.ErrNoAgent):
		return false, nil // stale, or it has just exited: start a new one
	}
	return false, err
}

// reportRunning says how long the running agent has left, asked after the
// key request that restarted its idle time (CLI-011). --ttl doesn't change
// a running agent, and passh says so rather than ignore it silently.
func (a *app) reportRunning(ctx context.Context, c *agent.Client, ttlSet bool) error {
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	a.statusf("Already unlocked: %s.", a.agentTimes(st))
	if ttlSet {
		a.warnf("--ttl was not applied: the agent was already running; run `passh lock`, then `passh unlock --ttl …`")
	}
	return nil
}

// agentOptions are the new agent's settings: its TTLs, and the key block
// the passphrase just decrypted, so the agent can tell when the vault's key
// block changes (a passwd elsewhere) and stop handing out its key.
func agentOptions(idle, maxTTL time.Duration, keyBlock []byte) agent.Options {
	return agent.Options{IdleTTL: idle, MaxTTL: maxTTL, KeyBlock: keyBlock}
}

// agentTimes describes when an agent exits, in the user's language.
func (a *app) agentTimes(st agent.Status) string {
	if st.IdleLeft >= st.MaxLeft {
		return a.T("the agent (pid %d) exits in %s", st.PID, fmtDuration(st.MaxLeft))
	}
	return a.T("the agent (pid %d) exits in %s if unused, in %s at the latest",
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
		Short: a.T("Stop the agent"),
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
				a.statusf("No agent is running for %s.", displayPath(path))
				return nil
			}
			a.statusf("Locked: the agent (pid %d) stopped.", st.PID)
			return nil
		},
	}
}

// stopStaleAgent stops the agent of path after passwd, rekey or recover
// wrote a new key block: the agent serves its key only for the key block it
// unlocked, so it is of no use any more. newKey says why: rekey replaced the
// vault key, rather than only the key block.
func (a *app) stopStaleAgent(ctx context.Context, path string, newKey bool) {
	stopped, _, err := stopAgent(ctx, path)
	switch {
	case err != nil:
		a.warnf("the agent couldn't be stopped: %v; stop it with `passh lock`", err)
	case stopped && newKey:
		a.statusf("The agent held the old key and was stopped; run `passh unlock` again if you need it.")
	case stopped:
		a.statusf("The agent was unlocked with the old key block and was stopped; run `passh unlock` again if you need it.")
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
