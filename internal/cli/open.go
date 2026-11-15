package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"

	"passh/internal/agent"
	"passh/internal/config"
	"passh/internal/keys"
	"passh/internal/tty"
	"passh/internal/vault"
	"passh/internal/vaultfile"
)

// errLocked is the message of §5.1 step 3: no agent, no terminal.
var errLocked = errors.New("vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)")

// passphraseAttempts is how often a wrong passphrase is asked again.
const passphraseAttempts = 3

// loadConfig resolves the config for this command (§3.3): --config,
// $PASSH_CONFIG or the default location; with --vault, a missing config
// file is fine.
func (a *app) loadConfig() (*config.Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	cfg, err := config.Resolve(a.configFlag, a.vaultFlag)
	if err != nil {
		return nil, err
	}
	a.cfg = cfg
	return cfg, nil
}

// vaultFile returns the config and the vault file it names, which must
// exist.
func (a *app) vaultFile() (*config.Config, string, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, "", err
	}
	if err := checkVaultExists(cfg.Vault); err != nil {
		return nil, "", err
	}
	return cfg, cfg.Vault, nil
}

func checkVaultExists(path string) error {
	_, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no vault at %s: run `passh init` to create one, or pass --vault <file>", config.ContractHome(path))
	case err != nil:
		return fmt.Errorf("vault %s: %w", config.ContractHome(path), err)
	}
	return nil
}

// openOpts tune how a vault is opened.
type openOpts struct {
	// agents are the vaults whose agents may hold the key, tried in order.
	// Empty means the vault itself.
	agents []string
	// reportOnly makes the rollback check report only (verify --full).
	reportOnly bool
	// noAgent skips the agent: the passphrase is asked for.
	noAgent bool
	// prompt is the passphrase prompt; empty means keys.DefaultPrompt.
	prompt string
}

// vaultOptions are the vault.Options from the config, with the rollback
// prompt on the terminal if there is one (§4.10).
func (a *app) vaultOptions(cfg *config.Config, reportOnly bool) vault.Options {
	o := vault.Options{
		BackupKeep:         cfg.Backup.Keep,
		RollbackWarn:       cfg.Rollback.Warn,
		RollbackReportOnly: reportOnly,
		Warn:               a.warnOnce,
	}
	if t, err := a.tty(); err == nil && !reportOnly {
		o.Prompt = func(warning string) (bool, error) {
			t.Printf("warning: %s\n", warning)
			return t.YesNo("Continue with this copy?", false)
		}
	}
	return o
}

// warnOnce prints a warning from the vault package once per command: the
// vault may be opened more than once (agent, then passphrase), and its
// warnings about the file would repeat.
func (a *app) warnOnce(msg string) {
	if a.warned == nil {
		a.warned = map[string]bool{}
	}
	if !a.warned[msg] {
		a.warned[msg] = true
		a.warnf("%s", msg)
	}
}

// unlock opens the vault named by the config with the key from the agent
// or the passphrase (§5.1).
func (a *app) unlock(ctx context.Context) (*vault.Vault, error) {
	cfg, path, err := a.vaultFile()
	if err != nil {
		return nil, err
	}
	return a.openVault(ctx, cfg, path, openOpts{})
}

// openVault opens path with the key from, in order (§5.1):
//
//  1. the agent, if one is running for the vault (or for another vault in
//     o.agents) and its key opens the data. No agent (agent.ErrNoAgent), an
//     agent that unlocked another key block (agent.ErrKeyBlockChanged: a
//     passwd or rekey elsewhere) falls through to the passphrase. The
//     agent's key belongs to the file's key block, so a data block it
//     doesn't open is damage, reported as such (§4.5) without asking for
//     the passphrase. A problem with the agent itself,
//     such as a refused agent folder, is reported on stderr, not skipped
//     silently;
//  2. a passphrase prompt on /dev/tty, if there is a terminal;
//  3. otherwise errLocked.
//
// The agent is asked through agent.KeySource inside vault.Open, so it sees
// the key block of the file being opened. No command starts an agent here;
// only `passh unlock` does.
func (a *app) openVault(ctx context.Context, cfg *config.Config, path string, o openOpts) (*vault.Vault, error) {
	vopts := a.vaultOptions(cfg, o.reportOnly)
	if !o.noAgent {
		candidates := o.agents
		if len(candidates) == 0 {
			candidates = []string{path}
		}
		for _, cand := range candidates {
			v, err := vault.Open(ctx, path, agentSource{vault: cand}, vopts)
			if err == nil {
				return v, nil
			}
			var ae *agentError
			switch {
			case errors.As(err, &ae) && errors.Is(err, agent.ErrNoAgent):
				if cand == path && errors.Is(ae.err, agent.ErrKeyBlockChanged) {
					a.notef("%v; asking for the passphrase", ae.err)
				}
				continue
			case errors.As(err, &ae):
				a.warnf("can't use the agent of %s: %v", displayPath(cand), ae.err)
				continue
			case errors.Is(err, keys.ErrKeyMismatch):
				if cand == path {
					a.notef("the agent's key doesn't open %s (was it rekeyed elsewhere?); asking for the passphrase", displayPath(path))
				}
				continue
			}
			return nil, explainOpenError(err)
		}
	}
	t, err := a.tty()
	if err != nil {
		return nil, errLocked
	}
	v, err := vault.Open(ctx, path, a.passphraseSource(t, o.prompt), vopts)
	return v, explainOpenError(err)
}

// explainOpenError adds what to do to the errors whose remedy isn't in the
// vault package's message.
func explainOpenError(err error) error {
	var de *vaultfile.DamagedError
	if errors.As(err, &de) && de.Block == 1 {
		return fmt.Errorf("%w\nThe key block only protects the vault key with the passphrase: if the data block is intact, "+
			"`passh recover` with the paper recovery key writes a new key block", err)
	}
	return err
}

// agentSource is agent.KeySource with its errors tagged as the agent's, so
// openVault tells them apart from problems with the vault file.
type agentSource struct{ vault string }

func (s agentSource) VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	id, err := agent.KeySource{Vault: s.vault}.VaultKey(ctx, keyBlock)
	if err != nil {
		return nil, &agentError{err: err}
	}
	return id, nil
}

// ChecksKeyBlock implements keys.KeyBlockChecker, as agent.KeySource does:
// with the agent's key, a data block that doesn't open is damaged ("data is
// damaged; restore a backup"), not a sign of a rekey.
func (s agentSource) ChecksKeyBlock() bool { return agent.KeySource{Vault: s.vault}.ChecksKeyBlock() }

// agentError is an error of the agent key source.
type agentError struct{ err error }

func (e *agentError) Error() string { return e.err.Error() }
func (e *agentError) Unwrap() error { return e.err }

// passphraseSource asks for the passphrase on t, up to passphraseAttempts
// times, saying so after a wrong one.
func (a *app) passphraseSource(t *tty.TTY, prompt string) keys.KeySource {
	asked := 0
	return &keys.PassphraseSource{
		Prompt:   prompt,
		Attempts: passphraseAttempts,
		Read: func(prompt string) ([]byte, error) {
			if asked > 0 {
				t.Printf("Wrong passphrase. Try again.\n")
			}
			asked++
			p, err := t.ReadPassphrase(prompt)
			if errors.Is(err, tty.ErrInterrupted) {
				return nil, errors.New("interrupted")
			}
			return p, err
		},
	}
}

// strengthCheck is the check NewPassphrase runs on a new passphrase
// (§5.4): a warning for a weak one, never a refusal.
func strengthCheck(p []byte) string {
	inputs := []string{"passh", "vault"}
	if u := os.Getenv("USER"); u != "" {
		inputs = append(inputs, u)
	}
	if h, err := os.Hostname(); err == nil {
		inputs = append(inputs, h)
	}
	if msg := keys.CheckStrength(p, inputs...).Message(); msg != "" {
		return "warning: " + msg
	}
	return ""
}

// newPassphrase asks for a new passphrase twice, with the strength warning.
func newPassphrase(t *tty.TTY) ([]byte, error) {
	p, err := t.NewPassphrase(strengthCheck)
	if errors.Is(err, tty.ErrInterrupted) {
		return nil, errors.New("interrupted")
	}
	return p, err
}

// sameFile reports whether a and b name the same file.
func sameFile(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}
