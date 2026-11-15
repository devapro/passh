package cli

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/spf13/cobra"

	"passh/internal/tui"
	"passh/internal/vault"
)

// errNoTerminalTUI: `passh` without arguments and without a terminal.
var errNoTerminalTUI = errors.New("the TUI needs a terminal: run passh in one (over SSH: `ssh -t host passh`); " +
	"without a terminal, use the commands (passh --help) after `passh unlock`")

// runTUI is `passh` without arguments: the TUI (§6.1, §6.2). It starts on
// the lock screen, which takes the key from the agent if one runs for the
// vault and was unlocked for the vault's current key block (the TUI's
// default agent uses agent.Client.KeyFor), else asks for the passphrase.
// tui.Run handles SIGHUP, SIGTERM and SIGINT itself: it locks first, then
// returns a *tui.SignalError.
func (a *app) runTUI(cmd *cobra.Command, _ []string) error {
	cfg, path, err := a.vaultFile()
	if err != nil {
		return err
	}
	t, err := a.tty()
	if err != nil {
		return errNoTerminalTUI
	}
	return tuiExit(tui.Run(cmd.Context(), tui.Options{Config: cfg, VaultPath: path, TTY: t.File()}))
}

// tuiExit maps how the TUI ended to an error and exit status.
func tuiExit(err error) error {
	var se *tui.SignalError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &se):
		// The session was locked first. Exit like a process killed by the
		// signal would report it: 128 + its number.
		code := exitError
		if s, ok := se.Signal.(syscall.Signal); ok {
			code = 128 + int(s)
		}
		return &exitCodeError{code: code, err: err}
	case errors.Is(err, vault.ErrRollbackDeclined):
		return err // "stopped: this copy is older …; nothing was changed"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("the TUI was stopped (%w); it locked first", err)
	}
	return err
}
