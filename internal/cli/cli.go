// Package cli holds passh's commands (spec §6.1). cmd/passh is a thin main
// that calls Main; keeping the commands here makes them testable.
//
// Conventions for every command:
//
//   - Data goes to stdout, warnings and errors to stderr, prompts to the
//     controlling terminal (/dev/tty, §5.1), so prompts never mix with data.
//   - Every value or path that came from the vault or from an imported store
//     is escaped with internal/sanitize before it reaches a terminal (S4).
//     The only exceptions are `show --raw` (exact bytes by explicit choice)
//     and `show --field` when stdout is not a terminal (a piped password
//     must be exact).
//   - Secrets are never taken from arguments or the environment (S2).
//   - Exit status: 0 on success, 1 on error, 2 on a usage error (unknown
//     command or flag, wrong number of arguments, a value that doesn't
//     parse).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"passh/internal/agent"
	"passh/internal/config"
	"passh/internal/sanitize"
	"passh/internal/tty"
)

// Version is printed by `passh --version` and `passh version`. cmd/passh
// sets it from its build-time version (-ldflags "-X main.version=…").
var Version = "dev"

// Exit statuses.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// app is the state of one passh invocation: its streams, the global flags,
// and the config and terminal, both loaded lazily (the agent's child
// command must not load the config, and many commands need no terminal).
type app struct {
	stdin  *os.File
	stdout *os.File
	stderr *os.File

	configFlag string // --config
	vaultFlag  string // --vault

	cfg *config.Config

	term      *tty.TTY
	termErr   error
	termTried bool

	warned map[string]bool // warnings already printed (warnOnce)
}

// Main runs passh with args (without the program name) and returns the exit
// status.
func Main(args []string) int {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	defer a.closeTTY()
	root := a.rootCommand()
	root.SetArgs(args)
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	err := root.ExecuteContext(context.Background())
	return a.exitStatus(err)
}

// usageError marks an error in how passh was called: exit status 2.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageErr(err error) error {
	if err == nil {
		return nil
	}
	return &usageError{err: err}
}

func usagef(format string, args ...any) error {
	return usageErr(fmt.Errorf(format, args...))
}

// errReported is returned by a command that has already printed why it
// failed (doctor): exit status 1 and no further message.
var errReported = errors.New("failed")

// exitCodeError is an error with its own exit status, such as 128 + the
// signal that ended the TUI.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }

// exitStatus prints err, if any, and maps it to an exit status.
func (a *app) exitStatus(err error) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, errReported) {
		return exitError
	}
	// Error messages can hold paths and values from the vault or an
	// imported store: escape them (S4). Text keeps the line breaks of
	// multi-line messages, such as the list of backups.
	fmt.Fprintf(a.stderr, "passh: %s\n", sanitize.Text(err.Error()))
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(a.stderr, "Run 'passh --help' or 'passh <command> --help' for usage.")
		return exitUsage
	}
	var ce *exitCodeError
	if errors.As(err, &ce) {
		return ce.code
	}
	return exitError
}

// warnf prints a warning on stderr. Arguments must already be escaped if
// they come from the vault; the whole line is escaped once more with Text,
// which leaves escaped text unchanged.
func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "passh: warning: %s\n", sanitize.Text(fmt.Sprintf(format, args...)))
}

// notef prints a note on stderr.
func (a *app) notef(format string, args ...any) {
	fmt.Fprintf(a.stderr, "passh: %s\n", sanitize.Text(fmt.Sprintf(format, args...)))
}

// printf writes to stdout.
func (a *app) printf(format string, args ...any) {
	fmt.Fprintf(a.stdout, format, args...)
}

// tty returns the controlling terminal, opened on first use. Without one the
// error wraps tty.ErrNoTerminal.
func (a *app) tty() (*tty.TTY, error) {
	if !a.termTried {
		a.termTried = true
		a.term, a.termErr = tty.Open()
	}
	return a.term, a.termErr
}

// needTTY returns the terminal, or an error saying that what needs it is
// impossible without one.
func (a *app) needTTY(what string) (*tty.TTY, error) {
	t, err := a.tty()
	if err != nil {
		return nil, fmt.Errorf("%s needs a terminal (over SSH: use `ssh -t`)", what)
	}
	return t, nil
}

func (a *app) closeTTY() {
	if a.term != nil {
		_ = a.term.Close()
	}
}

// stdoutIsTerminal reports whether stdout is a terminal.
func (a *app) stdoutIsTerminal() bool { return tty.IsTerminal(a.stdout) }

// rootCommand builds the command tree.
func (a *app) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "passh",
		Short: "A password manager with one encrypted vault file",
		Long: "passh keeps passwords in one age-encrypted vault file.\n\n" +
			"Run `passh init` to create a vault, then `passh` alone for the TUI. Commands that\n" +
			"read or change entries ask for the passphrase on the terminal, or use the agent\n" +
			"started by `passh unlock`.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q for passh", args[0])
			}
			return nil
		},
		RunE:              a.runTUI,
		Version:           Version, // adds --version
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetVersionTemplate("passh {{.Version}}\n") // the same as versionLine
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr(err) })
	pf := root.PersistentFlags()
	pf.StringVar(&a.configFlag, "config", "", "config file (default $PASSH_CONFIG, then ~/.config/passh/config.toml)")
	pf.StringVar(&a.vaultFlag, "vault", "", "vault file, overriding the config's vault (no config file needed)")

	root.AddCommand(
		a.cmdInit(),
		a.cmdLs(),
		a.cmdFind(),
		a.cmdShow(),
		a.cmdCopy(),
		a.cmdAdd(),
		a.cmdGenerate(),
		a.cmdEdit(),
		a.cmdMv(),
		a.cmdRm(),
		a.cmdTag(),
		a.cmdTags(),
		a.cmdUnlock(),
		a.cmdLock(),
		a.cmdPasswd(),
		a.cmdRekey(),
		a.cmdRecover(),
		a.cmdRecoveryKey(),
		a.cmdVerify(),
		a.cmdBackup(),
		a.cmdBackups(),
		a.cmdImport(),
		a.cmdExport(),
		a.cmdPrint(),
		a.cmdDoctor(),
		a.cmdVersion(),
		agentChildCommand(),
	)
	return root
}

// versionLine is what `passh --version` and `passh version` print.
func versionLine() string { return "passh " + Version + "\n" }

// cmdVersion is `passh version`, the same as `passh --version`.
func (a *app) cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print passh's version",
		Args:  noArgs(),
		RunE: func(*cobra.Command, []string) error {
			return writeAll(a.stdout, versionLine())
		},
	}
}

// agentChildCommand is the hidden command the agent runs as (§5.3). It
// takes its arguments unparsed and loads no config.
func agentChildCommand() *cobra.Command {
	return &cobra.Command{
		Use:                agent.ChildCommand,
		Hidden:             true,
		DisableFlagParsing: true,
		Run: func(_ *cobra.Command, args []string) {
			os.Exit(agent.ChildMain(args))
		},
	}
}

// Argument validators that report usage errors.

func exactArgs(n int) cobra.PositionalArgs { return wrapArgs(cobra.ExactArgs(n)) }

func rangeArgs(lo, hi int) cobra.PositionalArgs { return wrapArgs(cobra.RangeArgs(lo, hi)) }

func noArgs() cobra.PositionalArgs { return wrapArgs(cobra.NoArgs) }

func wrapArgs(f cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		return usageErr(f(cmd, args))
	}
}

// line escapes a single-line value from the vault for the terminal (S4).
func line(s string) string { return sanitize.Line(s) }

// displayPath is a file path for messages: ~/… under $HOME, escaped.
func displayPath(p string) string { return sanitize.Line(config.ContractHome(p)) }

// writeAll writes s to w and reports a write error (e.g. a closed pipe).
func writeAll(w io.Writer, s string) error {
	_, err := io.WriteString(w, s)
	return err
}

// joinLines joins non-empty parts with newlines.
func joinLines(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}
