// Package cli holds passh's commands (spec §6.1). cmd/passh is a thin main
// that calls Main; keeping the commands here makes them testable.
//
// Conventions for every command:
//
//   - stdout carries only data (OUT-1): entries and fields, listings and
//     reports (ls, find, tags, show, verify, backups, doctor, the checksum
//     of a backup, the import report), exports and sheets, the version and
//     help. Everything that only says what happened or what to do next goes
//     to stderr through one helper, say: confirmations ("Saved x.",
//     "Locked: …"; statusf), notes (notef), warnings (warnf) and errors
//     (exitStatus). Prompts and their messages go to the controlling
//     terminal (/dev/tty, §5.1; termf), so they never mix with data.
//   - Every value or path that came from the vault or from an imported store
//     is escaped with internal/sanitize before it reaches a terminal (S4).
//     The only exceptions are `show --raw` (exact bytes by explicit choice)
//     and `show --field` when stdout is not a terminal (a piped password
//     must be exact).
//   - Secrets are never taken from arguments or the environment (S2).
//   - Text for people is in the config's language (§3.3): a.T, a.p (an
//     i18n.Printer chosen before the command tree is built, language.go),
//     and the Printer passed on to tui, editor, print, printweb and the
//     terminal; cobra's own help texts are set up in help.go. Data on
//     stdout, names and confirmation phrases are never translated
//     (docs/translations.md).
//   - Exit status: 0 on success, 1 on error, 2 on a usage error (unknown
//     command or flag, wrong number of arguments, a value that doesn't
//     parse), 128 + n when signal n ended the TUI or a prompt.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/tty"
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

// app is the state of one passh invocation: its streams, its language, the
// global flags, and the config and terminal, both loaded lazily (the agent's
// child command must not load the config, and many commands need no
// terminal).
type app struct {
	stdin  *os.File
	stdout *os.File
	stderr *os.File

	// p prints in the config's language (§3.3), chosen before the command
	// tree is built (language); a.T is p.T. Pass it to packages that write
	// text for people (tui, editor, print, printweb, the terminal).
	p i18n.Printer

	configFlag string // --config
	vaultFlag  string // --vault

	cfg *config.Config

	term      *tty.TTY
	termErr   error
	termTried bool

	warned map[string]bool // warnings already printed (warnOnce)
}

// Main runs passh with args (without the program name) and returns the exit
// status. warnings are problems from before Main that don't stop passh
// (core dumps that couldn't be turned off, S7); Main prints them in the
// user's language.
func Main(args []string, warnings ...error) int {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, p: i18n.New(language(args))}
	defer a.closeTTY()
	for _, w := range warnings {
		a.warnf("%v", w)
	}
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

// usagef is a usage error with a translatable message (i18n.Errorf):
// exitStatus prints it in the user's language.
//
// i18n:wrapper
func usagef(format string, args ...any) error {
	return usageErr(i18n.Errorf(format, args...))
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
	// multi-line messages, such as the list of backups. The error is
	// rendered in the user's language (§3.3).
	fmt.Fprintf(a.stderr, "passh: %s\n", sanitize.Text(a.p.Error(err)))
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(a.stderr, a.T("Run 'passh --help' or 'passh <command> --help' for usage."))
		return exitUsage
	}
	var ce *exitCodeError
	if errors.As(err, &ce) {
		return ce.code
	}
	// A signal ended a prompt; the terminal was restored (OUT-6).
	var se *tty.SignalError
	if errors.As(err, &se) {
		if n, ok := se.Signal.(syscall.Signal); ok {
			return 128 + int(n)
		}
	}
	return exitError
}

// T returns msg in the user's language, formatted with args if there are
// any: a.p.T (internal/i18n, docs/translations.md).
//
// i18n:wrapper
func (a *app) T(msg string, args ...any) string { return a.p.T(msg, args...) }

// say writes one human message to stderr (OUT-1): prefix, then msg (both
// already in the user's language), escaped with sanitize.Text (S4), which
// leaves text that is already escaped unchanged, then a newline. Best
// effort: a failed write to stderr is ignored (OUT-4). Every status line,
// note and warning goes through it; data goes to a.stdout through writeAll
// or write.
func (a *app) say(prefix, msg string) {
	fmt.Fprintf(a.stderr, "%s%s\n", prefix, sanitize.Text(msg))
}

// statusf prints a confirmation or hint on stderr, translated, as a
// sentence of its own: "Saved work/github.", "Locked: the agent (pid 42)
// stopped.".
//
// i18n:wrapper
func (a *app) statusf(format string, args ...any) { a.say("", a.T(format, args...)) }

// notef prints a note on stderr, translated: "passh: …".
//
// i18n:wrapper
func (a *app) notef(format string, args ...any) { a.say("passh: ", a.T(format, args...)) }

// warnf prints a warning on stderr, translated: "passh: warning: …".
//
// i18n:wrapper
func (a *app) warnf(format string, args ...any) {
	a.say("passh: "+a.T("warning: "), a.T(format, args...))
}

// termf writes a message to the terminal t, translated and escaped with
// sanitize.Text (S4, INV-5): prompts' explanations and retries, which can
// hold an error or a path. Control sequences that passh sends on purpose go
// through t.Write.
//
// i18n:wrapper
func (a *app) termf(t *tty.TTY, format string, args ...any) {
	t.Printf("%s", sanitize.Text(a.T(format, args...)))
}

// tty returns the controlling terminal, opened on first use. Without one the
// error wraps tty.ErrNoTerminal.
func (a *app) tty() (*tty.TTY, error) {
	if !a.termTried {
		a.termTried = true
		a.term, a.termErr = tty.Open()
		if a.termErr == nil {
			a.term.SetPrinter(a.p)
		}
	}
	return a.term, a.termErr
}

// needTTY returns the terminal, or an error saying that command (such as
// "passh init") is impossible without one.
func (a *app) needTTY(command string) (*tty.TTY, error) {
	t, err := a.tty()
	if err != nil {
		return nil, i18n.Errorf("%s needs a terminal (over SSH: use `ssh -t`)", command)
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
		Short: a.T("A password manager with one encrypted vault file"),
		Long: a.T("passh keeps passwords in one age-encrypted vault file.\n\n" +
			"Run `passh init` to create a vault, then `passh` alone for the TUI. Commands that\n" +
			"read or change entries ask for the passphrase on the terminal, or use the agent\n" +
			"started by `passh unlock`."),
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
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr(flagError(err)) })
	pf := root.PersistentFlags()
	pf.StringVar(&a.configFlag, "config", "", a.T("config file (default $PASSH_CONFIG, then ~/.config/passh/config.toml)"))
	pf.StringVar(&a.vaultFlag, "vault", "", a.T("vault file, overriding the config's vault (no config file needed)"))

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
	a.setupHelp(root)
	return root
}

// versionLine is what `passh --version` and `passh version` print.
func versionLine() string { return "passh " + Version + "\n" }

// cmdVersion is `passh version`, the same as `passh --version`.
func (a *app) cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: a.T("Print passh's version"),
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

// Argument validators that report usage errors. They are cobra's
// ExactArgs, RangeArgs and NoArgs (v1.10) with the same English messages,
// made with i18n.Errorf so they are shown in the user's language.

func exactArgs(n int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != n {
			return usagef("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}

func rangeArgs(lo, hi int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) < lo || len(args) > hi {
			return usagef("accepts between %d and %d arg(s), received %d", lo, hi, len(args))
		}
		return nil
	}
}

func noArgs() cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return usagef("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		return nil
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
