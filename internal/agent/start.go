package agent

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"github.com/devapro/passh/internal/exec"
	"github.com/devapro/passh/internal/harden"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
)

// Options configure an agent.
type Options struct {
	// KeyBlock is the vault's key block (binary, as vault.Vault.KeyBlock
	// returns it) that `passh unlock` just unwrapped with the passphrase.
	// The agent keeps only its SHA-256 and serves the key to a KeySource
	// only for that key block (ErrKeyBlockChanged otherwise). Required.
	KeyBlock []byte
	// IdleTTL: the agent exits after this long without a key request
	// (agent.idle_ttl).
	IdleTTL time.Duration
	// MaxTTL: the agent exits after this long in any case (agent.max_ttl,
	// or `unlock --ttl`).
	MaxTTL time.Duration
}

// startTimeout bounds the wait for a new agent to report that it is ready.
var startTimeout = 10 * time.Second

// readyFD is the child's file descriptor for its readiness report: one
// line, "ok", "running" (another agent holds the socket) or "error: <why>".
const readyFD = 3

// Readiness report lines.
const (
	readyOK      = "ok"
	readyRunning = "running"
	readyError   = "error: "
)

// Start starts an agent for vault that holds key, for `passh unlock`. It is
// the only function that starts an agent.
//
// If an agent is already running for the vault, Start returns an
// *AlreadyRunningError (errors.Is(err, ErrAlreadyRunning)) with its time
// left. Otherwise it re-executes the passh binary (exec.Self) as
// `passh __agent --vault=<real path> --idle-ttl=<d> --max-ttl=<d>` in a new
// session, hands it the key through its stdin pipe only (never arguments or
// the environment), waits until the agent listens on its socket (or fails,
// or startTimeout passes) and returns its status. The agent process is not
// waited for; it outlives the caller.
func Start(ctx context.Context, vault string, key *age.X25519Identity, opts Options) (Status, error) {
	if key == nil {
		return Status{}, errors.New("agent: no vault key")
	}
	if len(opts.KeyBlock) == 0 {
		return Status{}, errors.New("agent: no key block: the agent needs the key block the passphrase opened")
	}
	if opts.IdleTTL <= 0 || opts.MaxTTL <= 0 {
		return Status{}, errors.New("agent: the idle and max TTL must be positive")
	}
	c, err := NewClient(vault)
	if err != nil {
		return Status{}, err
	}
	if st, err := c.Status(ctx); err == nil {
		return Status{}, &AlreadyRunningError{Status: st}
	} else if !errors.Is(err, ErrNoAgent) {
		return Status{}, err
	}

	self, err := exec.Self()
	if err != nil {
		return Status{}, i18n.Errorf("agent: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return Status{}, i18n.Errorf("agent: %w", err)
	}
	defer r.Close()
	// stdin: the key, then the key block's SHA-256 (hex), one per line.
	text := []byte(key.String() + "\n" + keyBlockSum(opts.KeyBlock) + "\n")
	defer keys.Zero(text)
	proc, err := exec.StartDetached(exec.Command{
		Name:       self,
		Args:       childArgs(c.vault, opts),
		ExtraFiles: []*os.File{w}, // fd 3: readiness report
	}, text)
	w.Close() // the child holds the only write end now
	if err != nil {
		return Status{}, i18n.Errorf("agent: starting the agent: %w", err)
	}

	line, err := waitReady(ctx, r)
	if err != nil || (line != readyOK && line != readyRunning) {
		_ = proc.Kill()
		_, _ = proc.Wait()
		if err == nil {
			// The agent's own report, in English: it runs without a
			// language. Printer.Error translates it if the whole text is
			// a catalog key.
			msg, _ := strings.CutPrefix(line, readyError)
			err = errors.New(strings.TrimPrefix(msg, "agent: "))
		}
		return Status{}, i18n.Errorf("agent: starting the agent: %w", err)
	}
	// Fire and forget (CONC-3): reap the agent when it exits, should this
	// process still be around. Nothing waits for this goroutine; the agent
	// outlives the caller by design.
	go func() { _, _ = proc.Wait() }()

	st, err := c.Status(ctx)
	if line == readyRunning {
		// Another unlock won the race for the socket.
		if err != nil {
			return Status{}, i18n.Errorf("agent: %w", ErrAlreadyRunning)
		}
		return Status{}, &AlreadyRunningError{Status: st}
	}
	if err != nil {
		return Status{}, i18n.Errorf("agent: the agent (pid %d) started but doesn't answer: %w", proc.Pid, err)
	}
	return st, nil
}

// childArgs are the agent's arguments: the hidden subcommand, the vault's
// real path and the TTLs. Never the key (S2).
func childArgs(real string, opts Options) []string {
	return []string{
		ChildCommand,
		"--vault=" + real,
		"--idle-ttl=" + opts.IdleTTL.String(),
		"--max-ttl=" + opts.MaxTTL.String(),
	}
}

// waitReady reads the child's readiness line from r.
func waitReady(ctx context.Context, r *os.File) (string, error) {
	deadline := time.Now().Add(startTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := r.SetReadDeadline(deadline); err != nil {
		return "", err
	}
	stop := context.AfterFunc(ctx, func() { _ = r.SetReadDeadline(time.Now()) })
	defer stop()
	msg, err := readMessage(r, 1024)
	switch {
	case err == nil:
		return string(msg), nil
	case ctx.Err() != nil:
		return "", ctx.Err()
	case errors.Is(err, os.ErrDeadlineExceeded):
		if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
			return "", context.DeadlineExceeded // ctx's timer hasn't fired yet
		}
		return "", i18n.Errorf("the agent didn't report ready within %s", startTimeout)
	case errors.Is(err, io.EOF), errors.Is(err, errNoLine):
		return "", i18n.NewError("the agent exited before it was ready")
	default:
		return "", err
	}
}

// ChildMain is the agent process: the hidden subcommand ChildCommand calls
// it with the arguments after the subcommand's name (unparsed; the cobra
// command should disable flag parsing and skip loading the config) and
// exits with the status it returns. It reads the vault key from stdin until
// EOF, reports readiness on file descriptor 3, and serves until the agent
// exits (see the package comment). Run by hand, without Start's pipe on
// fd 3, it refuses to run.
func ChildMain(args []string) int {
	ready := os.NewFile(readyFD, "ready")
	if fi, err := ready.Stat(); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		fmt.Fprintf(os.Stderr, "passh: %s is started by `passh unlock`, not by hand\n", ChildCommand)
		return 2
	}
	return runChild(args, os.Stdin, ready)
}

// runChild is ChildMain with its files passed in.
func runChild(args []string, stdin io.ReadCloser, ready *os.File) int {
	defer func() { _ = stdin.Close() }() // read-only; closed again below on the main path
	report := func(line string) {
		_, _ = io.WriteString(ready, line+"\n")
		ready.Close()
	}
	// The agent process has no language (cli speaks English for the
	// child command), so its errors are reported in English: Start passes
	// the text on, and Printer.Error translates it only when the whole
	// text is a catalog key. The agent's own errors (here, in newServer
	// and listen) are therefore plain fmt.Errorf.
	fail := func(err error) int {
		report(readyError + strings.ReplaceAll(err.Error(), "\n", " "))
		return 1
	}

	unix.Umask(0o077)
	if err := harden.DisableCoreDumps(); err != nil { // S7, before the key is read
		return fail(err)
	}
	real, opts, err := parseChildArgs(args)
	if err != nil {
		return fail(err)
	}
	key, sum, err := readInput(stdin)
	_ = stdin.Close() // read-only: nothing to flush; the key was read or not
	if err != nil {
		return fail(err)
	}

	// Signals are set up before the agent reports ready, so a SIGTERM
	// right after Start returns is handled.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)
	signal.Ignore(syscall.SIGHUP) // the end of the SSH session

	srv, err := newServer(real, key, sum, opts.IdleTTL, opts.MaxTTL)
	if err != nil {
		keys.Zero(key)
		if errors.Is(err, errRunning) {
			report(readyRunning)
			return 1
		}
		return fail(err)
	}
	report(readyOK)
	srv.run(sigs)
	return 0
}

// parseChildArgs parses `--vault=<path> --idle-ttl=<d> --max-ttl=<d>`.
func parseChildArgs(args []string) (string, Options, error) {
	fs := flag.NewFlagSet(ChildCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vault := fs.String("vault", "", "")
	var opts Options
	fs.DurationVar(&opts.IdleTTL, "idle-ttl", 0, "")
	fs.DurationVar(&opts.MaxTTL, "max-ttl", 0, "")
	if err := fs.Parse(args); err != nil {
		return "", Options{}, fmt.Errorf("agent: %w", err)
	}
	if fs.NArg() != 0 {
		return "", Options{}, fmt.Errorf("agent: unexpected argument %q", fs.Arg(0))
	}
	if !filepath.IsAbs(*vault) {
		return "", Options{}, errors.New("agent: --vault must be an absolute path")
	}
	if opts.IdleTTL <= 0 || opts.MaxTTL <= 0 {
		return "", Options{}, errors.New("agent: --idle-ttl and --max-ttl must be positive")
	}
	real, err := realPath(*vault)
	if err != nil {
		return "", Options{}, err
	}
	return real, opts, nil
}

// readInput reads the agent's stdin until EOF into a buffer of its own: the
// vault key text on one line, then the hex SHA-256 of the key block it was
// unwrapped from (Start sends both; without the digest the agent could serve
// no key request, INV-12). Blank lines and surrounding white space are
// ignored.
func readInput(r io.Reader) (key []byte, keyBlockSum string, err error) {
	buf := make([]byte, 512)
	defer clear(buf)
	n := 0
	for {
		if n == len(buf) {
			return nil, "", errors.New("agent: the key on stdin is too long")
		}
		m, err := r.Read(buf[n:])
		n += m
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("agent: reading the key: %w", err)
		}
	}
	var lines [][]byte
	for l := range bytes.SplitSeq(buf[:n], []byte("\n")) {
		if l = bytes.TrimSpace(l); len(l) > 0 {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return nil, "", errors.New("agent: the key on stdin: nothing was sent")
	}
	if len(lines) > 2 {
		return nil, "", errors.New("agent: the key on stdin: unexpected extra lines")
	}
	if _, err := parseKey(lines[0]); err != nil {
		return nil, "", fmt.Errorf("agent: the key on stdin: %w", err)
	}
	if len(lines) < 2 {
		return nil, "", errors.New("agent: the key block digest is missing on stdin")
	}
	keyBlockSum = string(lines[1])
	if !validSum(keyBlockSum) {
		return nil, "", errors.New("agent: the key block digest on stdin is not a SHA-256")
	}
	return bytes.Clone(lines[0]), keyBlockSum, nil
}
