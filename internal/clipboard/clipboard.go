// Package clipboard copies values to the clipboard and clears them again
// (§6.3, S6).
//
// Two methods, chosen once by New from the config and the environment:
//
//   - the local command (clipboard.command, e.g. ["wl-copy"]) when one is
//     configured: it is started through internal/exec (S8) with the value on
//     its stdin, never in its arguments or environment (S2);
//   - otherwise OSC 52 through the terminal, if clipboard.osc52 is on and a
//     terminal is available: passh writes ESC ] 52 ; c ; <base64> BEL.
//
// Neither available gives an error matching ErrNoClipboard, whose message
// carries the hint `passh show <path> --field password | pbcopy`. The secret
// is never printed.
//
// Clearing sends an empty value the same way. CopyFor schedules it (the TUI
// keeps the *Pending handle); CopyAndWait blocks until it happens and clears
// at once when interrupted (the non-TUI `passh copy`). Clearing is best
// effort: passh can't read the clipboard back, so it clears whatever is there
// by then, and a clipboard history kept by other tools is out of its reach.
//
// tmux: OSC 52 is written as is, without a DCS passthrough wrapper. tmux with
// `set-clipboard on` takes a plain OSC 52 from the program, stores it in its
// own paste buffer and forwards it to the outer terminal. A passthrough
// wrapper would need `allow-passthrough on`, would bypass tmux's buffer, and
// is not what the spec promises. GNU screen gets no special treatment either.
package clipboard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/exec"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/tty"
)

// TestString is what Test copies, for `passh doctor`.
const TestString = "passh clipboard test"

// commandTimeout bounds one run of the clipboard command. Tools such as
// wl-copy and xclip fork a background process that serves the clipboard;
// their foreground process exits at once.
const commandTimeout = 10 * time.Second

// Method is how values reach the clipboard.
type Method int

const (
	// MethodCommand runs clipboard.command with the value on stdin.
	MethodCommand Method = iota + 1
	// MethodOSC52 writes an OSC 52 sequence to the terminal.
	MethodOSC52
)

func (m Method) String() string {
	switch m {
	case MethodCommand:
		return "clipboard command"
	case MethodOSC52:
		return "OSC 52"
	}
	return "none"
}

// ErrNoClipboard is matched (errors.Is) by the error New returns when
// neither the command nor OSC 52 can be used.
var ErrNoClipboard = errors.New("no clipboard")

// NoClipboardError says why there is no clipboard and how to copy instead.
// Path and Field fill in the hint; WithHint sets them.
type NoClipboardError struct {
	Reason string // e.g. "clipboard.osc52 is off and clipboard.command is empty"
	Path   string // entry path for the hint; "" gives "<path>"
	Field  string // field for the hint; "" gives "password"
}

func (e *NoClipboardError) Error() string {
	return "no clipboard: " + e.Reason + "; copy with: " + Hint(e.Path, e.Field)
}

// Is makes errors.Is(err, ErrNoClipboard) true.
func (e *NoClipboardError) Is(target error) bool { return target == ErrNoClipboard }

// WithHint returns err with the hint's path and field filled in when err is
// a *NoClipboardError, and err unchanged otherwise.
func WithHint(err error, path, field string) error {
	var nc *NoClipboardError
	if !errors.As(err, &nc) {
		return err
	}
	c := *nc
	c.Path, c.Field = path, field
	return &c
}

// Hint returns the command that copies a field without passh's clipboard:
// passh show <path> --field <field> | pbcopy. path and field are quoted for
// a POSIX shell when needed; an empty path gives "<path>" and an empty field
// "password".
func Hint(path, field string) string {
	p := "<path>"
	if path != "" {
		p = shellQuote(path)
	}
	if field == "" {
		field = model.FieldPassword
	}
	return sanitize.Line("passh show " + p + " --field " + shellQuote(field) + " | pbcopy")
}

// shellQuote quotes s for a POSIX shell unless it only holds characters
// that need no quoting.
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("_-./@%+=:,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// OSC52 returns the sequence that sets the system clipboard to value:
// ESC ] 52 ; c ; <standard base64 of the UTF-8 bytes> BEL. An empty value
// gives ESC ] 52 ; c ; BEL, which clears it.
func OSC52(value string) []byte {
	const prefix = "\x1b]52;c;"
	b := make([]byte, 0, len(prefix)+base64.StdEncoding.EncodedLen(len(value))+1)
	b = append(b, prefix...)
	b = base64.StdEncoding.AppendEncode(b, []byte(value))
	return append(b, '\a')
}

// Clipboard copies values with one method. It is safe for concurrent use:
// a scheduled clear runs on a timer goroutine.
type Clipboard struct {
	method  Method
	command []string  // MethodCommand: program and arguments
	term    io.Writer // MethodOSC52

	mu      sync.Mutex // serializes copies and clears, guards pending
	pending *Pending
}

// New chooses the method (§6.3): the command if cfg.Command is set, else
// OSC 52 if cfg.OSC52 is on and term is usable, else an error matching
// ErrNoClipboard. term is where OSC 52 goes; the CLI passes /dev/tty, nil
// when there is none. An *os.File that is not a terminal counts as none.
// Inside a running Bubble Tea program, writes to the same terminal are
// single write calls, so they don't interleave with the renderer's frames.
//
// A configured command whose program isn't found is an error, not a
// fallback: the config asked for it.
func New(cfg config.Clipboard, term io.Writer) (*Clipboard, error) {
	if len(cfg.Command) > 0 {
		if strings.TrimSpace(cfg.Command[0]) == "" {
			return nil, errors.New("clipboard.command: the program name (first element) is empty")
		}
		if _, err := exec.LookPath(cfg.Command[0]); err != nil {
			return nil, fmt.Errorf("clipboard.command: %w", err)
		}
		return &Clipboard{method: MethodCommand, command: append([]string(nil), cfg.Command...)}, nil
	}
	if !cfg.OSC52 {
		return nil, &NoClipboardError{Reason: "clipboard.osc52 is off and clipboard.command is empty"}
	}
	if !usableTerminal(term) {
		return nil, &NoClipboardError{Reason: "OSC 52 needs a terminal and there is none, and clipboard.command is empty"}
	}
	return &Clipboard{method: MethodOSC52, term: term}, nil
}

func usableTerminal(w io.Writer) bool {
	if w == nil {
		return false
	}
	if f, ok := w.(*os.File); ok {
		return tty.IsTerminal(f) // false for a nil *os.File too
	}
	return true
}

// Method returns the method in use.
func (c *Clipboard) Method() Method { return c.method }

// String describes the method for messages and `passh doctor`, e.g.
// "OSC 52 through the terminal" or `command "wl-copy"`.
func (c *Clipboard) String() string {
	if c.method == MethodCommand {
		return fmt.Sprintf("command %q", sanitize.Line(strings.Join(c.command, " ")))
	}
	return "OSC 52 through the terminal"
}

// Copy puts value on the clipboard. It doesn't schedule a clear.
func (c *Clipboard) Copy(ctx context.Context, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.send(ctx, value)
}

// Clear empties the clipboard now, by sending an empty value, and drops
// any scheduled clear.
func (c *Clipboard) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		c.pending.finish(nil)
		c.pending = nil
	}
	return c.send(ctx, "")
}

// send writes value with the chosen method. c.mu is held.
func (c *Clipboard) send(ctx context.Context, value string) error {
	switch c.method {
	case MethodOSC52:
		if _, err := c.term.Write(OSC52(value)); err != nil {
			return fmt.Errorf("clipboard: writing to the terminal: %w", err)
		}
		return nil
	case MethodCommand:
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		defer cancel()
		// Stdout and Stderr stay nil (/dev/null): a pipe would be held open
		// by the tool's background process and Run would never return.
		err := exec.Run(ctx, exec.Command{
			Name:  c.command[0],
			Args:  c.command[1:],
			Stdin: strings.NewReader(value),
		})
		if err != nil {
			return fmt.Errorf("clipboard command: %w", err)
		}
		return nil
	}
	return errors.New("clipboard: no method")
}

// clearContext returns a context for a clear that must happen even though
// ctx is done (an interrupted wait).
func clearContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), commandTimeout)
}

// Pending is a scheduled clear, returned by CopyFor.
type Pending struct {
	c        *Clipboard
	deadline time.Time
	timer    *time.Timer
	done     chan struct{}
	finished bool  // guarded by c.mu
	err      error // the clear's error; set before done is closed
}

// CopyFor copies value and schedules a clear after d. A later CopyFor or
// Clear replaces the schedule: the earlier handle finishes without clearing,
// so an old timer never wipes a newer value. d <= 0 clears at once after
// copying (useful only for tests).
//
// The TUI keeps the handle to show the countdown (Deadline) and to clear at
// once on lock or quit (ClearNow, or Clipboard.ClearPending).
func (c *Clipboard) CopyFor(ctx context.Context, value string, d time.Duration) (*Pending, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		c.pending.finish(nil)
		c.pending = nil
	}
	if err := c.send(ctx, value); err != nil {
		return nil, err
	}
	p := &Pending{c: c, deadline: time.Now().Add(d), done: make(chan struct{})}
	c.pending = p
	p.timer = time.AfterFunc(max(d, 0), p.fire)
	return p, nil
}

// fire runs on the timer goroutine.
func (p *Pending) fire() {
	ctx, cancel := clearContext(context.Background())
	defer cancel()
	_ = p.ClearNow(ctx)
}

// finish marks p done. p.c.mu is held.
func (p *Pending) finish(err error) {
	if p.finished {
		return
	}
	p.finished = true
	p.err = err
	if p.timer != nil {
		p.timer.Stop()
	}
	close(p.done)
}

// Deadline returns when the clear is due.
func (p *Pending) Deadline() time.Time { return p.deadline }

// Done is closed when the clear has happened, failed, was stopped or was
// replaced by a newer copy.
func (p *Pending) Done() <-chan struct{} { return p.done }

// Err returns the clear's error once Done is closed; nil before, and nil
// when the clear was stopped or replaced.
func (p *Pending) Err() error {
	select {
	case <-p.done:
		return p.err
	default:
		return nil
	}
}

// ClearNow clears at once instead of waiting. It does nothing (and returns
// the earlier result) if the clear already happened, and nothing if a newer
// copy replaced this one.
func (p *Pending) ClearNow(ctx context.Context) error {
	c := p.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.finished {
		return p.err
	}
	err := c.send(ctx, "")
	p.finish(err)
	if c.pending == p {
		c.pending = nil
	}
	return err
}

// Stop cancels the scheduled clear and leaves the clipboard as it is. It
// reports whether the clear was still scheduled.
func (p *Pending) Stop() bool {
	c := p.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.finished {
		return false
	}
	p.finish(nil)
	if c.pending == p {
		c.pending = nil
	}
	return true
}

// ClearPending clears at once if a clear is scheduled, as the TUI does when
// it locks or quits. Without one it does nothing.
func (c *Clipboard) ClearPending(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil {
		return nil
	}
	err := c.send(ctx, "")
	p.finish(err)
	c.pending = nil
	return err
}

// Pending returns when the scheduled clear is due, and false when no clear
// is scheduled (none was, it happened, or it was stopped). The TUI shows the
// countdown from it and, when quitting, waits for it like `passh copy`.
func (c *Clipboard) Pending() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil || c.pending.finished {
		return time.Time{}, false
	}
	return c.pending.deadline, true
}

// waitSignals are the signals that end a CopyAndWait early, with a clear.
var waitSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// CopyAndWait copies value, waits d, clears, and returns: the non-TUI
// `passh copy`, which waits for the clear before it exits (§6.3). When ctx
// is cancelled or SIGINT, SIGTERM or SIGHUP arrives during the wait, it
// clears at once and returns an error wrapping ErrInterrupted. While it
// waits, those signals don't kill the process.
func (c *Clipboard) CopyAndWait(ctx context.Context, value string, d time.Duration) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, waitSignals...)
	defer signal.Stop(sigs)

	p, err := c.CopyFor(ctx, value, d)
	if err != nil {
		return err
	}
	var why string
	select {
	case <-p.Done():
		return p.Err()
	case <-ctx.Done():
		why = context.Cause(ctx).Error()
	case s := <-sigs:
		why = s.String()
	}
	cctx, cancel := clearContext(ctx)
	defer cancel()
	if err := p.ClearNow(cctx); err != nil {
		return fmt.Errorf("%w (%s), and clearing the clipboard failed: %w", ErrInterrupted, why, err)
	}
	return fmt.Errorf("%w (%s); the clipboard was cleared", ErrInterrupted, why)
}

// ErrInterrupted is wrapped by CopyAndWait's error when the wait was cut
// short.
var ErrInterrupted = errors.New("interrupted")

// Test copies TestString, waits (so the user can paste it somewhere to
// check), then clears; for `passh doctor`. It behaves like CopyAndWait.
func (c *Clipboard) Test(ctx context.Context, wait time.Duration) error {
	return c.CopyAndWait(ctx, TestString, wait)
}

// EnvironmentNotes returns advice about the terminal environment for
// `passh doctor`, from environment variables (getenv is os.Getenv in
// production): tmux needs set-clipboard on, GNU screen and Terminal.app
// don't pass OSC 52.
func EnvironmentNotes(getenv func(string) string) []string {
	var notes []string
	if getenv("TMUX") != "" {
		notes = append(notes, "inside tmux: OSC 52 needs `set -g set-clipboard on` in ~/.tmux.conf")
	}
	if getenv("STY") != "" {
		notes = append(notes, "inside GNU screen: screen doesn't pass OSC 52 to the terminal; set clipboard.command or run passh outside screen")
	}
	if getenv("TERM_PROGRAM") == "Apple_Terminal" {
		notes = append(notes, `Terminal.app has no OSC 52: set clipboard.command = ["pbcopy"]`)
	}
	return notes
}
