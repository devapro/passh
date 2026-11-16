// Package tty talks to the user on the controlling terminal (§5.1, §5.4,
// §7.1).
//
// Prompts are read from and written to /dev/tty, not stdin and stdout, so
// they work while stdout is piped (`passh show … | pbcopy`) and never mix
// with data. When there is no terminal, Open returns an error wrapping
// ErrNoTerminal, and callers fall back (§5.1 step 3) or require a flag such
// as --confirm-plaintext (§7.1).
//
// ReadPassphrase and ReadMaskedLines switch the terminal to raw mode, so
// echo is off and Ctrl-C arrives as a key instead of a signal: the prompt
// returns ErrInterrupted with the terminal restored, never leaving it
// without echo. The other prompts read a line in the terminal's normal
// (cooked) mode.
//
// # Signals and cancellation
//
// While a prompt waits for input, SIGINT, SIGTERM and SIGHUP are caught
// (OUT-6, CONC-6): the terminal is restored first, then the blocked read is
// interrupted with a read deadline, and the prompt returns a *SignalError
// (which matches ErrInterrupted); the CLI exits with 128 + the signal's
// number. The …Context prompts also return when their context ends, the
// same way, with the context's error (CONC-1). A signal is never swallowed:
// one that arrives just after the input was complete still ends the prompt
// with a *SignalError.
//
// A read deadline can only interrupt a read on a file the Go runtime polls
// in non-blocking mode. /dev/tty on macOS isn't one (kqueue doesn't support
// terminals), and no file is once something called its Fd method (which
// puts it into blocking mode: bubbletea and editors started on the terminal
// do). There a blocked read can't be interrupted portably, so on a signal
// the prompt restores the terminal, stops catching the signal and raises it
// again: the process ends as the signal asked, never with echo off. A
// cancelled context then takes effect only when the read returns (the next
// key). This package never calls Fd on the terminal; it uses SyscallConn.
package tty

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Confirmation phrases the user types to allow a dangerous action.
const (
	PhrasePrintRecoveryKey = "PRINT RECOVERY KEY" // §5.4
	PhraseExportPlaintext  = "EXPORT PLAINTEXT"   // §7.1, §7.2
	PhrasePrint            = "PRINT"              // §7.4
)

// Limits on what a prompt accepts.
const (
	MaxPassphrase = 4096
	MaxLine       = 64 << 10
)

var (
	// ErrNoTerminal means there is no controlling terminal (or the given
	// file is not one).
	ErrNoTerminal = errors.New("no terminal")
	// ErrInterrupted means the user pressed Ctrl-C at a passphrase prompt,
	// or a signal ended a prompt (a *SignalError matches it too).
	ErrInterrupted = errors.New("interrupted")
	// ErrNotConfirmed means the user declined or didn't type the
	// confirmation phrase exactly.
	ErrNotConfirmed = errors.New("not confirmed")
	// ErrMismatch means the new passphrase and its repetition differed on
	// every attempt.
	ErrMismatch = errors.New("passphrases don't match")
)

// SignalError is returned by a prompt that SIGINT, SIGTERM or SIGHUP ended.
// The terminal was restored before the prompt returned. errors.Is(err,
// ErrInterrupted) is true for it; callers that exit should do so with
// status 128 + the signal's number.
type SignalError struct {
	Signal os.Signal
}

func (e *SignalError) Error() string {
	return fmt.Sprintf("%v (%v)", ErrInterrupted, e.Signal)
}

// Is makes errors.Is(err, ErrInterrupted) true.
func (e *SignalError) Is(target error) bool { return target == ErrInterrupted }

// TTY is a terminal used for prompts. One goroutine at a time may prompt.
type TTY struct {
	f     *os.File
	owned bool
}

// Open opens the controlling terminal, /dev/tty. Without one it returns an
// error wrapping ErrNoTerminal.
func Open() (*TTY, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, err)
	}
	if !IsTerminal(f) {
		_ = f.Close() // nothing was written to it
		return nil, fmt.Errorf("%w: /dev/tty is not a terminal", ErrNoTerminal)
	}
	return &TTY{f: f, owned: true}, nil
}

// New uses f, which must be a terminal, for prompts. Close doesn't close f.
// This is how tests inject a pseudo-terminal.
func New(f *os.File) (*TTY, error) {
	if !IsTerminal(f) {
		return nil, fmt.Errorf("%w: %s is not a terminal", ErrNoTerminal, name(f))
	}
	return &TTY{f: f}, nil
}

// IsTerminal reports whether f is a terminal. Export uses it to refuse to
// write data to a terminal (§7.1). It doesn't put f into blocking mode, as
// f.Fd would.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	ok := false
	if err := control(f, func(fd int) { ok = term.IsTerminal(fd) }); err != nil {
		return false
	}
	return ok
}

// File returns the terminal's file, e.g. to wire it to an editor. Calling
// its Fd method puts it into blocking mode, after which a signal at a later
// prompt is handled by raising it again (see the package comment).
func (t *TTY) File() *os.File { return t.f }

// Close closes the terminal if Open opened it.
func (t *TTY) Close() error {
	if t.owned {
		return t.f.Close()
	}
	return nil
}

// Write writes p to the terminal as is: control sequences included.
func (t *TTY) Write(p []byte) (int, error) { return t.f.Write(p) }

// Printf writes a formatted message to the terminal, as is: arguments that
// come from the vault, an import, a file name, the environment or an error
// must be escaped by the caller (S4; internal/cli does it in one helper).
func (t *TTY) Printf(format string, args ...any) {
	fmt.Fprintf(t.f, format, args...)
}

// Wipe overwrites b with zeros. Callers wipe passphrases when done.
func Wipe(b []byte) {
	clear(b)
}

// control runs fn with f's file descriptor. Unlike f.Fd, it leaves f in
// non-blocking mode, so read deadlines keep working.
func control(f *os.File, fn func(fd int)) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { fn(int(fd)) })
}

// promptSignals end a waiting prompt after the terminal is restored.
var promptSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}

// Test hooks; the production values are below. canInterrupt reports whether
// a read deadline interrupts a blocked read on f; setReadDeadline sets one.
var (
	canInterrupt    = interruptible
	setReadDeadline = (*os.File).SetReadDeadline
)

// interruptible reports whether a read deadline can interrupt a blocked
// read on f: the runtime polls it, and it is still in non-blocking mode.
func interruptible(f *os.File) bool {
	nonblock := false
	if err := control(f, func(fd int) {
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		nonblock = err == nil && fl&unix.O_NONBLOCK != 0
	}); err != nil {
		return false
	}
	return nonblock && setReadDeadline(f, time.Time{}) == nil
}

// watch guards one prompt: until stop, the end of ctx and promptSignals
// interrupt the prompt's read.
type watch struct {
	f      *os.File
	sigs   chan os.Signal // buffered: signal.Notify doesn't block
	done   chan struct{}  // closed by stop
	exited chan struct{}  // closed when the goroutine returns

	mu  sync.Mutex
	sig os.Signal // the signal that ended the prompt
}

// watch starts guarding a prompt on t. restore, if not nil, puts the
// terminal back into its normal mode; it must be safe to call more than
// once and from another goroutine. The caller must call stop.
func (t *TTY) watch(ctx context.Context, restore func()) *watch {
	w := &watch{f: t.f, sigs: make(chan os.Signal, 1), done: make(chan struct{}), exited: make(chan struct{})}
	signal.Notify(w.sigs, promptSignals...) // CONC-6: stop calls signal.Stop; every caller runs it
	// The goroutine ends when the prompt does (stop closes done), or after
	// it has handled a signal or the end of ctx; stop waits for it.
	go w.run(ctx, restore)
	return w
}

func (w *watch) run(ctx context.Context, restore func()) {
	defer close(w.exited)
	select {
	case s := <-w.sigs:
		w.setSignal(s)
		if restore != nil {
			restore()
		}
		if canInterrupt(w.f) {
			_ = setReadDeadline(w.f, time.Now()) // the read returns at once
			return
		}
		// The read can't be interrupted (see the package comment): raise the
		// signal again with its default action, now that the terminal is
		// restored. If something else in the process catches it too, the
		// prompt returns the *SignalError after the next key.
		signal.Stop(w.sigs)
		if n, ok := s.(syscall.Signal); ok {
			_ = syscall.Kill(syscall.Getpid(), n)
		}
	case <-ctx.Done():
		if canInterrupt(w.f) {
			_ = setReadDeadline(w.f, time.Now())
		}
	case <-w.done:
	}
}

func (w *watch) setSignal(s os.Signal) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sig == nil {
		w.sig = s
	}
}

// stop ends the watch, waits for its goroutine and clears the read
// deadline. It returns the signal that arrived while the prompt waited, if
// any, including one that came just after the input was complete.
func (w *watch) stop() os.Signal {
	signal.Stop(w.sigs)
	close(w.done)
	<-w.exited
	select {
	case s := <-w.sigs:
		w.setSignal(s)
	default:
	}
	_ = setReadDeadline(w.f, time.Time{}) // ErrNoDeadline on files without deadlines
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sig
}

// readErr is what a prompt returns for err, the error of its read, once its
// watch has stopped with sig: a signal first, then the end of ctx (whose
// read deadline caused err).
func readErr(ctx context.Context, sig os.Signal, err error) error {
	switch {
	case sig != nil:
		return &SignalError{Signal: sig}
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	}
	return err
}

// ReadPassphrase is ReadPassphraseContext without a context.
func (t *TTY) ReadPassphrase(prompt string) ([]byte, error) {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.ReadPassphraseContext(context.Background(), prompt)
}

// ReadPassphraseContext prints prompt and reads a line with echo off.
// Backspace, Ctrl-U (erase the line) and Ctrl-W (erase a word) edit the
// input; escape sequences (arrow and function keys) are ignored; Ctrl-C
// returns ErrInterrupted and Ctrl-D on an empty line returns io.EOF. A
// signal returns a *SignalError, the end of ctx ctx's error (see the
// package comment). The returned slice should be wiped by the caller.
func (t *TTY) ReadPassphraseContext(ctx context.Context, prompt string) ([]byte, error) {
	return t.readRaw(ctx, func(rs *rawSession) ([]byte, error) {
		if err := rs.prompt(prompt); err != nil {
			return nil, err
		}
		ed := &lineEditor{t: t, max: MaxPassphrase, what: "passphrase"}
		return ed.readLine()
	})
}

// ReadMaskedLines is ReadMaskedLinesContext without a context.
func (t *TTY) ReadMaskedLines(prompt string) ([]byte, error) {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.ReadMaskedLinesContext(context.Background(), prompt)
}

// ReadMaskedLinesContext reads a secret typed or pasted on several lines,
// such as the paper recovery key (§5.4), so that it never shows on the
// screen or in the scrollback: each character is echoed as *, a space as a
// space. Each line starts with prompt. Empty lines before the first
// character are ignored; the first empty line after it ends the input, as
// does Ctrl-D (io.EOF if nothing was typed). Editing keys, Ctrl-C, signals
// and ctx work as for ReadPassphraseContext. It returns the lines, each
// ended by "\n"; the caller wipes the result.
func (t *TTY) ReadMaskedLinesContext(ctx context.Context, prompt string) ([]byte, error) {
	return t.readRaw(ctx, func(rs *rawSession) ([]byte, error) {
		out := make([]byte, 0, MaxLine) // no regrowth: no unwiped copies
		fail := func(err error) ([]byte, error) {
			clear(out[:cap(out)])
			return nil, err
		}
		ed := &lineEditor{t: t, prompt: prompt, masked: true, what: "input"}
		for {
			if err := rs.prompt(prompt); err != nil {
				return fail(err)
			}
			ed.max = MaxLine - len(out) - 1
			line, err := ed.readLine()
			switch {
			case errors.Is(err, io.EOF) && len(out) > 0:
				return out, nil
			case err != nil:
				return fail(err)
			}
			blank := len(bytes.TrimSpace(line)) == 0
			if !blank {
				out = append(out, line...)
				out = append(out, '\n')
			}
			clear(line[:cap(line)])
			if blank && len(out) > 0 {
				return out, nil
			}
			if err := rs.newline(); err != nil {
				return fail(err)
			}
		}
	})
}

// rawSession is one stay in raw mode: the prompts of readRaw's read.
type rawSession struct {
	t *TTY
	// midLine is set while the cursor is after a prompt: echo is off, so
	// the user's Enter doesn't move it, and the restore ends the line.
	midLine atomic.Bool
}

// prompt shows a prompt. Echo is off already (getpass order: raw mode,
// then the prompt, then the read), so nothing typed early is echoed.
func (rs *rawSession) prompt(p string) error {
	rs.midLine.Store(true)
	return rs.t.writeRaw(p)
}

// newline ends the line of an answered prompt.
func (rs *rawSession) newline() error {
	rs.midLine.Store(false)
	return rs.t.writeRaw("\n")
}

// say prints msg on lines of its own, after newline.
func (rs *rawSession) say(msg string) error {
	return rs.t.writeRaw(strings.TrimRight(msg, "\n") + "\n")
}

// readRaw runs read with the terminal in raw mode for its whole run, and
// the prompts watched (see watch). The terminal is restored, and a line a
// prompt left open is ended, before it returns. When the prompt didn't end
// with an answer (a signal, Ctrl-C, ctx, an error), whatever was typed and
// not read yet is discarded first, while echo is still off: a partial
// secret is never echoed when echo comes back, nor read by the shell.
func (t *TTY) readRaw(ctx context.Context, read func(rs *rawSession) ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var (
		old    *term.State
		rawErr error
	)
	if err := control(t.f, func(fd int) { old, rawErr = term.MakeRaw(fd) }); err != nil || rawErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, errors.Join(err, rawErr))
	}
	rs := &rawSession{t: t}
	var once sync.Once
	restore := func(interrupted bool) {
		once.Do(func() {
			_ = control(t.f, func(fd int) {
				if interrupted {
					_ = flushInput(fd) // best effort, before echo is back
				}
				_ = term.Restore(fd, old)
			})
			if rs.midLine.Load() {
				_, _ = t.f.WriteString("\n")
			}
		})
	}
	w := t.watch(ctx, func() { restore(true) })
	buf, err := read(rs)
	sig := w.stop()
	err = readErr(ctx, sig, err)
	restore(err != nil)
	if err != nil {
		clear(buf[:cap(buf)])
		return nil, err
	}
	return buf, nil
}

// writeRaw writes s in raw mode, where output processing is off: line
// breaks need a carriage return.
func (t *TTY) writeRaw(s string) error {
	_, err := t.f.WriteString(strings.ReplaceAll(s, "\n", "\r\n"))
	return err
}

// Escape sequence states of lineEditor.
const (
	escNone = iota
	escStart
	escCSI // ESC [ parameters … final
	escSS3 // ESC O final
)

// lineEditor reads one line in raw mode, byte by byte, and edits it.
type lineEditor struct {
	t      *TTY
	prompt string // redrawn after Ctrl-U and Ctrl-W when masked
	masked bool   // echo * for each character
	max    int    // the longest line, in bytes
	what   string // for errors: "passphrase", "input"

	esc    int  // escape sequence state, kept between lines
	lastCR bool // the previous line ended with CR: skip a LF right after it
}

// readLine reads up to the end of a line (CR or LF). Its buffer has room for
// max bytes and is wiped on error; the caller wipes the result.
func (ed *lineEditor) readLine() ([]byte, error) {
	buf := make([]byte, 0, ed.max)
	fail := func(err error) ([]byte, error) {
		clear(buf[:cap(buf)])
		return nil, err
	}
	var key [1]byte
	for {
		n, err := ed.t.f.Read(key[:])
		if n == 0 {
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fail(io.EOF)
			}
			return fail(fmt.Errorf("reading the %s: %w", ed.what, err))
		}
		c := key[0]
		lastCR := ed.lastCR
		ed.lastCR = false
		if ed.skipEscape(c) {
			continue
		}
		switch c {
		case '\n':
			if lastCR && len(buf) == 0 {
				continue // the LF of a CR LF line ending (a paste)
			}
			return buf, nil
		case '\r':
			ed.lastCR = true
			return buf, nil
		case 0x03: // Ctrl-C
			return fail(ErrInterrupted)
		case 0x04: // Ctrl-D
			if len(buf) == 0 {
				return fail(io.EOF)
			}
		case 0x7f, 0x08: // Backspace
			if len(buf) > 0 {
				buf = eraseRune(buf)
				ed.echo("\b \b")
			}
		case 0x15: // Ctrl-U
			clear(buf)
			buf = buf[:0]
			ed.redraw(buf)
		case 0x17: // Ctrl-W
			buf = eraseWord(buf)
			ed.redraw(buf)
		case 0x1b: // ESC: the start of a sequence, see skipEscape
			ed.esc = escStart
		default:
			if c < 0x20 {
				continue // other control keys are ignored
			}
			if len(buf) == ed.max {
				return fail(fmt.Errorf("%s longer than %d bytes", ed.what, ed.max))
			}
			buf = append(buf, c)
			ed.echo(maskOf(c))
		}
	}
}

// skipEscape swallows the bytes of an escape sequence that an arrow or
// function key sends (ESC [ … final, ESC O final), so they don't end up in
// the input. It reports whether c was part of one. After ESC and any other
// byte, ESC is dropped and the byte counts as typed.
func (ed *lineEditor) skipEscape(c byte) bool {
	switch ed.esc {
	case escStart:
		switch c {
		case '[':
			ed.esc = escCSI
			return true
		case 'O':
			ed.esc = escSS3
			return true
		case 0x1b:
			return true
		}
		ed.esc = escNone
		return false
	case escCSI:
		switch {
		case c >= 0x20 && c <= 0x3f: // parameter and intermediate bytes
			return true
		case c >= 0x40 && c <= 0x7e: // final byte
			ed.esc = escNone
			return true
		}
		ed.esc = escNone // a broken sequence: c is a key of its own
		return false
	case escSS3:
		ed.esc = escNone
		return c >= 0x40 && c <= 0x7e
	}
	return false
}

// echo writes s when masked; a passphrase prompt echoes nothing.
func (ed *lineEditor) echo(s string) {
	if ed.masked && s != "" {
		_, _ = ed.t.f.WriteString(s)
	}
}

// redraw shows the line again after Ctrl-U or Ctrl-W, masked.
func (ed *lineEditor) redraw(buf []byte) {
	if !ed.masked {
		return
	}
	var b strings.Builder
	b.WriteString("\r")
	b.WriteString(ed.prompt[strings.LastIndexByte(ed.prompt, '\n')+1:])
	for _, c := range buf {
		b.WriteString(maskOf(c))
	}
	b.WriteString("\x1b[K")
	_, _ = ed.t.f.WriteString(b.String())
}

// maskOf is what a masked prompt shows for the byte c: a space as is, a *
// for the first byte of any other character, nothing for the rest of it.
func maskOf(c byte) string {
	switch {
	case c == ' ':
		return " "
	case utf8.RuneStart(c):
		return "*"
	}
	return ""
}

// eraseRune removes the last UTF-8 character of b, wiping its bytes.
func eraseRune(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	_, size := utf8.DecodeLastRune(b)
	clear(b[len(b)-size:])
	return b[:len(b)-size]
}

// eraseWord removes trailing spaces and then the last word, like Ctrl-W in
// a shell.
func eraseWord(b []byte) []byte {
	n := len(b)
	for n > 0 && b[n-1] == ' ' {
		n--
	}
	for n > 0 && b[n-1] != ' ' {
		n--
	}
	clear(b[n:])
	return b[:n]
}

// NewPassphrase is NewPassphraseContext without a context.
func (t *TTY) NewPassphrase(check func(passphrase []byte) string) ([]byte, error) {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.NewPassphraseContext(context.Background(), check)
}

// NewPassphraseContext asks for a new passphrase twice (§5.4). An empty
// passphrase or a mismatch asks again, up to three attempts; then it
// returns ErrMismatch. If check is not nil, it is called with the first
// entry and a non-empty result (e.g. a strength warning) is printed before
// the repetition is asked for; it warns, it doesn't refuse. It is
// ReadPairContext with passh's wording.
func (t *TTY) NewPassphraseContext(ctx context.Context, check func(passphrase []byte) string) ([]byte, error) {
	return t.ReadPairContext(ctx, Pair{
		First:    "New passphrase: ",
		Repeat:   "Repeat passphrase: ",
		Empty:    "The passphrase must not be empty.",
		Mismatch: "Passphrases don't match. Try again.",
		Check:    check,
	})
}

// Pair configures ReadPairContext.
type Pair struct {
	First, Repeat string // the two prompts
	// Empty is said when the first answer is empty, which is then asked
	// again. If Empty is "", an empty first answer is returned at once, as
	// an empty slice, without asking for the repetition.
	Empty string
	// Mismatch is said when the repetition differs; both are asked again.
	Mismatch string
	// Check, if not nil, gets the first answer; a non-empty result (a
	// warning) is said before the repetition is asked for.
	Check func(secret []byte) string
	// Attempts bounds the tries; values below 1 mean 3.
	Attempts int
}

// ReadPairContext reads a secret and its repetition with echo off, the
// whole exchange in one stay in raw mode: what is typed or pasted ahead,
// even between the two prompts, is never echoed. After Attempts
// mismatches it returns ErrMismatch. Editing keys, Ctrl-C, signals and ctx
// work as for ReadPassphraseContext. The caller wipes the result.
func (t *TTY) ReadPairContext(ctx context.Context, p Pair) ([]byte, error) {
	attempts := p.Attempts
	if attempts < 1 {
		attempts = 3
	}
	return t.readRaw(ctx, func(rs *rawSession) ([]byte, error) {
		read := func(prompt string) ([]byte, error) {
			if err := rs.prompt(prompt); err != nil {
				return nil, err
			}
			ed := &lineEditor{t: t, max: MaxPassphrase, what: "passphrase"}
			b, err := ed.readLine()
			if err != nil {
				return nil, err
			}
			return b, rs.newline()
		}
		for range attempts {
			p1, err := read(p.First)
			if err != nil {
				return nil, err
			}
			if len(p1) == 0 {
				if p.Empty == "" {
					return p1, nil
				}
				if err := rs.say(p.Empty); err != nil {
					return nil, err
				}
				continue
			}
			if p.Check != nil {
				if w := p.Check(p1); w != "" {
					if err := rs.say(w); err != nil {
						Wipe(p1)
						return nil, err
					}
				}
			}
			p2, err := read(p.Repeat)
			if err != nil {
				Wipe(p1)
				return nil, err
			}
			same := subtle.ConstantTimeCompare(p1, p2) == 1
			Wipe(p2)
			if same {
				return p1, nil
			}
			Wipe(p1)
			if err := rs.say(p.Mismatch); err != nil {
				return nil, err
			}
		}
		return nil, ErrMismatch
	})
}

// ReadLine is ReadLineContext without a context.
func (t *TTY) ReadLine(prompt string) (string, error) {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.ReadLineContext(context.Background(), prompt)
}

// ReadLineContext prints prompt and reads one line with echo on, without
// the line ending. It expects the terminal in its normal (cooked) mode.
// Ctrl-D on an empty line returns io.EOF. Signals and ctx work as for
// ReadPassphraseContext.
func (t *TTY) ReadLineContext(ctx context.Context, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	w := t.watch(ctx, nil) // before the prompt shows: a signal from then on ends it
	if _, err := t.f.WriteString(prompt); err != nil {
		w.stop()
		return "", err
	}
	line, err := t.readCooked()
	if err = readErr(ctx, w.stop(), err); err != nil {
		return "", err
	}
	return line, nil
}

// readCooked reads one line in cooked mode.
func (t *TTY) readCooked() (string, error) {
	var (
		line []byte
		key  [1]byte
	)
	for {
		n, err := t.f.Read(key[:])
		if n == 1 {
			if key[0] == '\n' {
				break
			}
			if len(line) == MaxLine {
				return "", fmt.Errorf("input line longer than %d bytes", MaxLine)
			}
			line = append(line, key[0])
			continue
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", io.EOF
			}
			break
		}
		return "", fmt.Errorf("reading from the terminal: %w", err)
	}
	return strings.TrimSuffix(string(line), "\r"), nil
}

// YesNo is YesNoContext without a context.
func (t *TTY) YesNo(prompt string, def bool) (bool, error) {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.YesNoContext(context.Background(), prompt, def)
}

// YesNoContext asks a yes/no question. An empty answer gives def. It
// accepts y, yes, n and no in any case and asks again on anything else, up
// to three times; then it returns ErrNotConfirmed. Signals and ctx work as
// for ReadLineContext.
func (t *TTY) YesNoContext(ctx context.Context, prompt string, def bool) (bool, error) {
	suffix := " [y/N] "
	if def {
		suffix = " [Y/n] "
	}
	for range 3 {
		ans, err := t.ReadLineContext(ctx, prompt+suffix)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		t.Printf("Please answer y or n.\n")
	}
	return false, ErrNotConfirmed
}

// Confirm is ConfirmContext without a context.
func (t *TTY) Confirm(phrase string) error {
	// exception CONC-2: kept for callers without a context; signals still
	// end the prompt.
	return t.ConfirmContext(context.Background(), phrase)
}

// ConfirmContext asks the user to type phrase (such as
// PhraseExportPlaintext) exactly, case included; surrounding spaces are
// ignored. Anything else returns an error wrapping ErrNotConfirmed. Signals
// and ctx work as for ReadLineContext.
func (t *TTY) ConfirmContext(ctx context.Context, phrase string) error {
	ans, err := t.ReadLineContext(ctx, "Type "+phrase+" to confirm: ")
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: no answer", ErrNotConfirmed)
		}
		return err
	}
	if strings.TrimSpace(ans) != phrase {
		return fmt.Errorf("%w: you didn't type %s", ErrNotConfirmed, phrase)
	}
	return nil
}

func name(f *os.File) string {
	if f == nil {
		return "<nil>"
	}
	return f.Name()
}
