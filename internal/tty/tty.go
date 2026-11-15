// Package tty talks to the user on the controlling terminal (§5.1, §5.4,
// §7.1).
//
// Prompts are read from and written to /dev/tty, not stdin and stdout, so
// they work while stdout is piped (`passh show … | pbcopy`) and never mix
// with data. When there is no terminal, Open returns an error wrapping
// ErrNoTerminal, and callers fall back (§5.1 step 3) or require a flag such
// as --confirm-plaintext (§7.1).
//
// ReadPassphrase switches the terminal to raw mode, so echo is off and
// Ctrl-C arrives as a key instead of a signal: the prompt returns
// ErrInterrupted with the terminal restored, never leaving it without echo.
// The other prompts read a line in the terminal's normal (cooked) mode.
package tty

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

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
	// ErrInterrupted means the user pressed Ctrl-C at a passphrase prompt.
	ErrInterrupted = errors.New("interrupted")
	// ErrNotConfirmed means the user declined or didn't type the
	// confirmation phrase exactly.
	ErrNotConfirmed = errors.New("not confirmed")
	// ErrMismatch means the new passphrase and its repetition differed on
	// every attempt.
	ErrMismatch = errors.New("passphrases don't match")
)

// TTY is a terminal used for prompts.
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
	if !term.IsTerminal(int(f.Fd())) {
		f.Close()
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
// write data to a terminal (§7.1).
func IsTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

// File returns the terminal's file, e.g. to wire it to an editor.
func (t *TTY) File() *os.File { return t.f }

// Close closes the terminal if Open opened it.
func (t *TTY) Close() error {
	if t.owned {
		return t.f.Close()
	}
	return nil
}

// Write writes p to the terminal as is.
func (t *TTY) Write(p []byte) (int, error) { return t.f.Write(p) }

// Printf writes a formatted message to the terminal.
func (t *TTY) Printf(format string, args ...any) {
	fmt.Fprintf(t.f, format, args...)
}

// Wipe overwrites b with zeros. Callers wipe passphrases when done.
func Wipe(b []byte) {
	clear(b)
}

// ReadPassphrase prints prompt and reads a line with echo off. Backspace,
// Ctrl-U (erase the line) and Ctrl-W (erase a word) edit the input; Ctrl-C
// returns ErrInterrupted and Ctrl-D on an empty line returns io.EOF. The
// returned slice should be wiped by the caller.
func (t *TTY) ReadPassphrase(prompt string) ([]byte, error) {
	fd := int(t.f.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = term.Restore(fd, old)
			// Echo was off, so the user's Enter didn't move the cursor.
			_, _ = t.f.WriteString("\n")
		}
	}
	defer restore()

	// Raw mode turns off output processing: write CR LF ourselves.
	if _, err := t.f.WriteString(strings.ReplaceAll(prompt, "\n", "\r\n")); err != nil {
		return nil, err
	}

	buf := make([]byte, 0, MaxPassphrase)
	fail := func(err error) ([]byte, error) {
		Wipe(buf[:cap(buf)])
		return nil, err
	}
	var key [1]byte
	for {
		n, err := t.f.Read(key[:])
		if n == 0 {
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fail(io.EOF)
			}
			return fail(fmt.Errorf("reading the passphrase: %w", err))
		}
		switch c := key[0]; c {
		case '\r', '\n':
			return buf, nil
		case 0x03: // Ctrl-C
			return fail(ErrInterrupted)
		case 0x04: // Ctrl-D
			if len(buf) == 0 {
				return fail(io.EOF)
			}
		case 0x7f, 0x08: // Backspace
			buf = eraseRune(buf)
		case 0x15: // Ctrl-U
			clear(buf)
			buf = buf[:0]
		case 0x17: // Ctrl-W
			buf = eraseWord(buf)
		default:
			if c < 0x20 {
				continue // other control keys are ignored
			}
			if len(buf) == MaxPassphrase {
				return fail(fmt.Errorf("passphrase longer than %d bytes", MaxPassphrase))
			}
			buf = append(buf, c)
		}
	}
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

// NewPassphrase asks for a new passphrase twice (§5.4). An empty passphrase
// or a mismatch asks again, up to three attempts; then it returns
// ErrMismatch. If check is not nil, it is called with the first entry and a
// non-empty result (e.g. a strength warning) is printed before the
// repetition is asked for; it warns, it doesn't refuse.
func (t *TTY) NewPassphrase(check func(passphrase []byte) string) ([]byte, error) {
	const attempts = 3
	for i := 0; i < attempts; i++ {
		p1, err := t.ReadPassphrase("New passphrase: ")
		if err != nil {
			return nil, err
		}
		if len(p1) == 0 {
			t.Printf("The passphrase must not be empty.\n")
			continue
		}
		if check != nil {
			if w := check(p1); w != "" {
				t.Printf("%s\n", strings.TrimRight(w, "\n"))
			}
		}
		p2, err := t.ReadPassphrase("Repeat passphrase: ")
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
		t.Printf("Passphrases don't match. Try again.\n")
	}
	return nil, ErrMismatch
}

// ReadLine prints prompt and reads one line with echo on, without the line
// ending. It expects the terminal in its normal (cooked) mode. Ctrl-D on an
// empty line returns io.EOF.
func (t *TTY) ReadLine(prompt string) (string, error) {
	if _, err := t.f.WriteString(prompt); err != nil {
		return "", err
	}
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

// YesNo asks a yes/no question. An empty answer gives def. It accepts y,
// yes, n and no in any case and asks again on anything else, up to three
// times; then it returns ErrNotConfirmed.
func (t *TTY) YesNo(prompt string, def bool) (bool, error) {
	suffix := " [y/N] "
	if def {
		suffix = " [Y/n] "
	}
	for i := 0; i < 3; i++ {
		ans, err := t.ReadLine(prompt + suffix)
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

// Confirm asks the user to type phrase (such as PhraseExportPlaintext)
// exactly, case included; surrounding spaces are ignored. Anything else
// returns an error wrapping ErrNotConfirmed.
func (t *TTY) Confirm(phrase string) error {
	ans, err := t.ReadLine("Type " + phrase + " to confirm: ")
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
