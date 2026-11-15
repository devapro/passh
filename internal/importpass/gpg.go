package importpass

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devapro/passh/internal/exec"
)

// Limits on what one pass entry may be.
const (
	maxCiphertext = 1 << 20 // bytes of a .gpg file
	maxPlaintext  = 4 << 20 // bytes gpg may write for one entry
	maxStatus     = 1 << 20 // bytes of --status-fd output
)

// statusTimeout bounds the wait for the status pipe's end after gpg has
// exited, in case a process gpg started (such as gpg-agent) kept a copy of
// the pipe open.
const statusTimeout = 2 * time.Second

var (
	// ErrNoGPG: neither gpg2 nor gpg is in $PATH.
	ErrNoGPG = errors.New("gpg not found: import pass needs GnuPG (gpg) to decrypt the store")
	// ErrCanceled: the user canceled the passphrase prompt (pinentry). The
	// import stops, so that the prompt doesn't come back for every entry.
	ErrCanceled = errors.New("import canceled at the passphrase prompt")
)

// GPG configures the gpg program used to decrypt entries.
type GPG struct {
	// Program is the gpg command; empty means "gpg2" if it is in $PATH,
	// else "gpg", as pass does.
	Program string
	// Args are extra options placed before passh's own (tests use
	// "--homedir …", "--batch", "--pinentry-mode …").
	Args []string
	// TTY is the value of GPG_TTY for gpg and its pinentry, such as
	// /dev/pts/3. Empty leaves the environment alone: gpg inherits $GPG_TTY,
	// if set. The CLI fills it from its terminal (tty.DeviceName, §4.9):
	// gpg's stdin is a pipe here, so gpg can't find the terminal itself.
	TTY string
	// Stderr receives gpg's human-readable messages; nil discards them.
	// Nothing in them is used to judge success (S8).
	Stderr io.Writer
}

// gpgRunner decrypts one file at a time.
type gpgRunner struct {
	path   string
	args   []string
	env    []string
	stderr io.Writer
}

func newGPGRunner(g GPG) (*gpgRunner, error) {
	path, err := findGPG(g.Program)
	if err != nil {
		return nil, err
	}
	r := &gpgRunner{path: path, stderr: g.Stderr}
	// gpg reads the ciphertext from stdin (no path argument), writes the
	// plaintext to stdout and status lines to fd 3, the first extra file.
	// No --batch: it would be harmless for pinentry with gpg ≥ 2.1, but pass
	// doesn't use it with a modern gpg either.
	r.args = append(append([]string{}, g.Args...), "--quiet", "--status-fd", "3", "--decrypt")
	if g.TTY != "" {
		r.env = []string{"GPG_TTY=" + g.TTY}
	}
	return r, nil
}

func findGPG(name string) (string, error) {
	if name != "" {
		p, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("%w (%v)", ErrNoGPG, err)
		}
		return p, nil
	}
	for _, n := range []string{"gpg2", "gpg"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", ErrNoGPG
}

// capped is a buffer that refuses to grow past max.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

var errTooLarge = errors.New("output too large")

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		return 0, errTooLarge
	}
	return c.buf.Write(p)
}

// wipe zeroes the buffer's whole backing array (best effort).
func (c *capped) wipe() {
	b := c.buf.Bytes()
	clear(b[:cap(b)])
	c.buf.Reset()
}

// decrypt runs gpg on one ciphertext. It returns the plaintext, or a
// non-empty failure that skips this file, or an error that stops the import
// (ErrCanceled, a canceled ctx, gpg failing to start). Success is judged
// only from the exit status and the --status-fd lines: DECRYPTION_OKAY must
// be there and no failure status.
func (g *gpgRunner) decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, failure string, err error) {
	sr, sw, err := os.Pipe()
	if err != nil {
		return nil, "", fmt.Errorf("gpg: %w", err)
	}
	defer func() { _ = sr.Close() }() // read side; also closed by the timer below
	statusDone := make(chan []byte, 1)
	// The status reader ends at the pipe's end: when gpg and whatever it
	// started have closed the write side, or when the timer below closes sr.
	// decrypt waits for it.
	go func() {
		// Keep the first maxStatus bytes but read to the end, so gpg
		// never blocks on a full pipe.
		var st bytes.Buffer
		_, _ = io.Copy(&st, io.LimitReader(sr, maxStatus))
		_, _ = io.Copy(io.Discard, sr)
		statusDone <- st.Bytes()
	}()

	out := &capped{max: maxPlaintext}
	out.buf.Grow(len(ciphertext) + 4096) // avoid copies of the plaintext from regrowing
	runErr := exec.Run(ctx, exec.Command{
		Name:       g.path,
		Args:       g.args,
		Env:        g.env,
		Stdin:      bytes.NewReader(ciphertext),
		Stdout:     out,
		Stderr:     g.stderr,
		ExtraFiles: []*os.File{sw},
	})
	_ = sw.Close() // our copy of the write side; gpg has exited
	// A process gpg started (gpg-agent) may keep its copy of the write side
	// open: closing sr after statusTimeout ends the reader in any case.
	stopTimer := time.AfterFunc(statusTimeout, func() { _ = sr.Close() })
	st := parseStatus(<-statusDone)
	stopTimer.Stop()

	if err := ctx.Err(); err != nil {
		out.wipe()
		return nil, "", err
	}
	if st.canceled {
		out.wipe()
		return nil, "", ErrCanceled
	}
	var exitErr *exec.ExitError
	switch {
	case out.over:
		out.wipe()
		return nil, fmt.Sprintf("the decrypted entry is larger than %d MiB", maxPlaintext>>20), nil
	case runErr != nil && !errors.As(runErr, &exitErr):
		out.wipe()
		return nil, "", fmt.Errorf("gpg: %w", runErr)
	case runErr == nil && st.ok():
		return out.buf.Bytes(), "", nil
	}
	out.wipe()
	return nil, st.failure(exitErr), nil
}

// gpgStatus is what the --status-fd lines said.
type gpgStatus struct {
	okay      bool     // DECRYPTION_OKAY
	failures  []string // failure keywords, with their arguments
	noSecKey  []string // key ids from NO_SECKEY
	canceled  bool     // an ERROR or FAILURE with GPG_ERR_CANCELED
	badPass   bool     // BAD_PASSPHRASE
	missPass  bool     // MISSING_PASSPHRASE
	malformed bool     // NODATA, BADARMOR, UNEXPECTED
}

// failureKeywords are status keywords that make a decryption fail even if
// DECRYPTION_OKAY was also reported.
var failureKeywords = map[string]bool{
	"DECRYPTION_FAILED": true,
	"BADMDC":            true,
	"NODATA":            true,
	"BADARMOR":          true,
	"UNEXPECTED":        true,
	"ERROR":             true,
	"FAILURE":           true,
	"BAD_PASSPHRASE":    true,
}

// gpg-error codes for a canceled pinentry.
const (
	gpgErrCanceled      = 99
	gpgErrFullyCanceled = 198
)

func parseStatus(b []byte) gpgStatus {
	var st gpgStatus
	for line := range strings.SplitSeq(string(b), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "[GNUPG:] ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		kw := f[0]
		switch kw {
		case "DECRYPTION_OKAY":
			st.okay = true
		case "NO_SECKEY":
			if len(f) > 1 {
				st.noSecKey = append(st.noSecKey, f[1])
			}
		case "BAD_PASSPHRASE":
			st.badPass = true
		case "MISSING_PASSPHRASE":
			st.missPass = true
		case "NODATA", "BADARMOR", "UNEXPECTED":
			st.malformed = true
		case "ERROR", "FAILURE":
			// ERROR <location> <code> …, FAILURE <location> <code>
			if len(f) > 2 {
				if code, err := strconv.ParseUint(f[2], 10, 32); err == nil {
					if c := code & 0xffff; c == gpgErrCanceled || c == gpgErrFullyCanceled {
						st.canceled = true
					}
				}
			}
		}
		if failureKeywords[kw] {
			st.failures = append(st.failures, strings.Join(f, " "))
		}
	}
	return st
}

func (st gpgStatus) ok() bool { return st.okay && len(st.failures) == 0 }

// failure explains a failed decryption from the status lines.
func (st gpgStatus) failure(exitErr *exec.ExitError) string {
	switch {
	case len(st.noSecKey) > 0 && !st.okay:
		return "no secret key for key ID " + strings.Join(st.noSecKey, ", ")
	case st.badPass:
		return "bad passphrase"
	case st.missPass:
		return "no passphrase given"
	case st.malformed:
		return "not an OpenPGP message (damaged file?)"
	case len(st.failures) > 0:
		return "gpg reported " + strings.Join(st.failures, "; ")
	case exitErr != nil:
		return fmt.Sprintf("gpg failed (exit status %d)", exitErr.ExitCode())
	}
	return "gpg did not report a successful decryption"
}
