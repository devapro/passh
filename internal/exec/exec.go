// Package exec is the only place in passh that starts processes (S8).
//
// Rules:
//
//   - No shell, ever. A program is a name resolved with LookPath plus an
//     argument list that reaches it literally: spaces, quotes, `$(...)`, `;`
//     and globs mean nothing here.
//   - Callers put "--" before paths in the argument list where the program
//     supports it.
//   - The environment is inherited by default; Command.Env adds or overrides
//     variables (such as GPG_TTY). Secrets never go into arguments or the
//     environment (S2): a secret goes through stdin, a pipe or a file
//     descriptor.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"syscall"

	"github.com/devapro/passh/internal/i18n"
)

// ExitError is returned (wrapped) when a program exits with a non-zero
// status. Use errors.As to get it.
type ExitError = osexec.ExitError

// ErrDetachedIO is returned by StartDetached when a Command sets Stdin,
// Stdout or Stderr: a detached child gets the secret pipe and /dev/null.
var ErrDetachedIO = errors.New("exec: a detached command takes no Stdin, Stdout or Stderr")

// Command describes one program run.
type Command struct {
	// Name is the program: a name looked up in $PATH, or a path containing
	// a slash. It is never interpreted by a shell.
	Name string
	// Args are the arguments after the program name, passed literally.
	Args []string
	// Env holds "KEY=value" entries added to the environment. An entry
	// replaces an inherited variable with the same key.
	Env []string
	// CleanEnv starts from an empty environment instead of inheriting this
	// process's environment. Env is still added.
	CleanEnv bool
	// Dir is the working directory; empty means the current one (for
	// StartDetached, "/").
	Dir string

	// Stdin, Stdout and Stderr default to /dev/null when nil.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// ExtraFiles become file descriptors 3, 4, … in the child, e.g. for
	// `gpg --status-fd 3`.
	ExtraFiles []*os.File
}

// LookPath resolves a program name the way Command.Name is resolved: names
// without a slash are searched in $PATH; a result relative to the current
// directory (from "." in $PATH) is refused.
func LookPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("exec: empty program name")
	}
	p, err := osexec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("exec: %w", err)
	}
	return p, nil
}

// Self returns the path of the running passh binary, for re-executing it
// (e.g. to start the agent).
func Self() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", i18n.Errorf("exec: locating the passh binary: %w", err)
	}
	return p, nil
}

// Run starts c, waits for it, and returns an error (wrapping *ExitError) if
// it fails or exits with a non-zero status. Cancelling ctx kills the
// process.
func Run(ctx context.Context, c Command) error {
	cmd, err := c.build(ctx)
	if err != nil {
		return err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	if err := cmd.Run(); err != nil {
		return i18n.Errorf("%s: %w", c.Name, err)
	}
	return nil
}

// Output runs c and returns its standard output. c.Stdout must be nil.
func Output(ctx context.Context, c Command) ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Output with Stdout set")
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	if err := Run(ctx, c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// StartDetached starts c as a background process that outlives this one:
// in a new session (setsid, so it has no controlling terminal and doesn't
// get the terminal's SIGHUP), with its working directory at "/" unless
// c.Dir says otherwise, and with stdout and stderr on /dev/null. Its stdin
// is a pipe: StartDetached writes secret into it and closes it, so the child
// reads the secret and then EOF. The secret never appears in the child's
// arguments or environment. It is written before StartDetached returns, so
// it should fit in the pipe buffer (64 KiB on Linux, 16 KiB on macOS); a key
// does easily.
//
// The caller owns the returned process: call Wait to reap it, or Release
// when this process exits soon anyway (as `passh unlock` does).
func StartDetached(c Command, secret []byte) (*os.Process, error) {
	if c.Stdin != nil || c.Stdout != nil || c.Stderr != nil {
		return nil, ErrDetachedIO
	}
	// A context root (CONC-2): the child must outlive the caller and its
	// context, so nothing may kill it when that context ends.
	cmd, err := c.build(context.Background())
	if err != nil {
		return nil, err
	}
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	defer r.Close()
	cmd.Stdin = r // an *os.File: passed to the child directly, no copying goroutine
	// Stdout and Stderr stay nil: os/exec connects them to /dev/null.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		w.Close()
		return nil, i18n.Errorf("%s: %w", c.Name, err)
	}
	r.Close()
	_, werr := w.Write(secret)
	cerr := w.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, i18n.Errorf("%s: writing to the child's stdin: %w", c.Name, err)
	}
	return cmd.Process, nil
}

// build resolves the program and prepares an *osexec.Cmd with the
// arguments, environment, directory and extra files of c.
func (c Command) build(ctx context.Context) (*osexec.Cmd, error) {
	path, err := LookPath(c.Name)
	if err != nil {
		return nil, err
	}
	env, err := c.environ()
	if err != nil {
		return nil, err
	}
	cmd := osexec.CommandContext(ctx, path, c.Args...)
	cmd.Env = env
	cmd.Dir = c.Dir
	cmd.ExtraFiles = c.ExtraFiles
	return cmd, nil
}

// environ returns the child's environment: the inherited one (unless
// CleanEnv) with c.Env applied on top, last value winning.
func (c Command) environ() ([]string, error) {
	var base []string
	if !c.CleanEnv {
		base = os.Environ()
	}
	for _, kv := range c.Env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("exec: environment entry %q is not KEY=value", kv)
		}
	}
	out := make([]string, 0, len(base)+len(c.Env))
	seen := make(map[string]int, len(base)+len(c.Env))
	for _, kv := range append(base, c.Env...) {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := seen[k]; ok {
			out[i] = kv
			continue
		}
		seen[k] = len(out)
		out = append(out, kv)
	}
	return out, nil
}
