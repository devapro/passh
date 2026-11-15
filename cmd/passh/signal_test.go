package main

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// echo reports whether the session's terminal echoes input, read on the
// master side (on Linux its termios calls reach the slave). SyscallConn,
// not Fd: Fd would put the master into blocking mode.
func (s *session) echo() bool {
	s.t.Helper()
	rc, err := s.ptm.SyscallConn()
	if err != nil {
		s.t.Fatal(err)
	}
	var (
		tio  *unix.Termios
		ierr error
	)
	if err := rc.Control(func(fd uintptr) { tio, ierr = unix.IoctlGetTermios(int(fd), ioctlGetTermios) }); err != nil || ierr != nil {
		s.t.Fatal(err, ierr)
	}
	return tio.Lflag&unix.ECHO != 0
}

// waitEcho waits until the terminal's echo is on or off.
func (s *session) waitEcho(on bool) {
	s.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for s.echo() != on {
		if time.Now().After(deadline) {
			s.t.Fatalf("passh %v: echo still %v; terminal:\n%s", s.args, !on, s.output())
		}
		time.Sleep(5 * time.Millisecond) // polling, with the deadline above
	}
}

// TestSignalAtPrompt (CLI-004, OUT-6): SIGTERM or SIGHUP while passh waits
// at the passphrase prompt (echo off) leaves the terminal with its echo
// back on, and passh exits with 128 + the signal's number.
func TestSignalAtPrompt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT} {
		s := e.start(sessOpts{}, "ls")
		s.expect("Passphrase:")
		s.waitEcho(false) // raw mode
		s.send("half typed")
		if err := s.cmd.Process.Signal(sig); err != nil {
			t.Fatal(err)
		}
		r := s.wait()
		if r.code != 128+int(sig) || !strings.Contains(r.out, "interrupted ("+sig.String()+")") {
			t.Errorf("%v at the prompt: %s", sig, r)
		}
		if !s.echo() {
			t.Errorf("%v at the prompt left the terminal without echo", sig)
		}
		mustNotContain(t, sig.String(), r.out, "half typed")
	}
}
