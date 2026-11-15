package acceptance

import (
	"strings"
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
		s.t.Fatalf("%s: reading the terminal mode: %v %v", s.name, err, ierr)
	}
	return tio.Lflag&unix.ECHO != 0
}

// waitEchoOff waits until the program has switched the terminal to raw
// mode (echo off) for a passphrase, so what is typed next is never echoed
// (CORE-004: a state, not a fixed sleep).
func (s *session) waitEchoOff() {
	s.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for s.echo() {
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: the terminal still echoes at a passphrase prompt; terminal:\n%s", s.name, s.output())
		}
		time.Sleep(2 * time.Millisecond) // polling, with the deadline above
	}
}

// typeSecret types a passphrase at a prompt that was just shown.
func (s *session) typeSecret(text string) {
	s.t.Helper()
	s.waitEchoOff()
	s.send(text + "\r")
}

// secretPrompt reports whether prompt asks for a passphrase or password,
// which passh reads with echo off.
func secretPrompt(prompt string) bool {
	p := strings.ToLower(prompt)
	return strings.Contains(p, "passphrase") || strings.Contains(p, "password")
}

// waitUntil polls cond until it holds, and fails the test after d.
func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond) // polling, with the deadline above
	}
}
