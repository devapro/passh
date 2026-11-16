// Package harden applies the process-level protections of S7.
package harden

import (
	"golang.org/x/sys/unix"

	"github.com/devapro/passh/internal/i18n"
)

// DisableCoreDumps sets RLIMIT_CORE to 0 (soft and hard limit) for the
// current process, so a crash can't write decrypted secrets to a core file.
// It changes nothing system-wide. The hard limit is lowered too, so the
// process can't raise it again; child processes (an editor, gpg) inherit the
// limit, which keeps their memory out of core files as well.
func DisableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return i18n.Errorf("disabling core dumps: %w", err)
	}
	return nil
}

// CoreDumpsDisabled reports whether the current process's core file size
// limit is 0.
func CoreDumpsDisabled() (bool, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return false, i18n.Errorf("reading core dump limit: %w", err)
	}
	return lim.Cur == 0, nil
}
