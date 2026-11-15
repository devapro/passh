package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/harden"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/vault"
	"github.com/devapro/passh/internal/vaultfile"
)

// scryptMemory is what scrypt needs to unlock a vault: N = 2^18, r = 8
// gives 128 · r · N bytes (§5.1).
const scryptMemory = 256 << 20

// Check levels, worst last.
type level int

const (
	levelOK level = iota
	levelInfo
	levelSkip
	levelWarn
	levelError
)

var levelNames = [...]string{"ok", "info", "skip", "warn", "error"}

// finding is one line of the doctor's report.
type finding struct {
	level level
	what  string
	msg   string
}

// doctor collects findings. Every check is read-only: doctor reports and
// never fixes (§6.1).
type doctor struct {
	a        *app
	findings []finding
	cfg      *config.Config
	vault    string // the vault file, if known
}

func (d *doctor) add(l level, what, format string, args ...any) {
	d.findings = append(d.findings, finding{level: l, what: what, msg: fmt.Sprintf(format, args...)})
}

// doctorCheck is one group of checks.
type doctorCheck func(d *doctor)

// clipboardTestWait is the longest doctor waits before clearing its test
// string; clipboard.clear_after if shorter.
const clipboardTestWait = 5 * time.Second

func (a *app) cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the config, the vault file, the state and agent folders, memory and swap",
		Long: "Read-only checks of everything passh depends on: the config file, the vault\n" +
			"file (structure, mode 0600, writable folder, leftover temporary files), the\n" +
			"state and agent folders, the agent, free memory for unlock (scrypt needs\n" +
			"256 MiB), swap, core dumps and the terminal. It reports, never fixes. The exit\n" +
			"status is 1 if a check found an error; warnings are advice.",
		Args: noArgs(),
		RunE: func(_ *cobra.Command, _ []string) error {
			d := &doctor{a: a}
			checks := []doctorCheck{
				checkConfig,
				checkVaultFile,
				checkStateDir,
				checkAgent,
				checkMemory,
				checkSwap,
				checkCoreDumps,
				checkTerminal,
				checkEditLeftovers,
				checkClipboard,
			}
			for _, c := range checks {
				c(d)
			}
			return d.report()
		},
	}
}

func (d *doctor) report() error {
	width := 0
	for _, f := range d.findings {
		width = max(width, len(f.what))
	}
	var b strings.Builder
	counts := map[level]int{}
	for _, f := range d.findings {
		counts[f.level]++
		fmt.Fprintf(&b, "%-5s  %-*s  %s\n", levelNames[f.level], width, f.what, sanitize.Text(f.msg))
	}
	fmt.Fprintf(&b, "%s, %s.\n", plural(counts[levelError], "error", "errors"), plural(counts[levelWarn], "warning", "warnings"))
	if err := writeAll(d.a.stdout, b.String()); err != nil {
		return err
	}
	if counts[levelError] > 0 {
		return errReported
	}
	return nil
}

func checkConfig(d *doctor) {
	a := d.a
	cfg, err := config.Resolve(a.configFlag, a.vaultFlag)
	if err != nil {
		d.add(levelError, "config", "%v", err)
		return
	}
	d.cfg = cfg
	switch {
	case cfg.Loaded:
		d.add(levelOK, "config", "%s", config.ContractHome(cfg.Location.Path))
	default:
		d.add(levelInfo, "config", "no config file at %s; using --vault and the defaults", config.ContractHome(cfg.Location.Path))
	}
	if cfg.VaultFromFlag && cfg.Loaded {
		d.add(levelInfo, "config", "--vault overrides the config's vault")
	}
}

func checkVaultFile(d *doctor) {
	if d.cfg == nil {
		d.add(levelSkip, "vault", "no config, so no vault to check")
		return
	}
	path := d.cfg.Vault
	show := config.ContractHome(path)
	lst, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		d.add(levelError, "vault", "%s doesn't exist: run `passh init`, or point the config's vault at your vault file", show)
		return
	}
	if err != nil {
		d.add(levelError, "vault", "%s: %v", show, err)
		return
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			d.add(levelError, "vault", "%s is a symlink that can't be resolved: %v", show, err)
			return
		}
		d.add(levelInfo, "vault", "%s is a symlink to %s; saves write the target", show, config.ContractHome(target))
	}
	data, err := readVaultBytes(path)
	if err != nil {
		d.add(levelError, "vault", "%s: %v", show, err)
		return
	}
	d.vault = path
	info, err := vaultfile.Check(data)
	if err != nil {
		d.add(levelError, "vault", "%s: %v (SHA-256 %s)", show, err, info.SHA256)
	} else {
		d.add(levelOK, "vault", "%s: structure OK, %d bytes", show, info.Size)
		for _, w := range info.Warnings {
			d.add(levelInfo, "vault", "%s", w)
		}
		if !info.Canonical {
			d.add(levelInfo, "vault", "not in canonical form (line endings or wrapping changed); it opens, and the next save rewrites it")
		}
	}

	st, err := os.Stat(path)
	if err == nil {
		if perm := st.Mode().Perm(); perm != 0o600 {
			l := levelWarn
			msg := "mode %04o, not 0600: fix it with chmod 600 %s"
			if perm&0o077 == 0 {
				l = levelInfo
			}
			d.add(l, "vault mode", msg, perm, show)
		} else {
			d.add(levelOK, "vault mode", "0600")
		}
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		real = path
	}
	dir := filepath.Dir(real)
	if err := unix.Access(dir, unix.W_OK|unix.X_OK); err != nil {
		d.add(levelError, "vault folder", "%s isn't writable (%v): saving needs a temporary file there", config.ContractHome(dir), err)
	} else {
		d.add(levelOK, "vault folder", "%s is writable", config.ContractHome(dir))
	}
	temps, err := vault.TempFiles(path)
	switch {
	case err != nil:
		d.add(levelWarn, "temp files", "can't list the vault's folder: %v", err)
	case len(temps) > 0:
		names := make([]string, len(temps))
		for i, t := range temps {
			names[i] = filepath.Base(t)
		}
		d.add(levelWarn, "temp files", "%s left by an interrupted save (%s); the next save removes them",
			plural(len(temps), "file", "files"), strings.Join(names, ", "))
	default:
		d.add(levelOK, "temp files", "none")
	}
}

func checkStateDir(d *doctor) {
	dir, err := config.StateDir()
	if err != nil {
		d.add(levelError, "state folder", "%v", err)
		return
	}
	show := config.ContractHome(dir)
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		d.add(levelInfo, "state folder", "%s doesn't exist yet; the first save creates it", show)
		return
	case err != nil:
		d.add(levelError, "state folder", "%s: %v", show, err)
		return
	case !st.IsDir():
		d.add(levelError, "state folder", "%s is not a folder (backups, locks and the agent's socket go there)", show)
		return
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		d.add(levelError, "state folder", "%s belongs to uid %d, not to you", show, sys.Uid)
		return
	}
	if err := unix.Access(dir, unix.W_OK|unix.X_OK); err != nil {
		d.add(levelError, "state folder", "%s isn't writable: %v", show, err)
		return
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		d.add(levelWarn, "state folder", "%s has mode %04o: other users can look inside (the backups are encrypted); chmod 700 is better", show, perm)
		return
	}
	d.add(levelOK, "state folder", "%s", show)
}

func checkAgent(d *doctor) {
	if d.vault == "" {
		d.add(levelSkip, "agent", "no vault to check the agent for")
		return
	}
	sock, err := agent.SocketPath(d.vault)
	if err != nil {
		d.add(levelError, "agent folder", "%v", err)
		return
	}
	dir := filepath.Dir(sock)
	show := config.ContractHome(dir)
	if err := config.CheckAgentDir(dir); errors.Is(err, fs.ErrNotExist) {
		d.add(levelInfo, "agent folder", "%s doesn't exist yet; `passh unlock` creates it", show)
	} else if err != nil {
		d.add(levelError, "agent folder", "%v", err)
		return
	} else {
		d.add(levelOK, "agent folder", "%s (0700, yours)", show)
	}
	c, err := agent.NewClient(d.vault)
	if err != nil {
		d.add(levelError, "agent", "%v", err)
		return
	}
	st, err := c.Status(context.Background())
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		d.add(levelInfo, "agent", "not running (`passh unlock` starts it)")
	case err != nil:
		d.add(levelError, "agent", "%v", err)
	default:
		d.add(levelInfo, "agent", "running: %s", agentTimes(st))
	}
}

func checkMemory(d *doctor) {
	l, msg := memoryCheck()
	d.add(l, "memory", "%s", msg)
}

func checkSwap(d *doctor) {
	l, msg := swapCheck()
	d.add(l, "swap", "%s", msg)
}

func checkCoreDumps(d *doctor) {
	off, err := harden.CoreDumpsDisabled()
	switch {
	case err != nil:
		d.add(levelWarn, "core dumps", "%v", err)
	case off:
		d.add(levelOK, "core dumps", "disabled for passh and the agent")
	default:
		d.add(levelWarn, "core dumps", "not disabled: a crash could write secrets to a core file")
	}
}

func checkTerminal(d *doctor) {
	if _, err := d.a.tty(); err != nil {
		d.add(levelInfo, "terminal", "none: prompts are impossible, so commands need the agent (`passh unlock` in a terminal)")
		return
	}
	d.add(levelOK, "terminal", "/dev/tty: passphrase prompts work")
}

// checkEditLeftovers looks for temporary folders an interrupted
// `edit --editor` left on tmpfs (they may hold an entry in plain text).
func checkEditLeftovers(d *doctor) {
	left := editor.Leftovers()
	if len(left) == 0 {
		d.add(levelOK, "edit temp", "no files left by an interrupted `edit --editor`")
		return
	}
	shown := make([]string, len(left))
	for i, l := range left {
		shown[i] = config.ContractHome(l)
	}
	d.add(levelWarn, "edit temp", "left by an interrupted `edit --editor`, possibly with an entry in plain text: %s; delete them (rm -r)",
		strings.Join(shown, ", "))
}

// checkClipboard sends a test string to the clipboard and clears it again
// (§6.3), so the user can paste to check that copying works. It needs a
// terminal: OSC 52 goes through it, and the user is told what to paste.
func checkClipboard(d *doctor) {
	if d.cfg == nil {
		d.add(levelSkip, "clipboard", "no config, so no clipboard settings to check")
		return
	}
	t, err := d.a.tty()
	if err != nil {
		d.add(levelSkip, "clipboard", "not tested without a terminal: run `passh doctor` in one (over SSH: ssh -t)")
		return
	}
	for _, n := range clipboard.EnvironmentNotes(os.Getenv) {
		d.add(levelInfo, "clipboard", "%s", n)
	}
	cb, err := d.a.clipboard(d.cfg)
	if errors.Is(err, clipboard.ErrNoClipboard) {
		d.add(levelWarn, "clipboard", "%v", err)
		return
	}
	if err != nil {
		d.add(levelError, "clipboard", "%v", err)
		return
	}
	wait := min(d.cfg.Clipboard.ClearAfter, clipboardTestWait)
	t.Printf("Testing the clipboard: copied %q (%s). Paste it somewhere to check; it is cleared in %s.\n",
		clipboard.TestString, cb, fmtDuration(wait))
	err = cb.Test(context.Background(), wait)
	switch {
	case err == nil, errors.Is(err, clipboard.ErrInterrupted) && !strings.Contains(err.Error(), "failed"):
		d.add(levelOK, "clipboard", "sent a test string with %s and cleared it; if pasting gave %q, copying works", cb, clipboard.TestString)
	default:
		d.add(levelError, "clipboard", "%v", err)
	}
}

// formatBytes writes n bytes for people: "512 MiB", "1.5 GiB".
func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// memoryVerdict judges available memory against what scrypt needs.
func memoryVerdict(avail uint64, what string) (level, string) {
	if avail < scryptMemory {
		return levelWarn, fmt.Sprintf("%s %s: unlock needs 256 MiB for scrypt and may fail or swap", formatBytes(avail), what)
	}
	return levelOK, fmt.Sprintf("%s %s (unlock needs 256 MiB)", formatBytes(avail), what)
}
