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
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/harden"
	"github.com/devapro/passh/internal/i18n"
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
	numLevels
)

// name is the level as the report's first column shows it, in p's
// language. The doctor's column words have a context of their own: short
// words like "ok" or "agent" are translated elsewhere for other places.
func (l level) name(p i18n.Printer) string {
	switch l {
	case levelOK:
		return p.TC("doctor", "ok")
	case levelInfo:
		return p.TC("doctor", "info")
	case levelSkip:
		return p.TC("doctor", "skip")
	case levelWarn:
		return p.TC("doctor", "warn")
	case levelError:
		return p.TC("doctor", "error")
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// check names a group of findings: the report's second column.
type check int

const (
	chkConfig check = iota
	chkVault
	chkVaultMode
	chkVaultFolder
	chkTempFiles
	chkStateFolder
	chkAgent
	chkAgentFolder
	chkMemory
	chkSwap
	chkCoreDumps
	chkTerminal
	chkEditTemp
	chkClipboard
)

// name is the check's name in p's language.
func (c check) name(p i18n.Printer) string {
	switch c {
	case chkConfig:
		return p.TC("doctor", "config")
	case chkVault:
		return p.TC("doctor", "vault")
	case chkVaultMode:
		return p.TC("doctor", "vault mode")
	case chkVaultFolder:
		return p.TC("doctor", "vault folder")
	case chkTempFiles:
		return p.TC("doctor", "temp files")
	case chkStateFolder:
		return p.TC("doctor", "state folder")
	case chkAgent:
		return p.TC("doctor", "agent")
	case chkAgentFolder:
		return p.TC("doctor", "agent folder")
	case chkMemory:
		return p.TC("doctor", "memory")
	case chkSwap:
		return p.TC("doctor", "swap")
	case chkCoreDumps:
		return p.TC("doctor", "core dumps")
	case chkTerminal:
		return p.TC("doctor", "terminal")
	case chkEditTemp:
		return p.TC("doctor", "edit temp")
	case chkClipboard:
		return p.TC("doctor", "clipboard")
	}
	return fmt.Sprintf("check(%d)", int(c))
}

// finding is one line of the doctor's report.
type finding struct {
	level level
	what  check
	msg   string // in the user's language
}

// doctor collects findings. Every check is read-only: doctor reports and
// never fixes (§6.1).
type doctor struct {
	a *app
	// ctx is the command's context. A doctor lives for one run of the
	// command, so it keeps it (CONC-1) for the checks that wait: the
	// agent's status and the clipboard test.
	ctx      context.Context
	findings []finding
	cfg      *config.Config
	vault    string // the vault file, if known
}

// addf records a finding of the check what; the message is translated.
//
// i18n:wrapper
func (d *doctor) addf(l level, what check, format string, args ...any) {
	d.findings = append(d.findings, finding{level: l, what: what, msg: d.a.T(format, args...)})
}

// doctorCheck is one group of checks.
type doctorCheck func(d *doctor)

// clipboardTestWait is the longest doctor waits before clearing its test
// string; clipboard.clear_after if shorter.
const clipboardTestWait = 5 * time.Second

func (a *app) cmdDoctor() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: a.T("Check the config, the vault file, the state and agent folders, memory and swap"),
		Long: a.T("Read-only checks of everything passh depends on: the config file, the vault\n" +
			"file (structure, mode 0600, writable folder, leftover temporary files), the\n" +
			"state and agent folders, the agent, free memory for unlock (scrypt needs\n" +
			"256 MiB), swap, core dumps and the terminal. It reports, never fixes. The exit\n" +
			"status is 1 if a check found an error; warnings are advice."),
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := &doctor{a: a, ctx: cmd.Context()}
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

// report prints the findings in the user's language (a report for people,
// on stdout as data: OUT-1). The columns are as wide as their longest
// text in that language, counted in characters (fmt pads by runes).
func (d *doctor) report() error {
	p := d.a.p
	levelWidth := 0
	for l := range numLevels {
		levelWidth = max(levelWidth, utf8.RuneCountInString(l.name(p)))
	}
	width := 0
	for _, f := range d.findings {
		width = max(width, utf8.RuneCountInString(f.what.name(p)))
	}
	var b strings.Builder
	counts := map[level]int{}
	for _, f := range d.findings {
		counts[f.level]++
		fmt.Fprintf(&b, "%-*s  %-*s  %s\n", levelWidth, f.level.name(p), width, f.what.name(p), sanitize.Text(f.msg))
	}
	errs, warns := counts[levelError], counts[levelWarn]
	fmt.Fprintf(&b, "%s, %s.\n", p.N(errs, "%d error", "%d errors", errs), p.N(warns, "%d warning", "%d warnings", warns))
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
		d.addf(levelError, chkConfig, "%v", err)
		return
	}
	d.cfg = cfg
	switch {
	case cfg.Loaded:
		d.addf(levelOK, chkConfig, "%s", config.ContractHome(cfg.Location.Path))
	default:
		d.addf(levelInfo, chkConfig, "no config file at %s; using --vault and the defaults", config.ContractHome(cfg.Location.Path))
	}
	if cfg.VaultFromFlag && cfg.Loaded {
		d.addf(levelInfo, chkConfig, "--vault overrides the config's vault")
	}
}

func checkVaultFile(d *doctor) {
	if d.cfg == nil {
		d.addf(levelSkip, chkVault, "no config, so no vault to check")
		return
	}
	path := d.cfg.Vault
	show := config.ContractHome(path)
	lst, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		d.addf(levelError, chkVault, "%s doesn't exist: run `passh init`, or point the config's vault at your vault file", show)
		return
	}
	if err != nil {
		d.addf(levelError, chkVault, "%s: %v", show, err)
		return
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			d.addf(levelError, chkVault, "%s is a symlink that can't be resolved: %v", show, err)
			return
		}
		d.addf(levelInfo, chkVault, "%s is a symlink to %s; saves write the target", show, config.ContractHome(target))
	}
	data, err := readVaultBytes(path)
	if err != nil {
		d.addf(levelError, chkVault, "%s: %v", show, err)
		return
	}
	d.vault = path
	info, err := vaultfile.Check(data)
	if err != nil {
		d.addf(levelError, chkVault, "%s: %v (SHA-256 %s)", show, err, info.SHA256)
	} else {
		size := int(min(info.Size, maxVaultSize)) // readVaultBytes read at most maxVaultSize
		d.addf(levelOK, chkVault, "%s", d.a.p.N(size, "%s: structure OK, %d bytes", "%s: structure OK, %d bytes", show, size))
		for _, w := range info.Warnings {
			d.addf(levelInfo, chkVault, "%s", w)
		}
		if !info.Canonical {
			d.addf(levelInfo, chkVault, "not in canonical form (line endings or wrapping changed); it opens, and the next save rewrites it")
		}
	}

	st, err := os.Stat(path)
	if err == nil {
		if perm := st.Mode().Perm(); perm != 0o600 {
			l := levelWarn
			if perm&0o077 == 0 {
				l = levelInfo
			}
			d.addf(l, chkVaultMode, "mode %04o, not 0600: fix it with chmod 600 %s", perm, show)
		} else {
			d.addf(levelOK, chkVaultMode, "0600")
		}
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		real = path
	}
	dir := filepath.Dir(real)
	if err := unix.Access(dir, unix.W_OK|unix.X_OK); err != nil {
		d.addf(levelError, chkVaultFolder, "%s isn't writable (%v): saving needs a temporary file there", config.ContractHome(dir), err)
	} else {
		d.addf(levelOK, chkVaultFolder, "%s is writable", config.ContractHome(dir))
	}
	temps, err := vault.TempFiles(path)
	switch {
	case err != nil:
		d.addf(levelWarn, chkTempFiles, "can't list the vault's folder: %v", err)
	case len(temps) > 0:
		names := make([]string, len(temps))
		for i, t := range temps {
			names[i] = filepath.Base(t)
		}
		d.addf(levelWarn, chkTempFiles, "%s", d.a.p.N(len(temps),
			"%d file left by an interrupted save (%s); the next save removes them",
			"%d files left by an interrupted save (%s); the next save removes them",
			len(temps), strings.Join(names, ", ")))
	default:
		d.addf(levelOK, chkTempFiles, "none")
	}
}

func checkStateDir(d *doctor) {
	dir, err := config.StateDir()
	if err != nil {
		d.addf(levelError, chkStateFolder, "%v", err)
		return
	}
	show := config.ContractHome(dir)
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		d.addf(levelInfo, chkStateFolder, "%s doesn't exist yet; the first save creates it", show)
		return
	case err != nil:
		d.addf(levelError, chkStateFolder, "%s: %v", show, err)
		return
	case !st.IsDir():
		d.addf(levelError, chkStateFolder, "%s is not a folder (backups, locks and the agent's socket go there)", show)
		return
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		d.addf(levelError, chkStateFolder, "%s belongs to uid %d, not to you", show, sys.Uid)
		return
	}
	if err := unix.Access(dir, unix.W_OK|unix.X_OK); err != nil {
		d.addf(levelError, chkStateFolder, "%s isn't writable: %v", show, err)
		return
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		d.addf(levelWarn, chkStateFolder, "%s has mode %04o: other users can look inside (the backups are encrypted); chmod 700 is better", show, perm)
		return
	}
	d.addf(levelOK, chkStateFolder, "%s", show)
}

func checkAgent(d *doctor) {
	if d.vault == "" {
		d.addf(levelSkip, chkAgent, "no vault to check the agent for")
		return
	}
	sock, err := agent.SocketPath(d.vault)
	if err != nil {
		d.addf(levelError, chkAgentFolder, "%v", err)
		return
	}
	dir := filepath.Dir(sock)
	show := config.ContractHome(dir)
	if err := config.CheckAgentDir(dir); errors.Is(err, fs.ErrNotExist) {
		d.addf(levelInfo, chkAgentFolder, "%s doesn't exist yet; `passh unlock` creates it", show)
	} else if err != nil {
		d.addf(levelError, chkAgentFolder, "%v", err)
		return
	} else {
		d.addf(levelOK, chkAgentFolder, "%s (0700, yours)", show)
	}
	c, err := agent.NewClient(d.vault)
	if err != nil {
		d.addf(levelError, chkAgent, "%v", err)
		return
	}
	st, err := c.Status(d.ctx)
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		d.addf(levelInfo, chkAgent, "not running (`passh unlock` starts it)")
	case err != nil:
		d.addf(levelError, chkAgent, "%v", err)
	default:
		d.addf(levelInfo, chkAgent, "running: %s", d.a.agentTimes(st))
	}
}

func checkMemory(d *doctor) {
	l, msg := memoryCheck(d.a.p)
	d.addf(l, chkMemory, "%s", msg)
}

func checkSwap(d *doctor) {
	l, msg := swapCheck(d.a.p)
	d.addf(l, chkSwap, "%s", msg)
}

func checkCoreDumps(d *doctor) {
	off, err := harden.CoreDumpsDisabled()
	switch {
	case err != nil:
		d.addf(levelWarn, chkCoreDumps, "%v", err)
	case off:
		d.addf(levelOK, chkCoreDumps, "disabled for passh and the agent")
	default:
		d.addf(levelWarn, chkCoreDumps, "not disabled: a crash could write secrets to a core file")
	}
}

func checkTerminal(d *doctor) {
	if _, err := d.a.tty(); err != nil {
		d.addf(levelInfo, chkTerminal, "none: prompts are impossible, so commands need the agent (`passh unlock` in a terminal)")
		return
	}
	d.addf(levelOK, chkTerminal, "/dev/tty: passphrase prompts work")
}

// checkEditLeftovers looks for temporary folders an interrupted
// `edit --editor` left on tmpfs (they may hold an entry in plain text).
func checkEditLeftovers(d *doctor) {
	left := editor.Leftovers()
	if len(left) == 0 {
		d.addf(levelOK, chkEditTemp, "no files left by an interrupted `edit --editor`")
		return
	}
	shown := make([]string, len(left))
	for i, l := range left {
		shown[i] = config.ContractHome(l)
	}
	d.addf(levelWarn, chkEditTemp, "left by an interrupted `edit --editor`, possibly with an entry in plain text: %s; delete them (rm -r)",
		strings.Join(shown, ", "))
}

// checkClipboard sends a test string to the clipboard and clears it again
// (§6.3), so the user can paste to check that copying works. It needs a
// terminal: OSC 52 goes through it, and the user is told what to paste.
func checkClipboard(d *doctor) {
	if d.cfg == nil {
		d.addf(levelSkip, chkClipboard, "no config, so no clipboard settings to check")
		return
	}
	t, err := d.a.tty()
	if err != nil {
		d.addf(levelSkip, chkClipboard, "not tested without a terminal: run `passh doctor` in one (over SSH: ssh -t)")
		return
	}
	for _, n := range clipboard.EnvironmentNotes(os.Getenv) {
		// The notes are keys marked in internal/clipboard.
		d.addf(levelInfo, chkClipboard, n) // i18n:dynamic
	}
	cb, err := d.a.clipboard(d.cfg)
	if errors.Is(err, clipboard.ErrNoClipboard) {
		d.addf(levelWarn, chkClipboard, "%v", err)
		return
	}
	if err != nil {
		d.addf(levelError, chkClipboard, "%v", err)
		return
	}
	wait := min(d.cfg.Clipboard.ClearAfter, clipboardTestWait)
	d.a.termf(t, "Testing the clipboard: copied %q (%s). Paste it somewhere to check; it is cleared in %s.\n",
		clipboard.TestString, cb, fmtDuration(wait))
	err = cb.Test(d.ctx, wait)
	switch {
	case clipboardCleared(err) && cb.Method() == clipboard.MethodCommand:
		// One message per method, so that each language can build its own
		// sentence (the method's name doesn't drop into another one). The
		// command is the configured one, as cb shows it.
		d.addf(levelOK, chkClipboard, "sent a test string with command %q and cleared it; if pasting gave %q, copying works",
			sanitize.Line(strings.Join(d.cfg.Clipboard.Command, " ")), clipboard.TestString)
	case clipboardCleared(err):
		d.addf(levelOK, chkClipboard, "sent a test string with OSC 52 through the terminal and cleared it; if pasting gave %q, copying works",
			clipboard.TestString)
	default:
		d.addf(levelError, chkClipboard, "%v", err)
	}
}

// formatBytes writes n bytes for people: "512 MiB", "1.5 GiB". The binary
// unit symbols are the same in every language; "bytes" is translated.
func formatBytes(p i18n.Printer, n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	small := int(n) // n < 1 KiB here
	return p.N(small, "%d byte", "%d bytes", small)
}

// memoryVerdict judges memory against what scrypt needs, in p's language:
// the memory available to a new process (Linux), or in total, where
// available memory can't be measured (macOS).
func memoryVerdict(p i18n.Printer, n uint64, total bool) (level, string) {
	size := formatBytes(p, n)
	switch {
	case n < scryptMemory && total:
		return levelWarn, p.T("%s in total: unlock needs 256 MiB for scrypt and may fail or swap; available memory isn't checked on macOS", size)
	case n < scryptMemory:
		return levelWarn, p.T("%s available: unlock needs 256 MiB for scrypt and may fail or swap", size)
	case total:
		return levelOK, p.T("%s in total (unlock needs 256 MiB); available memory isn't checked on macOS", size)
	}
	return levelOK, p.T("%s available (unlock needs 256 MiB)", size)
}
