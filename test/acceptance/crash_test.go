package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// leftovers lists the temporary files of interrupted saves (§4.6).
func leftovers(t *testing.T, e *env) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(e.vault), ".vault.passh.tmp-*"))
	return m
}

// crashState checks the vault after a killed save: it passes `verify`,
// decrypts at revision prev or prev+1, and has the new entry exactly when
// the revision moved. It returns the revision.
func crashState(t *testing.T, e *env, f *fixtureSet, prev int, newPath string) int {
	t.Helper()
	if r := e.run("verify"); r.code != 0 {
		t.Fatalf("after a killed save, verify fails: %s", r)
	}
	d := mustDecrypt(t, e.vault, f.key)
	_, has := d.entry(newPath)
	switch {
	case d.Revision == prev && !has:
	case d.Revision == prev+1 && has:
	default:
		t.Fatalf("after a killed save: revision %d (before %d), new entry present %v", d.Revision, prev, has)
	}
	return d.Revision
}

// startKillable starts passh (optionally under strace) without a terminal
// and returns the passh process and a wait function.
func startKillable(e *env, prefix []string, args ...string) (*exec.Cmd, func() error) {
	bin, all := passhBin, args
	if len(prefix) > 0 {
		bin, all = prefix[0], append(append(append([]string{}, prefix[1:]...), passhBin), args...)
	}
	cmd := exec.Command(bin, all...)
	cmd.Env = e.vars()
	cmd.Dir = e.root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	return cmd, cmd.Wait
}

// passhChild finds the passh process running args under root (the tracee
// when strace runs it).
func passhChild(root, arg string) int {
	for _, p := range passhProcs(root) {
		if bytes.Contains(p.cmdline, []byte(arg)) {
			return p.pid
		}
	}
	return 0
}

// §13.2.9: a save killed at any moment leaves a vault that opens at the old
// or the new revision; leftovers are removed by the next save.
func TestS9_KilledSaves(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	rev := f.popRev

	// How long one save takes.
	t0 := time.Now()
	e.ok("generate", "timing/one")
	dur := time.Since(t0)
	rev++

	var sawOld, sawNew, sawLeftover int
	// 1. Random moments over the whole run of `passh generate`.
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		p := fmt.Sprintf("crash/r%d", i)
		cmd, wait := startKillable(e, nil, "generate", p)
		time.Sleep(time.Duration(rnd.Int63n(int64(dur * 13 / 10))))
		_ = cmd.Process.Kill()
		_ = wait()
		if len(leftovers(t, e)) > 0 {
			sawLeftover++
		}
		nr := crashState(t, e, f, rev, p)
		if nr == rev {
			sawOld++
		} else {
			sawNew++
		}
		rev = nr
	}

	// 2. A sweep through every step of the save: strace stretches each
	// fsync, rename and unlink by 80 ms after it ran, and the kill moves
	// in 30 ms steps, so every "after step k" window is hit at least twice.
	if strace, err := exec.LookPath("strace"); err == nil {
		calls := "fsync,fdatasync,rename,renameat,renameat2,unlink,unlinkat"
		prefix := []string{strace, "-f", "-qq", "-o", "/dev/null", "-e", "trace=" + calls, "-e", "inject=fsync,fdatasync,rename,renameat,renameat2,unlink,unlinkat:delay_exit=80000"}
		// Learn the length of a stretched save.
		t0 := time.Now()
		cmd, wait := startKillable(e, prefix, "generate", "crash/sweep-timing")
		if err := wait(); err != nil {
			t.Fatalf("stretched save: %v", err)
		}
		_ = cmd
		total := time.Since(t0)
		t.Logf("a save stretched by strace takes %v", total)
		rev = crashState(t, e, f, rev, "crash/sweep-timing")
		for i, at := 0, 20*time.Millisecond; at < total+60*time.Millisecond; i, at = i+1, at+30*time.Millisecond {
			p := fmt.Sprintf("crash/s%d", i)
			_, wait := startKillable(e, prefix, "generate", p)
			start := time.Now()
			var pid int
			for pid == 0 && time.Since(start) < 2*time.Second {
				pid = passhChild(e.root, p)
				if pid == 0 {
					time.Sleep(2 * time.Millisecond)
				}
			}
			time.Sleep(time.Until(start.Add(at)))
			if pid != 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			_ = wait()
			if len(leftovers(t, e)) > 0 {
				sawLeftover++
			}
			nr := crashState(t, e, f, rev, p)
			if nr == rev {
				sawOld++
			} else {
				sawNew++
			}
			rev = nr
		}
	} else {
		t.Log("strace not installed: no step-by-step sweep")
	}
	t.Logf("killed saves: %d left the old revision, %d the new one, %d left a temporary file", sawOld, sawNew, sawLeftover)
	if sawOld == 0 || sawNew == 0 {
		t.Errorf("the kills didn't cover both outcomes (old %d, new %d): the test is too coarse", sawOld, sawNew)
	}

	// 3. Leftover temporary files are removed by the next save (plant one
	// if no kill left one).
	planted := filepath.Join(filepath.Dir(e.vault), ".vault.passh.tmp-planted1")
	writeFile(t, planted, []byte("leftover"), 0o600)
	r := e.ok("generate", "crash/final")
	if l := leftovers(t, e); len(l) > 0 {
		t.Errorf("temporary files left after the next save: %v", l)
	}
	if strings.Contains(r.stderr, "older than one seen") {
		t.Errorf("a killed save left a false rollback warning: %s", r.stderr)
	}
	// Backups are capped at backup.keep (default 10).
	bks, _ := filepath.Glob(filepath.Join(e.state, "backups", f.popData.VaultID, "*.passh"))
	if len(bks) > 10 {
		t.Errorf("%d automatic backups, keep = 10", len(bks))
	}
}

// §13.2.9: a vault changed on disk after it was opened is not overwritten.
func TestS9_ChangedOnDisk(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()

	// add opens the vault, then waits for input on the terminal.
	s := e.start(sessOpts{}, "add", "race/slow")
	s.expect("Password (empty to generate):")
	// Meanwhile another process saves a change.
	e.ok("generate", "race/fast")
	afterFast := readFile(t, e.vault)
	s.send("\r") // generate
	s.answer("Username:", "u")
	s.answer("URL:", "")
	s.answer("Tags (comma-separated):", "")
	s.expect("Notes")
	time.Sleep(20 * time.Millisecond)
	s.send("\r")
	r := s.wait()
	if r.code == 0 {
		t.Errorf("add saved over a vault that changed after it was opened: %s", r)
	}
	if !bytes.Equal(afterFast, readFile(t, e.vault)) {
		t.Errorf("the vault changed on disk was overwritten")
	}
	d := mustDecrypt(t, e.vault, f.key)
	if _, ok := d.entry("race/fast"); !ok {
		t.Errorf("the other process's change was lost")
	}
	t.Logf("the refused add says: %s", lastLines(r.term, 3))
	if !strings.Contains(strings.ToLower(r.term), "changed") {
		t.Errorf("the refusal doesn't say the vault changed: %s", r.term)
	}
}

// §13.2.9: of passh processes saving to the same vault at the same time,
// none loses a change silently: every one that reports success has its
// change in the vault, the others fail with a message.
func TestS9_ConcurrentWriters(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	const rounds, writers = 12, 4
	var okPaths []string
	refused := 0
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		res := make([]result, writers)
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				res[w] = e.run("generate", fmt.Sprintf("conc/r%d-w%d", r, w))
			}(w)
		}
		wg.Wait()
		for w, x := range res {
			p := fmt.Sprintf("conc/r%d-w%d", r, w)
			if x.code == 0 {
				okPaths = append(okPaths, p)
				continue
			}
			refused++
			if refused == 1 {
				t.Logf("a refused writer says: %s", strings.TrimSpace(x.stderr))
			}
			if strings.TrimSpace(x.stderr) == "" {
				t.Errorf("writer %s failed silently: %s", p, x)
			}
		}
	}
	d := mustDecrypt(t, e.vault, f.key)
	for _, p := range okPaths {
		if _, ok := d.entry(p); !ok {
			t.Errorf("%s reported success, but its change is lost", p)
		}
	}
	t.Logf("%d saves succeeded, %d were refused", len(okPaths), refused)
	if _, err := os.Stat(e.vault); err != nil {
		t.Fatal(err)
	}
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

// §4.6: if the vault path is a symlink, passh writes to its target and keeps
// the link.
func TestS9_SymlinkedVault(t *testing.T) {
	e, f := popEnv(t, "")
	target := filepath.Join(e.root, "real", "vault.passh")
	writeFile(t, target, readFile(t, e.vault), 0o600)
	if err := os.Remove(e.vault); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, e.vault); err != nil {
		t.Fatal(err)
	}
	e.unlock(fixPass)
	defer e.lock()
	e.ok("generate", "link/one")
	st, err := os.Lstat(e.vault)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the vault symlink was replaced by a file")
	}
	d := mustDecrypt(t, target, f.key)
	if _, ok := d.entry("link/one"); !ok || d.Revision != f.popRev+1 {
		t.Errorf("the link's target wasn't updated (revision %d)", d.Revision)
	}
}

// §4.2: unknown keys, at any level, are kept on save.
func TestS9_UnknownKeysKept(t *testing.T) {
	e, f := popEnv(t, "")
	orig := readFile(t, e.vault)
	_, plain, err := decryptVault(orig, f.key)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		t.Fatal(err)
	}
	m["future_top"] = map[string]any{"x": 1.0}
	ents := m["entries"].([]any)
	ents[0].(map[string]any)["future_entry"] = "kept"
	if fl, ok := ents[0].(map[string]any)["fields"].([]any); ok && len(fl) > 0 {
		fl[0].(map[string]any)["future_field"] = true
	}
	nb, _ := json.Marshal(m)
	writeFile(t, e.vault, spliceData(t, orig, encryptArmored(t, nb, f.key.Recipient())), 0o600)
	e.unlock(fixPass)
	defer e.lock()
	e.ok("generate", "unknown/one")
	_, after, err := decryptVault(readFile(t, e.vault), f.key)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"future_top"`, `"future_entry"`} {
		if !strings.Contains(string(after), want) {
			t.Errorf("unknown key %s dropped on save", want)
		}
	}
}
