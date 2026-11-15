package acceptance

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// §13.2.5: plaintext export without confirmation fails; with confirmation
// the data holds no prompt text; export data is never written to a
// terminal.
func TestS5_ExportConfirmation(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	out := filepath.Join(e.root, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	promptWords := []string{"EXPORT PLAINTEXT", "Type ", "confirm", "unencrypted", "passh:", "warning"}

	// No terminal, no --confirm-plaintext: refused, nothing written.
	for _, format := range []string{"csv", "json", "bitwarden-json"} {
		r := e.run("export", "--format", format)
		if r.code == 0 || r.stdout != "" {
			t.Errorf("export %s without confirmation and without a terminal: want refusal and no data, got %s", format, r)
		}
		mustContain(t, "refusal hint", r.stderr, "--confirm-plaintext")
		p := filepath.Join(out, "noconfirm."+format)
		if r := e.run("export", "--format", format, "-o", p); r.code == 0 {
			t.Errorf("export -o without confirmation succeeded")
		}
		if _, err := os.Stat(p); err == nil {
			t.Errorf("export without confirmation created %s", p)
		}
	}

	// With --confirm-plaintext (no terminal): the data has no prompt text.
	r := e.ok("export", "--format", "csv", "--confirm-plaintext")
	mustNotContain(t, "confirmed CSV export", r.stdout, promptWords...)
	parseCSV(t, r.stdout)

	// A terminal: a wrong phrase refuses; stdout stays empty.
	s := e.start(sessOpts{pipeStdout: true}, "export", "--format", "csv")
	s.answer("to confirm:", "export plaintext")
	if r := s.wait(); r.code == 0 || r.stdout != "" {
		t.Errorf("wrong confirmation phrase: want refusal and no data, got %s", r)
	}
	// The right phrase: stdout is exactly the data.
	s = e.start(sessOpts{pipeStdout: true}, "export", "--format", "bitwarden-json")
	s.answer("to confirm:", "EXPORT PLAINTEXT")
	r = s.waitOK()
	mustNotContain(t, "export confirmed on the terminal", r.stdout, promptWords...)
	checkBitwarden(t, []byte(r.stdout), f.popData)
	mustNotContain(t, "terminal during export", r.term, "s3cr3t-P@ss")

	// stdout on the terminal: refused, with or without confirmation; no
	// value reaches the terminal.
	for _, args := range [][]string{
		{"export", "--format", "csv", "--confirm-plaintext"},
		{"export", "--format", "csv"},
		{"export", "--format", "json", "--age", f.recip},
	} {
		s := e.start(sessOpts{}, args...)
		if s.expectWithin("to confirm:", 3*time.Second) {
			s.send("EXPORT PLAINTEXT\r")
		}
		r := s.wait()
		if r.code == 0 {
			t.Errorf("%v with stdout on a terminal succeeded", args)
		}
		mustNotContain(t, "terminal", r.term, "s3cr3t-P@ss", "arsenii", "github.com")
	}

	// -o on a terminal after confirmation: a 0600 file, nothing on screen.
	p := filepath.Join(out, "plain.json")
	s = e.start(sessOpts{}, "export", "--format", "json", "-o", p)
	s.answer("to confirm:", "EXPORT PLAINTEXT")
	r = s.waitOK()
	mustNotContain(t, "terminal with -o", r.term, "s3cr3t-P@ss")
	if m := perm(t, p); m != 0o600 {
		t.Errorf("export -o mode %o, want 0600", m)
	}
	var sfs syscall.Statfs_t
	if err := syscall.Statfs(out, &sfs); err == nil && sfs.Type != 0x01021994 { // not tmpfs
		mustContain(t, "plaintext export to persistent disk (§7.1)", r.term, "tmpfs")
	}
	mustNotContain(t, "export file", string(readFile(t, p)), promptWords...)
	// An existing file is not overwritten.
	before := readFile(t, p)
	if r := e.run("export", "--format", "csv", "--confirm-plaintext", "-o", p); r.code == 0 || !bytes.Equal(before, readFile(t, p)) {
		t.Errorf("export -o overwrote an existing file: %s", r)
	}

	// --age: no confirmation needed; only the identity reads it.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r = e.ok("export", "--format", "csv", "--age", id.Recipient().String())
	mustNotContain(t, "--age export", r.stdout, "s3cr3t-P@ss", "arsenii")
	var rd io.Reader = strings.NewReader(r.stdout)
	if strings.HasPrefix(r.stdout, "-----BEGIN") {
		rd = armor.NewReader(rd)
	}
	plain, err := age.Decrypt(rd, id)
	if err != nil {
		t.Fatalf("--age export doesn't decrypt with the identity: %v", err)
	}
	parseCSV(t, string(readAllLimited(plain)))
	if r := e.run("export", "--format", "csv", "--age", id.Recipient().String(), "--confirm-plaintext"); r.code == 0 {
		t.Errorf("--age with --confirm-plaintext accepted")
	}
}

// socketsOf lists the agent sockets an environment may have.
func socketsOf(e *env) []string {
	uid := strconv.Itoa(os.Getuid())
	var out []string
	for _, pat := range []string{
		filepath.Join(e.state, "agent", "*.sock"),
		filepath.Join(e.tmp, "passh-"+uid, "*.sock"),
	} {
		m, _ := filepath.Glob(pat)
		out = append(out, m...)
	}
	return out
}

// §13.2.6: the agent's folder and socket modes, its lifetimes (lock, idle
// and max TTL, a removed socket, SIGTERM), the key never in /proc/<pid>/
// cmdline or environ of any passh process, and only `unlock` starts it.
func TestS6_Agent(t *testing.T) {
	e, f := popEnv(t, "[agent]\nidle_ttl = \"1h\"\nmax_ttl = \"2h\"\n")
	keyStr := f.key.String()
	secrets := []string{keyStr, strings.ToLower(keyStr), strings.TrimPrefix(strings.ToLower(keyStr), "age-secret-key-1"), fixPass}

	// Watch every passh process of this environment while unlock runs and
	// while the agent lives.
	var mu sync.Mutex
	seen := map[int][]byte{}
	var leaks []string
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, p := range passhProcs(e.root) {
				mu.Lock()
				seen[p.pid] = p.cmdline
				for _, s := range secrets {
					if bytes.Contains(p.cmdline, []byte(s)) {
						leaks = append(leaks, "cmdline of "+strconv.Itoa(p.pid))
					}
					if bytes.Contains(p.environ, []byte(s)) {
						leaks = append(leaks, "environ of "+strconv.Itoa(p.pid))
					}
				}
				mu.Unlock()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	s := e.start(sessOpts{}, "unlock")
	s.answer("Passphrase:", fixPass)
	r := s.waitOK()
	m := agentPIDRe.FindStringSubmatch(r.term)
	if m == nil {
		t.Fatalf("no agent pid: %s", r)
	}
	pid, _ := strconv.Atoi(m[1])
	e.ok("show", "work/github", "--field", "password") // a client process too
	time.Sleep(100 * time.Millisecond)
	close(stop)
	<-done
	mu.Lock()
	if len(leaks) > 0 {
		t.Errorf("the vault key or passphrase appears in: %v", leaks)
	}
	agentSeen, unlockSeen := false, false
	for _, cl := range seen {
		if bytes.Contains(cl, []byte("__agent")) {
			agentSeen = true
		}
		if bytes.Contains(cl, []byte("unlock")) {
			unlockSeen = true
		}
	}
	mu.Unlock()
	if !agentSeen || !unlockSeen {
		t.Errorf("the /proc watcher missed the agent (%v) or the unlocking process (%v)", agentSeen, unlockSeen)
	}

	// Folder 0700, socket 0600, a real folder of the user.
	socks := socketsOf(e)
	if len(socks) != 1 {
		t.Fatalf("agent sockets: %v", socks)
	}
	dir := filepath.Dir(socks[0])
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		t.Errorf("agent folder %s isn't a real folder of the user", dir)
	}
	if m := perm(t, dir); m != 0o700 {
		t.Errorf("agent folder mode %o, want 0700", m)
	}
	if st, _ := os.Lstat(socks[0]); st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Errorf("agent socket mode %v, want a 0600 socket", st.Mode())
	}

	// It survives the end of the terminal session that started it.
	s.ptm.Close()
	time.Sleep(500 * time.Millisecond)
	if !alive(pid) {
		t.Fatalf("the agent died with the terminal session of unlock")
	}
	// A second unlock reports the time left and starts nothing.
	s = e.start(sessOpts{}, "unlock")
	r = s.waitOK()
	mustContain(t, "second unlock", r.term, "Already unlocked")
	if n := len(agentProcs(e.root)); n != 1 {
		t.Errorf("%d agents after a second unlock", n)
	}

	// The socket removed: the agent exits.
	if err := os.Remove(socks[0]); err != nil {
		t.Fatal(err)
	}
	if !waitGone(pid, 10*time.Second) {
		t.Errorf("the agent keeps running after its socket was removed")
	}

	// SIGTERM: exits and removes its socket.
	pid = e.unlock(fixPass)
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if !waitGone(pid, 5*time.Second) {
		t.Errorf("the agent ignores SIGTERM")
	}
	time.Sleep(100 * time.Millisecond)
	if socks := socketsOf(e); len(socks) != 0 {
		t.Errorf("socket left after the agent exited: %v", socks)
	}

	// max TTL (unlock --ttl): it exits although it is in use.
	pid = e.unlock(fixPass, "--ttl", "3s")
	start := time.Now()
	for time.Since(start) < 2*time.Second {
		e.run("show", "work/github", "--field", "username")
		time.Sleep(300 * time.Millisecond)
	}
	if !alive(pid) {
		t.Errorf("agent gone before its max TTL (3s): after %v", time.Since(start))
	}
	if !waitGone(pid, 6*time.Second) {
		t.Errorf("agent still running %v after start with --ttl 3s", time.Since(start))
	}
	if r := e.run("show", "work/github"); r.code == 0 || !strings.Contains(r.stderr, lockedHint) {
		t.Errorf("after the max TTL: want the locked hint, got %s", r)
	}
}

// §13.2.6: no command other than unlock starts an agent.
func TestS6_OnlyUnlockStartsAgent(t *testing.T) {
	e, _ := popEnv(t, "")
	var mu sync.Mutex
	var started []string
	stop := make(chan struct{})
	done := make(chan struct{})
	current := ""
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if len(agentProcs(e.root)) > 0 {
				mu.Lock()
				started = append(started, current)
				mu.Unlock()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	set := func(s string) { mu.Lock(); current = s; mu.Unlock() }
	out := filepath.Join(e.root, "o")
	_ = os.MkdirAll(out, 0o700)

	for _, args := range [][]string{
		{"ls"}, {"show", "work/github"}, {"find", "git"}, {"tags"}, {"verify"}, {"verify", "--full"},
		{"backup", out + "/"}, {"backups"}, {"doctor"}, {"lock"}, {"generate", "x/y"},
		{"export", "--format", "csv", "--confirm-plaintext"}, {"import", "pass", "--dry-run"},
	} {
		set(strings.Join(args, " ") + " (no terminal)")
		e.run(args...)
	}
	for _, args := range [][]string{
		{"ls"}, {"show", "work/github"}, {"find", "git"}, {"tags"}, {"verify", "--full"},
		{"generate", "x/z"}, {"tag", "work/github", "--add", "q"}, {"mv", "x/z", "x/w"}, {"rm", "--force", "x/w"},
		{"export", "--format", "csv", "-o", out + "/e.csv"},
	} {
		set(strings.Join(args, " ") + " (terminal)")
		s := e.start(sessOpts{pipeStdout: true}, args...)
		for {
			w := s.expectAny(15*time.Second, "Passphrase:", "to confirm:")
			if w == "" {
				break
			}
			time.Sleep(20 * time.Millisecond)
			if w == "Passphrase:" {
				s.send(fixPass + "\r")
			} else {
				s.send("EXPORT PLAINTEXT\r")
			}
		}
		if r := s.wait(); r.code != 0 {
			t.Errorf("passh %v: %s", args, r)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// add on a terminal with the passphrase.
	set("add (terminal)")
	e.add(fixPass, newEntry{path: "x/added", password: "pw", username: "u"})
	time.Sleep(100 * time.Millisecond)
	close(stop)
	<-done
	if len(started) > 0 {
		t.Errorf("an agent ran during: %v", uniq(started))
	}
	if socks := socketsOf(e); len(socks) != 0 {
		t.Errorf("agent sockets exist without unlock: %v", socks)
	}
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// §5.3: when the state folder's path is too long for a socket, the agent
// uses passh-<uid>/ in $TMPDIR, with the same checks: a symlink or a folder
// open to others is refused, not used or fixed.
func TestS6_AgentFolderFallback(t *testing.T) {
	e, _ := popEnv(t, "")
	e.stateH = filepath.Join(e.root, "s", strings.Repeat("x", 100))
	e.state = filepath.Join(e.stateH, "passh")
	if err := os.MkdirAll(e.stateH, 0o700); err != nil {
		t.Fatal(err)
	}
	fb := filepath.Join(e.tmp, "passh-"+strconv.Itoa(os.Getuid()))

	// A symlink planted where the folder goes is refused.
	elsewhere := filepath.Join(e.root, "elsewhere")
	_ = os.MkdirAll(elsewhere, 0o700)
	if err := os.Symlink(elsewhere, fb); err != nil {
		t.Fatal(err)
	}
	s := e.start(sessOpts{}, "unlock")
	if s.expectWithin("Passphrase:", 10*time.Second) {
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	if r := s.wait(); r.code == 0 || len(agentProcs(e.root)) > 0 {
		t.Errorf("unlock used a symlinked agent folder: %s", r)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) > 0 {
		t.Errorf("unlock wrote through the symlink: %v", ents)
	}
	_ = os.Remove(fb)

	// A folder open to others is refused too.
	if err := os.Mkdir(fb, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(fb, 0o777)
	s = e.start(sessOpts{}, "unlock")
	if s.expectWithin("Passphrase:", 10*time.Second) {
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	if r := s.wait(); r.code == 0 || len(agentProcs(e.root)) > 0 {
		t.Errorf("unlock used an agent folder with mode 0777: %s", r)
	}
	if m := perm(t, fb); m != 0o777 {
		t.Errorf("unlock changed the refused folder's mode to %o (doctor/unlock must not fix)", m)
	}
	_ = os.Remove(fb)

	// Otherwise the fallback folder is made 0700 with a 0600 socket.
	e.unlock(fixPass)
	defer e.lock()
	socks := socketsOf(e)
	if len(socks) != 1 || filepath.Dir(socks[0]) != fb {
		t.Fatalf("agent socket %v, want one in %s", socks, fb)
	}
	if m := perm(t, fb); m != 0o700 {
		t.Errorf("fallback agent folder mode %o", m)
	}
	if st, _ := os.Lstat(socks[0]); st.Mode().Perm() != 0o600 {
		t.Errorf("fallback socket mode %v", st.Mode())
	}
	if r := e.ok("show", "work/github", "--field", "password"); r.stdout != "s3cr3t-P@ss" {
		t.Errorf("the agent on the fallback socket doesn't serve: %q", r.stdout)
	}
}

// §5.3: re-running unlock while an agent runs for the same key block
// reports the time left and restarts its idle timer; an agent holding an
// older key block (after passwd elsewhere) is replaced.
func TestS6_UnlockRestartsAndReplaces(t *testing.T) {
	e, _ := popEnv(t, "[agent]\nidle_ttl = \"3s\"\n")
	pid := e.unlock(fixPass)
	time.Sleep(2 * time.Second)
	s := e.start(sessOpts{}, "unlock")
	r := s.waitOK()
	mustContain(t, "unlock again", r.term, "Already unlocked")
	time.Sleep(2500 * time.Millisecond) // 4.5 s after start, 2.5 s after the restart
	if !alive(pid) {
		t.Errorf("re-running unlock didn't restart the idle timer (§5.3)")
	}
	if !waitGone(pid, 6*time.Second) {
		t.Errorf("the agent didn't exit after idle_ttl")
	}

	// passwd made elsewhere: a copy gets a new passphrase and comes back.
	e.writeConfig("")
	pid = e.unlock(fixPass)
	const pass2 = "orchid basalt meteor tundra pickle anchor"
	cp := filepath.Join(e.root, "elsewhere.passh")
	copyFile(t, e.vault, cp)
	s = e.start(sessOpts{}, "--vault", cp, "passwd")
	if s.expectAny(15*time.Second, "Current passphrase:", "Passphrase:") != "" {
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	s.answer("New passphrase:", pass2)
	s.answer("Repeat passphrase:", pass2)
	s.waitOK()
	copyFile(t, cp, e.vault)
	if r := e.run("show", "work/github"); r.code == 0 {
		t.Errorf("an agent holding the old key block still served the key: %s", r)
	}
	s = e.start(sessOpts{}, "unlock")
	s.answer("Passphrase:", pass2)
	r = s.waitOK()
	m := agentPIDRe.FindStringSubmatch(r.term)
	if m == nil {
		t.Fatalf("unlock didn't start a new agent: %s", r)
	}
	if npid, _ := strconv.Atoi(m[1]); npid == pid {
		t.Errorf("the agent holding the older key block wasn't replaced")
	}
	if !waitGone(pid, 5*time.Second) {
		t.Errorf("the old agent keeps running after it was replaced")
	}
	if r := e.ok("show", "work/github", "--field", "password"); r.stdout != "s3cr3t-P@ss" {
		t.Errorf("the new agent doesn't serve: %q", r.stdout)
	}
	e.lock()
}
