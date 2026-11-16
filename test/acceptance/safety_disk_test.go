package acceptance

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Distinctive values: no file on disk may hold them (§13.2.2).
var markers = newEntry{
	path:     "pathmarker/entrymarker",
	password: "PWmarker-Zq81x",
	username: "USERmarker-Lk2",
	url:      "https://URLmarker.example/",
	tags:     "tagmarker, othertagmarker",
	notes:    "NOTESmarker-line1\nNOTESmarker-line2",
}

var markerValues = []string{"PWmarker-Zq81x", "USERmarker-Lk2", "URLmarker.example", "tagmarker", "NOTESmarker", "pathmarker", "entrymarker"}

// writeOp is one syscall that changed the file system.
type writeOp struct {
	call, path, line string
}

var straceLineRe = regexp.MustCompile(`^(\d+)\s+(\w+)\((.*)\)\s+=\s+(.*)$`)

// splitArgs splits strace's argument list at top-level commas.
func splitArgs(s string) []string {
	var out []string
	depth, inQ, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ && c == '\\':
			i++
		case c == '"':
			inQ = !inQ
		case inQ:
		case c == '{' || c == '[' || c == '<' || c == '(':
			depth++
		case c == '}' || c == ']' || c == '>' || c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func unquote(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return strings.Trim(s, `"`)
}

// fdPath is the path strace -y shows for a descriptor: 3</a/b> → /a/b.
func fdPath(tok, cwd string) string {
	if i := strings.IndexByte(tok, '<'); i >= 0 && strings.HasSuffix(tok, ">") {
		return tok[i+1 : len(tok)-1]
	}
	return cwd
}

func resolveAt(dirTok, p, cwd string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(fdPath(dirTok, cwd), p)
}

// parseTrace lists the successful file system changes in an strace -f -y log.
func parseTrace(t *testing.T, log, cwd string) []writeOp {
	t.Helper()
	f, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pending := map[string]string{}
	var ops []writeOp
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		l := sc.Text()
		pid, rest, _ := strings.Cut(l, " ")
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "---") || strings.HasPrefix(rest, "+++") {
			continue
		}
		if i := strings.Index(rest, " <unfinished ...>"); i >= 0 {
			pending[pid] = rest[:i]
			continue
		}
		if strings.HasPrefix(rest, "<... ") {
			_, after, ok := strings.Cut(rest, " resumed>")
			if !ok {
				continue
			}
			rest = pending[pid] + after
			delete(pending, pid)
		}
		m := straceLineRe.FindStringSubmatch(pid + " " + rest)
		if m == nil {
			continue
		}
		call, args, ret := m[2], splitArgs(m[3]), m[4]
		if strings.HasPrefix(ret, "-1") || strings.HasPrefix(ret, "?") {
			continue
		}
		add := func(p string) { ops = append(ops, writeOp{call: call, path: p, line: l}) }
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		writeFlags := func(fl string) bool {
			for _, w := range []string{"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"} {
				if strings.Contains(fl, w) {
					return true
				}
			}
			return false
		}
		switch call {
		case "open":
			if writeFlags(arg(1)) {
				add(fdPath(ret, resolveAt("", unquote(arg(0)), cwd)))
			}
		case "openat":
			if writeFlags(arg(2)) {
				p := resolveAt(arg(0), unquote(arg(1)), cwd)
				if strings.Contains(ret, "<") {
					p = fdPath(strings.TrimSpace(ret), p)
				}
				add(p)
			}
		case "creat", "mkdir", "unlink", "rmdir", "chmod", "truncate":
			add(resolveAt("", unquote(arg(0)), cwd))
		case "mkdirat", "unlinkat", "fchmodat":
			add(resolveAt(arg(0), unquote(arg(1)), cwd))
		case "rename", "link", "symlink":
			if call == "rename" {
				add(resolveAt("", unquote(arg(0)), cwd))
			}
			add(resolveAt("", unquote(arg(1)), cwd))
		case "renameat", "renameat2", "linkat":
			if call != "linkat" {
				add(resolveAt(arg(0), unquote(arg(1)), cwd))
			}
			add(resolveAt(arg(2), unquote(arg(3)), cwd))
		case "symlinkat":
			add(resolveAt(arg(1), unquote(arg(2)), cwd))
		case "utimensat":
			if arg(1) != "NULL" {
				add(resolveAt(arg(0), unquote(arg(1)), cwd))
			}
		case "bind":
			if sm := regexp.MustCompile(`sun_path="([^"]*)"`).FindStringSubmatch(arg(1)); sm != nil && sm[1] != "" {
				add(resolveAt("", sm[1], cwd))
			}
		}
	}
	return ops
}

// footprint describes where §3.2 lets passh write in an environment, plus
// explicit outputs the user named.
type footprint struct {
	e        *env
	explicit []string // files or folders (with a trailing /) the user named
}

func (fp footprint) allowed(p string) bool {
	e := fp.e
	vdir := filepath.Dir(e.vault)
	uid := strconv.Itoa(os.Getuid())
	switch {
	case p == e.vault, strings.HasPrefix(p, vdir+"/.vault.passh.tmp-"):
		return true
	case p == e.config:
		return true
	case p == vdir || p == filepath.Dir(e.config): // init makes the folders of the vault and config
		return true
	case p == e.state, strings.HasPrefix(p, e.state+"/"):
		return true
	case strings.HasPrefix(p, e.tmp+"/passh-"+uid), strings.HasPrefix(p, "/tmp/passh-"+uid):
		return true
	case p == "/dev/tty", p == "/dev/null", p == "/dev/ptmx", strings.HasPrefix(p, "/dev/pts/"):
		return true
	case strings.HasPrefix(p, "/dev/shm/passh-edit-"), strings.HasPrefix(p, e.runtime+"/passh-edit-"):
		return true // the tmpfs folder of edit --editor (S1)
	}
	for _, x := range fp.explicit {
		if p == x || (strings.HasSuffix(x, "/") && strings.HasPrefix(p, x)) {
			return true
		}
	}
	return false
}

// snapshot records every path under root (files, folders, links) with a
// hash of its content and mode.
func snapshot(root string, skip string) map[string]string {
	out := map[string]string{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip what can't be read; the walk goes on
		}
		if skip != "" && (p == skip || strings.HasPrefix(p, skip+"/")) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		v := fmt.Sprintf("%v", info.Mode())
		if info.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			v += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		out[p] = v
		return nil
	})
	return out
}

func dirNames(d string) map[string]bool {
	out := map[string]bool{}
	ents, _ := os.ReadDir(d)
	for _, x := range ents {
		out[x.Name()] = true
	}
	return out
}

// §13.2.2 and §13.2.8: a full session (init, add, unlock, edit in the form
// and in $EDITOR, the other commands, export, the print page, passwd, lock)
// under strace writes only to the places of
// §3.2 (plus the outputs the user named), and no file other than the
// explicit plaintext export holds an entry's value.
func TestS2S8_DiskFootprint(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace not installed")
	}
	e := newEnv(t)
	traces := filepath.Join(e.root, "traces")
	if err := os.MkdirAll(traces, 0o700); err != nil {
		t.Fatal(err)
	}
	outCSV := filepath.Join(e.root, "out", "plain.csv")
	outAge := filepath.Join(e.root, "out", "enc.age")
	backupDir := filepath.Join(e.root, "usb") + "/"
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(e.root, "out", "id.txt")
	if err := os.MkdirAll(filepath.Dir(idFile), 0o700); err != nil {
		t.Fatal(err)
	}
	kg := exec.Command(keygenBn, "-o", idFile)
	kgOut, err := kg.CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v %s", err, kgOut)
	}
	exportRecip := regexp.MustCompile(`age1[0-9a-z]+`).FindString(string(kgOut))

	before := snapshot(e.root, traces)
	shmBefore := dirNames("/dev/shm")
	fp := footprint{e: e, explicit: []string{outCSV, outAge, backupDir}}

	n := 0
	trArgs := func(args ...string) []string {
		n++
		log := filepath.Join(traces, fmt.Sprintf("%02d-%s.log", n, args[0]))
		return append([]string{"-f", "-qq", "-y", "-s", "4096", "-e", "signal=none",
			"-e", "trace=open,openat,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,link,linkat,symlink,symlinkat,chmod,fchmodat,truncate,utimensat,bind",
			"-o", log, "--", passhBin}, args...)
	}
	startT := func(o sessOpts, args ...string) *session {
		o.bin = strace
		return e.start(o, trArgs(args...)...)
	}
	okT := func(args ...string) result {
		t.Helper()
		r := e.runCmd(strace, nil, trArgs(args...)...)
		if r.code != 0 {
			t.Fatalf("passh %v: %s", args, r)
		}
		return r
	}

	// init
	s := startT(sessOpts{}, "init")
	s.answer("New passphrase:", fixPass)
	s.answer("Repeat passphrase:", fixPass)
	if s.expectWithin("recovery key now?", 30*time.Second) {
		s.send("n\r")
	}
	if r := s.wait(); r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	// add with the passphrase
	s = startT(sessOpts{}, "add", markers.path)
	e.typeEntry(s, fixPass, markers)
	if r := s.wait(); r.code != 0 {
		t.Fatalf("add: %s", r)
	}
	// unlock: strace follows the agent until it exits.
	us := startT(sessOpts{}, "unlock")
	us.answer("Passphrase:", fixPass)
	us.expect("Unlocked")

	okT("generate", "gen/marker")
	if r := okT("show", markers.path, "--field", "password"); r.stdout != markers.password {
		t.Fatalf("show: %q", r.stdout)
	}
	values := append([]string(nil), markerValues...)

	// edit in the built-in form: generate a new password, save.
	okT("generate", "form/marker")
	s = startT(sessOpts{cols: 100, rows: 30}, "edit", "form/marker")
	s.mustScreen(15*time.Second, "ctrl+s save")
	s.key("\x07")
	s.mustScreen(5*time.Second, "Generated a new password")
	s.key("\x13")
	if r := s.wait(); r.code != 0 {
		t.Fatalf("edit (form): %s", r)
	}
	values = append(values, okT("show", "form/marker", "--field", "password").stdout)

	// edit --editor with a fake vim that sets a marker password.
	edDir := filepath.Join(traces, "ed") // test tooling: outside the diff
	writeFile(t, filepath.Join(edDir, "vim"), []byte("#!/bin/sh\neval f=\\${$#}\nrest=$(tail -n +2 \"$f\")\nprintf '%s\\n%s\\n' 'EDITORmarker-77' \"$rest\" > \"$f\"\n"), 0o755)
	savedPath := e.path
	e.extra, e.path = []string{"EDITOR=vim"}, edDir+":"+e.path
	s = startT(sessOpts{}, "edit", "--editor", markers.path)
	if r := s.wait(); r.code != 0 {
		t.Fatalf("edit --editor: %s", r)
	}
	e.extra, e.path = nil, savedPath
	if r := okT("show", markers.path, "--field", "password"); r.stdout != "EDITORmarker-77" {
		t.Fatalf("edit --editor didn't save: %q", r.stdout)
	}
	values = append(values, "EDITORmarker-77")

	// The print page, loaded once.
	if ifname, ip, _, _ := lanAddress(); ip != nil {
		port := freePort(t, ip)
		writeFile(t, e.config, []byte(fmt.Sprintf("vault = %q\n[print_web]\nenabled = true\nport = %d\ninterfaces = [%q]\n", e.vault, port, ifname)), 0o600)
		s = startT(sessOpts{}, "print", "--web")
		s.answer("to confirm:", "PRINT")
		if !s.expectWithin("Esc stops", 20*time.Second) {
			t.Fatalf("print --web: %s", s.output())
		}
		m := printURLRe.FindStringSubmatch(s.output())
		if m == nil {
			t.Fatalf("no print page URL: %s", s.output())
		}
		if r, err := fetch(ip, port, "", "/p/"+m[3], nil, 0); err != nil || !strings.Contains(r.body, "EDITORmarker-77") {
			t.Fatalf("print page: %v %d", err, r.status)
		}
		if r := s.wait(); r.code != 0 {
			t.Fatalf("print --web: %s", r)
		}
	} else {
		t.Log("no RFC 1918 address: the print page isn't part of this session")
	}
	okT("show", markers.path)
	okT("ls")
	okT("ls", "--tag", "tagmarker")
	okT("find", "marker")
	okT("tags")
	okT("tag", markers.path, "--add", "addedtagmarker", "--remove", "othertagmarker")
	okT("mv", "gen/marker", "gen/moved")
	okT("rm", "--force", "gen/moved")
	okT("export", "--format", "csv", "--confirm-plaintext", "-o", outCSV)
	okT("export", "--format", "bitwarden-json", "--age", exportRecip, "-o", outAge)
	okT("export", "--format", "json", "--confirm-plaintext") // to a pipe
	okT("backup", backupDir)
	okT("verify")
	okT("verify", "--full")
	okT("backups")
	e.runCmd(strace, nil, trArgs("doctor")...)
	// passwd: the current passphrase even with the agent running (CLI-018);
	// it stops the agent, so the traced unlock ends.
	s = startT(sessOpts{}, "passwd")
	s.answer("Current passphrase:", fixPass)
	s.answer("New passphrase:", fixPass+" two")
	s.answer("Repeat passphrase:", fixPass+" two")
	if r := s.wait(); r.code != 0 {
		t.Fatalf("passwd: %s", r)
	}
	okT("lock")
	if r := us.wait(); r.code != 0 {
		t.Fatalf("unlock (traced with its agent): %s", r)
	}

	// 1. The syscall trace: every change is in an allowed place.
	var sawVault, sawSocket bool
	logs, _ := filepath.Glob(filepath.Join(traces, "*.log"))
	for _, lg := range logs {
		for _, op := range parseTrace(t, lg, e.root) {
			if op.path == e.vault {
				sawVault = true
			}
			if op.call == "bind" {
				sawSocket = true
			}
			if os.Getenv("DEBUGTRACE") != "" {
				t.Logf("TRACE %s %s %s", filepath.Base(lg), op.call, op.path)
			}
			// §4.2: opening and reading never rewrite the vault.
			cmd := strings.TrimSuffix(filepath.Base(lg)[3:], ".log")
			readOnly := map[string]bool{"show": true, "ls": true, "find": true, "tags": true, "verify": true, "backups": true, "doctor": true, "export": true, "backup": true, "lock": true}
			if readOnly[cmd] && (op.path == e.vault || strings.HasPrefix(op.path, filepath.Dir(e.vault)+"/")) {
				t.Errorf("%s: the read-only command %s changed the vault: %s %s", filepath.Base(lg), cmd, op.call, op.path)
			}
			if !fp.allowed(op.path) {
				t.Errorf("%s: write outside §3.2: %s %s\n  %s", filepath.Base(lg), op.call, op.path, op.line)
			}
		}
	}
	if !sawVault || !sawSocket {
		t.Errorf("the trace parser saw no vault write (%v) or no socket bind (%v): the trace check is broken", sawVault, sawSocket)
	}

	// 2. The file system diff under the environment (HOME, XDG folders,
	// TMPDIR, the vault folder).
	after := snapshot(e.root, traces)
	for p, v := range after {
		if before[p] == v {
			continue
		}
		if !fp.allowed(p) && p != filepath.Dir(outCSV) {
			t.Errorf("new or changed outside §3.2: %s", p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok && !fp.allowed(p) {
			t.Errorf("removed outside §3.2: %s", p)
		}
	}

	// 3. No plaintext: no file other than the explicit plaintext export
	// holds an entry's value; the vault, temp files and backups included.
	for p, b := range walkFiles(e.root) {
		if strings.HasPrefix(p, traces) || p == outCSV {
			continue
		}
		for _, m := range values {
			if strings.Contains(string(b), m) {
				t.Errorf("%s holds the entry value %q", p, m)
			}
		}
	}
	if b := readFile(t, outCSV); !strings.Contains(string(b), markers.username) {
		t.Errorf("the explicit export lacks the data (the scan is broken)")
	}
	for name := range dirNames("/dev/shm") {
		if shmBefore[name] {
			continue
		}
		if strings.HasPrefix(name, "passh") {
			t.Errorf("/dev/shm/%s was left behind", name)
		}
		b, err := os.ReadFile(filepath.Join("/dev/shm", name))
		if err != nil {
			continue
		}
		for _, m := range values {
			if strings.Contains(string(b), m) {
				t.Errorf("/dev/shm/%s holds the entry value %q", name, m)
			}
		}
	}
	if n := len(agentProcs(e.root)); n != 0 {
		t.Errorf("%d agents left", n)
	}
}
