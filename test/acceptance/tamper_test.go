package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// namedErrors are the messages of the §4.5 table.
var namedErrors = []string{
	"not a passh vault",
	"made by a newer passh",
	"file is truncated",
	"file is damaged",
	"wrong passphrase, or the key block is damaged",
	"data is damaged",
}

func namesProblem(s string) bool {
	for _, n := range namedErrors {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// lineSpans returns the [start, end) byte range of every line.
func lineSpans(b []byte) [][2]int {
	var out [][2]int
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, [2]int{start, i + 1})
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, [2]int{start, len(b)})
	}
	return out
}

// spliceData replaces the data block of a canonical vault.
func spliceData(t *testing.T, vault []byte, newBlock []byte) []byte {
	t.Helper()
	s := string(vault)
	i := strings.Index(s, "-----END AGE ENCRYPTED FILE-----\n")
	if i < 0 {
		t.Fatal("no END line")
	}
	head := s[:i+len("-----END AGE ENCRYPTED FILE-----\n")]
	return append([]byte(head), newBlock...)
}

func encryptArmored(t *testing.T, plain []byte, r age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("\n")
	return buf.Bytes()
}

// §13.2.10: flipping a byte or truncating the vault anywhere gives an error
// that names the problem and never shows partial data; a data block
// encrypted to another key is rejected.
func TestS10_DamageAndTampering(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()
	e.ok("generate", "tamper/one") // so an automatic backup exists
	orig := readFile(t, e.vault)
	d := mustDecrypt(t, e.vault, f.key)
	rev, n := d.Revision, len(d.Entries)
	spans := lineSpans(orig)

	// Where the structure lives: every byte of the magic, BEGIN/END lines
	// and the first lines of each block (age headers), the last two lines
	// of each block; every 9th byte elsewhere.
	dense := map[int]bool{}
	var keyEnd int
	blk := 0
	for li, sp := range spans {
		line := string(orig[sp[0]:sp[1]])
		isMarker := strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "passh-vault")
		near := false
		for _, dl := range []int{-2, -1, 1, 2, 3} {
			j := li + dl
			if j >= 0 && j < len(spans) {
				l := string(orig[spans[j][0]:spans[j][1]])
				if strings.HasPrefix(l, "-----") {
					near = true
				}
			}
		}
		if strings.HasPrefix(line, "-----END") {
			blk++
			if blk == 1 {
				keyEnd = sp[1]
			}
		}
		if isMarker || near {
			for p := sp[0]; p < sp[1]; p++ {
				dense[p] = true
			}
		}
	}
	var positions []int
	for p := range orig {
		if dense[p] || p%9 == 0 {
			positions = append(positions, p)
		}
	}
	sort.Ints(positions)

	type job struct {
		name string
		data []byte
		pos  int
	}
	var jobs []job
	for i, p := range positions {
		masks := []byte{0x01}
		if i%3 == 0 {
			masks = append(masks, 0x20)
		}
		for _, m := range masks {
			b := append([]byte(nil), orig...)
			b[p] ^= m
			jobs = append(jobs, job{fmt.Sprintf("flip %#02x at %d", m, p), b, p})
		}
	}
	size := len(orig)
	for l := 0; l < size-1; l++ {
		if l < 60 || l%13 == 0 || l > size-80 {
			jobs = append(jobs, job{fmt.Sprintf("truncated to %d of %d bytes", l, size), orig[:l], -1})
		}
	}

	dir := filepath.Join(e.root, "damaged")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var problems, cosmetic, locked, agentMisnamed []string
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				j := jobs[i]
				p := filepath.Join(dir, fmt.Sprintf("d%d.passh", i))
				if err := os.WriteFile(p, j.data, 0o600); err != nil {
					mu.Lock()
					problems = append(problems, err.Error())
					mu.Unlock()
					continue
				}
				report := func(format string, a ...any) {
					mu.Lock()
					problems = append(problems, j.name+": "+fmt.Sprintf(format, a...))
					mu.Unlock()
				}
				r, err := e.exec(passhBin, nil, "verify", p)
				if err != nil {
					report("%v", err)
					continue
				}
				if r.code != 0 {
					if !namesProblem(r.stderr) {
						report("verify: error doesn't name a §4.5 problem: %q", r.stderr)
					}
					continue
				}
				if j.pos < 0 {
					report("verify says OK for a truncated file")
					continue
				}
				r, err = e.exec(passhBin, nil, "verify", "--full", p)
				if err != nil {
					report("%v", err)
					continue
				}
				switch {
				case r.code == 0:
					// Opens completely: the change was cosmetic (whitespace,
					// unused base64 bits); age authenticates the rest.
					if !strings.Contains(r.stdout, fmt.Sprintf("revision  %d", rev)) || !strings.Contains(r.stdout, fmt.Sprintf("entries   %d", n)) {
						report("verify --full opened it with other data: %s", r.stdout)
					}
					mu.Lock()
					cosmetic = append(cosmetic, fmt.Sprintf("%s (%q→%q)", j.name, orig[j.pos], j.data[j.pos]))
					mu.Unlock()
				case strings.Contains(r.stdout, "revision") || strings.Contains(r.stdout, "entries"):
					report("verify --full failed but printed data: %s", r)
				case namesProblem(r.stderr):
				case j.pos < keyEnd && strings.Contains(r.stderr, lockedHint):
					// A damaged key block: the agent refuses it, and without
					// a terminal no passphrase can be asked.
					mu.Lock()
					locked = append(locked, j.name)
					mu.Unlock()
				case j.pos >= keyEnd && strings.Contains(r.stderr, lockedHint):
					// A damaged data block reported as "locked": see the
					// subtest below.
					mu.Lock()
					agentMisnamed = append(agentMisnamed, j.name)
					mu.Unlock()
				default:
					report("verify --full: error doesn't name a §4.5 problem: %q", r.stderr)
				}
			}
		}()
	}
	for i := range jobs {
		work <- i
	}
	close(work)
	wg.Wait()
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
	t.Logf("%d damaged copies checked; %d opened unchanged (cosmetic), %d key-block flips and %d data-block flips reported as locked through the agent",
		len(jobs), len(cosmetic), len(locked), len(agentMisnamed))
	if len(cosmetic) > 0 {
		t.Logf("cosmetic flips: %v", cosmetic)
	}

	// show on the damaged vault itself: an error, a backup list, no data.
	var dataPos []int
	for _, p := range positions {
		if p > keyEnd+200 && p < size-100 {
			dataPos = append(dataPos, p)
		}
	}
	for i := 0; i < len(dataPos); i += len(dataPos)/12 + 1 {
		p := dataPos[i]
		b := append([]byte(nil), orig...)
		b[p] ^= 0x01
		writeFile(t, e.vault, b, 0o600)
		r := e.run("show", "work/github")
		if r.code == 0 || r.stdout != "" || !namesProblem(r.stderr) {
			t.Errorf("show with byte %d flipped: want a named error and no output, got %s", p, r)
		}
		if strings.Contains(r.stderr, "data is damaged") && !strings.Contains(r.stderr, "backups") {
			t.Errorf("'data is damaged' must list the backups (§4.5): %s", r.stderr)
		}
	}
	writeFile(t, e.vault, orig, 0o600)

	// A damaged key block with the passphrase on a terminal.
	for _, off := range []int{200, 300} {
		p := filepath.Join(dir, fmt.Sprintf("kb%d.passh", off))
		b := append([]byte(nil), orig...)
		pos := off
		for pos < keyEnd && (b[pos] == '\n' || b[pos] == '-') {
			pos++
		}
		b[pos] ^= 0x01
		writeFile(t, p, b, 0o600)
		s := e.start(sessOpts{pipeStdout: true}, "--vault", p, "show", "work/github")
		for s.expectAny(20*time.Second, "Passphrase:") != "" {
			time.Sleep(20 * time.Millisecond)
			s.send(fixPass + "\r")
		}
		r := s.wait()
		if r.code == 0 || r.stdout != "" || !namesProblem(r.term) {
			t.Errorf("key block byte %d flipped, passphrase typed: want a named error, got %s", pos, r)
		}
	}

	// A data block encrypted to another key (valid JSON inside) is rejected,
	// with the passphrase on a terminal and through the agent.
	_, plain, err := decryptVault(orig, f.key)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := age.GenerateX25519Identity()
	forged := spliceData(t, orig, encryptArmored(t, plain, other.Recipient()))
	p := filepath.Join(dir, "forged.passh")
	writeFile(t, p, forged, 0o600)
	s := e.start(sessOpts{pipeStdout: true}, "--vault", p, "show", "work/github")
	for s.expectAny(20*time.Second, "Passphrase:") != "" {
		time.Sleep(20 * time.Millisecond)
		s.send(fixPass + "\r")
	}
	if r := s.wait(); r.code == 0 || r.stdout != "" || !strings.Contains(r.term, "data is damaged") {
		t.Errorf("forged data block, passphrase on a terminal: want 'data is damaged', got %s", r)
	}
	writeFile(t, e.vault, forged, 0o600)
	forgedAgent := e.run("show", "work/github")
	if forgedAgent.code == 0 || forgedAgent.stdout != "" {
		t.Errorf("forged data block through the agent: want rejection, got %s", forgedAgent)
	}
	forgedVerify := e.run("verify", "--full", p)
	if forgedVerify.code == 0 || strings.Contains(forgedVerify.stdout, "revision") {
		t.Errorf("verify --full of a forged data block: %s", forgedVerify)
	}
	// §4.5: with the agent's key, a data block that doesn't decrypt is
	// reported as damaged data (a damaged key block may say "locked").
	t.Run("through the agent, data damage is named", func(t *testing.T) {
		for _, n := range agentMisnamed {
			t.Errorf("%s: through the agent, damaged data is reported as locked", n)
		}
		if !strings.Contains(forgedAgent.stderr, "data is damaged") {
			t.Errorf("forged data block through the agent: want 'data is damaged', got %s", forgedAgent)
		}
		if strings.Contains(forgedVerify.stderr, lockedHint) || !namesProblem(forgedVerify.stderr) {
			t.Errorf("verify --full of a forged data block through the agent: %s", forgedVerify)
		}
	})

	// Newer versions are refused with "made by a newer passh".
	writeFile(t, e.vault, bytes.Replace(orig, []byte("passh-vault 1"), []byte("passh-vault 2"), 1), 0o600)
	if r := e.run("verify"); r.code == 0 || !strings.Contains(r.stderr, "made by a newer passh") {
		t.Errorf("container version 2: %s", r)
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = 2
	nb, _ := json.Marshal(m)
	writeFile(t, e.vault, spliceData(t, orig, encryptArmored(t, nb, f.key.Recipient())), 0o600)
	if r := e.run("show", "work/github"); r.code == 0 || r.stdout != "" || !strings.Contains(r.stderr, "made by a newer passh") {
		t.Errorf("data version 2: %s", r)
	}
	writeFile(t, e.vault, orig, 0o600)
}

// §13.2.10 (S9): the vault key's recipient (age1…) never appears in the
// vault, backups, exports or any output, also after passwd and rekey.
func TestS10_RecipientNeverWritten(t *testing.T) {
	e, f := popEnv(t, "")
	recips := []string{f.recip}
	e.unlock(fixPass)
	out := filepath.Join(e.root, "out")
	_ = os.MkdirAll(out, 0o700)
	other, _ := age.GenerateX25519Identity()
	for _, args := range [][]string{
		{"ls"}, {"show", "work/github"}, {"find", "a"}, {"tags"}, {"generate", "r/one"},
		{"verify"}, {"verify", "--full"}, {"backups"}, {"doctor"}, {"backup", out + "/"},
		{"export", "--format", "json", "--confirm-plaintext", "-o", out + "/e.json"},
		{"export", "--format", "csv", "--confirm-plaintext", "-o", out + "/e.csv"},
		{"export", "--format", "bitwarden-json", "--confirm-plaintext", "-o", out + "/e.bw"},
		{"export", "--format", "json", "--age", other.Recipient().String(), "-o", out + "/e.age"},
	} {
		e.run(args...)
	}
	// passwd, then rekey: a new vault key with its own recipient.
	s := e.start(sessOpts{}, "passwd")
	if s.expectAny(10*time.Second, "Current passphrase:", "New passphrase:") == "Current passphrase:" {
		s.send(fixPass + "\r")
		s.expect("New passphrase:")
	}
	time.Sleep(20 * time.Millisecond)
	s.send(fixPass + "\r")
	s.answer("Repeat passphrase:", fixPass)
	s.waitOK()
	s = e.start(sessOpts{}, "rekey")
	if s.expectAny(10*time.Second, "Current passphrase:", "New passphrase:") == "Current passphrase:" {
		s.send(fixPass + "\r")
		s.expect("New passphrase:")
	}
	time.Sleep(20 * time.Millisecond)
	s.send(fixPass + "\r")
	s.answer("Repeat passphrase:", fixPass)
	s.waitOK()
	nk, err := vaultKeyFromPass(readFile(t, e.vault), fixPass)
	if err != nil {
		t.Fatalf("after rekey: %v", err)
	}
	if nk.String() == f.key.String() {
		t.Errorf("rekey kept the vault key")
	}
	recips = append(recips, nk.Recipient().String())
	e.unlock(fixPass)
	e.ok("generate", "r/two")
	e.run("export", "--format", "json", "--confirm-plaintext", "-o", out+"/e2.json")
	e.lock()

	for p, b := range walkFiles(e.root) {
		for _, rc := range recips {
			if bytes.Contains(b, []byte(rc)) {
				t.Errorf("%s holds the vault's recipient", p)
			}
		}
	}
	for _, o := range allOutputs() {
		for _, rc := range append(recips, fixtures(t).recip) {
			if strings.Contains(o, rc) {
				t.Errorf("an output holds the vault's recipient: %.200q", o)
			}
		}
	}
}
