package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// printPaperKey runs `passh recovery-key print --format txt -o out` on a
// terminal and returns the sheet.
func (e *env) printPaperKey(out, pass string) string {
	e.t.Helper()
	s := e.start(sessOpts{}, "recovery-key", "print", "--format", "txt", "-o", out)
	for {
		w := s.expectAny(20*time.Second, "Passphrase:", "to confirm:")
		if w == "" {
			break
		}
		if w == "to confirm:" {
			s.send("PRINT RECOVERY KEY\r")
		} else {
			s.typeSecret(pass)
		}
	}
	if r := s.wait(); r.code != 0 {
		e.t.Fatalf("recovery-key print: %s", r)
	}
	return string(readFile(e.t, out))
}

// sheetKey reads the vault key off the sheet: the lines under "Vault key",
// joined without spaces, as §8 says to type it.
func sheetKey(t *testing.T, sheet string) (key string, groups []string) {
	t.Helper()
	_, after, ok := strings.Cut(sheet, "Vault key\n")
	if !ok {
		t.Fatalf("no 'Vault key' section on the sheet:\n%s", sheet)
	}
	var b strings.Builder
	for _, l := range strings.Split(after, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "---") {
			continue
		}
		if l == "" {
			if b.Len() > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(l, "AGE-SECRET-KEY-1") {
			groups = append(groups, strings.Fields(l)...)
		}
		b.WriteString(strings.ReplaceAll(l, " ", ""))
	}
	return b.String(), groups
}

// specSection8 returns the bash commands of spec §8 "Without passh".
func specSection8(t *testing.T) []string {
	t.Helper()
	spec := string(readFile(t, filepath.Join(repoRoot, "spec.md")))
	_, after, ok := strings.Cut(spec, "**Without passh**")
	if !ok {
		t.Fatal("spec.md has no 'Without passh' part")
	}
	_, block, _ := strings.Cut(after, "```bash\n")
	block, _, _ = strings.Cut(block, "```")
	return strings.Split(strings.TrimSpace(block), "\n")
}

// §13.1.9 (paper key) and §13.1.10: the sheet from `recovery-key print`
// holds the key, and §8's paper-key steps with the stock age tool produce
// the vault's JSON; `passh recover` with the key sets a new passphrase.
func TestF9F10_PaperKey(t *testing.T) {
	e, f := popEnv(t, "")
	shm, err := os.MkdirTemp("/dev/shm", "passh-acc-")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	defer os.RemoveAll(shm)
	out := filepath.Join(shm, "sheet.txt")
	sheet := e.printPaperKey(out, fixPass)
	if m := perm(t, out); m != 0o600 {
		t.Errorf("sheet file mode %o, want 0600", m)
	}

	// §5.4: what the sheet holds.
	key, groups := sheetKey(t, sheet)
	if key != f.key.String() {
		t.Fatalf("the sheet's key %q isn't the vault key", key)
	}
	for i, g := range groups {
		if len(g) != 4 && i != len(groups)-1 {
			t.Errorf("key group %q isn't four characters", g)
		}
	}
	mustContain(t, "sheet", sheet, f.popData.VaultID, time.Now().Format("2006-01-02"), "Whoever has this sheet and a copy of the vault can read everything")
	for _, cmd := range specSection8(t) {
		if !strings.Contains(sheet, cmd) {
			t.Errorf("the sheet lacks §8's command %q", cmd)
		}
	}
	if strings.Contains(sheet, f.recip) {
		t.Errorf("the sheet holds the recipient (S9)")
	}

	// §8 with the paper key: write the key as one line without spaces,
	// then the second, fourth and fifth commands, verbatim.
	cmds := specSection8(t)
	writeFile(t, filepath.Join(shm, "key.txt"), []byte(key+"\n"), 0o600)
	work := filepath.Join(e.root, "manual")
	writeFile(t, filepath.Join(work, "vault.passh"), readFile(t, e.vault), 0o600)
	e.path = filepath.Dir(ageBin) + ":/usr/bin:/bin"
	for _, i := range []int{1, 3, 4} {
		st := strings.ReplaceAll(cmds[i], "/dev/shm/", shm+"/")
		if j := strings.Index(st, " #"); j >= 0 {
			st = st[:j]
		}
		r := e.runCmd("/bin/sh", nil, "-c", "cd "+work+" && "+st)
		if r.code != 0 {
			t.Fatalf("§8 step %q: %s", st, r)
		}
	}
	var d vData
	if err := json.Unmarshal(readFile(t, filepath.Join(shm, "vault.json")), &d); err != nil {
		t.Fatalf("vault.json: %v", err)
	}
	if d.VaultID != f.popData.VaultID || d.Revision != f.popRev || len(d.Entries) != len(f.popData.Entries) {
		t.Errorf("vault.json from the paper key: id %s rev %d entries %d", d.VaultID, d.Revision, len(d.Entries))
	}
	if _, err := os.Stat(filepath.Join(shm, "key.txt")); err == nil {
		t.Errorf("the fifth command didn't remove key.txt")
	}
	e.path = binDir + ":/usr/bin:/bin"

	// §13.1.10: forgotten passphrase. A typo is caught by the checksum;
	// spaces, line breaks and case don't matter.
	const newPass = "saffron kettle ribbon glacier walnut pylon"
	s := e.start(sessOpts{}, "recover")
	s.expect("> ")
	typo := []byte(strings.ToLower(key))
	typo[len(typo)-3] = map[bool]byte{true: 'q', false: 'p'}[typo[len(typo)-3] != 'q']
	typed := string(typo)
	for i := 0; i < len(typed); i += 9 {
		s.send(typed[i:min(i+9, len(typed))] + " \r")
	}
	s.send("\r")
	if !s.expectWithin("again", 10*time.Second) {
		t.Fatalf("a mistyped paper key wasn't refused; terminal:\n%s", s.output())
	}
	// As printed, group per group, some in lower case, once the prompt is
	// back (its terminal mode set: the key shows as *).
	s.expect("> ")
	s.waitEchoOff()
	s.send("age-secret-key-1\r")
	for i, g := range groups {
		if i%2 == 0 {
			g = strings.ToLower(g)
		}
		s.send(g + "  ")
		if i%5 == 4 {
			s.send("\r")
		}
	}
	s.send("\r\r")
	s.answer("New passphrase:", newPass)
	s.answer("Repeat passphrase:", newPass)
	r := s.wait()
	if r.code != 0 {
		t.Fatalf("recover: %s", r)
	}
	raw := readFile(t, e.vault)
	if _, err := vaultKeyFromPass(raw, fixPass); err == nil {
		t.Errorf("the old passphrase still opens the vault after recover")
	}
	nk, err := vaultKeyFromPass(raw, newPass)
	if err != nil {
		t.Fatalf("the new passphrase doesn't open the vault: %v", err)
	}
	if nk.String() != f.key.String() {
		t.Errorf("recover changed the vault key; the paper key must stay valid")
	}
	if d := mustDecrypt(t, e.vault, f.key); len(d.Entries) != len(f.popData.Entries) {
		t.Errorf("entries after recover: %d", len(d.Entries))
	}
	s = e.start(sessOpts{pipeStdout: true}, "show", "work/github", "--field", "password")
	s.answer("Passphrase:", newPass)
	if r := s.waitOK(); r.stdout != "s3cr3t-P@ss" {
		t.Errorf("show with the new passphrase: %q", r.stdout)
	}
}
