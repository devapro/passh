package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vaultfile"
)

func listBackups(t testing.TB, state string) []Backup {
	t.Helper()
	list, err := ListBackups(state, "")
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// checkNoPlaintext fails if any file below dirs holds one of values.
func checkNoPlaintext(t testing.TB, values []string, dirs ...string) {
	t.Helper()
	for _, f := range filesUnder(t, dirs...) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			if bytes.Contains(b, []byte(v)) {
				t.Fatalf("%s holds %q", f, v)
			}
		}
	}
}

// checkNoRecipient fails if the vault key's public recipient appears in any
// file below dirs, in the blocks' binary form, or anywhere outside base64
// (S9).
func checkNoRecipient(t testing.TB, id *age.X25519Identity, dirs ...string) {
	t.Helper()
	recipient := id.Recipient().String()
	for _, f := range filesUnder(t, dirs...) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(recipient)) {
			t.Fatalf("%s holds the recipient", f)
		}
		vf, err := vaultfile.Parse(b)
		if err != nil {
			// Not a vault (lock, record): plain text, no age1 at all.
			if bytes.Contains(b, []byte("age1")) {
				t.Fatalf("%s holds age1", f)
			}
			continue
		}
		for _, block := range [][]byte{vf.KeyBlock, vf.DataBlock} {
			hdr := block[:bytes.Index(block, []byte("\n---"))]
			if bytes.Contains(block, []byte(recipient)) || bytes.Contains(hdr, []byte("age1")) {
				t.Fatalf("%s: a block holds the recipient", f)
			}
		}
		// Outside the armored base64, the file is fixed text.
		for _, line := range strings.Split(string(b), "\n") {
			if line == armor.Header || line == armor.Footer || strings.HasPrefix(line, "passh-vault") {
				continue
			}
			if strings.Contains(line, "age1") && strings.ContainsAny(line, " -:") {
				t.Fatalf("%s: line %q", f, line)
			}
		}
	}
}

// Safety test 2 (storage part) and S1: after saves, the vault, its
// temporary files, the backups and the rest of the state folder hold none
// of the entries' values, names or tags.
func TestNoPlaintextOnDisk(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	secrets := []string{"Zebra-Secret-91", "Quokka-Secret-47", "Ibis-Secret-23"}
	for i, s := range secrets {
		mustAdd(t, v, "bank/account-"+s, s)
		if i == 1 {
			// Keep a copy of one save's temporary file, as a crash would
			// leave it (under a name the next save doesn't remove).
			setHook(t, func(p, file string) {
				if p == hookTempSynced {
					b, _ := os.ReadFile(file)
					os.WriteFile(filepath.Join(filepath.Dir(file), "kept.tmp-copy"), b, 0o600)
				}
			})
		}
	}
	testHook = nil // keep only the second save's file
	if _, _, err := v.EditTags(paths.MustParse("bank/account-"+secrets[0]), []string{"Tag-Secret-55"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove(paths.MustParse("bank/account-" + secrets[2])); err != nil {
		t.Fatal(err)
	}
	if len(temps(t, e.dir)) != 1 {
		t.Fatal("the kept temporary file is missing")
	}
	if len(listBackups(t, e.state)) < 4 {
		t.Fatal("too few backups to check")
	}
	values := []string{"Tag-Secret-55", "account-", "bank/"}
	for _, s := range secrets {
		values = append(values, s, "user-"+s, "pin-"+s, "notes-"+s, "example.com/"+s)
	}
	checkNoPlaintext(t, values, e.dir, e.state)
	checkNoRecipient(t, e.key, e.dir, e.state)
}

// S9 across passwd-like key block changes and rekey: the recipient of no
// key ever reaches the disk.
func TestNoRecipientAfterRekey(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	newKey, _ := age.GenerateX25519Identity()
	v.mu.Lock()
	err := v.commit(t.Context(), v.data.Clone(), lowKeyBlock(t, newKey, "x"), newKey)
	v.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, v, "b", "pw")
	checkNoRecipient(t, e.key, e.dir, e.state)
	checkNoRecipient(t, newKey, e.dir, e.state)
}
