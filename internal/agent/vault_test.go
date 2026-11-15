package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"passh/internal/keys"
	"passh/internal/model"
	"passh/internal/paths"
	"passh/internal/vault"
	"passh/internal/vaultfile"
)

// cheapKeyBlock is a key block like keys.WrapKey's, with a tiny scrypt work
// factor so the test stays fast.
func cheapKeyBlock(t *testing.T, id *age.X25519Identity, pass string) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(4)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(id.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A key block damaged (or replaced) after `passh unlock` isn't carried into
// saves through the agent: the agent refuses the key for it, the caller
// falls back to the passphrase, and the backups keep opening with it.
func TestDamagedKeyBlockNotCarried(t *testing.T) {
	e := isolate(t)
	ctx := context.Background()
	const pass = "agent test passphrase"
	e.keyBlock = cheapKeyBlock(t, e.key, pass)
	plain := `{"format":"passh-vault-data","version":1,"vault_id":"0f6c1d2e-agent-test","revision":1,` +
		`"saved_at":"2026-11-15T12:00:00Z","entries":[],"deleted":[]}`
	db, err := keys.EncryptData(e.key, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(e.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.vault, file, 0o600); err != nil {
		t.Fatal(err)
	}
	serve(t, e, time.Minute, time.Minute)

	opts := vault.Options{StateDir: filepath.Join(e.root, "vault-state"), BackupKeep: 3}
	ks := KeySource{Vault: e.vault}
	v, err := vault.Open(ctx, e.vault, ks, opts)
	if err != nil {
		t.Fatalf("open through the agent: %v", err)
	}
	if _, err := v.Add(model.Entry{Path: paths.MustParse("a"), Password: "pw"}, false); err != nil {
		t.Fatal(err)
	}

	// One byte of the key block's encrypted payload flips on disk.
	cur, _ := os.ReadFile(e.vault)
	f, err := vaultfile.Parse(cur)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(f.KeyBlock)
	bad[len(bad)-3] ^= 0x01
	damaged, err := vaultfile.Encode(bad, f.DataBlock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.vault, damaged, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = vault.Open(ctx, e.vault, ks, opts)
	if !errors.Is(err, ErrKeyBlockChanged) || !errors.Is(err, ErrNoAgent) {
		t.Fatalf("open of the damaged vault through the agent: %v", err)
	}
	if _, err := v.Add(model.Entry{Path: paths.MustParse("b"), Password: "pw"}, false); !errors.Is(err, vault.ErrChanged) {
		t.Fatalf("save of the vault opened before: %v", err)
	}
	if err := v.Reload(ctx); !errors.Is(err, ErrKeyBlockChanged) {
		t.Fatalf("reload: %v", err)
	}
	if got, _ := os.ReadFile(e.vault); !bytes.Equal(got, damaged) {
		t.Fatal("the vault was saved")
	}
	// The passphrase tells the user, and every backup still opens with it.
	pp := &keys.PassphraseSource{Read: func(string) ([]byte, error) { return []byte(pass), nil }}
	if _, err := vault.Open(ctx, e.vault, pp, opts); !errors.Is(err, vault.ErrWrongPassphrase) {
		t.Fatalf("passphrase on the damaged vault: %v", err)
	}
	list, err := vault.ListBackups(opts.StateDir, "")
	if err != nil || len(list) == 0 {
		t.Fatalf("backups %v, %v", list, err)
	}
	for _, b := range list {
		if _, err := vault.Open(ctx, b.Path, pp, opts); err != nil {
			t.Errorf("backup r%d with the passphrase: %v", b.Revision, err)
		}
	}
}

// Through the agent, a data block the agent's key doesn't open is named as
// damage (§4.5): the agent's key belongs to the file's key block, and a
// rekey always writes a new one. No fallback to the passphrase.
func TestDataDamageThroughAgent(t *testing.T) {
	e := isolate(t)
	ctx := context.Background()
	e.keyBlock = cheapKeyBlock(t, e.key, "agent test passphrase")
	plain := []byte(`{"format":"passh-vault-data","version":1,"vault_id":"0f6c1d2e-agent-damage","revision":1,` +
		`"saved_at":"2026-11-15T12:00:00Z","entries":[],"deleted":[]}`)
	db, err := keys.EncryptData(e.key, plain)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, e, time.Minute, time.Minute)
	opts := vault.Options{StateDir: filepath.Join(e.root, "vault-state"), BackupKeep: 3}

	// A stanza no key opens (a damaged age header in block 2), and a data
	// block encrypted to a fresh key.
	flipped := bytes.Clone(db)
	i := bytes.Index(flipped, []byte("\n-> X25519 "))
	body := i + 1 + bytes.IndexByte(flipped[i+1:], '\n') + 1
	if flipped[body] == 'A' {
		flipped[body] = 'B'
	} else {
		flipped[body] = 'A'
	}
	fresh, _ := age.GenerateX25519Identity()
	foreign, err := keys.EncryptData(fresh, plain)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string][]byte{"damaged header": flipped, "another key": foreign} {
		file, err := vaultfile.Encode(e.keyBlock, block)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(e.vault, file, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = vault.Open(ctx, e.vault, KeySource{Vault: e.vault}, opts)
		if !errors.Is(err, keys.ErrDataDamaged) || errors.Is(err, keys.ErrKeyMismatch) || errors.Is(err, ErrNoAgent) ||
			!strings.Contains(err.Error(), "data is damaged; restore a backup") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
