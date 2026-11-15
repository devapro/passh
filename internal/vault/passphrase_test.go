package vault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/vaultfile"
)

// These tests use passh's real scrypt work factor (2^18, about a second and
// 256 MiB each), so they run in parallel and keep the number of
// passphrase operations small.

// Create (passh init) with a real passphrase: the passphrase opens it.
func TestCreateWithPassphrase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "vault.passh")
	o := Options{StateDir: filepath.Join(dir, "state"), BackupKeep: 10, RollbackWarn: true}
	v, err := Create(path, []byte("correct horse battery staple"), o)
	if err != nil {
		t.Fatal(err)
	}
	if v.Key() == nil || v.Info().Revision != FirstRevision || v.Info().Entries != 0 {
		t.Fatalf("created %+v", v.Info())
	}
	var asked atomic.Int32
	w, err := Open(context.Background(), path, passSource("correct horse battery staple", &asked), o)
	if err != nil {
		t.Fatal(err)
	}
	if w.Info().VaultID != v.Info().VaultID || w.Key().String() != v.Key().String() || asked.Load() != 1 {
		t.Fatal("reopened vault differs")
	}
	if m := mode(t, path); m != 0o600 {
		t.Fatalf("mode %o", m)
	}
	checkNoRecipient(t, v.Key(), dir)
	// An empty passphrase is refused before anything is written.
	if _, err := Create(filepath.Join(dir, "empty.passh"), nil, o); !errors.Is(err, keys.ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
}

// Passwd rewrites the key block only: the vault key (the paper key) stays
// valid, the new passphrase opens the vault and the old one doesn't.
func TestPasswd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	before, _ := vaultfile.Parse(e.read())

	if err := v.Passwd([]byte("new passphrase words")); err != nil {
		t.Fatal(err)
	}
	after, _ := vaultfile.Parse(e.read())
	if bytes.Equal(after.KeyBlock, before.KeyBlock) || v.Info().Revision != 3 {
		t.Fatal("the key block didn't change")
	}
	// The old paper key still opens the new file.
	if w := e.open(); w.Info().Revision != 3 || w.Info().Entries != 1 {
		t.Fatalf("paper key after passwd: %+v", w.Info())
	}
	if _, err := Open(context.Background(), e.path, passSource("new passphrase words", nil), e.opts()); err != nil {
		t.Fatalf("new passphrase: %v", err)
	}
	if _, err := Open(context.Background(), e.path, passSource(testPass, nil), e.opts()); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase: %v", err)
	}
	// The backup made by passwd still opens with the old passphrase.
	list, _ := v.Backups()
	if _, err := Open(context.Background(), list[0].Path, passSource(testPass, nil), e.opts()); err != nil {
		t.Fatalf("backup with the old passphrase: %v", err)
	}
	// Further saves copy the new key block byte for byte.
	mustAdd(t, v, "b", "pw")
	if again, _ := vaultfile.Parse(e.read()); !bytes.Equal(again.KeyBlock, after.KeyBlock) {
		t.Fatal("a save changed the key block")
	}
}

// Rekey makes a new vault key: the old key no longer opens new versions;
// old backups still open with the old key and passphrase.
func TestRekey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	oldKey := e.key

	newKey, err := v.Rekey([]byte("rekeyed passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if newKey == nil || newKey.String() == oldKey.String() || v.Key() != newKey {
		t.Fatal("Rekey kept the key")
	}
	if v.Info().Revision != 3 || v.Info().Entries != 1 {
		t.Fatalf("after rekey %+v", v.Info())
	}
	// The old key (agent, paper) is stale: said so, without advice to
	// restore a backup over the newer vault.
	_, err = Open(context.Background(), e.path, keys.FromIdentity(oldKey), e.opts())
	if !errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrWrongKey) || errors.Is(err, ErrDataDamaged) ||
		strings.Contains(err.Error(), "restore") {
		t.Fatalf("old key after rekey: %v", err)
	}
	w, err := Open(context.Background(), e.path, passSource("rekeyed passphrase", nil), e.opts())
	if err != nil || w.Key().String() != newKey.String() || w.Info().VaultID != v.Info().VaultID {
		t.Fatalf("new passphrase: %v", err)
	}
	// Backups from before the rekey open with what was valid then.
	list, _ := v.Backups()
	if len(list) != 2 {
		t.Fatalf("backups %v", list)
	}
	for _, b := range list {
		if _, err := Open(context.Background(), b.Path, keys.FromIdentity(oldKey), e.opts()); err != nil {
			t.Fatalf("backup r%d with the old key: %v", b.Revision, err)
		}
		if _, err := Open(context.Background(), b.Path, passSource(testPass, nil), e.opts()); err != nil {
			t.Fatalf("backup r%d with the old passphrase: %v", b.Revision, err)
		}
	}
	// Saves go on with the new key.
	mustAdd(t, v, "b", "pw")
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(newKey), e.opts()); err != nil {
		t.Fatal(err)
	}
	checkNoRecipient(t, oldKey, e.dir, e.state)
	checkNoRecipient(t, newKey, e.dir, e.state)
}

// passh recover: the typed paper key opens the vault, then a new
// passphrase is set; the forgotten one no longer matters. Here the key
// block is damaged too, the case recovery exists for.
func TestRecover(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	e.write(damageKeyBlockHeader(t, e.read()))

	typed := "  " + keys.FormatRecoveryKey(e.key) + "\n"
	paper, err := keys.ParseRecoveryKey(typed)
	if err != nil {
		t.Fatal(err)
	}
	o := e.opts()
	o.Recovery = true
	r, err := Open(context.Background(), e.path, keys.FromIdentity(paper), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Passwd([]byte("remembered this time")); err != nil {
		t.Fatal(err)
	}
	w, err := Open(context.Background(), e.path, passSource("remembered this time", nil), e.opts())
	if err != nil || w.Info().Entries != 1 || w.Key().String() != e.key.String() {
		t.Fatalf("after recover: %v", err)
	}
	// A paper key of another vault doesn't open it.
	stranger, _ := keys.NewVaultKey()
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(stranger), e.opts()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("another vault's paper key: %v", err)
	}
}
