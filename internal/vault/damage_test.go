package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/vaultfile"
)

// knownErr reports whether err is one of the problems of §4.5.
func knownErr(err error) bool {
	for _, target := range []error{ErrNotVault, ErrNewer, ErrTruncated, ErrDamaged, ErrWrongPassphrase, ErrNotVaultKey, ErrDataDamaged} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// Safety test 10 at the vault level: truncating the vault at any point, or
// flipping any byte, gives an *OpenError naming the problem and no data.
// The few mutations that open are layout-only (§4.5 leniency) and give the
// complete, original data. The passphrase is used (with a cheap key block),
// so damage to the key block is detected too.
func TestDamageAtEveryOffset(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	const secret = "Damage-Secret-17"
	mustAdd(t, v, "w/x", secret)
	orig := e.read()
	want := v.Entries()
	recipient := e.key.Recipient().String()
	path := filepath.Join(e.dir, "damaged.passh")
	ks := passSource(testPass, nil)

	kinds := map[string]int{}
	try := func(desc string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := Open(context.Background(), path, ks, e.opts())
		if err == nil {
			if !slices.EqualFunc(w.Entries(), want, model.Entry.Equal) {
				t.Fatalf("%s: opened with different data", desc)
			}
			kinds["opened"]++
			return
		}
		if w != nil {
			t.Fatalf("%s: a vault came back with the error %v", desc, err)
		}
		var oe *OpenError
		if !errors.As(err, &oe) || !knownErr(err) {
			t.Fatalf("%s: error doesn't name a problem of §4.5: %v", desc, err)
		}
		msg := err.Error()
		if strings.Contains(msg, secret) || strings.Contains(msg, "age1") || strings.Contains(msg, recipient) {
			t.Fatalf("%s: error message leaks: %q", desc, msg)
		}
		for _, k := range []error{ErrNotVault, ErrTruncated, ErrDamaged, ErrWrongPassphrase, ErrDataDamaged, ErrNewer, ErrNotVaultKey} {
			if errors.Is(err, k) {
				kinds[k.Error()]++
				break
			}
		}
	}

	for n := range len(orig) {
		try("truncated at "+strconv.Itoa(n), orig[:n])
	}
	if kinds["opened"] != 1 { // only dropping the final newline
		t.Fatalf("truncations that opened: %d", kinds["opened"])
	}
	for i := range orig {
		for _, m := range []byte{0x01, 0x40, 0xff} {
			b := bytes.Clone(orig)
			b[i] ^= m
			try("flip "+strconv.Itoa(int(m))+" at "+strconv.Itoa(i), b)
		}
	}
	t.Logf("%d bytes: %v", len(orig), kinds)
	for _, k := range []error{ErrNotVault, ErrTruncated, ErrDamaged, ErrWrongPassphrase, ErrDataDamaged} {
		if kinds[k.Error()] == 0 {
			t.Errorf("no mutation gave %q", k)
		}
	}
}

// A data block encrypted to another key is rejected, with the key or with
// the passphrase, even when its content is a valid vault of the same id.
func TestDataBlockOfAnotherKey(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	snap := v.Snapshot()
	snap.Revision++
	plain, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := keys.NewVaultKey()
	db, err := keys.EncryptData(other, plain)
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(e.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	e.write(file)
	// With the passphrase or the agent, the key belongs to this file's key
	// block: the file is damaged (or tampered with), "data is damaged",
	// and not a key mismatch that would send the CLI to another key.
	var oe *OpenError
	for name, ks := range map[string]keys.KeySource{"passphrase": passSource(testPass, nil), "agent": checkedSource{keys.FromIdentity(e.key)}} {
		_, err = Open(context.Background(), e.path, ks, e.opts())
		if !errors.As(err, &oe) || errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrDataDamaged) {
			t.Fatalf("foreign data block, %s: %v", name, err)
		}
		if !strings.Contains(err.Error(), "data is damaged; restore a backup") || !oe.BackupsMatched || len(oe.Backups) == 0 {
			t.Errorf("%s: message %q", name, err)
		}
	}
	// With a key from elsewhere (agent, paper key), the key may just be
	// stale: no advice to restore a backup over a possibly newer vault.
	_, err = Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	if !errors.As(err, &oe) || !errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrWrongKey) || errors.Is(err, ErrDataDamaged) {
		t.Fatalf("foreign data block, key: %v", err)
	}
	if msg := err.Error(); msg != e.path+": this key doesn't open this vault (rekeyed elsewhere? wrong recovery key?)" || len(oe.Backups) != 0 {
		t.Errorf("message %q", msg)
	}
	// The other key opens its data block, but not with this key block's
	// passphrase: the vault is all or nothing.
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(other), e.opts()); err != nil {
		t.Fatalf("the data block's own key: %v", err)
	}
}

// A key block of another passphrase-wrapped key, or one holding something
// else than one vault key, is reported as such.
func TestBadKeyBlock(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	f, _ := vaultfile.Parse(e.read())

	_, err := Open(context.Background(), e.path, passSource("not the passphrase", nil), e.opts())
	if !errors.Is(err, ErrWrongPassphrase) || !strings.HasSuffix(err.Error(), "wrong passphrase, or the key block is damaged") {
		t.Fatalf("wrong passphrase: %v", err)
	}

	other, _ := keys.NewVaultKey()
	file, _ := vaultfile.Encode(lowKeyBlock(t, other, testPass), f.DataBlock)
	e.write(file)
	if _, err := Open(context.Background(), e.path, passSource(testPass, nil), e.opts()); !errors.Is(err, ErrDataDamaged) || errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("key block of another key: %v", err)
	}
}

// Errors of the key source that aren't about the file pass through as
// they are (e.g. "vault is locked" from the CLI).
func TestKeySourceError(t *testing.T) {
	e := newEnv(t)
	locked := errors.New("vault is locked: run `passh unlock` in a terminal")
	_, err := Open(context.Background(), e.path, failingSource{locked}, e.opts())
	if err != locked {
		t.Fatalf("key source error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, e.path, keys.FromIdentity(e.key), e.opts()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	if _, err := Open(context.Background(), e.path, nil, e.opts()); err == nil {
		t.Fatal("no key source")
	}
}

type failingSource struct{ err error }

func (f failingSource) VaultKey(context.Context, []byte) (*age.X25519Identity, error) {
	return nil, f.err
}

// checkedSource is a key source that checks the key block, as the agent's
// does (keys.KeyBlockChecker).
type checkedSource struct{ keys.KeySource }

func (checkedSource) ChecksKeyBlock() bool { return true }

// flipStanza changes one character of the wrapped file key in the data
// block's X25519 stanza: the block still parses, but no key opens it.
func flipStanza(t *testing.T, file []byte) []byte {
	t.Helper()
	f, err := vaultfile.Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	db := bytes.Clone(f.DataBlock)
	i := bytes.Index(db, []byte("\n-> X25519 "))
	if i < 0 {
		t.Fatal("no X25519 stanza")
	}
	body := i + 1 + bytes.IndexByte(db[i+1:], '\n') + 1 // the stanza's body line
	if db[body] == 'A' {
		db[body] = 'B'
	} else {
		db[body] = 'A'
	}
	out, err := vaultfile.Encode(f.KeyBlock, db)
	if err != nil {
		t.Fatalf("the flipped block doesn't parse: %v", err)
	}
	return out
}

// A damaged data block header (a stanza no key opens) is "data is damaged"
// for a key that belongs to the key block (passphrase, agent), also on
// Reload; a paper key is told it doesn't open this vault.
func TestDamagedStanza(t *testing.T) {
	e := newEnv(t)
	agentLike := checkedSource{keys.FromIdentity(e.key)}
	a, err := Open(context.Background(), e.path, agentLike, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	paper := e.open()
	mustAdd(t, a, "a", "pw")
	if err := paper.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.write(flipStanza(t, e.read()))

	for name, ks := range map[string]keys.KeySource{"passphrase": passSource(testPass, nil), "agent": agentLike} {
		_, err := Open(context.Background(), e.path, ks, e.opts())
		var oe *OpenError
		if !errors.As(err, &oe) || !errors.Is(err, ErrDataDamaged) || errors.Is(err, ErrKeyMismatch) || len(oe.Backups) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := a.Reload(context.Background()); !errors.Is(err, ErrDataDamaged) || errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("reload of a vault opened through the agent: %v", err)
	}
	if _, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts()); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("paper key: %v", err)
	}
	if err := paper.Reload(context.Background()); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("reload of a vault opened with a paper key: %v", err)
	}
}
