// Package vault opens and saves the passh vault file (spec §4.5–§4.7,
// §4.10, §5.4, §10.3): opening with the strict checks of §4.5, saving in the
// seven steps of §4.6 (lock, change check, encrypt, temporary file, read-back
// check, automatic backup, rename), the automatic backups of §4.7 and the
// rollback record of §4.10.
//
// A Vault holds the vault key and the decrypted data in memory, never on
// disk. Every change works on a copy of the data and replaces the in-memory
// state only after the save succeeded, so a failed save leaves the Vault as
// it was and the caller keeps the user's input.
//
// The package doesn't talk to the terminal: questions and warnings go
// through the callbacks in Options.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"passh/internal/config"
	"passh/internal/keys"
	"passh/internal/model"
	"passh/internal/paths"
	"passh/internal/vaultfile"
)

// FirstRevision is the revision of a new vault: Create is its first save.
const FirstRevision = 1

// Options configure a Vault. The zero value turns backups and the rollback
// warning off; passh passes the config file's values.
type Options struct {
	// StateDir is passh's state folder (§3.2): backups, locks and the
	// rollback record. Empty means config.StateDir().
	StateDir string
	// BackupKeep is backup.keep: how many automatic backups to keep for
	// each vault (§4.7). 0 turns backups off.
	BackupKeep int
	// RollbackWarn is rollback.warn (§4.10).
	RollbackWarn bool
	// RollbackReportOnly makes the rollback comparison without asking or
	// warning, and without lowering the record; the caller shows
	// Vault.Rollback() itself. For `verify --full` and merge's other file.
	RollbackReportOnly bool
	// Prompt asks whether to continue with a copy older than one seen
	// before. It gets the warning text of §4.10 and returns the answer.
	// nil means there is no terminal: the warning goes to Warn instead and
	// the command continues.
	Prompt func(warning string) (bool, error)
	// Warn receives warnings: text ignored around the vault (§4.5), the
	// rollback warning without a terminal, problems with backups or the
	// rollback record that don't stop the command. passh prints them to
	// stderr. nil drops them.
	Warn func(msg string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Recovery opens the vault for `passh recover`: a key block too
	// damaged to parse is tolerated if the data block opens with the key
	// (a paper key, keys.FromIdentity). Such a Vault saves only through
	// Passwd or Rekey, which write a new key block; other changes fail
	// with ErrKeyBlockDamaged.
	Recovery bool
}

// The callbacks run while the Vault is busy (opening, reloading or
// saving); they must not call the Vault's methods.

func (o Options) withDefaults() (Options, error) {
	if o.StateDir == "" {
		d, err := config.StateDir()
		if err != nil {
			return o, err
		}
		o.StateDir = d
	}
	d, err := filepath.Abs(o.StateDir)
	if err != nil {
		return o, err
	}
	o.StateDir = d
	if o.Now == nil {
		o.Now = time.Now
	}
	o.BackupKeep = max(o.BackupKeep, 0)
	return o, nil
}

// Vault is an opened vault. Its methods are safe for concurrent use.
type Vault struct {
	mu      sync.Mutex
	display string // the path as given, for messages
	path    string // absolute, possibly a symlink
	opts    Options
	ks      keys.KeySource

	real      string // path with symlinks resolved, when opened or saved
	sum       [sha256.Size]byte
	keyBlock  []byte
	key       *age.X25519Identity
	data      *model.Data
	warnings  []string
	canonical bool
	rollback  RollbackStatus
	closed    bool
	// keyChecked: the key is known to belong to keyBlock (a key source
	// that checks it, or a key block passh wrote itself).
	keyChecked bool
}

// Open opens the vault file (§4.5): lenient parse, the vault key from ks,
// decryption, strict checks, then the rollback check (§4.10). Every problem
// with the file comes back as an *OpenError; errors of ks (other than a
// wrong passphrase) come back as they are. Opening never writes the vault
// file; it may write the rollback record.
//
// The key block is checked only by a key source that uses it: a
// passphrase (keys.PassphraseSource) unwraps it, and the agent's
// KeySource compares it with the one `passh unlock` unwrapped. A vault
// opened with keys.FromIdentity (a paper key) has an unchecked key block,
// which every save copies; that is meant for `passh recover`, which
// rewrites the key block at once (Passwd).
func Open(ctx context.Context, file string, ks keys.KeySource, opts Options) (*Vault, error) {
	if ks == nil {
		return nil, errors.New("vault: no key source")
	}
	v, err := newVault(file, opts)
	if err != nil {
		return nil, err
	}
	v.ks = ks
	l, err := v.load(ctx, ks, nil)
	if err != nil {
		return nil, err
	}
	v.set(l)
	return v, nil
}

func newVault(file string, opts Options) (*Vault, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	return &Vault{display: file, path: abs, opts: o}, nil
}

// loaded is the state read from disk by load.
type loaded struct {
	real      string
	sum       [sha256.Size]byte
	keyBlock  []byte
	key       *age.X25519Identity
	data      *model.Data
	warnings  []string
	canonical bool
	rollback  RollbackStatus
	checked   bool
}

func (v *Vault) set(l *loaded) {
	v.real, v.sum, v.keyBlock, v.key, v.data = l.real, l.sum, l.keyBlock, l.key, l.data
	v.warnings, v.canonical, v.rollback, v.keyChecked = l.warnings, l.canonical, l.rollback, l.checked
}

// load reads and decrypts the vault file. If cur is set (Reload) and the
// key block is the one cur came with, cur is tried first and ks is asked
// only if it doesn't fit; a changed key block always goes through ks.
func (v *Vault) load(ctx context.Context, ks keys.KeySource, cur *age.X25519Identity) (*loaded, error) {
	real, err := realPath(v.path)
	if err != nil {
		return nil, fmt.Errorf("opening the vault: %w", err)
	}
	raw, err := readVaultFile(real)
	switch {
	case errors.Is(err, errTooLarge), errors.Is(err, errNotRegular):
		return nil, &OpenError{Path: v.display, Err: err}
	case err != nil:
		return nil, fmt.Errorf("opening the vault: %w", err)
	}
	l := &loaded{real: real, sum: sha256.Sum256(raw)}

	var keyBlock, dataBlock []byte
	f, err := vaultfile.Parse(raw)
	switch {
	case err == nil:
		keyBlock, dataBlock = f.KeyBlock, f.DataBlock
		l.warnings, l.canonical = f.Warnings, f.Canonical
		for _, w := range f.Warnings {
			v.warn(v.display + ": " + w)
		}
	case v.opts.Recovery && damagedKeyBlock(err):
		// For recover: the data block alone, opened with the paper key.
		db, ok := lastBlock(raw)
		if !ok {
			return nil, &OpenError{Path: v.display, Err: err}
		}
		dataBlock = db
		l.warnings = []string{"the key block is damaged; setting a new passphrase rewrites it"}
		v.warn(v.display + ": " + l.warnings[0])
	default:
		return nil, &OpenError{Path: v.display, Err: err}
	}
	l.keyBlock = keyBlock

	var plain []byte
	if cur != nil {
		if keyBlock == nil || !bytes.Equal(keyBlock, v.keyBlock) {
			if ks == nil {
				return nil, ErrKeyBlockChanged
			}
		} else {
			plain, err = keys.DecryptData(cur, dataBlock)
			switch {
			case err == nil:
				l.key, l.checked = cur, v.keyChecked
			case !errors.Is(err, ErrKeyMismatch) || ks == nil || v.keyChecked:
				return nil, v.damaged(keyBlock, cur, v.keyChecked, err)
			}
		}
	}
	if l.key == nil {
		key, err := ks.VaultKey(ctx, keyBlock)
		if err != nil {
			if errors.Is(err, ErrWrongPassphrase) || errors.Is(err, ErrNotVaultKey) {
				return nil, &OpenError{Path: v.display, Err: err}
			}
			return nil, err
		}
		if key == nil {
			return nil, errors.New("vault: the key source gave no key")
		}
		plain, err = keys.DecryptData(key, dataBlock)
		if err != nil {
			if l.keyBlock == nil {
				// Recovery: report the damaged key block, not the key.
				_, perr := vaultfile.Parse(raw)
				return nil, &OpenError{Path: v.display, Err: perr}
			}
			return nil, v.damaged(keyBlock, key, keys.ChecksKeyBlock(ks), err)
		}
		l.key, l.checked = key, keys.ChecksKeyBlock(ks)
	}
	data, err := model.Decode(plain)
	keys.Zero(plain)
	if err != nil {
		if errors.Is(err, model.ErrNewerVersion) {
			return nil, &OpenError{Path: v.display, Err: fmt.Errorf("%w (data version)", ErrNewer)}
		}
		return nil, v.damaged(keyBlock, l.key, l.checked, dataDamaged(err))
	}
	l.data = data

	l.rollback, err = v.checkRollback(data.VaultID, data.Revision, data.SavedAt, real)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// damagedKeyBlock reports whether a parse error is about block 1 only.
func damagedKeyBlock(err error) bool {
	var de *vaultfile.DamagedError
	return errors.As(err, &de) && de.Block == 1
}

// lastBlock extracts the last armored age block of a vault file (the data
// block) without looking at what comes before it, for recovering a vault
// whose key block is damaged. It is as lenient as vaultfile.Parse about
// line endings and wrapping; decryption checks every byte.
func lastBlock(raw []byte) ([]byte, bool) {
	var lines [][]byte
	for _, l := range bytes.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' }) {
		lines = append(lines, bytes.TrimSpace(l))
	}
	begin := -1
	for i, l := range lines {
		if string(l) == armor.Header {
			begin = i
		}
	}
	if begin < 0 {
		return nil, false
	}
	var b64 []byte
	for _, l := range lines[begin+1:] {
		if string(l) == armor.Footer {
			block := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
			n, err := base64.StdEncoding.Strict().Decode(block, b64)
			if err != nil || n == 0 {
				return nil, false
			}
			return block[:n], true
		}
		b64 = append(b64, l...)
	}
	return nil, false
}

// damaged builds the "data is damaged" error with the automatic backups
// that may hold this vault. A data block that isn't encrypted to the key
// is damage (or a replaced block) if the key is known to belong to this
// file's key block (checked: a passphrase, the agent; see
// keys.KeyBlockChecker), since a rekey always writes a new key block. A key
// from elsewhere (a paper key) may simply be another vault's or older than
// a rekey: ErrWrongKey, without backups.
func (v *Vault) damaged(keyBlock []byte, key *age.X25519Identity, checked bool, err error) error {
	if errors.Is(err, ErrKeyMismatch) {
		if !checked {
			return &OpenError{Path: v.display, Err: wrongKey{}}
		}
		// Not keys.ErrKeyMismatch any more: callers must not fall back to
		// another key source for a damaged file.
		err = errNotEncryptedToKey
	}
	e := &OpenError{Path: v.display, Err: err}
	list, matched, lerr := findBackups(v.opts.StateDir, keyBlock, key)
	if lerr == nil {
		e.Backups, e.BackupsMatched = list, matched
	}
	return e
}

// Create makes a new vault at file for `passh init` (§5.4): a new vault key
// wrapped with passphrase, a new vault_id, no entries, revision
// FirstRevision. It refuses if anything exists at file (ErrExists). The
// file is written like every save: temporary file, fsync, read-back check,
// rename, folder fsync. Missing folders are created with mode 0700.
//
// The returned Vault is open; Key gives the vault key for the recovery
// sheet. The caller owns passphrase and should wipe it.
func Create(file string, passphrase []byte, opts Options) (*Vault, error) {
	v, err := newVault(file, opts)
	if err != nil {
		return nil, err
	}
	// Refuse before running scrypt.
	if err := v.checkFree(); err != nil {
		return nil, err
	}
	key, err := keys.NewVaultKey()
	if err != nil {
		return nil, err
	}
	keyBlock, err := keys.WrapKey(key, passphrase)
	if err != nil {
		return nil, err
	}
	if err := v.create(key, keyBlock); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Vault) checkFree() error {
	if _, err := os.Lstat(v.path); err == nil {
		return fmt.Errorf("%s: %w", v.display, ErrExists)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// create writes a new, empty vault with the given key and key block.
func (v *Vault) create(key *age.X25519Identity, keyBlock []byte) error {
	o := &v.opts
	if err := mkdirs(filepath.Dir(v.path)); err != nil {
		return fmt.Errorf("creating the vault's folder: %w", err)
	}
	dir, err := realPath(filepath.Dir(v.path))
	if err != nil {
		return err
	}
	name := filepath.Base(v.path)
	real := filepath.Join(dir, name)
	if v.inBackups(real) {
		return ErrBackupFile
	}
	if err := mkdirs(locksDir(o.StateDir)); err != nil {
		return fmt.Errorf("creating the state folder: %w", err)
	}
	lock, err := lockFile(vaultLockPath(o.StateDir, real))
	if err != nil {
		return err
	}
	defer lock.unlock()
	if _, err := removeTemps(dir, name); err != nil {
		return fmt.Errorf("removing leftover temporary files: %w", err)
	}
	hook(hookLocked, real)
	if err := v.checkFree(); err != nil {
		return err
	}

	data := model.NewData()
	data.Revision = FirstRevision
	data.SavedAt = o.Now().UTC().Truncate(time.Second)
	content, err := encodeVault(data, keyBlock, key)
	if err != nil {
		return err
	}
	t, err := writeTemp(dir, name, content, hookTempCreated, hookTempWritten, hookTempSynced)
	if err != nil {
		return fmt.Errorf("writing the vault file: %w", err)
	}
	if err := verifyFile(t.path, content, keyBlock, key, data); err != nil {
		t.discard()
		return err
	}
	hook(hookVerified, t.path)
	hook(hookBeforeRename, t.path)
	// Never over a file that appeared since the check (a sync tool, a
	// copy): the rename fails instead.
	if err := renameNoReplace(t.path, real); err != nil {
		t.discard()
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", v.display, ErrExists)
		}
		return fmt.Errorf("writing the vault file: %w", err)
	}
	t.close()
	hook(hookRenamed, real)
	if err := syncDir(dir); err != nil {
		v.warn(fmt.Sprintf("the vault's folder couldn't be flushed to disk: %v", err))
	}
	hook(hookDirSynced, dir)

	v.real, v.sum, v.keyBlock, v.key, v.data = real, sha256.Sum256(content), keyBlock, key, data
	v.canonical, v.keyChecked = true, true
	v.rollback = RollbackStatus{Revision: data.Revision, SavedAt: data.SavedAt}
	v.record(data.VaultID, data.Revision, data.SavedAt, false)
	return nil
}

func vaultLockPath(stateDir, real string) string {
	return filepath.Join(locksDir(stateDir), "vault-"+hashName(real)+".lock")
}

// encodeVault serializes data, encrypts it to key and returns the canonical
// vault file with keyBlock.
func encodeVault(data *model.Data, keyBlock []byte, key *age.X25519Identity) ([]byte, error) {
	plain, err := data.Encode()
	if err != nil {
		return nil, err
	}
	defer keys.Zero(plain)
	dataBlock, err := keys.EncryptData(key, plain)
	if err != nil {
		return nil, err
	}
	return vaultfile.Encode(keyBlock, dataBlock)
}

// verifyFile is step 5 of §4.6: the temporary file must hold exactly
// content, parse, carry keyBlock, and decrypt with key to data.
func verifyFile(tmp string, content, keyBlock []byte, key *age.X25519Identity, data *model.Data) error {
	got, err := os.ReadFile(tmp)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if !bytes.Equal(got, content) {
		return fmt.Errorf("%w: the bytes differ", ErrVerify)
	}
	f, err := vaultfile.Parse(got)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if !bytes.Equal(f.KeyBlock, keyBlock) {
		return fmt.Errorf("%w: the key block differs", ErrVerify)
	}
	plain, err := keys.DecryptData(key, f.DataBlock)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	defer keys.Zero(plain)
	want, err := data.Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	defer keys.Zero(want)
	if !bytes.Equal(plain, want) {
		return fmt.Errorf("%w: the data differs", ErrVerify)
	}
	back, err := model.Decode(plain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	if back.VaultID != data.VaultID || back.Revision != data.Revision || len(back.Entries) != len(data.Entries) {
		return fmt.Errorf("%w: the data differs", ErrVerify)
	}
	return nil
}

// commit saves next as a new revision with keyBlock and key, in the steps
// of §4.6, and makes it the in-memory state. v.mu is held.
//
// The file is checked against the one that was opened three times: under
// the lock (step 2), again right before the backup and the rename (step
// 6), and by the rename itself: the new file is exchanged with the vault
// atomically, and if what came out isn't the opened file, the exchange is
// undone (ErrChanged). So a copy that a sync tool or another program puts
// in place meanwhile is never overwritten. Where the file system can't
// exchange files (macOS without RENAME_SWAP, FAT, some network file
// systems), a plain rename follows the second check, which leaves a window
// of microseconds.
func (v *Vault) commit(next *model.Data, keyBlock []byte, key *age.X25519Identity) error {
	o := &v.opts
	if keyBlock == nil {
		return ErrKeyBlockDamaged
	}

	// 1. Lock, keyed by the real path; remove leftover temporary files.
	real, err := realPath(v.path)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrChanged
	}
	if err != nil {
		return err
	}
	if real != v.real {
		return ErrChanged // the symlink points elsewhere now
	}
	if v.inBackups(real) {
		return ErrBackupFile
	}
	if err := mkdirs(locksDir(o.StateDir)); err != nil {
		return fmt.Errorf("creating the state folder: %w", err)
	}
	lock, err := lockFile(vaultLockPath(o.StateDir, real))
	if err != nil {
		return err
	}
	defer lock.unlock()
	dir, name := filepath.Dir(real), filepath.Base(real)
	if _, err := removeTemps(dir, name); err != nil {
		return fmt.Errorf("removing leftover temporary files: %w", err)
	}
	hook(hookLocked, real)

	// 2. The file must still be the one that was opened.
	if _, err := v.readUnchanged(real); err != nil {
		return err
	}
	hook(hookChecked, real)

	// 3. Revision + 1, encrypt; the key block as given (the current one,
	// byte for byte, except for passwd and rekey).
	now := o.Now()
	next.Revision = max(next.Revision, v.data.Revision) + 1
	next.SavedAt = now.UTC().Truncate(time.Second)
	content, err := encodeVault(next, keyBlock, key)
	if err != nil {
		return err
	}

	// 4. Temporary file, mode 0600, fsync.
	t, err := writeTemp(dir, name, content, hookTempCreated, hookTempWritten, hookTempSynced)
	if err != nil {
		return fmt.Errorf("writing the new vault file: %w; the vault is unchanged", err)
	}
	installed := false
	defer func() {
		if !installed {
			t.discard()
		}
	}()

	// 5. Read back and compare.
	if err := verifyFile(t.path, content, keyBlock, key, next); err != nil {
		return err
	}
	hook(hookVerified, t.path)

	// 6. Read the vault again and back up exactly those bytes.
	cur, err := v.readUnchanged(real)
	if err != nil {
		return err
	}
	hook(hookRechecked, real)
	if o.BackupKeep > 0 {
		_, rotErr, err := writeBackup(o.StateDir, v.data.VaultID, v.data.Revision, cur, now, o.BackupKeep, real)
		if err != nil {
			return fmt.Errorf("making the automatic backup: %w; the vault is unchanged", err)
		}
		if rotErr != nil {
			v.warn(fmt.Sprintf("old automatic backups couldn't be removed: %v", rotErr))
		}
	}

	// 7. Replace the vault (its target, if it is a symlink), then fsync
	// the folder.
	hook(hookBeforeRename, t.path)
	if err := v.replace(t, real, content, now); err != nil {
		return err
	}
	installed = true
	// The new file is in place: from here on the save has happened.
	if err := syncDir(dir); err != nil {
		v.warn(fmt.Sprintf("the vault's folder couldn't be flushed to disk: %v", err))
	}
	hook(hookDirSynced, dir)

	if !bytes.Equal(keyBlock, v.keyBlock) {
		v.keyChecked = true // Passwd, Rekey: passh wrapped this key itself
	}
	v.sum, v.keyBlock, v.key, v.data = sha256.Sum256(content), keyBlock, key, next
	v.canonical, v.warnings = true, nil
	v.record(next.VaultID, next.Revision, next.SavedAt, false)
	return nil
}

// readUnchanged reads the vault file and checks that it is the one that
// was opened or last saved (ErrChanged otherwise).
func (v *Vault) readUnchanged(real string) ([]byte, error) {
	cur, err := readVaultFile(real)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrChanged
	}
	if err != nil {
		return nil, fmt.Errorf("reading the vault file again: %w", err)
	}
	if sha256.Sum256(cur) != v.sum {
		return nil, ErrChanged
	}
	return cur, nil
}

// replace puts the temporary file t (holding content) in place of the vault
// at real. With an exchanging rename, the file that comes out must be the
// one that was opened; if it isn't, the exchange is undone and ErrChanged
// returned. On success t is closed.
func (v *Vault) replace(t *tempFile, real string, content []byte, now time.Time) error {
	err := exchangeFiles(t.path, real)
	switch {
	case errors.Is(err, errNoAtomicRename):
		if err := os.Rename(t.path, real); err != nil {
			return fmt.Errorf("replacing the vault file: %w; the vault is unchanged", err)
		}
		hook(hookRenamed, real)
		return t.close()
	case errors.Is(err, fs.ErrNotExist):
		return ErrChanged // the vault was removed
	case err != nil:
		return fmt.Errorf("replacing the vault file: %w; the vault is unchanged", err)
	}
	hook(hookRenamed, real)

	// t.path now holds what was the vault an instant ago.
	old, err := readVaultFile(t.path)
	if err == nil && sha256.Sum256(old) != v.sum {
		// Replaced after the check: put the other file back.
		if err := exchangeFiles(t.path, real); err != nil {
			kept := v.keepAside(t.path, now)
			return fmt.Errorf("%w; the save couldn't be undone (%v): the vault now holds this save, the other version is in %s", ErrChanged, err, kept)
		}
		if back, err := readVaultFile(t.path); err != nil || sha256.Sum256(back) != sha256.Sum256(content) {
			// Yet another replacement in between: keep whatever came out.
			kept := v.keepAside(t.path, now)
			return fmt.Errorf("%w; a file that was in its place is kept in %s", ErrChanged, kept)
		}
		return ErrChanged
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		v.warn(fmt.Sprintf("the replaced vault file couldn't be checked: %v", err))
	}
	if err := os.Remove(t.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		v.warn(fmt.Sprintf("the replaced vault file couldn't be removed (the next save removes it): %v", err))
	}
	hook(hookOldRemoved, t.path)
	return t.close()
}

// keepAside renames a file that must not be lost to a visible name next to
// the vault: <name>.conflict-<UTC time>.passh. It returns where it is.
func (v *Vault) keepAside(path string, now time.Time) string {
	dir := filepath.Dir(path)
	base := strings.TrimSuffix(filepath.Base(v.real), ".passh") + ".conflict-" + now.UTC().Format(BackupTimeFormat)
	for n := 1; n < 100; n++ {
		dst := filepath.Join(dir, base+".passh")
		if n > 1 {
			dst = filepath.Join(dir, base+"-"+strconv.Itoa(n)+".passh")
		}
		err := renameNoReplace(path, dst)
		if err == nil {
			return dst
		}
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	return path
}

func (v *Vault) warn(msg string) {
	if v.opts.Warn != nil {
		v.opts.Warn(msg)
	}
}

// mutate applies fn to a copy of the data and saves the copy if fn reports
// a change. The in-memory data changes only if the save succeeds.
func (v *Vault) mutate(fn func(d *model.Data, now time.Time) (changed bool, err error)) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	next := v.data.Clone()
	changed, err := fn(next, v.opts.Now())
	if err != nil || !changed {
		return err
	}
	return v.commit(next, v.keyBlock, v.key)
}

// Entries returns copies of all entries, sorted by path.
func (v *Vault) Entries() []model.Entry {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	return v.data.List()
}

// Get returns a copy of the entry at p.
func (v *Vault) Get(p paths.Path) (model.Entry, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return model.Entry{}, false
	}
	return v.data.Get(p)
}

// GetByID returns a copy of the entry with this id.
func (v *Vault) GetByID(id string) (model.Entry, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return model.Entry{}, false
	}
	return v.data.GetByID(id)
}

// Snapshot returns a deep copy of the data, for listing, filtering, tag
// counts and export. Changing it changes nothing in the vault.
func (v *Vault) Snapshot() *model.Data {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	return v.data.Clone()
}

// Put stores e and saves (§10.3). An e.ID of an existing entry updates that
// entry (Update, which also moves it if e.Path differs); an empty e.ID adds
// a new entry and fails with model.ErrExists if e.Path is taken (Add
// without overwrite).
func (v *Vault) Put(e model.Entry) error {
	if e.ID != "" {
		_, err := v.Update(e)
		return err
	}
	_, err := v.Add(e, false)
	return err
}

// Add stores a new entry at e.Path and saves (`passh add`, `generate`).
// If the path is taken it fails with model.ErrExists, unless overwrite is
// set (--force): then the entry keeps its id and takes e's content. It
// returns the stored entry. Nothing is saved if nothing changed.
func (v *Vault) Add(e model.Entry, overwrite bool) (model.Entry, error) {
	var stored model.Entry
	err := v.mutate(func(d *model.Data, now time.Time) (bool, error) {
		old, existed := d.Get(e.Path)
		s, err := d.Add(e, now, overwrite)
		if err != nil {
			return false, err
		}
		stored = s
		return !existed || !old.Equal(s), nil
	})
	if err != nil {
		return model.Entry{}, err
	}
	return stored, nil
}

// Update replaces the entry with id e.ID by e (the edit form) and saves.
// It reports whether anything changed; if not, nothing is saved.
func (v *Vault) Update(e model.Entry) (changed bool, err error) {
	err = v.mutate(func(d *model.Data, now time.Time) (bool, error) {
		changed, err = d.Update(e, now)
		return changed, err
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

// Move renames the entry at src to dst and saves.
func (v *Vault) Move(src, dst paths.Path) error {
	return v.mutate(func(d *model.Data, now time.Time) (bool, error) {
		return true, d.Move(src, dst, now)
	})
}

// Remove deletes the entry at p, leaving a tombstone, and saves.
func (v *Vault) Remove(p paths.Path) error {
	return v.mutate(func(d *model.Data, now time.Time) (bool, error) {
		_, err := d.Remove(p, now)
		return true, err
	})
}

// EditTags adds and removes tags of the entry at p (`passh tag`) and
// saves. Tags are normalized; removing a tag the entry doesn't have is not
// an error. It returns the entry and whether it changed.
func (v *Vault) EditTags(p paths.Path, add, remove []string) (e model.Entry, changed bool, err error) {
	rm := make([]string, 0, len(remove))
	for _, t := range remove {
		n, err := model.NormalizeTag(t)
		if err != nil {
			return model.Entry{}, false, err
		}
		rm = append(rm, n)
	}
	err = v.mutate(func(d *model.Data, now time.Time) (bool, error) {
		cur, ok := d.Get(p)
		if !ok {
			return false, fmt.Errorf("%s: %w", p, model.ErrNotFound)
		}
		cur.Tags = slices.DeleteFunc(append(cur.Tags, add...), func(t string) bool {
			n, err := model.NormalizeTag(t)
			return err == nil && slices.Contains(rm, n)
		})
		if changed, err = d.Update(cur, now); err != nil {
			return false, err
		}
		e, _ = d.Get(p)
		return changed, nil
	})
	if err != nil {
		return model.Entry{}, false, err
	}
	return e, changed, nil
}

// Apply runs fn on a copy of the data and saves the copy as one revision if
// fn reports a change: for changes made of many steps, such as `import
// pass`. If fn returns an error, nothing is saved. The new revision is one
// more than the higher of the current revision and the copy's Revision (so
// a merge can set the other copy's).
func (v *Vault) Apply(fn func(d *model.Data, now time.Time) (changed bool, err error)) error {
	return v.mutate(fn)
}

// Passwd changes the passphrase (§5.4): it wraps the same vault key with
// newPassphrase and saves. The data and the paper recovery key stay valid;
// like every change, it is a new revision. The caller owns newPassphrase
// and should wipe it.
//
// `passh recover` is Open with keys.FromIdentity(paper key), then Passwd.
func (v *Vault) Passwd(newPassphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	keyBlock, err := keys.WrapKey(v.key, newPassphrase)
	if err != nil {
		return err
	}
	return v.commit(v.data.Clone(), keyBlock, v.key)
}

// Rekey makes a new vault key, wraps it with newPassphrase, re-encrypts the
// data to it and saves (§5.4). It returns the new key, for a new recovery
// sheet. The old key and key block don't open the new file; older copies
// and backups still open with them. The caller owns newPassphrase and
// should wipe it.
func (v *Vault) Rekey(newPassphrase []byte) (*age.X25519Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrClosed
	}
	key, err := keys.NewVaultKey()
	if err != nil {
		return nil, err
	}
	keyBlock, err := keys.WrapKey(key, newPassphrase)
	if err != nil {
		return nil, err
	}
	if err := v.commit(v.data.Clone(), keyBlock, key); err != nil {
		return nil, err
	}
	return key, nil
}

// KeyBlock returns a copy of the vault's key block as opened or last saved
// (binary, as in vaultfile.File): `passh unlock` hands it to the agent
// (agent.Options.KeyBlock), which then serves the key only for this key
// block. It is nil for a vault opened with Options.Recovery whose key
// block is damaged.
func (v *Vault) KeyBlock() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return bytes.Clone(v.keyBlock)
}

// Key returns the vault key (for the agent and the recovery sheet).
func (v *Vault) Key() *age.X25519Identity {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.key
}

// Info describes an opened vault.
type Info struct {
	Path     string // as given
	RealPath string // symlinks resolved: the file that is read and written
	VaultID  string
	Revision uint64
	SavedAt  time.Time
	Entries  int
	// SHA256 is the file's SHA-256 (lower-case hex) when it was opened or
	// last saved.
	SHA256 string
	// Warnings lists text ignored around the vault when it was opened
	// (§4.5); Canonical reports whether the file was in canonical form.
	// Both refer to the file as opened: after a save it is canonical.
	Warnings  []string
	Canonical bool
}

// Info returns the vault's description.
func (v *Vault) Info() Info {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return Info{Path: v.display}
	}
	return Info{
		Path:      v.display,
		RealPath:  v.real,
		VaultID:   v.data.VaultID,
		Revision:  v.data.Revision,
		SavedAt:   v.data.SavedAt,
		Entries:   len(v.data.Entries),
		SHA256:    hex.EncodeToString(v.sum[:]),
		Warnings:  slices.Clone(v.warnings),
		Canonical: v.canonical,
	}
}

// Rollback returns the comparison with the rollback record made when the
// vault was opened or reloaded (§4.10).
func (v *Vault) Rollback() RollbackStatus {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rollback
}

// Changed reports whether the vault file is no longer the one that was
// opened or last saved (§6.2: "vault changed on disk"): different content,
// gone, or a symlink that points elsewhere now. Saving is refused then
// until Reload.
func (v *Vault) Changed() (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return false, ErrClosed
	}
	real, err := realPath(v.path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if real != v.real {
		return true, nil
	}
	data, err := readVaultFile(real)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return sha256.Sum256(data) != v.sum, nil
}

// Reload reads the vault file again, e.g. after "vault changed on disk".
// The current vault key is tried first; the key source is asked only if
// the file was rekeyed. On error the Vault keeps its current state.
func (v *Vault) Reload(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	l, err := v.load(ctx, v.ks, v.key)
	if err != nil {
		return err
	}
	v.set(l)
	return nil
}

// Backups lists the automatic backups of this vault, newest first.
func (v *Vault) Backups() ([]Backup, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrClosed
	}
	return ListBackups(v.opts.StateDir, v.data.VaultID)
}

// Close drops the vault key and the data. It is a best effort: Go strings
// and the age identity can't be overwritten, so it only makes them
// unreachable. Further calls fail with ErrClosed or return nothing.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	v.key, v.data, v.ks = nil, nil, nil
	keys.Zero(v.keyBlock)
	v.keyBlock = nil
}
