package vault

import (
	"errors"
	"fmt"
	"strings"

	"passh/internal/keys"
	"passh/internal/vaultfile"
)

// The problems of §4.5. An *OpenError wraps exactly one of them, so callers
// test with errors.Is. They are the vaultfile and keys errors, under one
// roof.
var (
	ErrNotVault        = vaultfile.ErrNotVault   // not a passh vault
	ErrNewer           = vaultfile.ErrNewer      // made by a newer passh; upgrade passh
	ErrTruncated       = vaultfile.ErrTruncated  // file is truncated
	ErrDamaged         = vaultfile.ErrDamaged    // file is damaged (block 1 or 2)
	ErrWrongPassphrase = keys.ErrWrongPassphrase // wrong passphrase, or the key block is damaged
	ErrNotVaultKey     = keys.ErrNotVaultKey     // the key block holds something else than one vault key
	ErrDataDamaged     = keys.ErrDataDamaged     // data is damaged; restore a backup
	ErrKeyMismatch     = keys.ErrKeyMismatch     // the key doesn't open the data block (is ErrDataDamaged too)
	errTooLarge        = fmt.Errorf("%w: the file is larger than 64 MiB", vaultfile.ErrNotVault)
	errNotRegular      = fmt.Errorf("%w: not a regular file", vaultfile.ErrNotVault)
)

// Errors of saving (§4.6) and of the rollback check (§4.10).
var (
	// ErrChanged: the vault file is not what was opened (step 2 of §4.6).
	// Nothing was saved; the caller keeps the user's input, so the change
	// can be repeated after Reload.
	ErrChanged = errors.New("vault changed on disk after it was opened (another passh, a sync tool or a copy); nothing was saved: reload and repeat the change")
	// ErrLocked: another passh process held the save lock for too long.
	ErrLocked = errors.New("vault is being saved by another passh process; nothing was saved: try again")
	// ErrVerify: the new file didn't read back as written (step 5 of §4.6).
	// The vault file is unchanged.
	ErrVerify = errors.New("the new vault file didn't read back as written; the vault is unchanged")
	// ErrExists: Create found something at the vault's path.
	ErrExists = errors.New("a file already exists there")
	// ErrRollbackDeclined: the user answered no to the rollback warning
	// (§4.10). Nothing was changed.
	ErrRollbackDeclined = errors.New("stopped: this copy is older than one seen before on this machine; nothing was changed")
	// ErrClosed: the Vault was closed.
	ErrClosed = errors.New("vault: closed")
	// ErrBackupFile: the vault file lies in the automatic backups folder.
	// It opens for reading, but saving is refused: rotation could remove
	// it.
	ErrBackupFile = errors.New("this is an automatic backup: copy it out first (e.g. over the vault file) and open the copy")
	// ErrKeyBlockChanged: Reload found another key block (passwd or rekey
	// elsewhere) and the Vault has no key source to check it with.
	ErrKeyBlockChanged = errors.New("the vault's key block changed on disk (passwd or rekey elsewhere?): open the vault again")
	// ErrKeyBlockDamaged: the vault was opened for recovery with a damaged
	// key block (Options.Recovery); only Passwd or Rekey, which write a new
	// one, may save.
	ErrKeyBlockDamaged = errors.New("the key block is damaged: set a new passphrase first (passh recover)")
	// ErrWrongKey: the key from the agent or a paper key doesn't open the
	// data block: the vault was rekeyed elsewhere, or the key belongs to
	// another vault. errors.Is(err, ErrKeyMismatch) is true for it too, but
	// not errors.Is(err, ErrDataDamaged): restoring a backup is the wrong
	// advice. Callers fall back to the passphrase.
	ErrWrongKey = errors.New("this key doesn't open this vault (rekeyed elsewhere? wrong recovery key?)")
)

// wrongKey is the error for ErrWrongKey; it also matches keys.ErrKeyMismatch,
// which callers already test for.
type wrongKey struct{}

func (wrongKey) Error() string        { return ErrWrongKey.Error() }
func (wrongKey) Is(target error) bool { return target == ErrWrongKey || target == ErrKeyMismatch }

// OpenError reports a file that can't be opened as a vault (§4.5). Err
// matches one of ErrNotVault, ErrNewer, ErrTruncated, ErrDamaged,
// ErrWrongPassphrase, ErrNotVaultKey or ErrDataDamaged.
type OpenError struct {
	Path string // the vault file, as given to Open
	Err  error
	// Backups lists, for ErrDataDamaged, the automatic backups that may
	// hold this vault, newest first (§4.7). BackupsMatched tells whether
	// they were recognized as this vault's (same key block or vault key);
	// if not, Backups holds every automatic backup on this machine.
	Backups        []Backup
	BackupsMatched bool
}

func (e *OpenError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %v", e.Path, e.Err)
	if !errors.Is(e.Err, ErrDataDamaged) {
		return b.String()
	}
	switch {
	case len(e.Backups) == 0:
		b.WriteString("\nno automatic backups of this vault were found; use another copy (passh verify --full <copy>)")
	case e.BackupsMatched:
		b.WriteString("\nautomatic backups of this vault, newest first:")
	default:
		b.WriteString("\nautomatic backups on this machine, newest first:")
	}
	for _, bk := range e.Backups {
		b.WriteString("\n  ")
		b.WriteString(bk.String())
	}
	return b.String()
}

func (e *OpenError) Unwrap() error { return e.Err }

// errNotEncryptedToKey: the data block isn't encrypted to the vault key
// that the file's own key block holds: damaged or replaced (§4.5).
var errNotEncryptedToKey = fmt.Errorf("%w (the data block isn't encrypted to this vault's key: damaged or replaced)", ErrDataDamaged)

// dataDamaged wraps ErrDataDamaged with a detail.
func dataDamaged(detail error) error {
	return fmt.Errorf("%w (%v)", ErrDataDamaged, detail)
}
