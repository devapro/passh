package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/vaultfile"
)

// The problems of §4.5. An *OpenError wraps exactly one of them, so callers
// test with errors.Is. They are the vaultfile and keys errors, under one
// roof.
var (
	// ErrNotVault means the file has no passh-vault line: "not a passh
	// vault".
	ErrNotVault = vaultfile.ErrNotVault
	// ErrNewer means the container or data version is higher than this
	// passh knows: "made by a newer passh; upgrade passh".
	ErrNewer = vaultfile.ErrNewer
	// ErrTruncated means a block or an END line is missing: "file is
	// truncated".
	ErrTruncated = vaultfile.ErrTruncated
	// ErrDamaged means a block has bad base64 or a bad age header: "file is
	// damaged (block 1 or 2)".
	ErrDamaged = vaultfile.ErrDamaged
	// ErrWrongPassphrase means the key block doesn't decrypt with the
	// passphrase: "wrong passphrase, or the key block is damaged".
	ErrWrongPassphrase = keys.ErrWrongPassphrase
	// ErrNotVaultKey means the key block decrypts to something other than
	// one vault key.
	ErrNotVaultKey = keys.ErrNotVaultKey
	// ErrWorkFactor means the key block asks for more scrypt work than
	// passh ever uses (2^18): the file is damaged or not made by passh.
	// It is refused before scrypt runs.
	ErrWorkFactor = keys.ErrWorkFactor
	// ErrDataDamaged means the data block doesn't decrypt or isn't valid
	// data: "data is damaged; restore a backup".
	ErrDataDamaged = keys.ErrDataDamaged
	// ErrKeyMismatch means the key doesn't open the data block. It is
	// ErrDataDamaged too.
	ErrKeyMismatch = keys.ErrKeyMismatch

	errTooLarge   = i18n.Errorf("%w: the file is larger than 64 MiB", vaultfile.ErrNotVault)
	errNotRegular = i18n.Errorf("%w: not a regular file", vaultfile.ErrNotVault)
)

// Errors of saving (§4.6) and of the rollback check (§4.10).
var (
	// ErrChanged means the vault file is not what was opened (step 2 of
	// §4.6). Nothing was saved; the caller keeps the user's input, so the
	// change can be repeated after Reload.
	ErrChanged = i18n.NewError("vault changed on disk after it was opened (another passh, a sync tool or a copy); nothing was saved: reload and repeat the change")
	// ErrLocked means another passh process held the save lock for too
	// long.
	ErrLocked = i18n.NewError("vault is being saved by another passh process; nothing was saved: try again")
	// ErrVerify means the new file didn't read back as written (step 5 of
	// §4.6). The vault file is unchanged.
	ErrVerify = i18n.NewError("the new vault file didn't read back as written; the vault is unchanged")
	// ErrExists is returned by Create when something exists at the vault's
	// path.
	ErrExists = i18n.NewError("a file already exists there")
	// ErrRollbackDeclined means the user answered no to the rollback
	// warning (§4.10). Nothing was changed.
	ErrRollbackDeclined = i18n.NewError("stopped: this copy is older than one seen before on this machine; nothing was changed")
	// ErrClosed is returned by the methods of a closed Vault.
	ErrClosed = i18n.NewError("vault: closed")
	// ErrBackupFile means the vault file lies in the automatic backups
	// folder. It opens for reading, but saving is refused: rotation could
	// remove it.
	ErrBackupFile = i18n.NewError("this is an automatic backup: copy it out first (e.g. over the vault file) and open the copy")
	// ErrKeyBlockChanged means Reload found another key block (passwd or
	// rekey elsewhere) and the Vault has no key source to check it with.
	ErrKeyBlockChanged = i18n.NewError("the vault's key block changed on disk (passwd or rekey elsewhere?): open the vault again")
	// ErrKeyBlockDamaged means the vault was opened for recovery with a
	// damaged key block (Options.Recovery); only Passwd or Rekey, which
	// write a new one, may save.
	ErrKeyBlockDamaged = i18n.NewError("the key block is damaged: set a new passphrase first (passh recover)")
	// ErrWrongKey means the key from the agent or a paper key doesn't open
	// the data block: the vault was rekeyed elsewhere, or the key belongs
	// to another vault. errors.Is(err, ErrKeyMismatch) is true for it too,
	// but not errors.Is(err, ErrDataDamaged): restoring a backup is the
	// wrong advice. Callers fall back to the passphrase.
	ErrWrongKey = i18n.NewError("this key doesn't open this vault (rekeyed elsewhere? wrong recovery key?)")
)

// wrongKey is the error for ErrWrongKey; it also matches keys.ErrKeyMismatch,
// which callers already test for.
type wrongKey struct{}

func (wrongKey) Error() string        { return ErrWrongKey.Error() }
func (wrongKey) Is(target error) bool { return target == ErrWrongKey || target == ErrKeyMismatch }

// Localize implements i18n.Localizer: ErrWrongKey in p's language.
func (wrongKey) Localize(p i18n.Printer) string { return p.Error(ErrWrongKey) }

// OpenError reports a file that can't be opened as a vault (§4.5). Err
// matches one of ErrNotVault, ErrNewer, ErrTruncated, ErrDamaged,
// ErrWrongPassphrase, ErrNotVaultKey, ErrWorkFactor or ErrDataDamaged.
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

func (e *OpenError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language, the
// cause and the list of backups included.
func (e *OpenError) Localize(p i18n.Printer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", e.Path, p.Error(e.Err))
	if !errors.Is(e.Err, ErrDataDamaged) {
		return b.String()
	}
	b.WriteString("\n")
	switch {
	case len(e.Backups) == 0:
		b.WriteString(p.T("no automatic backups of this vault were found; use another copy (passh verify --full <copy>)"))
	case e.BackupsMatched:
		b.WriteString(p.T("automatic backups of this vault, newest first:"))
	default:
		b.WriteString(p.T("automatic backups on this machine, newest first:"))
	}
	for _, bk := range e.Backups {
		b.WriteString("\n  ")
		b.WriteString(bk.String())
	}
	return b.String()
}

func (e *OpenError) Unwrap() error { return e.Err }

// errNotEncryptedToKey means the data block isn't encrypted to the vault
// key that the file's own key block holds: damaged or replaced (§4.5).
var errNotEncryptedToKey = i18n.Errorf("%w (the data block isn't encrypted to this vault's key: damaged or replaced)", ErrDataDamaged)

// dataDamaged wraps ErrDataDamaged with a detail.
func dataDamaged(detail error) error {
	return i18n.Errorf("%w (%v)", ErrDataDamaged, detail)
}
