// Package keys handles passh's keys (spec §4.1, §5.4, ADR-6): the random
// vault key, its passphrase wrapping (the key block), encryption of the data
// block to the vault key, the paper recovery key format and passphrase
// strength estimates.
//
// The vault key's public half (the age1… recipient) is never turned into a
// string by this package (S9): it exists only as an in-memory
// *age.X25519Recipient while a data block is encrypted.
//
// Key blocks and data blocks are binary age files. The vaultfile package
// adds and removes the ASCII armor.
package keys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"

	"filippo.io/age"

	"github.com/devapro/passh/internal/i18n"
)

// KeySource yields the vault key: from the agent, a passphrase prompt or a paper key.
//
// keyBlock is the binary (de-armored) key block of the vault being opened, as
// returned by vaultfile.Parse. Sources that already hold the key ignore it.
type KeySource interface {
	VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error)
}

// scryptWorkFactor is the scrypt work factor (log2 of N) of new key blocks:
// 2^18, age's default (§4.1). Production code never changes it; tests of
// this package may lower it to stay fast.
var scryptWorkFactor = 18

// maxWorkFactor is the highest scrypt work factor UnwrapKey accepts: 2^18,
// the only one passh writes (§4.1: "there is no lighter setting", and none
// heavier either). age's own default maximum is 2^22, 4 GiB of memory per
// attempt, which a damaged or crafted key block could impose on every
// passphrase try; on a 1 GiB Raspberry Pi that is an out-of-memory kill
// (INV-10). It is a constant, not tied to scryptWorkFactor, so tests that
// lower the latter still unwrap 2^18 blocks.
const maxWorkFactor = 18

// maxKeyPlaintext caps the plaintext of a key block. A vault key is one
// 74-character line; the cap leaves room for comments in a hand-made identity file.
const maxKeyPlaintext = 4096

var (
	// ErrWrongPassphrase means the key block doesn't decrypt with the
	// passphrase (§4.5).
	ErrWrongPassphrase = i18n.NewError("wrong passphrase, or the key block is damaged")
	// ErrEmptyPassphrase means the passphrase is empty: it can neither wrap
	// nor unwrap a key.
	ErrEmptyPassphrase = i18n.NewError("passphrase is empty")
	// ErrNotVaultKey means the key block decrypts, but its plaintext isn't
	// exactly one age X25519 identity.
	ErrNotVaultKey = i18n.NewError("the key block is damaged: it doesn't hold exactly one vault key")
	// ErrWorkFactor means the key block asks for a higher scrypt work
	// factor than passh uses (2^18): it is damaged or wasn't made by passh.
	// UnwrapKey refuses it before running scrypt; the error's text names
	// the factor asked for.
	ErrWorkFactor = i18n.NewError("key block asks for more scrypt work than passh uses")
	// ErrDataDamaged means the data block doesn't decrypt (§4.5). Callers
	// list the automatic backups after this message.
	ErrDataDamaged = i18n.NewError("data is damaged; restore a backup")
	// ErrKeyMismatch means the data block isn't encrypted to the given key,
	// e.g. a recovery key of another vault, or a key from before a rekey.
	// It satisfies errors.Is(err, ErrDataDamaged).
	ErrKeyMismatch = i18n.Errorf("the key doesn't open the data block: %w", ErrDataDamaged)

	errNoKey = errors.New("keys: no vault key")
)

// workFactorError is the ErrWorkFactor of one key block.
type workFactorError struct{ logN int }

func (e workFactorError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (e workFactorError) Localize(p i18n.Printer) string {
	return p.T("key block asks for scrypt work factor 2^%d; passh uses 2^%d: the file is damaged or not made by passh",
		e.logN, maxWorkFactor)
}

func (e workFactorError) Is(target error) bool { return target == ErrWorkFactor }

// NewVaultKey generates a random vault key.
func NewVaultKey() (*age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, i18n.Errorf("generating the vault key: %w", err)
	}
	return id, nil
}

// WrapKey encrypts the vault key with the passphrase and returns the key
// block: a binary age file with one scrypt stanza (work factor 2^18) whose
// plaintext is the key followed by a newline, a valid age identity file.
//
// The caller owns passphrase and should Zero it when done.
func WrapKey(id *age.X25519Identity, passphrase []byte) ([]byte, error) {
	if id == nil {
		return nil, errNoKey
	}
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(scryptWorkFactor)

	s := id.String()
	plain := make([]byte, 0, len(s)+1)
	plain = append(plain, s...)
	plain = append(plain, '\n')
	defer Zero(plain)

	return encrypt(r, plain)
}

// UnwrapKey decrypts a key block with the passphrase and returns the vault
// key. A wrong passphrase or a damaged key block gives ErrWrongPassphrase; a
// key block whose plaintext isn't exactly one X25519 identity gives
// ErrNotVaultKey. A key block asking for a scrypt work factor above 2^18
// gives an error matching ErrWorkFactor, before any scrypt work (INV-10).
//
// The caller owns passphrase and should Zero it when done.
func UnwrapKey(keyBlock, passphrase []byte) (*age.X25519Identity, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	sid, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, ErrEmptyPassphrase
	}
	sid.SetMaxWorkFactor(maxWorkFactor) // also enforced by workFactorCheck
	plain, err := decrypt(keyBlock, maxKeyPlaintext, workFactorCheck{sid})
	if err != nil {
		switch {
		case errors.Is(err, errTooLarge):
			return nil, ErrNotVaultKey
		case errors.Is(err, ErrWorkFactor):
			return nil, err
		}
		return nil, ErrWrongPassphrase
	}
	defer Zero(plain)
	return parseVaultKey(plain)
}

// workFactorCheck is the scrypt identity with passh's limit checked first,
// so that a key block asking for more than 2^18 is refused before scrypt
// runs, with an error that names the factor. Everything else, including
// the checks on the stanza's form, is left to age.
type workFactorCheck struct{ id *age.ScryptIdentity }

// Unwrap implements age.Identity.
func (c workFactorCheck) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) == 1 && stanzas[0].Type == "scrypt" && len(stanzas[0].Args) == 2 {
		if n, err := strconv.Atoi(stanzas[0].Args[1]); err == nil && n > maxWorkFactor {
			return nil, workFactorError{logN: n}
		}
	}
	return c.id.Unwrap(stanzas)
}

// parseVaultKey accepts an age identity file holding exactly one X25519
// identity. Blank lines and # comments are allowed, as in any age identity file.
func parseVaultKey(plain []byte) (*age.X25519Identity, error) {
	var key []byte
	for line := range bytes.SplitSeq(plain, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if key != nil {
			return nil, ErrNotVaultKey
		}
		key = line
	}
	if key == nil || !bytes.HasPrefix(key, []byte(recoveryPrefix)) {
		return nil, ErrNotVaultKey
	}
	id, err := age.ParseX25519Identity(string(key))
	if err != nil {
		return nil, ErrNotVaultKey
	}
	return id, nil
}

// EncryptData encrypts plaintext to the vault key and returns the data
// block, a binary age file with one X25519 stanza.
func EncryptData(id *age.X25519Identity, plaintext []byte) ([]byte, error) {
	if id == nil {
		return nil, errNoKey
	}
	return encrypt(id.Recipient(), plaintext)
}

// DecryptData decrypts a data block with the vault key. Every byte is
// authenticated before anything is returned: on error no plaintext comes
// back. Errors satisfy errors.Is(err, ErrDataDamaged); a data block that
// isn't encrypted to id also satisfies errors.Is(err, ErrKeyMismatch).
func DecryptData(id *age.X25519Identity, dataBlock []byte) ([]byte, error) {
	if id == nil {
		return nil, errNoKey
	}
	plain, err := decrypt(dataBlock, -1, id)
	if err != nil {
		if errors.As(err, new(*age.NoIdentityMatchError)) {
			return nil, ErrKeyMismatch
		}
		return nil, ErrDataDamaged
	}
	return plain, nil
}

// Zero overwrites b with zeros (SEC-1). It is a best effort: copies made by
// the Go runtime, by string conversions or inside age can't be reached.
func Zero(b []byte) {
	clear(b)
}

func encrypt(r age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, i18n.Errorf("encrypting: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, i18n.Errorf("encrypting: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, i18n.Errorf("encrypting: %w", err)
	}
	return buf.Bytes(), nil
}

var errTooLarge = errors.New("plaintext too large")

// decrypt decrypts a whole age file into one buffer of the exact plaintext
// size, so no partial copies of the plaintext are left behind in grown
// buffers. On error the buffer is zeroed and nil is returned. limit < 0
// means no limit.
func decrypt(block []byte, limit int64, id age.Identity) ([]byte, error) {
	ra, size, err := age.DecryptReaderAt(bytes.NewReader(block), int64(len(block)), id)
	if err != nil {
		return nil, err
	}
	if limit >= 0 && size > limit {
		return nil, errTooLarge
	}
	plain := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(ra, 0, size), plain); err != nil {
		Zero(plain)
		return nil, err
	}
	return plain, nil
}
