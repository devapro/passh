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
	"fmt"
	"io"

	"filippo.io/age"
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

// maxKeyPlaintext caps the plaintext of a key block. A vault key is one
// 74-character line; the cap leaves room for comments in a hand-made identity file.
const maxKeyPlaintext = 4096

var (
	// ErrWrongPassphrase: the key block doesn't decrypt with the passphrase (§4.5).
	ErrWrongPassphrase = errors.New("wrong passphrase, or the key block is damaged")
	// ErrEmptyPassphrase: an empty passphrase can neither wrap nor unwrap a key.
	ErrEmptyPassphrase = errors.New("passphrase is empty")
	// ErrNotVaultKey: the key block decrypts, but its plaintext isn't exactly
	// one age X25519 identity.
	ErrNotVaultKey = errors.New("the key block is damaged: it doesn't hold exactly one vault key")
	// ErrDataDamaged: the data block doesn't decrypt (§4.5). Callers list
	// the automatic backups after this message.
	ErrDataDamaged = errors.New("data is damaged; restore a backup")
	// ErrKeyMismatch: the data block isn't encrypted to the given key, e.g.
	// a recovery key of another vault, or a key from before a rekey. It
	// satisfies errors.Is(err, ErrDataDamaged).
	ErrKeyMismatch = fmt.Errorf("the key doesn't open the data block: %w", ErrDataDamaged)

	errNoKey = errors.New("keys: no vault key")
)

// NewVaultKey generates a random vault key.
func NewVaultKey() (*age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating the vault key: %w", err)
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
// ErrNotVaultKey. age's default maximum work factor (2^22) applies, so a
// crafted key block can't make passh run an unbounded scrypt.
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
	plain, err := decrypt(keyBlock, maxKeyPlaintext, sid)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			return nil, ErrNotVaultKey
		}
		return nil, ErrWrongPassphrase
	}
	defer Zero(plain)
	return parseVaultKey(plain)
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

// Zero overwrites b with zeros. It is a best effort: copies made by the Go
// runtime, by string conversions or inside age can't be reached.
func Zero(b []byte) {
	clear(b)
}

func encrypt(r age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
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
