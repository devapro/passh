package keys

import (
	"context"
	"errors"
	"fmt"

	"filippo.io/age"
)

// KeyBlockChecker is implemented by key sources whose key is known to
// belong to the key block passed to VaultKey: PassphraseSource unwraps it,
// and the agent's key source gets the key only for the key block `passh
// unlock` unwrapped. A rekey always writes a new key block, so for such a
// source a data block that the key doesn't open is damaged or replaced,
// not encrypted to a newer key: the vault reports "data is damaged", not a
// stale key. FromIdentity (a paper key) doesn't implement it.
type KeyBlockChecker interface {
	KeySource
	// ChecksKeyBlock reports whether the source checks the key block.
	ChecksKeyBlock() bool
}

// ChecksKeyBlock reports whether ks implements KeyBlockChecker and checks
// the key block.
func ChecksKeyBlock(ks KeySource) bool {
	c, ok := ks.(KeyBlockChecker)
	return ok && c.ChecksKeyBlock()
}

// FromIdentity returns a KeySource that always yields id, e.g. a parsed paper
// recovery key or a key received from the agent. It ignores the key block;
// whether id fits the vault shows when the data block is decrypted
// (ErrKeyMismatch).
func FromIdentity(id *age.X25519Identity) KeySource {
	return identitySource{id: id}
}

type identitySource struct {
	id *age.X25519Identity
}

func (s identitySource) VaultKey(ctx context.Context, _ []byte) (*age.X25519Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.id == nil {
		return nil, errNoKey
	}
	return s.id, nil
}

// DefaultPrompt is the prompt PassphraseSource shows when Prompt is empty.
const DefaultPrompt = "Passphrase: "

// PassphraseSource is a KeySource that asks for the passphrase through Read
// and unwraps the key block with it. Read is injected so this package needs
// no terminal; passh passes a function that reads /dev/tty with echo off (S2).
//
// Each passphrase is zeroed (best effort) right after use, so Read must
// return a slice it doesn't use again.
type PassphraseSource struct {
	// Read asks for the passphrase, showing prompt.
	Read func(prompt string) ([]byte, error)
	// Prompt defaults to DefaultPrompt.
	Prompt string
	// Attempts is how often to ask when the passphrase is wrong; values
	// below 1 mean 1.
	Attempts int
}

// ChecksKeyBlock implements KeyBlockChecker: the key comes from the key
// block itself.
func (s *PassphraseSource) ChecksKeyBlock() bool { return true }

// VaultKey implements KeySource.
func (s *PassphraseSource) VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	if s == nil || s.Read == nil {
		return nil, errors.New("keys: no passphrase reader")
	}
	prompt := s.Prompt
	if prompt == "" {
		prompt = DefaultPrompt
	}
	var lastErr error
	for range max(s.Attempts, 1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pass, err := s.Read(prompt)
		if err != nil {
			Zero(pass)
			return nil, fmt.Errorf("reading the passphrase: %w", err)
		}
		if err := ctx.Err(); err != nil {
			Zero(pass)
			return nil, err
		}
		id, err := UnwrapKey(keyBlock, pass)
		Zero(pass)
		if err == nil {
			return id, nil
		}
		lastErr = err
		if !errors.Is(err, ErrWrongPassphrase) && !errors.Is(err, ErrEmptyPassphrase) {
			break
		}
	}
	return nil, lastErr
}
