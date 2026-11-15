package keys

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
)

// The paper recovery key (§5.4) is the vault key itself, printed so that it
// is easy to read and to type back:
//
//	AGE-SECRET-KEY-1
//	QPZR Y9X8 GF2T VDW0 S3JN
//	54KH CE6M UA7L QPZR Y9X8
//	GF2T VDW0 S3JN 54KH CE
//
// After the prefix come 58 bech32 characters (52 data, 6 checksum) in groups
// of four, five groups per line.

const (
	recoveryPrefix  = "AGE-SECRET-KEY-1"
	recoveryDataLen = 58
	recoveryGroup   = 4
	recoveryPerLine = 5
	// bech32Charset is the bech32 alphabet in upper case. B, I, O and 1
	// never appear after the prefix.
	bech32Charset = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
)

var (
	// ErrRecoveryKeyTypo means the typed key has the right shape, but its
	// bech32 checksum doesn't match, so at least one character is wrong.
	ErrRecoveryKeyTypo = errors.New("recovery key has a typo (checksum mismatch)")
	// ErrRecoveryKeyInvalid means the typed text isn't shaped like a
	// recovery key. Errors wrap it with the detail (wrong start, length,
	// character).
	ErrRecoveryKeyInvalid = errors.New("not a valid recovery key")
)

// FormatRecoveryKey lays out the vault key for paper: the AGE-SECRET-KEY-1
// prefix on its own line, then the rest in groups of four characters, five
// groups per line. Lines are separated by "\n", without a final newline.
// ParseRecoveryKey reads it back.
func FormatRecoveryKey(id *age.X25519Identity) string {
	s := id.String()
	data := strings.TrimPrefix(s, recoveryPrefix)
	var b strings.Builder
	b.WriteString(recoveryPrefix)
	for i := 0; i < len(data); i += recoveryGroup {
		if i%(recoveryGroup*recoveryPerLine) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(data[i:min(i+recoveryGroup, len(data))])
	}
	return b.String()
}

// ParseRecoveryKey reads a typed recovery key. Whitespace (including line
// breaks), hyphens and letter case are ignored; the key's bech32 checksum
// catches typos (ErrRecoveryKeyTypo). Errors never echo the typed characters.
//
// The key is a secret held in a string, which can't be wiped; callers that
// read it into a []byte use ParseRecoveryKeyBytes (SEC-1).
func ParseRecoveryKey(typed string) (*age.X25519Identity, error) {
	b := []byte(typed)
	defer clear(b)
	return ParseRecoveryKeyBytes(b)
}

// ParseRecoveryKeyBytes is ParseRecoveryKey for a key typed into a []byte.
// It doesn't change typed, which the caller owns and should wipe; its own
// working copy is wiped, and the key becomes a string only once, where age
// parses it (SEC-1, best effort).
func ParseRecoveryKeyBytes(typed []byte) (*age.X25519Identity, error) {
	norm := make([]byte, 0, len(typed))
	defer func() { clear(norm[:cap(norm)]) }()
	for i := 0; i < len(typed); {
		r, size := utf8.DecodeRune(typed[i:])
		i += size
		switch {
		case unicode.IsSpace(r), r == '-':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		if r == utf8.RuneError && size == 1 {
			norm = append(norm, typed[i-1]) // not UTF-8: refused below as a character
			continue
		}
		norm = utf8.AppendRune(norm, r)
	}

	const bare = "AGESECRETKEY1"
	if len(norm) == 0 {
		return nil, fmt.Errorf("%w: nothing was typed", ErrRecoveryKeyInvalid)
	}
	if !bytes.HasPrefix(norm, []byte(bare)) {
		return nil, fmt.Errorf("%w: it must start with %s", ErrRecoveryKeyInvalid, recoveryPrefix)
	}
	data := norm[len(bare):]
	for i := 0; i < len(data); i++ {
		if strings.IndexByte(bech32Charset, data[i]) < 0 {
			return nil, fmt.Errorf("%w: group %d, character %d is not used in keys (B, I, O and 1 never appear after %s)",
				ErrRecoveryKeyInvalid, i/recoveryGroup+1, i%recoveryGroup+1, recoveryPrefix)
		}
	}
	if len(data) != recoveryDataLen {
		return nil, fmt.Errorf("%w: it has %d characters after %s instead of %d; a character is missing or extra",
			ErrRecoveryKeyInvalid, len(data), recoveryPrefix, recoveryDataLen)
	}
	key := make([]byte, 0, len(recoveryPrefix)+len(data))
	key = append(append(key, recoveryPrefix...), data...)
	defer clear(key)
	id, err := age.ParseX25519Identity(string(key)) // the one string: age's parser takes no []byte
	if err != nil {
		return nil, ErrRecoveryKeyTypo
	}
	return id, nil
}
