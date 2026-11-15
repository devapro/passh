package keys

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

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
	// ErrRecoveryKeyTypo: the typed key has the right shape, but its bech32
	// checksum doesn't match, so at least one character is wrong.
	ErrRecoveryKeyTypo = errors.New("recovery key has a typo (checksum mismatch)")
	// ErrRecoveryKeyInvalid: the typed text isn't shaped like a recovery
	// key. Errors wrap it with the detail (wrong start, length, character).
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
func ParseRecoveryKey(typed string) (*age.X25519Identity, error) {
	var b strings.Builder
	b.Grow(len(typed))
	for _, r := range typed {
		switch {
		case unicode.IsSpace(r), r == '-':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		b.WriteRune(r)
	}
	s := b.String()

	const bare = "AGESECRETKEY1"
	if s == "" {
		return nil, fmt.Errorf("%w: nothing was typed", ErrRecoveryKeyInvalid)
	}
	if !strings.HasPrefix(s, bare) {
		return nil, fmt.Errorf("%w: it must start with %s", ErrRecoveryKeyInvalid, recoveryPrefix)
	}
	data := s[len(bare):]
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
	id, err := age.ParseX25519Identity(recoveryPrefix + data)
	if err != nil {
		return nil, ErrRecoveryKeyTypo
	}
	return id, nil
}
