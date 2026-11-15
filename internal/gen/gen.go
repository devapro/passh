// Package gen generates passwords (S3).
//
// Characters are drawn uniformly from an alphabet with crypto/rand and
// rejection sampling: a random byte b is used only if b < 256 - 256%n (n is
// the alphabet size), and then maps to alphabet[b%n]. Bytes at or above that
// limit are thrown away, not reduced, so every character is equally likely.
//
// Character classes are not forced ("at least one digit"): that would make
// some passwords more likely than others. Sites with composition rules get a
// regenerated password or a custom alphabet.
//
// Alphabets are sequences of Unicode code points (runes). A valid alphabet
// has 2 to 256 distinct runes, is valid UTF-8 and holds no control
// characters (C0, DEL, C1) and no spaces, so a password is always one word
// on one line, with nothing to lose to trimming.
package gen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultLength is the password length when none is given.
	DefaultLength = 24
	// MaxLength is the longest password Generate makes.
	MaxLength = 4096
	// MaxAlphabet is the largest alphabet size: one random byte per draw.
	MaxAlphabet = 256

	// Letters are the ASCII letters.
	Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// Digits are the ASCII digits.
	Digits = "0123456789"
	// Symbols are the 32 printable ASCII punctuation characters.
	Symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

	// DefaultAlphabet is letters and digits (62 characters).
	DefaultAlphabet = Letters + Digits
	// SymbolsAlphabet is the default alphabet plus Symbols (94 characters,
	// which doesn't divide 256, so rejection sampling matters).
	SymbolsAlphabet = DefaultAlphabet + Symbols
)

// Options configure Generate. The zero value gives a 24-character password
// of letters and digits from crypto/rand.
type Options struct {
	// Length is the number of characters; 0 means DefaultLength.
	Length int
	// Symbols adds Symbols to the default alphabet. It is ignored when
	// Alphabet is set.
	Symbols bool
	// Alphabet, if not empty, replaces the default alphabet.
	Alphabet string
	// Rand is the randomness source; nil means crypto/rand.Reader.
	// Tests inject a deterministic reader.
	Rand io.Reader
}

// ErrBadAlphabet is wrapped by every alphabet validation error.
var ErrBadAlphabet = errors.New("invalid alphabet")

// Generate returns a new random password.
func Generate(opts Options) (string, error) {
	alphabet, err := opts.alphabet()
	if err != nil {
		return "", err
	}
	length := opts.Length
	if length == 0 {
		length = DefaultLength
	}
	if length < 0 || length > MaxLength {
		return "", fmt.Errorf("password length must be between 1 and %d, got %d", MaxLength, length)
	}
	r := opts.Rand
	if r == nil {
		r = rand.Reader
	}
	idx, err := sample(r, len(alphabet), length)
	if err != nil {
		return "", err
	}
	out := make([]rune, length)
	for i, k := range idx {
		out[i] = alphabet[k]
	}
	return string(out), nil
}

// Bits returns the strength of a password made with opts, in bits:
// length × log2(alphabet size).
func Bits(opts Options) (float64, error) {
	alphabet, err := opts.alphabet()
	if err != nil {
		return 0, err
	}
	length := opts.Length
	if length == 0 {
		length = DefaultLength
	}
	return float64(length) * math.Log2(float64(len(alphabet))), nil
}

// ValidateAlphabet checks that a is usable as an alphabet: valid UTF-8,
// 2 to 256 runes, no duplicates, no control or space characters.
func ValidateAlphabet(a string) error {
	_, err := parseAlphabet(a)
	return err
}

func (o Options) alphabet() ([]rune, error) {
	switch {
	case o.Alphabet != "":
		return parseAlphabet(o.Alphabet)
	case o.Symbols:
		return []rune(SymbolsAlphabet), nil
	default:
		return []rune(DefaultAlphabet), nil
	}
}

func parseAlphabet(a string) ([]rune, error) {
	if !utf8.ValidString(a) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrBadAlphabet)
	}
	runes := []rune(a)
	if len(runes) < 2 {
		return nil, fmt.Errorf("%w: needs at least 2 characters", ErrBadAlphabet)
	}
	if len(runes) > MaxAlphabet {
		return nil, fmt.Errorf("%w: %d characters, at most %d allowed", ErrBadAlphabet, len(runes), MaxAlphabet)
	}
	seen := make(map[rune]bool, len(runes))
	for _, r := range runes {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return nil, fmt.Errorf("%w: control or space character %U", ErrBadAlphabet, r)
		}
		if seen[r] {
			return nil, fmt.Errorf("%w: %q appears more than once", ErrBadAlphabet, r)
		}
		seen[r] = true
	}
	return runes, nil
}

// sample returns count indexes, each uniform in [0, n), 2 <= n <= 256.
// It reads exactly as many bytes as it examines: each read asks only for the
// number of indexes still missing.
func sample(r io.Reader, n, count int) ([]int, error) {
	limit := 256 - 256%n // largest multiple of n that is <= 256
	idx := make([]int, 0, count)
	buf := make([]byte, count)
	for len(idx) < count {
		need := buf[:count-len(idx)]
		if _, err := io.ReadFull(r, need); err != nil {
			return nil, fmt.Errorf("reading random bytes: %w", err)
		}
		for _, b := range need {
			if int(b) < limit {
				idx = append(idx, int(b)%n)
			}
		}
		clear(need)
	}
	return idx, nil
}
