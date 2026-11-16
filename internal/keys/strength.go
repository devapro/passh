package keys

import (
	"unicode/utf8"

	"github.com/trustelem/zxcvbn"
	"github.com/trustelem/zxcvbn/match"

	"github.com/devapro/passh/internal/i18n"
)

// StrengthAdvice is the advice given with every weak passphrase (§5.4, §8).
const StrengthAdvice = "use 6 or more random words"

// maxStrengthRunes caps the input to zxcvbn, whose matching grows faster
// than linearly. A longer passphrase is judged by its first part.
const maxStrengthRunes = 100

// Strength is a passphrase strength estimate (§5.4). It only informs: passh
// warns about weak passphrases but never refuses one.
type Strength struct {
	// Score is the zxcvbn score: 0 (too guessable) to 4 (very unguessable).
	Score int
	// Warning briefly says why a weak passphrase is weak, e.g. "this is a
	// very common password", in English: a catalog key (i18n.Mark) that
	// Localize translates. It is empty when the passphrase isn't weak or no
	// specific reason is known.
	Warning string
}

// Weak reports whether the score is below 3.
func (s Strength) Weak() bool { return s.Score < 3 }

// Message is the line to show the user, in English: empty if the
// passphrase isn't weak, otherwise "weak passphrase: <warning>; use 6 or
// more random words". Localize gives it in the user's language.
func (s Strength) Message() string { return s.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: Message in p's language.
func (s Strength) Localize(p i18n.Printer) string {
	switch {
	case !s.Weak():
		return ""
	case s.Warning == "":
		return p.T("weak passphrase; use 6 or more random words")
	}
	return p.T("weak passphrase: %s; use 6 or more random words", p.T(s.Warning)) // i18n:dynamic: the warnings are marked in warning
}

// CheckStrength estimates the strength of a passphrase with zxcvbn.
// userInputs are words an attacker might try first (user name, host name).
// The caller owns passphrase; this function keeps no reference to it, but the
// string copy zxcvbn needs can't be zeroed.
func CheckStrength(passphrase []byte, userInputs ...string) Strength {
	p := passphrase
	if n := utf8.RuneCount(p); n > maxStrengthRunes {
		cut := 0
		for range maxStrengthRunes {
			_, size := utf8.DecodeRune(p[cut:])
			cut += size
		}
		p = p[:cut]
	}
	res := zxcvbn.PasswordStrength(string(p), userInputs)
	s := Strength{Score: res.Score}
	if s.Weak() {
		s.Warning = warning(res.Sequence)
	}
	return s
}

// warning follows zxcvbn's feedback rules: the longest match explains the score.
func warning(seq []*match.Match) string {
	if len(seq) == 0 {
		return i18n.Mark("it is empty or too short")
	}
	longest := seq[0]
	for _, m := range seq[1:] {
		if len(m.Token) > len(longest.Token) {
			longest = m
		}
	}
	sole := len(seq) == 1
	switch longest.Pattern {
	case "dictionary":
		return dictionaryWarning(longest, sole)
	case "spatial":
		if longest.Turns == 1 {
			return i18n.Mark("straight rows of keys are easy to guess")
		}
		return i18n.Mark("short keyboard patterns are easy to guess")
	case "repeat":
		if utf8.RuneCountInString(longest.BaseToken) == 1 {
			return i18n.Mark(`repeats like "aaa" are easy to guess`)
		}
		return i18n.Mark(`repeats like "abcabcabc" are only slightly harder to guess than "abc"`)
	case "sequence":
		return i18n.Mark("sequences like abc or 6543 are easy to guess")
	case "regex":
		if longest.RegexName == "recent_year" {
			return i18n.Mark("recent years are easy to guess")
		}
	case "date":
		return i18n.Mark("dates are often easy to guess")
	}
	return ""
}

func dictionaryWarning(m *match.Match, sole bool) string {
	switch m.DictionaryName {
	case "passwords":
		if sole && !m.L33t && !m.Reversed {
			switch {
			case m.Rank <= 10:
				return i18n.Mark("this is a top-10 common password")
			case m.Rank <= 100:
				return i18n.Mark("this is a top-100 common password")
			default:
				return i18n.Mark("this is a very common password")
			}
		}
		return i18n.Mark("this is similar to a commonly used password")
	case "english_wikipedia", "us_tv_and_film":
		if sole {
			return i18n.Mark("a word by itself is easy to guess")
		}
		return i18n.Mark("common words are easy to guess")
	case "surnames", "male_names", "female_names":
		if sole {
			return i18n.Mark("names and surnames by themselves are easy to guess")
		}
		return i18n.Mark("common names and surnames are easy to guess")
	}
	return ""
}
