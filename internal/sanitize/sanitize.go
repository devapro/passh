// Package sanitize makes entry content safe to print on a terminal (S4).
//
// Entry values may come from imports or other people, so they can hold
// escape sequences that drive the terminal: an OSC 52 clipboard write, a
// title change, cursor movement that hides text, and so on. Everything that a
// terminal could interpret is rendered visibly instead:
//
//   - C0 controls (U+0000–U+001F) and DEL (U+007F) as \xHH, with \t, \n
//     and \r spelled out; ESC becomes \x1b, so no sequence can start;
//   - C1 controls (U+0080–U+009F, including the 8-bit CSI U+009B) as \u00HH;
//   - bytes that are not valid UTF-8 (including a raw 0x9B) as \xHH;
//   - Unicode format characters (category Cf) as \uHHHH (\UHHHHHHHH above
//     U+FFFF): bidi embeddings, overrides and isolates (U+202A–U+202E,
//     U+2066–U+2069) and bidi marks (U+200E, U+200F, U+061C), so text can't
//     be reordered on screen; zero-width and invisible characters (U+200B,
//     U+2060, U+FEFF, the soft hyphen U+00AD, the tag characters
//     U+E0000–U+E007F, …), so two names can't look alike while differing;
//   - the line and paragraph separators U+2028 and U+2029, which some
//     terminals break lines at, in Text as well as in Line.
//
// The zero-width joiner and non-joiner (U+200D, U+200C) are kept where
// they join two visible non-ASCII characters (letters, marks, numbers or
// symbols): emoji sequences (a family is U+1F468 U+200D U+1F469), Indic
// conjuncts and Persian words need them. Anywhere else (next to ASCII, a space, another format
// character or the end of the string) they are escaped too.
//
// Everything else, including Cyrillic, CJK and emoji, passes through
// unchanged. A backslash is not escaped: the output is for people, and
// doubling every backslash in a password would mislead more often than the
// rare ambiguity with a literal "\x1b" in a value. `show --raw` prints exact
// bytes for the cases where that matters.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// Line escapes s for display on a single line: every control character,
// newlines and tabs included, is rendered visibly.
func Line(s string) string {
	return escape(s, false)
}

// Text escapes s for multi-line display. It is Line, except that newline
// (\n) and tab are kept. A carriage return is escaped, because a lone \r can
// overwrite what was printed before it on the same line.
func Text(s string) string {
	return escape(s, true)
}

// IsSafe reports whether s would be printed unchanged by Line
// (multiline = false) or Text (multiline = true).
func IsSafe(s string, multiline bool) bool {
	return safePrefix(s, multiline) == len(s)
}

// safePrefix returns the length of the longest prefix of s that needs no
// escaping.
func safePrefix(s string, multiline bool) int {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if dangerousASCII(c, multiline) {
				return i
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || dangerousRune(s, i, r, size) {
			return i
		}
		i += size
	}
	return len(s)
}

func escape(s string, multiline bool) string {
	n := safePrefix(s, multiline)
	if n == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:n])
	for i := n; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if dangerousASCII(c, multiline) {
				writeASCIIEscape(&b, c)
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			writeByteEscape(&b, c)
		case dangerousRune(s, i, r, size):
			writeRuneEscape(&b, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func dangerousASCII(c byte, multiline bool) bool {
	if c >= 0x20 && c != 0x7f {
		return false
	}
	if multiline && (c == '\n' || c == '\t') {
		return false
	}
	return true
}

const (
	zwnj = 0x200c // zero-width non-joiner
	zwj  = 0x200d // zero-width joiner
)

// dangerousRune reports whether the non-ASCII rune r, found at s[i:i+size],
// is escaped.
func dangerousRune(s string, i int, r rune, size int) bool {
	switch {
	case r >= 0x80 && r <= 0x9f: // C1 controls, including 8-bit CSI U+009B
		return true
	case r == 0x2028 || r == 0x2029: // line and paragraph separators (Zl, Zp)
		return true
	case r == zwnj || r == zwj:
		return !joinsText(s, i, size)
	case unicode.Is(unicode.Cf, r): // bidi controls and marks, zero-width, tags, soft hyphen, …
		return true
	}
	return false
}

// joinsText reports whether the joiner at s[i:i+size] sits between two
// visible non-ASCII characters, where it shapes the text.
func joinsText(s string, i, size int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	return visibleNonASCII(prev) && visibleNonASCII(next)
}

// visibleNonASCII reports whether r is a non-ASCII letter, mark, number or
// symbol. U+FFFD is excluded: it also stands for bytes that aren't UTF-8.
func visibleNonASCII(r rune) bool {
	return r >= utf8.RuneSelf && r != utf8.RuneError && unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.S)
}

func writeASCIIEscape(b *strings.Builder, c byte) {
	switch c {
	case '\t':
		b.WriteString(`\t`)
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	default:
		writeByteEscape(b, c)
	}
}

func writeByteEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0xf])
}

// writeRuneEscape writes \uHHHH, or \UHHHHHHHH above U+FFFF.
func writeRuneEscape(b *strings.Builder, r rune) {
	shift := 12
	if r > 0xffff {
		b.WriteString(`\U`)
		shift = 28
	} else {
		b.WriteString(`\u`)
	}
	for ; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>shift)&0xf])
	}
}
