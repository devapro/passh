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
//   - Unicode bidi embeddings, overrides and isolates (U+202A–U+202E,
//     U+2066–U+2069) as \uHHHH, so text can't be reordered on screen.
//
// Everything else, including Cyrillic, CJK and emoji, passes through
// unchanged. A backslash is not escaped: the output is for people, and
// doubling every backslash in a password would mislead more often than the
// rare ambiguity with a literal "\x1b" in a value. `show --raw` prints exact
// bytes for the cases where that matters.
package sanitize

import (
	"strings"
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
		if (r == utf8.RuneError && size == 1) || dangerousRune(r) {
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
		case dangerousRune(r):
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

func dangerousRune(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f: // C1 controls, including 8-bit CSI U+009B
		return true
	case r >= 0x202a && r <= 0x202e: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	}
	return false
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

func writeRuneEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>shift)&0xf])
	}
}
