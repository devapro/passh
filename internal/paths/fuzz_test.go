package paths

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// FuzzParse checks the §4.4 rules on any input (TEST-12): Parse never
// panics; it fails only with an *Error wrapping one rule error, and
// ParseFolder agrees with it; what it accepts is NFC, at most MaxLen bytes,
// free of control characters, made of segments that are not empty, "." or
// ".." and don't start with "-"; and it is a fixed point: parsing the
// result, or its text form, gives the same Path. The seed corpus runs as a
// normal test.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"github", "work/github", "bank/My Bank", "...", ".hidden/x", "~2", "почта/яндекс",
		"cafe\u0301", "emoji/🔑", "x/\u200b", "a\\b", strings.Repeat("a", 1021) + "e\u0301",
		"", "/", "/work", "work/", "a//b", ".", "..", "a/../b", "-rf", "a/-x", "a\x00b", "\x1b[31m",
		"a\u009bb", "a\xffb", "\xed\xa0\x80", strings.Repeat("a", 1025), "Å", "שּׁ",
	} {
		f.Add(s)
	}
	rules := []error{ErrEmpty, ErrInvalidUTF8, ErrTooLong, ErrControlChar, ErrLeadingSlash,
		ErrTrailingSlash, ErrEmptySegment, ErrDotSegment, ErrDashSegment}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		fp, ferr := ParseFolder(s)
		if (err == nil) != (ferr == nil) || p != fp {
			t.Fatalf("Parse(%q) = %q, %v but ParseFolder = %q, %v", s, p, err, fp, ferr)
		}
		if err != nil {
			var pe *Error
			if !errors.As(err, &pe) || pe.Kind != "path" || !slices.Contains(rules, pe.Rule) || !p.IsZero() {
				t.Fatalf("Parse(%q) = %q, %v: not a path *Error with a rule", s, p, err)
			}
			return
		}
		got := p.String()
		switch {
		case got == "" || !utf8.ValidString(got) || !norm.NFC.IsNormalString(got) || len(got) > MaxLen:
			t.Fatalf("Parse(%q) = %q: empty, not UTF-8, not NFC or too long", s, got)
		case strings.IndexFunc(got, unicode.IsControl) >= 0:
			t.Fatalf("Parse(%q) = %q: a control character", s, got)
		case got != norm.NFC.String(s):
			t.Fatalf("Parse(%q) = %q, want the NFC form %q", s, got, norm.NFC.String(s))
		}
		for _, seg := range p.Segments() {
			if seg == "" || seg == "." || seg == ".." || seg[0] == '-' {
				t.Fatalf("Parse(%q) = %q: bad segment %q", s, got, seg)
			}
		}
		if q, err := Parse(got); err != nil || q != p {
			t.Fatalf("Parse(Parse(%q).String()) = %q, %v", s, q, err)
		}
		text, err := p.MarshalText()
		var q Path
		if err != nil || q.UnmarshalText(text) != nil || q != p {
			t.Fatalf("text round trip of %q: %v", got, err)
		}
		if strings.Join(p.Segments(), "/") != got || p.Name() != p.Segments()[len(p.Segments())-1] {
			t.Fatalf("Segments or Name of %q", got)
		}
	})
}
