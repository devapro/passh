package sanitize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestLineEscapesTerminalSequences(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"OSC 52 with BEL", "\x1b]52;c;cHduZWQ=\x07", `\x1b]52;c;cHduZWQ=\x07`},
		{"OSC 52 with ST", "\x1b]52;c;cHduZWQ=\x1b\\", `\x1b]52;c;cHduZWQ=\x1b\`},
		{"OSC 52 with 8-bit ST", "\x1b]52;c;cHduZWQ=\u009c", `\x1b]52;c;cHduZWQ=\u009c`},
		{"title OSC", "\x1b]0;pwned\x07", `\x1b]0;pwned\x07`},
		{"title OSC 2 with ST", "\x1b]2;pwned\x1b\\", `\x1b]2;pwned\x1b\`},
		{"CSI clear screen", "a\x1b[2Jb", `a\x1b[2Jb`},
		{"CSI SGR hide", "\x1b[8mhidden\x1b[0m", `\x1b[8mhidden\x1b[0m`},
		{"8-bit CSI raw byte", "\x9b2J", `\x9b2J`},
		{"8-bit CSI as U+009B", "\u009b2J", `\u009b2J`},
		{"8-bit OSC as U+009D", "\u009d52;c;eA==\u009c", `\u009d52;c;eA==\u009c`},
		{"invalid UTF-8", "ab\xff\xfe\xc3", `ab\xff\xfe\xc3`},
		{"truncated rune", "x\xe2\x82", `x\xe2\x82`},
		{"surrogate encoding", "\xed\xa0\x80", `\xed\xa0\x80`},
		{"NUL and BEL", "a\x00b\x07", `a\x00b\x07`},
		{"DEL", "a\x7fb", `a\x7fb`},
		{"backspace overwrite", "secret\x08\x08\x08\x08\x08\x08public", `secret\x08\x08\x08\x08\x08\x08public`},
		{"CR overwrite", "evil\rgood", `evil\rgood`},
		{"newline and tab", "a\nb\tc", `a\nb\tc`},
		{"bidi RLO", "abc\u202edcba", `abc\u202edcba`},
		{"bidi isolates", "\u2066x\u2069\u2067\u2068", `\u2066x\u2069\u2067\u2068`},
		{"bidi range ends", "\u202a\u202b\u202c\u202d", `\u202a\u202b\u202c\u202d`},
		// CORE-008: the rest of category Cf, and the line separators.
		{"bidi marks", "a\u200eb\u200fc\u061cd", `a\u200eb\u200fc\u061cd`},
		{"zero width space", "ba\u200bnk", `ba\u200bnk`},
		{"word joiner and BOM", "a\u2060b\ufeffc", `a\u2060b\ufeffc`},
		{"soft hyphen", "pay\u00adpal", `pay\u00adpal`},
		{"invisible operators", "a\u2061\u2062\u2063\u2064b", `a\u2061\u2062\u2063\u2064b`},
		{"Mongolian vowel separator", "a\u180eb", `a\u180eb`},
		{"line and paragraph separators", "a\u2028b\u2029c", `a\u2028b\u2029c`},
		{"tag characters", "x\U000e0041\U000e007f", `x\U000e0041\U000e007f`},
		{"joiner between ASCII", "ba\u200dnk", `ba\u200dnk`},
		{"non-joiner between ASCII", "ba\u200cnk", `ba\u200cnk`},
		{"joiner at the ends", "\u200dé\u200d", `\u200dé\u200d`},
		{"joiner next to a space", "é\u200d é", `é\u200d é`},
		{"two joiners", "é\u200d\u200dé", `é\u200d\u200dé`},
		{"joiner next to invalid UTF-8", "\xff\u200dé", `\xff\u200dé`},
		{"joiner next to U+FFFD", "\ufffd\u200dé", "\ufffd" + `\u200dé`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Line(tt.in)
			if got != tt.want {
				t.Errorf("Line(%q) = %q, want %q", tt.in, got, tt.want)
			}
			assertInert(t, got, false)
		})
	}
}

func TestTextKeepsNewlinesAndTabs(t *testing.T) {
	in := "line one\n\tindented\r\nosc \x1b]52;c;eA==\x07 end\n"
	want := "line one\n\tindented\\r\nosc \\x1b]52;c;eA==\\x07 end\n"
	got := Text(in)
	if got != want {
		t.Errorf("Text(%q) = %q, want %q", in, got, want)
	}
	assertInert(t, got, true)
}

func TestNormalUnicodeUnchanged(t *testing.T) {
	for _, s := range []string{
		"",
		"plain ASCII with symbols !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
		"Привет, мир",
		"日本語のテキスト 中文 한국어",
		"emoji 🔐🙂👍🏽 👨\u200d👩\u200d👧 🏳\ufe0f\u200d🌈",
		"العربية עברית",            // RTL scripts without bidi controls
		"\u00a0non-breaking space", // U+00A0 is just above the C1 range
		"\ufffd replacement char",
		"می\u200cخواهم",                // Persian: a non-joiner inside a word
		"क्\u200dष",                    // Devanagari: a joiner after a virama
		"combining e\u0301 and \ufe0f", // marks and variation selectors are not Cf
	} {
		if got := Line(s); got != s {
			t.Errorf("Line(%q) = %q, want unchanged", s, got)
		}
		if got := Text(s); got != s {
			t.Errorf("Text(%q) = %q, want unchanged", s, got)
		}
		if !IsSafe(s, false) || !IsSafe(s, true) {
			t.Errorf("IsSafe(%q) = false, want true", s)
		}
	}
}

func TestIsSafe(t *testing.T) {
	if IsSafe("a\nb", false) {
		t.Error(`IsSafe("a\nb", false) = true`)
	}
	if !IsSafe("a\nb", true) {
		t.Error(`IsSafe("a\nb", true) = false`)
	}
	if IsSafe("\x1b", true) {
		t.Error(`IsSafe("\x1b", true) = true`)
	}
}

func TestEveryByteAndC1Rune(t *testing.T) {
	for c := 0; c < 256; c++ {
		s := string([]byte{byte(c)})
		assertInert(t, Line(s), false)
		assertInert(t, Text(s), true)
	}
	for r := rune(0x80); r <= 0x9f; r++ {
		s := string(r)
		if got := Line(s); got == s {
			t.Errorf("Line(%U) unchanged", r)
		}
	}
}

// assertInert checks that s contains nothing a terminal would interpret.
func assertInert(t *testing.T, s string, multiline bool) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Errorf("output %q is not valid UTF-8", s)
	}
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			if !multiline {
				t.Errorf("output %q contains %U in single-line mode", s, r)
			}
		case r < 0x20 || r == 0x7f:
			t.Errorf("output %q contains control %U", s, r)
		case r >= 0x80 && r <= 0x9f:
			t.Errorf("output %q contains C1 control %U", s, r)
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			t.Errorf("output %q contains bidi control %U", s, r)
		case r == 0x2028 || r == 0x2029:
			t.Errorf("output %q contains line separator %U", s, r)
		}
	}
	// A format character survives only as a joiner between visible
	// non-ASCII characters.
	runes := []rune(s)
	for i, r := range runes {
		if !unicode.Is(unicode.Cf, r) {
			continue
		}
		ok := (r == 0x200c || r == 0x200d) && i > 0 && i < len(runes)-1 &&
			visibleOther(runes[i-1]) && visibleOther(runes[i+1])
		if !ok {
			t.Errorf("output %q contains format character %U", s, r)
		}
	}
	if strings.ContainsRune(s, 0x1b) {
		t.Errorf("output %q contains ESC", s)
	}
}

// visibleOther is the test's own notion of a character a joiner may
// connect: non-ASCII, a letter, mark, number or symbol, not U+FFFD.
func visibleOther(r rune) bool {
	return r > 0x7f && r != 0xfffd && (unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) || unicode.IsSymbol(r))
}

// FuzzLine checks the S4 invariants of Line and Text (TEST-12): the output
// is inert and safe, escaping is idempotent, IsSafe agrees with both, and
// Text differs from Line only by keeping newlines and tabs. The seed
// corpus runs as a normal test.
func FuzzLine(f *testing.F) {
	for _, s := range []string{
		"\x1b]52;c;eA==\x07", "\x9b31m", "Привет", "a\u202eb", "\xff", "a\nb\tc\r",
		"ba\u200dnk", "👨\u200d👩", "\u200d", "é\u200d", "x\U000e0041", "\u2028", "\xed\xa0\x80\u200dé",
		"\xe2\x80", "\xe2\x80\x8d", "é\xe2\x80\x8dé",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		line, text := Line(s), Text(s)
		assertInert(t, line, false)
		assertInert(t, text, true)
		if !IsSafe(line, false) || !IsSafe(text, true) {
			t.Errorf("escaped output of %q isn't safe: %q, %q", s, line, text)
		}
		if Line(line) != line || Text(text) != text {
			t.Errorf("escaping %q twice changes it", s)
		}
		if IsSafe(s, false) != (line == s) || IsSafe(s, true) != (text == s) {
			t.Errorf("IsSafe disagrees with Line or Text for %q", s)
		}
		if strings.ReplaceAll(strings.ReplaceAll(text, "\n", `\n`), "\t", `\t`) != line {
			t.Errorf("Text(%q) = %q and Line = %q differ beyond newlines and tabs", s, text, line)
		}
	})
}
