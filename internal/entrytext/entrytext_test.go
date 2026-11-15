package entrytext

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

const specExample = `s3cr3t-P@ss
username: arsenii
url: https://github.com
tags: work, dev, 2fa
recovery-email: me@example.com
---
Free-form notes. Recovery codes, etc.
`

func specEntry() model.Entry {
	return model.Entry{
		Password: "s3cr3t-P@ss",
		Username: "arsenii",
		URL:      "https://github.com",
		Tags:     []string{"work", "dev", "2fa"},
		Fields:   []model.Field{{Key: "recovery-email", Value: "me@example.com"}},
		Notes:    "Free-form notes. Recovery codes, etc.",
	}
}

// sameContent compares what the text form carries.
func sameContent(a, b model.Entry) bool {
	return a.Password == b.Password && a.Username == b.Username && a.URL == b.URL &&
		a.Notes == b.Notes && slices.Equal(a.Tags, b.Tags) &&
		slices.EqualFunc(a.Fields, b.Fields, func(x, y model.Field) bool { return x.Key == y.Key && x.Value == y.Value })
}

func mustParse(t *testing.T, text string, imp bool) model.Entry {
	t.Helper()
	parse := Parse
	if imp {
		parse = ParseImport
	}
	e, err := parse(text)
	if err != nil {
		t.Fatalf("parse(%q): %v", text, err)
	}
	return e
}

func TestFormatSpecExample(t *testing.T) {
	e := specEntry()
	e.Path = paths.MustParse("work/github") // not part of the text form
	e.ID = "x"
	if got := Format(e); got != specExample {
		t.Errorf("Format =\n%s\nwant\n%s", got, specExample)
	}
	if got := mustParse(t, specExample, false); !sameContent(got, specEntry()) {
		t.Errorf("Parse = %+v", got)
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		e    model.Entry
		want string
	}{
		{model.Entry{}, "\n"},
		{model.Entry{Password: "pw"}, "pw\n"},
		{model.Entry{Password: "pw", Notes: "n"}, "pw\n---\nn\n"},
		{model.Entry{Password: "pw", Fields: []model.Field{{Key: "k"}, {Key: "k", Value: " v"}}}, "pw\nk:\nk:  v\n"},
		{model.Entry{Password: "pw", Tags: []string{"a"}, URL: "u"}, "pw\nurl: u\ntags: a\n"},
	}
	for _, tt := range tests {
		if got := Format(tt.e); got != tt.want {
			t.Errorf("Format(%+v) = %q, want %q", tt.e, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	f := func(kv ...string) []model.Field {
		var out []model.Field
		for i := 0; i < len(kv); i += 2 {
			out = append(out, model.Field{Key: kv[i], Value: kv[i+1]})
		}
		return out
	}
	tests := []struct {
		name string
		in   string
		want model.Entry
	}{
		{"empty", "", model.Entry{}},
		{"password only, no newline", "pw", model.Entry{Password: "pw"}},
		{"password only", "pw\n", model.Entry{Password: "pw"}},
		{"empty password", "\nusername: u\n", model.Entry{Username: "u"}},
		{"password is exact", "  p: w --- \t\n", model.Entry{Password: "  p: w --- \t"}},
		{"password ---", "---\nurl: u\n", model.Entry{Password: "---", URL: "u"}},
		{"trailing CR dropped", "pw\r", model.Entry{Password: "pw"}},
		{"spec example CRLF", strings.ReplaceAll(specExample, "\n", "\r\n"), specEntry()},
		{"CRLF notes", "pw\r\n---\r\na\r\nb\r\n", model.Entry{Password: "pw", Notes: "a\nb"}},
		{"LF keeps CR in notes", "pw\n---\na\r\nb\n", model.Entry{Password: "pw", Notes: "a\r\nb"}},
		{"url line is notes", "pw\nhttps://example.com\nmore\n", model.Entry{Password: "pw", Notes: "https://example.com\nmore"}},
		{"no space after colon", "pw\nPIN:1234\n", model.Entry{Password: "pw", Notes: "PIN:1234"}},
		{"tab after colon", "pw\nk:\tv\n", model.Entry{Password: "pw", Notes: "k:\tv"}},
		{"space in key", "pw\nSecurity question: x\n", model.Entry{Password: "pw", Notes: "Security question: x"}},
		{"leading space", "pw\n username: u\n", model.Entry{Password: "pw", Notes: " username: u"}},
		{"metadata stops at first non-match", "pw\nk: 1\nfree text\nk2: 2\n", model.Entry{Password: "pw", Fields: f("k", "1"), Notes: "free text\nk2: 2"}},
		{"blank line ends metadata", "pw\nk: 1\n\n\n  \nnotes\nk2: 2\n", model.Entry{Password: "pw", Fields: f("k", "1"), Notes: "notes\nk2: 2"}},
		{"only blank lines", "pw\n\n\n", model.Entry{Password: "pw"}},
		{"blank last line without newline", "pw\nk: 1\n  ", model.Entry{Password: "pw", Fields: f("k", "1")}},
		{"--- keeps blank lines", "pw\n---\n\nnotes\n\n", model.Entry{Password: "pw", Notes: "\nnotes\n"}},
		{"--- at end", "pw\nk: 1\n---\n", model.Entry{Password: "pw", Fields: f("k", "1")}},
		{"--- without newline", "pw\n---", model.Entry{Password: "pw"}},
		{"notes without final newline", "pw\n---\nabc", model.Entry{Password: "pw", Notes: "abc"}},
		{"second --- is notes", "pw\n---\n---\nx\n", model.Entry{Password: "pw", Notes: "---\nx"}},
		{"empty values", "pw\nusername:\nurl:\ntags:\nk:\n", model.Entry{Password: "pw", Fields: f("k", "")}},
		{"value keeps spaces", "pw\nk:  two \n", model.Entry{Password: "pw", Fields: f("k", " two ")}},
		{"value with colon", "pw\nurl: https://x:8080/a\n", model.Entry{Password: "pw", URL: "https://x:8080/a"}},
		{"repeated fields in order", "pw\nb: 1\na: 2\nb: 3\n", model.Entry{Password: "pw", Fields: f("b", "1", "a", "2", "b", "3")}},
		{"tags lines add up", "pw\ntags: a, b\nTags: b,c,\n", model.Entry{Password: "pw", Tags: []string{"a", "b", "c"}}},
		{"keys any case", "pw\nUsername: u\nURL: x\nTAGS: t\n", model.Entry{Password: "pw", Username: "u", URL: "x", Tags: []string{"t"}}},
		{"user is a custom field", "pw\nuser: u\nlogin: l\n", model.Entry{Password: "pw", Fields: f("user", "u", "login", "l")}},
		{"otpauth is notes", "pw\notpauth://totp/x\n", model.Entry{Password: "pw", Notes: "otpauth://totp/x"}},
		{"otp field", "pw\notp: otpauth://totp/x\n", model.Entry{Password: "pw", Fields: f("otp", "otpauth://totp/x")}},
		{"unicode keys", "pw\nлогин: вася\nпин-код: 1\n", model.Entry{Password: "pw", Fields: f("логин", "вася", "пин-код", "1")}},
		{"metadata CR in LF text", "pw\nk: v\r\n", model.Entry{Password: "pw", Fields: f("k", "v")}},
		{"control chars in values", "p\x1bw\nk: \x1b[31m\n---\n\x07", model.Entry{Password: "p\x1bw", Fields: f("k", "\x1b[31m"), Notes: "\x07"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.in, false)
			if !sameContent(got, tt.want) {
				t.Errorf("Parse(%q)\n got %#v\nwant %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in, want string
		is       error
		line     int // the *SyntaxError's line; 0: not a SyntaxError
	}{
		{"pw\nusername: a\nusername: b\n", "line 3: username appears twice", ErrDuplicate, 3},
		{"pw\nusername: a\nUserName: b\n", "line 3: username appears twice", ErrDuplicate, 3},
		{"pw\nurl: a\nk: v\nurl: b\n", "line 4: url appears twice", ErrDuplicate, 4},
		{"pw\ntags: a, b\x1b\n", `line 2: invalid tag "b\x1b": it contains a control character`, model.ErrInvalidTag, 2},
		{"pw\xff\n", "the text is not valid UTF-8", nil, 0},
		{"p\rw\n", "invalid entry: password must be a single line", model.ErrInvalidEntry, 0},
	}
	for _, tt := range tests {
		_, err := Parse(tt.in)
		if err == nil || err.Error() != tt.want {
			t.Errorf("Parse(%q) error = %v, want %q", tt.in, err, tt.want)
		}
		if tt.is != nil && !errors.Is(err, tt.is) {
			t.Errorf("Parse(%q) error %v is not %v", tt.in, err, tt.is)
		}
		var se *SyntaxError
		switch got := errors.As(err, &se); {
		case tt.line == 0 && got:
			t.Errorf("Parse(%q) error %v is a *SyntaxError (line %d), want another error", tt.in, err, se.Line)
		case tt.line != 0 && (!got || se.Line != tt.line):
			t.Errorf("Parse(%q) error %v: SyntaxError %v, want line %d", tt.in, err, se, tt.line)
		}
	}
}

func TestParseImport(t *testing.T) {
	f := func(kv ...string) []model.Field {
		var out []model.Field
		for i := 0; i < len(kv); i += 2 {
			out = append(out, model.Field{Key: kv[i], Value: kv[i+1]})
		}
		return out
	}
	tests := []struct {
		name string
		in   string
		want model.Entry
	}{
		{"spec example", specExample, specEntry()},
		{"user", "pw\nuser: bob\n", model.Entry{Password: "pw", Username: "bob"}},
		{"login", "pw\nLogin: bob\n", model.Entry{Password: "pw", Username: "bob"}},
		{"second user is a field", "pw\nusername: a\nuser: b\nlogin: c\n", model.Entry{Password: "pw", Username: "a", Fields: f("user", "b", "login", "c")}},
		{"second username goes to notes", "pw\nuser: a\nUsername: b\n---\nn\n", model.Entry{Password: "pw", Username: "a", Notes: "Username: b\nn"}},
		{"second url goes to notes", "pw\nurl: a\nurl: b\n", model.Entry{Password: "pw", URL: "a", Notes: "url: b"}},
		{"bad tags go to notes", "pw\ntags: a\x1b\nk: v\nfree\n", model.Entry{Password: "pw", Fields: f("k", "v"), Notes: "tags: a\x1b\nfree"}},
		{"pass-otp at the end", "pw\nlogin: me\n\nsome notes\notpauth://totp/x?secret=AB\n", model.Entry{Password: "pw", Username: "me", Fields: f("otp", "otpauth://totp/x?secret=AB"), Notes: "some notes"}},
		{"pass-otp only", "pw\notpauth://totp/x?secret=AB\n", model.Entry{Password: "pw", Fields: f("otp", "otpauth://totp/x?secret=AB")}},
		{"otpauth in metadata keeps metadata going", "pw\nk: 1\n  otpauth://totp/a \nurl: u\n", model.Entry{Password: "pw", URL: "u", Fields: f("k", "1", "otp", "otpauth://totp/a")}},
		{"otpauth after ---", "pw\n---\nline\nOTPAUTH://hotp/b\nmore\n", model.Entry{Password: "pw", Fields: f("otp", "OTPAUTH://hotp/b"), Notes: "line\nmore"}},
		{"otp key", "pw\notp: otpauth://totp/c\n", model.Entry{Password: "pw", Fields: f("otp", "otpauth://totp/c")}},
		{"otpauth on line 1 is the password", "otpauth://totp/p\n", model.Entry{Password: "otpauth://totp/p"}},
		{"otpauth mid-line stays", "pw\nsee otpauth://totp/x\n", model.Entry{Password: "pw", Notes: "see otpauth://totp/x"}},
		{"CRLF", "pw\r\nuser: u\r\nnotes\r\notpauth://totp/x\r\n", model.Entry{Password: "pw", Username: "u", Fields: f("otp", "otpauth://totp/x"), Notes: "notes"}},
		{"trailing blank lines dropped", "pw\n---\nn\n\n  \n\n", model.Entry{Password: "pw", Notes: "n"}},
		{"empty", "", model.Entry{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustParse(t, tt.in, true)
			if !sameContent(got, tt.want) {
				t.Errorf("ParseImport(%q)\n got %#v\nwant %#v", tt.in, got, tt.want)
			}
		})
	}
	if _, err := ParseImport("p\rw\n"); !errors.Is(err, model.ErrInvalidEntry) {
		t.Errorf("ParseImport bad password error = %v", err)
	}
	if _, err := ParseImport("\xff"); err == nil {
		t.Error("ParseImport accepted invalid UTF-8")
	}
	// The result is always storable.
	d := model.NewData()
	e := mustParse(t, "pw\nuser: a\nUsername: b\ntags: x,\x01\notpauth://x\n", true)
	e.Path = paths.MustParse("imported")
	if _, err := d.Add(e, d.SavedAt, false); err != nil {
		t.Errorf("Add(ParseImport(…)): %v", err)
	}
}

// Parse(Format(e)) gives back e's content for every valid entry.
func TestRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	// Pieces chosen to hit the grammar's edges.
	pieces := []string{
		"a", "Z", "0", " ", "  ", ":", ": ", "-", "---", "/", "//", "https://x", "\t", ",", "é", "e\u0301",
		"😀", "\x1b[31m", "\x00", "\u0085", "otpauth://totp/x", "username: u", "url:", "tags: a", "key: v",
		"\u00a0", "\\", "\"", "<>", "#",
	}
	multi := append(slices.Clone(pieces), "\n", "\r\n", "\r", "\n---\n", "\n\n", "\nusername: x\n")
	str := func(pool []string, max int) string {
		var b strings.Builder
		for range r.IntN(max + 1) {
			b.WriteString(pool[r.IntN(len(pool))])
		}
		return b.String()
	}
	keyRunes := []rune("abcXYZ019_.-логé")
	key := func() string {
		for {
			var b strings.Builder
			for range 1 + r.IntN(8) {
				b.WriteRune(keyRunes[r.IntN(len(keyRunes))])
			}
			k := b.String()
			if model.ValidFieldKey(k) && !model.IsReservedKey(k) {
				return k
			}
		}
	}
	checked := 0
	for range 20000 {
		e := model.Entry{
			Password: str(pieces, 6),
			Username: str(pieces, 3),
			URL:      str(pieces, 3),
			Notes:    str(multi, 10),
		}
		for range r.IntN(4) {
			e.Tags = append(e.Tags, str(pieces, 3))
		}
		for range r.IntN(5) {
			e.Fields = append(e.Fields, model.Field{Key: key(), Value: str(pieces, 4)})
		}
		if r.IntN(4) == 0 { // empty everything but the password, sometimes
			e.Username, e.URL, e.Tags, e.Fields, e.Notes = "", "", nil, nil, ""
		}
		if err := e.NormalizeContent(); err != nil {
			continue // e.g. a tag with a comma or a control character
		}
		checked++
		text := Format(e)
		got, err := Parse(text)
		if err != nil {
			t.Fatalf("Parse(Format(%#v)) error: %v\ntext: %q", e, err, text)
		}
		if !sameContent(got, e) {
			t.Fatalf("round trip differs\n  in: %#v\n out: %#v\ntext: %q", e, got, text)
		}
		if again := Format(got); again != text {
			t.Fatalf("Format not stable: %q != %q", again, text)
		}
	}
	if checked < 5000 {
		t.Fatalf("only %d valid entries generated", checked)
	}
}

// Text a user may write by hand round-trips through Parse and Format to a
// fixed point.
func TestParseFormatFixedPoint(t *testing.T) {
	for _, in := range []string{
		specExample,
		"pw\nuser: x\nhttps://y\n",
		"pw\r\nurl: u\r\n\r\nnotes\r\n",
		"pw\n\n\nnotes",
	} {
		e := mustParse(t, in, false)
		text := Format(e)
		e2 := mustParse(t, text, false)
		if !sameContent(e, e2) || Format(e2) != text {
			t.Errorf("not a fixed point: %q → %q", in, text)
		}
	}
}
