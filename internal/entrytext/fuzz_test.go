package entrytext

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
)

// textSeeds are texts that reach every branch of the grammar: the seed
// corpus that every `go test` runs (TEST-12).
var textSeeds = []string{
	specExample,
	"",
	"pw",
	"pw\n",
	"pw\r\nusername: u\r\nurl: x\r\n\r\nnotes\r\n",
	"pw\nusername: a\nusername: b\n",
	"pw\nuser: a\nlogin: b\nurl: u\nurl: v\n",
	"pw\ntags: a, b\ntags: c\n---\n---\nnotes\n",
	"pw\ntags: a, b\x1b\n",
	"pw\nk:\nk: v\nK: w\n\n\n  \nnotes\nk2: 2\n",
	"pw\nhttps://example.com\nPIN:1234\n",
	"pw\notpauth://totp/x?secret=A\nnotes\n otpauth://hotp/y \n",
	"otpauth://totp/p\n",
	"pw\xff\n",
	"p\rw\n",
	"pw\n\u202eevil: x\n\x00\x7f\u0085\n",
	"pw\n---",
	"\n\n\n",
}

// FuzzParse feeds arbitrary text to Parse and ParseImport: they never panic,
// a line error names a line of the text, and whatever they accept survives
// Format and Parse unchanged (§4.3).
func FuzzParse(f *testing.F) {
	for _, s := range textSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		lines := strings.Count(text, "\n") + 1
		for _, imp := range []bool{false, true} {
			parse, name := Parse, "Parse"
			if imp {
				parse, name = ParseImport, "ParseImport"
			}
			e, err := parse(text)
			var se *SyntaxError
			if errors.As(err, &se) {
				if se.Line < 2 || se.Line > lines {
					t.Fatalf("%s(%q): %v names line %d of %d", name, text, err, se.Line, lines)
				}
				if want := fmt.Sprintf("line %d: ", se.Line); !strings.HasPrefix(err.Error(), want) {
					t.Fatalf("%s(%q): message %q doesn't start with %q", name, text, err, want)
				}
			}
			if err != nil {
				continue
			}
			checkRoundTrip(t, e)
		}
	})
}

// FuzzFormat builds an entry from arbitrary values: every entry that
// model.Entry.NormalizeContent accepts comes back from Parse(Format(e))
// with the same content, and Format is stable.
func FuzzFormat(f *testing.F) {
	e := specEntry()
	f.Add(e.Password, e.Username, e.URL, "work, dev, 2fa", e.Fields[0].Key, e.Fields[0].Value, e.Notes)
	f.Add("", "", "", "", "k", "", "")
	f.Add("p\x1b[31m", "u:", "url: x", "a,b", "username", "v", "---\nx\n---")
	f.Add("pw", "x\u202e", "", "", "otp", "otpauth://totp/x", "\n\nnotes\n\n")
	f.Add("pw", "", "", "", "key", "value", "line\r\nusername: x\n")
	f.Fuzz(func(t *testing.T, password, username, url, tags, key, value, notes string) {
		e := model.Entry{Password: password, Username: username, URL: url, Notes: notes}
		if tags != "" {
			e.Tags = strings.Split(tags, ",")
		}
		if key != "" {
			e.Fields = []model.Field{{Key: key, Value: value}}
		}
		if err := e.NormalizeContent(); err != nil {
			return // not a valid entry: Format makes no promise
		}
		checkRoundTrip(t, e)
	})
}

// checkRoundTrip checks that e's text form parses back to e's content and
// formats to the same text again.
func checkRoundTrip(t *testing.T, e model.Entry) {
	t.Helper()
	text := Format(e)
	got, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(Format(%#v)) error: %v\ntext: %q", e, err, text)
	}
	if !sameContent(got, e) {
		t.Fatalf("Parse(Format(e)) differs\n  in: %#v\n out: %#v\ntext: %q", e, got, text)
	}
	if again := Format(got); again != text {
		t.Fatalf("Format(Parse(Format(e))) = %q, want %q", again, text)
	}
}
