package model

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

type jsonRaw = json.RawMessage

func TestNormalizeTag(t *testing.T) {
	good := []struct{ in, want string }{
		{"work", "work"},
		{"  dev\t", "dev"},
		{"2fa", "2fa"},
		{"rotate soon", "rotate soon"},
		{"café", "café"},
		{" nbsp ", "nbsp"},
		{"Work", "Work"},
	}
	for _, tt := range good {
		got, err := NormalizeTag(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("NormalizeTag(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	bad := []string{"", "   ", "a,b", ",", "a\x00b", "a\x1bb", "a\x7f", "a\u0085b", "a\u009bb", "a\tb", "a\nb", "\xff"}
	for _, in := range bad {
		if got, err := NormalizeTag(in); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("NormalizeTag(%q) = %q, %v; want ErrInvalidTag", in, got, err)
		}
	}
}

func TestNormalizeTags(t *testing.T) {
	got, err := NormalizeTags([]string{"b", " a", "b", "a ", "c"})
	if err != nil || !slices.Equal(got, []string{"b", "a", "c"}) {
		t.Errorf("NormalizeTags = %q, %v", got, err)
	}
	got, err = NormalizeTags(nil)
	if err != nil || got != nil {
		t.Errorf("NormalizeTags(nil) = %q, %v", got, err)
	}
	if _, err := NormalizeTags([]string{"a", ""}); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("NormalizeTags with empty error = %v", err)
	}
}

func TestParseTagList(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"work, dev, 2fa", []string{"work", "dev", "2fa"}},
		{"work,dev", []string{"work", "dev"}},
		{" a , , b,", []string{"a", "b"}},
		{"a, a, b", []string{"a", "b"}},
		{"", nil},
		{" , ", nil},
	}
	for _, tt := range tests {
		got, err := ParseTagList(tt.in)
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("ParseTagList(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	if _, err := ParseTagList("a, b\x1b"); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("ParseTagList control error = %v", err)
	}
}

func TestValidFieldKey(t *testing.T) {
	good := []string{"recovery-email", "a", "A1", "1password", "pin_code", "x.y", "otp", "логин", "пин-код", "é", "Ключ_2"}
	for _, k := range good {
		if !ValidFieldKey(k) {
			t.Errorf("ValidFieldKey(%q) = false", k)
		}
	}
	bad := []string{"", "-x", "_x", ".x", "has space", "a:b", "https://x", "a/b", "a\tb", " a", "a ", "́e", "---", "a@b", "a\x00"}
	for _, k := range bad {
		if ValidFieldKey(k) {
			t.Errorf("ValidFieldKey(%q) = true", k)
		}
	}
}

func TestIsReservedKey(t *testing.T) {
	for _, k := range []string{"username", "Username", "URL", "url", "tags", "TAGS"} {
		if !IsReservedKey(k) {
			t.Errorf("IsReservedKey(%q) = false", k)
		}
	}
	for _, k := range []string{"user", "login", "password", "notes", "otp", "urls", "tag"} {
		if IsReservedKey(k) {
			t.Errorf("IsReservedKey(%q) = true", k)
		}
	}
}

func TestIsSecret(t *testing.T) {
	tests := []struct {
		key, value string
		want       bool
	}{
		{"password", "x", true},
		{"otp", "123", true},
		{"OTP", "", true},
		{"backup", "otpauth://totp/x?secret=A", true},
		{"backup", "OTPAUTH://totp/x", true},
		{"url", "https://x", false},
		{"recovery-email", "me@example.com", false},
		{"note", "see otpauth://x", false},
		{"Password", "x", false}, // a custom field; only the standard name is secret by key
		{"x", "otpauth:/", false},
	}
	for _, tt := range tests {
		if got := IsSecret(tt.key, tt.value); got != tt.want {
			t.Errorf("IsSecret(%q, %q) = %v", tt.key, tt.value, got)
		}
	}
	if !(Field{Key: "otp", Value: "x"}).IsSecret() || (Field{Key: "k", Value: "v"}).IsSecret() {
		t.Error("Field.IsSecret")
	}
}

func TestEntryField(t *testing.T) {
	e := Entry{
		Path: p("a"), Password: "pw", Username: "u", URL: "https://x",
		Tags:   []string{"work", "dev"},
		Fields: []Field{{Key: "k", Value: "1"}, {Key: "k", Value: "2"}, {Key: "Password", Value: "custom"}, {Key: "empty"}},
		Notes:  "n\nm",
	}
	tests := []struct {
		name, want string
		ok         bool
	}{
		{"password", "pw", true},
		{"username", "u", true},
		{"url", "https://x", true},
		{"tags", "work, dev", true},
		{"notes", "n\nm", true},
		{"k", "1", true},
		{"Password", "custom", true},
		{"empty", "", true},
		{"K", "", false},
		{"missing", "", false},
	}
	for _, tt := range tests {
		got, ok := e.Field(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Field(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
	if got, ok := (Entry{}).Field("username"); got != "" || !ok {
		t.Error("empty standard field must exist")
	}
}

func TestNormalizeContent(t *testing.T) {
	e := Entry{
		Password: "any\tthing\x00 \x1b[31m", // control characters other than line breaks are fine
		Tags:     []string{"b ", "a", "b"},
		Fields:   []Field{{Key: "otp", Value: "otpauth://totp/x"}, {Key: "otp", Value: "dup ok"}, {Key: "Password", Value: "x"}},
		Notes:    "multi\nline\r\n---\n",
	}
	if err := e.NormalizeContent(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.Tags, []string{"b", "a"}) {
		t.Errorf("tags = %q", e.Tags)
	}
	msgs := map[string]Entry{
		"invalid entry: password must be a single line":                                  {Password: "a\nb"},
		"invalid entry: url must be a single line":                                       {URL: "a\rb"},
		"invalid entry: username is not valid UTF-8":                                     {Username: "\xff"},
		"invalid entry: field k must be a single line":                                   {Fields: []Field{{Key: "k", Value: "\n"}}},
		`invalid entry: "Tags" can't be a custom field key`:                              {Fields: []Field{{Key: "Tags"}}},
		"invalid entry: notes are not valid UTF-8":                                       {Notes: "\xc3"},
		`invalid tag "a,b": it contains a comma`:                                         {Tags: []string{"a,b"}},
		`invalid entry: field key "a b" is not valid (letters, digits, then also _ . -)`: {Fields: []Field{{Key: "a b"}}},
	}
	for want, e := range msgs {
		err := e.NormalizeContent()
		if err == nil || err.Error() != want {
			t.Errorf("NormalizeContent error = %v, want %q", err, want)
		}
	}
}
