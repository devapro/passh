package paths

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct{ in, want string }{
		{"github", "github"},
		{"work/github", "work/github"},
		{"a/b/c/d", "a/b/c/d"},
		{"bank/My Bank", "bank/My Bank"},
		{"work/git-hub", "work/git-hub"},
		{"work/x-", "work/x-"},
		{"...", "..."},
		{".hidden/x", ".hidden/x"},
		{"a./..b", "a./..b"},
		{"~2", "~2"},
		{"work/github~2", "work/github~2"},
		{"Work/GitHub", "Work/GitHub"},
		{"почта/яндекс", "почта/яндекс"},
		{"é", "é"},              // NFD → NFC
		{"café", "café"},         // already NFC
		{"a\\b", "a\\b"},         // backslash is an ordinary character
		{"emoji/🔑", "emoji/🔑"},   // non-BMP
		{"x/\u200b", "x/\u200b"}, // format characters are not Cc
		{strings.Repeat("a", 1024), strings.Repeat("a", 1024)},
		// 1025 bytes decomposed, 1024 after NFC: the limit applies after normalization.
		{strings.Repeat("a", 1021) + "é", strings.Repeat("a", 1021) + "é"},
	}
	for _, tt := range tests {
		p, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.in, err)
			continue
		}
		if p.String() != tt.want {
			t.Errorf("Parse(%q) = %q, want %q", tt.in, p.String(), tt.want)
		}
	}
}

// Safety test 1 (§13.2), path part.
func TestParseInvalid(t *testing.T) {
	tests := []struct {
		in   string
		rule error
	}{
		{"", ErrEmpty},
		{"/", ErrLeadingSlash},
		{"/work", ErrLeadingSlash},
		{"//work", ErrLeadingSlash},
		{"work/", ErrTrailingSlash},
		{"work//github", ErrEmptySegment},
		{"a///b", ErrEmptySegment},
		{".", ErrDotSegment},
		{"..", ErrDotSegment},
		{"./a", ErrDotSegment},
		{"../a", ErrDotSegment},
		{"a/./b", ErrDotSegment},
		{"a/../b", ErrDotSegment},
		{"a/..", ErrDotSegment},
		{"a/.", ErrDotSegment},
		{"../../etc/passwd", ErrDotSegment},
		{"-rf", ErrDashSegment},
		{"work/-x", ErrDashSegment},
		{"a/b/--force", ErrDashSegment},
		{"-", ErrDashSegment},
		{"a\x00b", ErrControlChar},
		{"a\nb", ErrControlChar},
		{"a\rb", ErrControlChar},
		{"a\tb", ErrControlChar},
		{"\x1b[31mred", ErrControlChar},
		{"\x1b]52;c;aGk=\x07", ErrControlChar},
		{"a\x7fb", ErrControlChar},
		{"a\u0080b", ErrControlChar},
		{"a\u0085b", ErrControlChar}, // NEL
		{"a\u009bb", ErrControlChar}, // C1 CSI
		{"a\u009fb", ErrControlChar},
		{"a\xffb", ErrInvalidUTF8},
		{"a\xc0\xafb", ErrInvalidUTF8},   // overlong "/"
		{"\xed\xa0\x80", ErrInvalidUTF8}, // surrogate
		{strings.Repeat("a", 1025), ErrTooLong},
		{strings.Repeat("ab/", 342) + "c", ErrTooLong},
	}
	for _, tt := range tests {
		p, err := Parse(tt.in)
		if err == nil {
			t.Errorf("Parse(%q) = %q, want error %v", tt.in, p, tt.rule)
			continue
		}
		if !errors.Is(err, tt.rule) {
			t.Errorf("Parse(%q) error = %v, want rule %v", tt.in, err, tt.rule)
		}
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != "path" {
			t.Errorf("Parse(%q) error %v is not a path *Error", tt.in, err)
		}
		if !p.IsZero() {
			t.Errorf("Parse(%q) returned non-zero path on error", tt.in)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "invalid path: it is empty"},
		{"a/../b", `invalid path: it has a "." or ".." segment`},
		{"a/-b", "invalid path: a segment starts with -"},
		{"a//b", "invalid path: it has an empty segment (//)"},
		{"/a", "invalid path: it starts with /"},
		{"a/", "invalid path: it ends with /"},
		{"a\x1b", "invalid path: it contains a control character"},
		{"a\xff", "invalid path: it is not valid UTF-8"},
		{strings.Repeat("x", 2000), "invalid path: it is longer than 1024 bytes"},
	}
	for _, tt := range tests {
		_, err := Parse(tt.in)
		if err == nil || err.Error() != tt.want {
			t.Errorf("Parse(%q) error = %v, want %q", tt.in, err, tt.want)
		}
	}
}

func TestParseFolder(t *testing.T) {
	f, err := ParseFolder("work/dev")
	if err != nil || f.String() != "work/dev" {
		t.Fatalf("ParseFolder = %q, %v", f, err)
	}
	for _, in := range []string{"", "work/", "/work", "..", "a/./b", "-x", "a\x1bb"} {
		_, err := ParseFolder(in)
		var pe *Error
		if !errors.As(err, &pe) || pe.Kind != "folder" {
			t.Errorf("ParseFolder(%q) error = %v, want folder *Error", in, err)
		}
	}
	_, err = ParseFolder("work/")
	if err == nil || err.Error() != "invalid folder: it ends with /" {
		t.Errorf("ParseFolder(work/) error = %v", err)
	}
}

func TestMustParse(t *testing.T) {
	if MustParse("a/b").String() != "a/b" {
		t.Fatal("MustParse")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustParse(..) did not panic")
		}
	}()
	MustParse("..")
}

func TestAccessors(t *testing.T) {
	tests := []struct {
		in     string
		segs   []string
		name   string
		folder string
	}{
		{"github", []string{"github"}, "github", ""},
		{"work/github", []string{"work", "github"}, "github", "work"},
		{"a/b/c", []string{"a", "b", "c"}, "c", "a/b"},
	}
	for _, tt := range tests {
		p := MustParse(tt.in)
		if got := p.Segments(); !slices.Equal(got, tt.segs) {
			t.Errorf("%q.Segments() = %q", tt.in, got)
		}
		if got := p.Name(); got != tt.name {
			t.Errorf("%q.Name() = %q", tt.in, got)
		}
		if got := p.Folder(); got != tt.folder {
			t.Errorf("%q.Folder() = %q", tt.in, got)
		}
	}
	var zero Path
	if !zero.IsZero() || zero.String() != "" || zero.Segments() != nil {
		t.Error("zero Path accessors")
	}
	p := MustParse("a/b")
	segs := p.Segments()
	segs[0] = "x"
	if p.String() != "a/b" {
		t.Error("Segments aliases the path")
	}
}

func TestInFolderHasPrefix(t *testing.T) {
	tests := []struct {
		path, folder string
		in, prefix   bool
	}{
		{"work/x", "work", true, true},
		{"work/a/b", "work", true, true},
		{"work/a/b", "work/a", true, true},
		{"workshop/x", "work", false, false},
		{"work-old/x", "work", false, false},
		{"work", "work", false, true},
		{"work", "work/x", false, false},
		{"Work/x", "work", false, false},
		{"other/work/x", "work", false, false},
	}
	for _, tt := range tests {
		p, f := MustParse(tt.path), MustParse(tt.folder)
		if got := p.InFolder(f); got != tt.in {
			t.Errorf("%q.InFolder(%q) = %v", tt.path, tt.folder, got)
		}
		if got := p.HasPrefix(f); got != tt.prefix {
			t.Errorf("%q.HasPrefix(%q) = %v", tt.path, tt.folder, got)
		}
	}
	if !MustParse("a").InFolder(Path{}) || !MustParse("a/b").InFolder(Path{}) {
		t.Error("every path is in the root")
	}
	if (Path{}).InFolder(Path{}) {
		t.Error("the zero path is not in the root")
	}
}

func TestWithName(t *testing.T) {
	p := MustParse("work/github")
	q, err := p.WithName(p.Name() + "~2")
	if err != nil || q.String() != "work/github~2" {
		t.Fatalf("WithName = %q, %v", q, err)
	}
	q, err = MustParse("top").WithName("top~3")
	if err != nil || q.String() != "top~3" {
		t.Fatalf("WithName top = %q, %v", q, err)
	}
	if _, err := p.WithName("../x"); !errors.Is(err, ErrDotSegment) {
		t.Errorf("WithName(../x) error = %v", err)
	}
	if _, err := p.WithName(""); !errors.Is(err, ErrTrailingSlash) {
		t.Errorf("WithName(\"\") error = %v", err)
	}
}

func TestCompare(t *testing.T) {
	in := []string{"work-old/y", "work/x", "a", "work", "b/a", "work/a/b", "B", "a/b", "work/a"}
	want := []string{"B", "a", "a/b", "b/a", "work", "work/a", "work/a/b", "work/x", "work-old/y"}
	ps := make([]Path, len(in))
	for i, s := range in {
		ps[i] = MustParse(s)
	}
	slices.SortFunc(ps, Compare)
	got := make([]string, len(ps))
	for i, p := range ps {
		got[i] = p.String()
	}
	if !slices.Equal(got, want) {
		t.Errorf("sorted = %q, want %q", got, want)
	}
	if Compare(MustParse("a/b"), MustParse("a/b")) != 0 {
		t.Error("Compare equal")
	}
	if Compare(Path{}, MustParse("a")) != -1 || Compare(MustParse("a"), Path{}) != 1 || Compare(Path{}, Path{}) != 0 {
		t.Error("Compare with zero")
	}
}

func TestEqualityAndMapKey(t *testing.T) {
	a := MustParse("café/x")
	b := MustParse("café/x")
	if a != b {
		t.Error("NFC-equal paths differ")
	}
	m := map[Path]int{a: 1}
	if m[b] != 1 {
		t.Error("map lookup")
	}
	if MustParse("Work") == MustParse("work") {
		t.Error("paths must be case-sensitive")
	}
}

func TestText(t *testing.T) {
	p := MustParse("work/github")
	b, err := p.MarshalText()
	if err != nil || string(b) != "work/github" {
		t.Fatalf("MarshalText = %q, %v", b, err)
	}
	if _, err := (Path{}).MarshalText(); !errors.Is(err, ErrEmpty) {
		t.Errorf("zero MarshalText error = %v", err)
	}
	var q Path
	if err := q.UnmarshalText([]byte("café")); err != nil || q.String() != "café" {
		t.Errorf("UnmarshalText = %q, %v", q, err)
	}
	q = p
	if err := q.UnmarshalText([]byte("../x")); !errors.Is(err, ErrDotSegment) {
		t.Errorf("UnmarshalText(../x) error = %v", err)
	}
	if q != p {
		t.Error("failed UnmarshalText changed the value")
	}

	// Through encoding/json, as the model uses it.
	var v struct {
		P Path `json:"p"`
	}
	if err := json.Unmarshal([]byte(`{"p":"a/b"}`), &v); err != nil || v.P.String() != "a/b" {
		t.Errorf("json decode = %q, %v", v.P, err)
	}
	if err := json.Unmarshal([]byte(`{"p":"a//b"}`), &v); !errors.Is(err, ErrEmptySegment) {
		t.Errorf("json decode invalid error = %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil || string(out) != `{"p":"a/b"}` {
		t.Errorf("json encode = %s, %v", out, err)
	}
}
