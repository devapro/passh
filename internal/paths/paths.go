// Package paths validates entry paths and folders (spec §4.4).
//
// A Path can only be obtained through Parse, ParseFolder, MustParse or
// UnmarshalText, so a Path value always satisfies the rules below. Path is
// comparable with == and usable as a map key; the zero Path is "no path".
//
// Rules:
//   - segments are separated by "/"; none is empty; no leading or trailing "/";
//   - no "." or ".." segment, and no segment starts with "-";
//   - no control characters (C0, DEL, C1);
//   - valid UTF-8, normalized to NFC before the checks;
//   - at most MaxLen bytes after normalization.
//
// Paths are case-sensitive.
package paths

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxLen is the longest path, in bytes, after NFC normalization.
const MaxLen = 1024

// Rule errors. Parse and ParseFolder return an *Error that wraps one of
// them, so callers can test with errors.Is.
var (
	// ErrEmpty means the path is empty.
	ErrEmpty = errors.New("it is empty")
	// ErrInvalidUTF8 means the path is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("it is not valid UTF-8")
	// ErrTooLong means the path is longer than MaxLen bytes after NFC
	// normalization.
	ErrTooLong = errors.New("it is longer than 1024 bytes")
	// ErrControlChar means the path contains a control character (C0, DEL
	// or C1).
	ErrControlChar = errors.New("it contains a control character")
	// ErrLeadingSlash means the path starts with "/".
	ErrLeadingSlash = errors.New("it starts with /")
	// ErrTrailingSlash means the path ends with "/".
	ErrTrailingSlash = errors.New("it ends with /")
	// ErrEmptySegment means the path has an empty segment ("//").
	ErrEmptySegment = errors.New("it has an empty segment (//)")
	// ErrDotSegment means the path has a "." or ".." segment.
	ErrDotSegment = errors.New(`it has a "." or ".." segment`)
	// ErrDashSegment means a segment starts with "-".
	ErrDashSegment = errors.New("a segment starts with -")
)

// Error reports which rule a path or folder failed.
type Error struct {
	Kind string // "path" or "folder"
	Rule error  // one of the Err* rule errors
}

func (e *Error) Error() string { return "invalid " + e.Kind + ": " + e.Rule.Error() }

// Unwrap returns the rule error.
func (e *Error) Unwrap() error { return e.Rule }

// Path is a validated entry path such as "work/github".
type Path struct {
	s string
}

// Parse validates s as an entry path and returns it in NFC form.
func Parse(s string) (Path, error) { return parse(s, "path") }

// ParseFolder validates s as a folder (for `ls [folder]`, `--folder`). The
// rules are the same as for an entry path; only the error wording differs.
func ParseFolder(s string) (Path, error) { return parse(s, "folder") }

// MustParse is Parse that panics on an invalid path. For constants and tests.
func MustParse(s string) Path {
	p, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return p
}

func parse(s, kind string) (Path, error) {
	n, err := normalize(s)
	if err != nil {
		return Path{}, &Error{Kind: kind, Rule: err}
	}
	return Path{s: n}, nil
}

// normalize returns the NFC form of s, or the first rule it breaks. Every
// rule applies to the NFC form.
func normalize(s string) (string, error) {
	if s == "" {
		return "", ErrEmpty
	}
	if !utf8.ValidString(s) {
		return "", ErrInvalidUTF8
	}
	s = norm.NFC.String(s)
	if len(s) > MaxLen {
		return "", ErrTooLong
	}
	for _, r := range s {
		if unicode.IsControl(r) { // Cc: C0, DEL and C1
			return "", ErrControlChar
		}
	}
	if s[0] == '/' {
		return "", ErrLeadingSlash
	}
	if s[len(s)-1] == '/' {
		return "", ErrTrailingSlash
	}
	for seg := range strings.SplitSeq(s, "/") {
		switch {
		case seg == "":
			return "", ErrEmptySegment
		case seg == "." || seg == "..":
			return "", ErrDotSegment
		case seg[0] == '-':
			return "", ErrDashSegment
		}
	}
	return s, nil
}

// String returns the path, e.g. "work/github". It is "" for the zero Path.
func (p Path) String() string { return p.s }

// IsZero reports whether p is the zero Path.
func (p Path) IsZero() bool { return p.s == "" }

// Segments returns the path's segments. The slice is a fresh copy.
func (p Path) Segments() []string {
	if p.s == "" {
		return nil
	}
	return strings.Split(p.s, "/")
}

// Name returns the last segment ("github" for "work/github").
func (p Path) Name() string {
	return p.s[strings.LastIndexByte(p.s, '/')+1:]
}

// Folder returns the parent folder ("work" for "work/github"), or "" at the
// top level.
func (p Path) Folder() string {
	i := strings.LastIndexByte(p.s, '/')
	if i < 0 {
		return ""
	}
	return p.s[:i]
}

// InFolder reports whether p lies inside folder (at any depth). The test is
// segment-aware: "work/x" is in "work", "workshop/x" is not, and "work" is
// not inside itself. Every path is inside the zero Path (the root).
func (p Path) InFolder(folder Path) bool {
	if folder.s == "" {
		return p.s != ""
	}
	return len(p.s) > len(folder.s) && p.s[len(folder.s)] == '/' && strings.HasPrefix(p.s, folder.s)
}

// HasPrefix reports whether p equals prefix or lies inside it (segment-aware).
func (p Path) HasPrefix(prefix Path) bool {
	return p == prefix || p.InFolder(prefix)
}

// WithName returns p with its last segment replaced by name, validated
// (merge uses it to append "~2" to a name).
func (p Path) WithName(name string) (Path, error) {
	if f := p.Folder(); f != "" {
		return Parse(f + "/" + name)
	}
	return Parse(name)
}

// Compare orders paths segment by segment, each segment by bytes, so a
// folder's entries stay together ("work/x" < "work-old/y"). The zero Path
// sorts first.
func Compare(a, b Path) int {
	as, bs := a.s, b.s
	for {
		if as == "" || bs == "" {
			return cmpInt(len(as), len(bs))
		}
		aseg, arest, _ := strings.Cut(as, "/")
		bseg, brest, _ := strings.Cut(bs, "/")
		if c := strings.Compare(aseg, bseg); c != 0 {
			return c
		}
		as, bs = arest, brest
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// MarshalText implements encoding.TextMarshaler. The zero Path fails.
func (p Path) MarshalText() ([]byte, error) {
	if p.s == "" {
		return nil, &Error{Kind: "path", Rule: ErrEmpty}
	}
	return []byte(p.s), nil
}

// UnmarshalText implements encoding.TextUnmarshaler; it validates.
func (p *Path) UnmarshalText(b []byte) error {
	q, err := Parse(string(b))
	if err != nil {
		return err
	}
	*p = q
	return nil
}
