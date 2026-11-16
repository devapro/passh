// Package entrytext converts an entry to and from the pass-style text form
// (spec §4.3) used by `show`, `show --raw`, `edit --editor` and
// `import pass`:
//
//	s3cr3t-P@ss
//	username: arsenii
//	url: https://github.com
//	tags: work, dev, 2fa
//	recovery-email: me@example.com
//	---
//	Free-form notes. Recovery codes, etc.
//
// Line 1 is the password, exactly (a trailing CR is dropped). Then come
// metadata lines "key: value" (or "key:" for an empty value), where key
// follows model.ValidFieldKey; metadata ends at a "---" line or at the first
// line that isn't metadata, and everything after is notes. The strict key
// grammar keeps lines such as "https://x" or "PIN:1234" out of the metadata.
// Keys username, url and tags (in any case) map to their fields; other keys
// become custom fields, in order, and may repeat.
//
// Format always writes "---" before non-empty notes, so Parse(Format(e))
// gives back e's content for every valid entry.
package entrytext

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
)

// ErrDuplicate is wrapped when Parse finds a second username or url line.
var ErrDuplicate = i18n.NewError("appears twice")

// SyntaxError is a metadata line that Parse can't accept: a second username
// or url line (ErrDuplicate) or invalid tags. Line is the 1-based line number
// in the text; Err says what is wrong. Callers get the line with errors.As
// instead of reading it out of the message, which is "line N: " followed by
// Err's.
type SyntaxError struct {
	Line int
	Err  error
}

func (e *SyntaxError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (e *SyntaxError) Localize(p i18n.Printer) string { return p.T("line %d: %v", e.Line, e.Err) }

// Unwrap returns Err, so errors.Is(err, ErrDuplicate) and the like work.
func (e *SyntaxError) Unwrap() error { return e.Err }

// Format returns the text form of e's content: password, username, url,
// tags, custom fields and notes. It ends with a newline. Empty username,
// url and tags are left out.
func Format(e model.Entry) string {
	var b strings.Builder
	b.WriteString(e.Password)
	b.WriteByte('\n')
	if e.Username != "" {
		writeMeta(&b, model.FieldUsername, e.Username)
	}
	if e.URL != "" {
		writeMeta(&b, model.FieldURL, e.URL)
	}
	if len(e.Tags) > 0 {
		writeMeta(&b, model.FieldTags, strings.Join(e.Tags, ", "))
	}
	for _, f := range e.Fields {
		writeMeta(&b, f.Key, f.Value)
	}
	if e.Notes != "" {
		b.WriteString("---\n")
		b.WriteString(e.Notes)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeMeta(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteByte(':')
	if value != "" {
		b.WriteByte(' ')
		b.WriteString(value)
	}
	b.WriteByte('\n')
}

// Parse reads the text form, as written by an editor, and returns an entry
// with only its content set (password, username, url, tags, fields, notes),
// validated and normalized by model.Entry.NormalizeContent.
//
// CRLF input is accepted: if line 1 ends in CRLF, every CRLF becomes LF.
// The notes lose one final newline (Format adds one). When metadata ends
// without a "---" line, blank lines before the notes are dropped. A second
// username or url line is an error (ErrDuplicate); tags lines add up.
// Errors about one line are a *SyntaxError.
func Parse(text string) (model.Entry, error) {
	return parse(text, false)
}

// ParseImport reads a pass entry for `import pass` (§4.9). It differs from
// Parse in that:
//   - "user:" and "login:" also map to username (any case);
//   - every line after line 1 that starts with "otpauth://", in the metadata
//     or in the notes (pass-otp appends it at the end), becomes an "otp"
//     field and is removed from the notes;
//   - nothing in the metadata is an error: a line that can't be stored (a
//     second username or url, bad tags) goes to the start of the notes, and
//     a second user/login line becomes a custom field;
//   - trailing blank lines of the notes are dropped.
func ParseImport(text string) (model.Entry, error) {
	return parse(text, true)
}

func parse(text string, imp bool) (model.Entry, error) {
	var e model.Entry
	if !utf8.ValidString(text) {
		return e, i18n.NewError("the text is not valid UTF-8")
	}
	first, rest, multiline := strings.Cut(text, "\n")
	if multiline && strings.HasSuffix(first, "\r") {
		rest = strings.ReplaceAll(rest, "\r\n", "\n")
	}
	e.Password = strings.TrimSuffix(first, "\r")

	var (
		haveUser, haveURL bool
		kept              []string // import: metadata lines moved to the notes
		notes             string
		separated         bool // the notes follow a "---" line
	)
	for n := 2; rest != ""; n++ {
		raw, after, _ := strings.Cut(rest, "\n")
		line := strings.TrimSuffix(raw, "\r")
		if line == "---" {
			notes, separated = after, true
			break
		}
		if imp && isOTPLine(line) {
			e.Fields = append(e.Fields, otpField(line))
			rest = after
			continue
		}
		key, value, ok := splitMeta(line)
		if !ok {
			notes = rest
			break
		}
		rest = after

		var err error
		switch {
		case strings.EqualFold(key, model.FieldUsername),
			imp && (strings.EqualFold(key, "user") || strings.EqualFold(key, "login")):
			if haveUser {
				err = duplicate(model.FieldUsername)
				break
			}
			e.Username, haveUser = value, true
		case strings.EqualFold(key, model.FieldURL):
			if haveURL {
				err = duplicate(model.FieldURL)
				break
			}
			e.URL, haveURL = value, true
		case strings.EqualFold(key, model.FieldTags):
			var tags []string
			if tags, err = model.ParseTagList(value); err == nil {
				e.Tags = append(e.Tags, tags...)
			}
		default:
			e.Fields = append(e.Fields, model.Field{Key: key, Value: value})
		}
		if err == nil {
			continue
		}
		if !imp {
			return model.Entry{}, &SyntaxError{Line: n, Err: err}
		}
		if errors.Is(err, ErrDuplicate) && !model.IsReservedKey(key) {
			e.Fields = append(e.Fields, model.Field{Key: key, Value: value}) // a second user/login
		} else {
			kept = append(kept, line)
		}
	}

	if !separated {
		notes = dropLeadingBlankLines(notes)
	}
	if imp {
		lines := kept
		for l := range strings.SplitSeq(notes, "\n") {
			if isOTPLine(strings.TrimSuffix(l, "\r")) {
				e.Fields = append(e.Fields, otpField(l))
				continue
			}
			lines = append(lines, l)
		}
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		notes = strings.Join(lines, "\n")
	} else {
		notes = strings.TrimSuffix(notes, "\n")
	}
	e.Notes = notes

	if err := e.NormalizeContent(); err != nil {
		return model.Entry{}, err
	}
	return e, nil
}

func duplicate(std string) error {
	return i18n.Errorf("%s %w", std, ErrDuplicate)
}

// splitMeta splits a metadata line "key: value" or "key:". ok is false for
// any other line.
func splitMeta(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 || !model.ValidFieldKey(line[:i]) {
		return "", "", false
	}
	switch v := line[i+1:]; {
	case v == "":
		return line[:i], "", true
	case v[0] == ' ':
		return line[:i], v[1:], true
	}
	return "", "", false
}

func isOTPLine(line string) bool {
	return model.IsOTPAuthURI(strings.TrimSpace(line))
}

func otpField(line string) model.Field {
	return model.Field{Key: model.FieldOTP, Value: strings.TrimSpace(line)}
}

// dropLeadingBlankLines removes whitespace-only lines at the start of s.
func dropLeadingBlankLines(s string) string {
	for s != "" {
		line, after, found := strings.Cut(s, "\n")
		if strings.TrimSpace(line) != "" {
			return s
		}
		if !found {
			return ""
		}
		s = after
	}
	return s
}
