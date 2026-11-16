package model

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/devapro/passh/internal/i18n"
)

// Standard field names, as used by `show --field` and the text form.
const (
	FieldPassword = "password"
	FieldUsername = "username"
	FieldURL      = "url"
	FieldTags     = "tags"
	FieldNotes    = "notes"
	// FieldOTP is the custom field key reserved for TOTP (v1.1).
	FieldOTP = "otp"
)

// NormalizeContent validates the entry's values and normalizes its tags in
// place (see NormalizeTags). It does not look at the id, path or times.
//
// Rules: password, username, url and field values are single lines (no LF
// or CR, so the text form can hold them); every string is valid UTF-8; field
// keys follow ValidFieldKey and are not reserved (IsReservedKey).
func (e *Entry) NormalizeContent() error {
	for _, v := range []struct{ name, val string }{
		{FieldPassword, e.Password},
		{FieldUsername, e.Username},
		{FieldURL, e.URL},
	} {
		if err := checkLine(v.name, v.val); err != nil {
			return err
		}
	}
	tags, err := NormalizeTags(e.Tags)
	if err != nil {
		return err
	}
	e.Tags = tags
	for _, f := range e.Fields {
		switch {
		case !ValidFieldKey(f.Key):
			return i18n.Errorf("%w: field key %q is not valid (letters, digits, then also _ . -)", ErrInvalidEntry, f.Key)
		case IsReservedKey(f.Key):
			return i18n.Errorf("%w: %q can't be a custom field key", ErrInvalidEntry, f.Key)
		}
		if err := checkLine(i18n.Msg("field %s", f.Key), f.Value); err != nil {
			return err
		}
	}
	if !utf8.ValidString(e.Notes) {
		return i18n.Errorf("%w: notes are not valid UTF-8", ErrInvalidEntry)
	}
	return nil
}

// checkLine checks the value v of the field name: a field's key, or a
// Message naming a custom field.
func checkLine(name any, v string) error {
	if !utf8.ValidString(v) {
		return i18n.Errorf("%w: %s is not valid UTF-8", ErrInvalidEntry, name)
	}
	if strings.ContainsAny(v, "\n\r") {
		return i18n.Errorf("%w: %s must be a single line", ErrInvalidEntry, name)
	}
	return nil
}

// ValidFieldKey reports whether k is a valid custom field key: a letter or
// digit, then letters, digits, combining marks, "_", "." or "-". The grammar
// is strict so that a text-form line such as "https://x" or "Note to self:
// …" is never read as metadata.
func ValidFieldKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
		case i > 0 && (unicode.IsMark(r) || r == '_' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// IsReservedKey reports whether k names a standard text-form line
// (username, url, tags, in any case) and so can't be a custom field key.
//
// "password" and "notes" are not reserved: §4.3 sends every key other than
// username, url and tags to the custom fields, and vaults may already hold
// such fields. Field gives the standard value for those names;
// CustomField reaches the custom field.
func IsReservedKey(k string) bool {
	return strings.EqualFold(k, FieldUsername) ||
		strings.EqualFold(k, FieldURL) ||
		strings.EqualFold(k, FieldTags)
}

// IsSecret reports whether a value is masked like a password (§4.2, S5):
// the password itself or a custom field named "password" in any case, an
// "otp" field, and any value that is an otpauth:// URI.
func IsSecret(key, value string) bool {
	return strings.EqualFold(key, FieldPassword) ||
		strings.EqualFold(key, FieldOTP) ||
		IsOTPAuthURI(value)
}

// IsSecret reports whether the field's value is masked like a password.
func (f Field) IsSecret() bool { return IsSecret(f.Key, f.Value) }

// IsOTPAuthURI reports whether v starts with "otpauth://" (scheme case
// ignored).
func IsOTPAuthURI(v string) bool {
	const scheme = "otpauth://"
	return len(v) >= len(scheme) && strings.EqualFold(v[:len(scheme)], scheme)
}

// Field returns one named value, for `show --field`: "password",
// "username", "url", "tags" (joined with ", "), "notes", else the value of
// the first custom field with exactly this key. ok is false if there is no
// such field; a standard field always exists, possibly empty.
//
// A custom field keyed exactly "password" or "notes" (allowed by §4.3, e.g.
// from an imported pass file) is shadowed here by the standard value;
// CustomField returns it.
func (e Entry) Field(name string) (value string, ok bool) {
	switch name {
	case FieldPassword:
		return e.Password, true
	case FieldUsername:
		return e.Username, true
	case FieldURL:
		return e.URL, true
	case FieldTags:
		return strings.Join(e.Tags, ", "), true
	case FieldNotes:
		return e.Notes, true
	}
	return e.CustomField(name)
}

// CustomField returns the value of the first custom field with exactly
// this key, never a standard value. ok is false if there is none.
func (e Entry) CustomField(key string) (value string, ok bool) {
	for _, f := range e.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return "", false
}

// NormalizeTag trims t, normalizes it to NFC and checks it: non-empty,
// valid UTF-8, no comma, no control character.
func NormalizeTag(t string) (string, error) {
	if !utf8.ValidString(t) {
		return "", i18n.Errorf("%w %q: not valid UTF-8", ErrInvalidTag, t)
	}
	n := strings.TrimSpace(norm.NFC.String(t))
	switch {
	case n == "":
		return "", i18n.Errorf("%w: a tag can't be empty", ErrInvalidTag)
	case strings.ContainsRune(n, ','):
		return "", i18n.Errorf("%w %q: it contains a comma", ErrInvalidTag, n)
	case strings.IndexFunc(n, unicode.IsControl) >= 0:
		return "", i18n.Errorf("%w %q: it contains a control character", ErrInvalidTag, n)
	}
	return n, nil
}

// NormalizeTags normalizes every tag (NormalizeTag) and removes duplicates,
// keeping the first occurrence. It returns nil for no tags.
func NormalizeTags(tags []string) ([]string, error) {
	var out []string
	for _, t := range tags {
		n, err := NormalizeTag(t)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// ParseTagList splits a comma-separated list ("work, dev, 2fa"), skips
// empty items and normalizes the rest (NormalizeTags).
func ParseTagList(s string) ([]string, error) {
	var tags []string
	for t := range strings.SplitSeq(s, ",") {
		if strings.TrimSpace(t) != "" {
			tags = append(tags, t)
		}
	}
	return NormalizeTags(tags)
}
