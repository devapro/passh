package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
)

// Decode parses the data block's plaintext. It refuses a "format" other than
// FormatName (ErrFormat, wrapped with ErrInvalid), returns ErrNewerVersion
// for a "version" above Version, and wraps every other problem with
// ErrInvalid. Unknown keys at every level are kept for Encode. Tags are
// normalized and the whole data is validated (see Validate).
func Decode(b []byte) (*Data, error) {
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		if errors.Is(err, ErrNewerVersion) || errors.Is(err, ErrInvalid) {
			return nil, err
		}
		return nil, i18n.Errorf("%w: %v", ErrInvalid, err)
	}
	return &d, nil
}

// Encode returns the JSON of d (indented, ending in a newline), with
// "format" and "version" set to this passh's and unknown keys kept. It
// fails if d doesn't pass Validate. It doesn't change d: the caller sets
// Revision and SavedAt before saving.
func (d *Data) Encode() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	b, err := d.MarshalJSON()
	if err != nil {
		return nil, err
	}
	// SEC-1: the compact form holds every secret; only the indented copy,
	// which the caller wipes, is returned.
	defer clear(b[:cap(b)])
	return indent(b)
}

// EncodeExport returns the JSON export of §7.3: d's header with
// "exported_at" added, the given entries (e.g. after a --tag/--folder
// filter), and no "deleted".
func (d *Data) EncodeExport(entries []Entry, exportedAt time.Time) ([]byte, error) {
	if entries == nil {
		entries = []Entry{}
	}
	var w objWriter
	d.writeHeader(&w)
	w.field("exported_at", formatTime(exportedAt))
	w.field("entries", entries)
	w.extras(d.extra)
	b, err := w.close()
	if err != nil {
		return nil, err
	}
	defer clear(b[:cap(b)]) // SEC-1, as in Encode
	return indent(b)
}

// indent returns b indented, ending in a newline. The buffer is sized up
// front so that it rarely has to grow: each reallocation would leave a copy
// of the plaintext behind where nothing can wipe it (SEC-1, best effort).
func indent(b []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(4*len(b) + 1)
	if err := json.Indent(&out, b, "", "  "); err != nil {
		clear(out.Bytes()[:out.Cap()])
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func (d *Data) writeHeader(w *objWriter) {
	w.field("format", FormatName)
	w.field("version", Version)
	w.field("vault_id", d.VaultID)
	w.field("revision", d.Revision)
	w.field("saved_at", formatTime(d.SavedAt))
}

// MarshalJSON implements json.Marshaler (compact form; see Encode).
func (d *Data) MarshalJSON() ([]byte, error) {
	var w objWriter
	d.writeHeader(&w)
	w.field("entries", nonNil(d.Entries))
	w.field("deleted", nonNil(d.Deleted))
	w.extras(d.extra)
	return w.close()
}

// UnmarshalJSON implements json.Unmarshaler; Decode is the usual entry
// point. Errors wrap ErrInvalid, except ErrNewerVersion.
func (d *Data) UnmarshalJSON(b []byte) error {
	*d = Data{}
	m, err := object(b)
	if err != nil {
		return invalid("%v", err)
	}
	var format string
	if ok, err := take(m, "format", &format); err != nil || !ok || format != FormatName {
		return i18n.Errorf("%w: %w", ErrInvalid, ErrFormat)
	}
	var version int64
	if ok, err := take(m, "version", &version); err != nil || !ok {
		return invalid("missing or bad version")
	}
	if version > Version {
		return ErrNewerVersion
	}
	if version < 1 {
		return invalid("unsupported version %d", version)
	}
	if ok, err := take(m, "vault_id", &d.VaultID); err != nil || !ok {
		return invalid("missing or bad vault_id")
	}
	if ok, err := take(m, "revision", &d.Revision); err != nil || !ok {
		return invalid("missing or bad revision")
	}
	if d.SavedAt, err = takeTime(m, "saved_at"); err != nil {
		return invalid("%v", err)
	}
	if _, err := take(m, "entries", &d.Entries); err != nil {
		return invalid("%v", err)
	}
	if _, err := take(m, "deleted", &d.Deleted); err != nil {
		return invalid("%v", err)
	}
	d.extra = extraOf(m)
	for i := range d.Entries {
		if err := d.Entries[i].NormalizeContent(); err != nil {
			return invalid("entry %d: %v", i+1, err)
		}
	}
	return d.Validate()
}

// Validate checks d: a vault_id; every entry has an id and a path, and
// passes NormalizeContent; ids and paths are unique; every tombstone has an
// id. Errors wrap ErrInvalid. Decode and Encode call it.
func (d *Data) Validate() error {
	if d.VaultID == "" {
		return invalid("missing vault_id")
	}
	ids := make(map[string]bool, len(d.Entries))
	ps := make(map[paths.Path]bool, len(d.Entries))
	for i := range d.Entries {
		e := &d.Entries[i]
		switch {
		case e.ID == "":
			return invalid("entry %d: missing id", i+1)
		case e.Path.IsZero():
			return invalid("entry %d: missing path", i+1)
		case ids[e.ID]:
			return invalid("entry %d: duplicate id %q", i+1, e.ID)
		case ps[e.Path]:
			return invalid("entry %d: duplicate path %q", i+1, e.Path.String())
		}
		ids[e.ID], ps[e.Path] = true, true
		c := e.Clone()
		if err := c.NormalizeContent(); err != nil {
			return invalid("entry %d: %v", i+1, err)
		}
	}
	for i, t := range d.Deleted {
		if t.ID == "" {
			return invalid("tombstone %d: missing id", i+1)
		}
	}
	return nil
}

// invalid is an ErrInvalid error with a detail.
//
// i18n:wrapper
func invalid(format string, args ...any) error {
	return i18n.Errorf("%w: %v", ErrInvalid, i18n.Msg(format, args...))
}

// MarshalJSON implements json.Marshaler.
func (e Entry) MarshalJSON() ([]byte, error) {
	if e.Path.IsZero() {
		return nil, i18n.Errorf("entry %q has no path", e.ID)
	}
	for _, t := range e.Tags {
		if !utf8.ValidString(t) {
			return nil, i18n.NewError("tag is not valid UTF-8")
		}
	}
	var w objWriter
	w.field("id", e.ID)
	w.field("path", e.Path.String())
	w.field("password", e.Password)
	w.field("username", e.Username)
	w.field("url", e.URL)
	w.field("tags", nonNil(e.Tags))
	w.field("fields", nonNil(e.Fields))
	w.field("notes", e.Notes)
	w.field("created_at", formatTime(e.CreatedAt))
	w.field("updated_at", formatTime(e.UpdatedAt))
	w.extras(e.extra)
	return w.close()
}

// UnmarshalJSON implements json.Unmarshaler. Unknown keys are kept; the
// values are not validated here (Decode does that).
func (e *Entry) UnmarshalJSON(b []byte) error {
	*e = Entry{}
	m, err := object(b)
	if err != nil {
		return err
	}
	for _, kv := range []struct {
		key string
		dst any
	}{
		{"id", &e.ID},
		{"path", &e.Path},
		{"password", &e.Password},
		{"username", &e.Username},
		{"url", &e.URL},
		{"tags", &e.Tags},
		{"fields", &e.Fields},
		{"notes", &e.Notes},
	} {
		if _, err := take(m, kv.key, kv.dst); err != nil {
			return err
		}
	}
	if e.CreatedAt, err = takeTime(m, "created_at"); err != nil {
		return err
	}
	if e.UpdatedAt, err = takeTime(m, "updated_at"); err != nil {
		return err
	}
	e.extra = extraOf(m)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (f Field) MarshalJSON() ([]byte, error) {
	var w objWriter
	w.field("key", f.Key)
	w.field("value", f.Value)
	w.extras(f.extra)
	return w.close()
}

// UnmarshalJSON implements json.Unmarshaler. Unknown keys are kept.
func (f *Field) UnmarshalJSON(b []byte) error {
	*f = Field{}
	m, err := object(b)
	if err != nil {
		return err
	}
	if _, err := take(m, "key", &f.Key); err != nil {
		return err
	}
	if _, err := take(m, "value", &f.Value); err != nil {
		return err
	}
	f.extra = extraOf(m)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (t Tombstone) MarshalJSON() ([]byte, error) {
	var w objWriter
	w.field("id", t.ID)
	w.field("deleted_at", formatTime(t.DeletedAt))
	w.extras(t.extra)
	return w.close()
}

// UnmarshalJSON implements json.Unmarshaler. Unknown keys are kept.
func (t *Tombstone) UnmarshalJSON(b []byte) error {
	*t = Tombstone{}
	m, err := object(b)
	if err != nil {
		return err
	}
	if _, err := take(m, "id", &t.ID); err != nil {
		return err
	}
	if t.DeletedAt, err = takeTime(m, "deleted_at"); err != nil {
		return err
	}
	t.extra = extraOf(m)
	return nil
}

// formatTime gives RFC 3339 in UTC with second precision:
// "2026-11-15T12:00:00Z".
func formatTime(t time.Time) string {
	return stamp(t).Format(time.RFC3339)
}

func object(b []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil { // JSON null
		return nil, i18n.NewError("expected an object, got null")
	}
	return m, nil
}

// take decodes and removes m[key]. A missing key leaves dst unchanged.
// The raw JSON, a copy that may hold secrets, is wiped once decoded: dst
// keeps nothing of it (SEC-1, best effort).
func take(m map[string]json.RawMessage, key string, dst any) (bool, error) {
	raw, ok := m[key]
	if !ok {
		return false, nil
	}
	delete(m, key)
	defer clear(raw)
	if err := json.Unmarshal(raw, dst); err != nil {
		return true, i18n.Errorf("%s: %w", key, err)
	}
	return true, nil
}

// takeTime decodes and removes an RFC 3339 time; missing or null is zero.
func takeTime(m map[string]json.RawMessage, key string) (time.Time, error) {
	var s *string
	if _, err := take(m, key, &s); err != nil || s == nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return time.Time{}, i18n.Errorf("%s: bad time %q", key, *s)
	}
	// In UTC the year must still have four digits, or formatTime would
	// write a time that RFC 3339 can't read back, and every later save
	// would fail its read-back check (found by FuzzDecode).
	if y := t.UTC().Year(); y < 0 || y > 9999 {
		return time.Time{}, i18n.Errorf("%s: time %q is out of range", key, *s)
	}
	return stamp(t), nil
}

// extraOf returns the keys left in m, values compacted, or nil.
func extraOf(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	for k, v := range m {
		var buf bytes.Buffer
		if json.Compact(&buf, v) == nil { // always valid: it came from the decoder
			m[k] = buf.Bytes()
		}
	}
	return m
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// objWriter writes a JSON object with keys in the order given, without
// HTML escaping, and fails on invalid UTF-8 instead of replacing it.
type objWriter struct {
	buf bytes.Buffer
	n   int
	err error
}

func (w *objWriter) key(k string) {
	if w.n == 0 {
		w.buf.WriteByte('{')
	} else {
		w.buf.WriteByte(',')
	}
	w.n++
	w.value(k)
	w.buf.WriteByte(':')
}

func (w *objWriter) field(k string, v any) {
	if w.err != nil {
		return
	}
	w.key(k)
	w.value(v)
}

func (w *objWriter) value(v any) {
	if w.err != nil {
		return
	}
	if s, ok := v.(string); ok && !utf8.ValidString(s) {
		w.err = i18n.NewError("value is not valid UTF-8")
		return
	}
	enc := json.NewEncoder(&w.buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		w.err = err
		return
	}
	w.buf.Truncate(w.buf.Len() - 1) // Encode appends a newline
}

// extras writes unknown keys, sorted, after the known ones.
func (w *objWriter) extras(m map[string]json.RawMessage) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if w.err != nil {
			return
		}
		w.key(k)
		w.buf.Write(m[k])
	}
}

func (w *objWriter) close() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	if w.n == 0 {
		w.buf.WriteByte('{')
	}
	w.buf.WriteByte('}')
	return w.buf.Bytes(), nil
}
