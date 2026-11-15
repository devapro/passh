// Package model holds the vault's data schema (spec §4.2): entries, custom
// fields and tombstones, their JSON form with unknown keys preserved at every
// level, and pure in-memory operations on the data.
//
// Operations mutate a *Data in place. Callers clone, mutate, then save:
//
//	next := cur.Clone()
//	if _, err := next.Add(e, time.Now(), false); err != nil { … }
//	save(next)
//
// Every operation that records a time takes it as a parameter. Times are kept
// in UTC with second precision.
package model

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/devapro/passh/internal/paths"
)

const (
	// FormatName is the value of the "format" key.
	FormatName = "passh-vault-data"
	// Version is the highest data version this passh knows, and the one it
	// writes.
	Version = 1
)

var (
	// ErrInvalid marks data that is not valid vault data (wrong format,
	// malformed JSON, missing or bad values). The vault reports it as
	// damage.
	ErrInvalid = errors.New("invalid vault data")
	// ErrFormat is wrapped (with ErrInvalid) when "format" is missing or
	// is not FormatName.
	ErrFormat = errors.New(`format is not "` + FormatName + `"`)
	// ErrNewerVersion is returned unwrapped when "version" is higher than
	// Version.
	ErrNewerVersion = errors.New("made by a newer passh; upgrade passh")

	// ErrExists means the destination path is already taken.
	ErrExists = errors.New("already exists")
	// ErrNotFound means no entry has this path or id.
	ErrNotFound = errors.New("not found")
	// ErrInvalidEntry wraps every content rule an entry breaks.
	ErrInvalidEntry = errors.New("invalid entry")
	// ErrInvalidTag wraps every rule a tag breaks.
	ErrInvalidTag = errors.New("invalid tag")
)

// Data is the plaintext of the data block.
type Data struct {
	VaultID  string // random, set by init, never changed
	Revision uint64 // +1 on every save
	SavedAt  time.Time
	Entries  []Entry
	Deleted  []Tombstone

	extra map[string]json.RawMessage // unknown keys, kept on save
}

// Entry is one stored secret. Copy entries with Clone: Tags and Fields are
// slices.
type Entry struct {
	ID        string // random, stays the same across edits and moves
	Path      paths.Path
	Password  string
	Username  string
	URL       string
	Tags      []string
	Fields    []Field // other key: value pairs, in order; keys may repeat
	Notes     string
	CreatedAt time.Time
	UpdatedAt time.Time

	extra map[string]json.RawMessage
}

// Field is one custom key: value pair.
type Field struct {
	Key   string
	Value string

	extra map[string]json.RawMessage
}

// Tombstone records a removed entry: only its id and the time.
type Tombstone struct {
	ID        string
	DeletedAt time.Time

	extra map[string]json.RawMessage
}

// NewData returns empty data for a new vault: a fresh vault_id, revision 0.
func NewData() *Data {
	return &Data{VaultID: NewID()}
}

// NewID returns a random UUID (version 4) from crypto/rand.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails (Go ≥ 1.24)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	var s [36]byte
	hex.Encode(s[0:8], b[0:4])
	s[8] = '-'
	hex.Encode(s[9:13], b[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], b[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], b[8:10])
	s[23] = '-'
	hex.Encode(s[24:36], b[10:16])
	return string(s[:])
}

// stamp brings t to the stored precision: UTC, whole seconds.
func stamp(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}

// Clone returns a deep copy of d.
func (d *Data) Clone() *Data {
	c := *d
	c.Entries = cloneEach(d.Entries, Entry.Clone)
	c.Deleted = cloneEach(d.Deleted, Tombstone.clone)
	c.extra = cloneExtra(d.extra)
	return &c
}

// Clone returns a deep copy of e.
func (e Entry) Clone() Entry {
	c := e
	c.Tags = slices.Clone(e.Tags)
	c.Fields = cloneEach(e.Fields, Field.clone)
	c.extra = cloneExtra(e.extra)
	return c
}

func (f Field) clone() Field {
	f.extra = cloneExtra(f.extra)
	return f
}

func (t Tombstone) clone() Tombstone {
	t.extra = cloneExtra(t.extra)
	return t
}

func cloneEach[T any](s []T, clone func(T) T) []T {
	if s == nil {
		return nil
	}
	out := make([]T, len(s))
	for i, v := range s {
		out[i] = clone(v)
	}
	return out
}

func cloneExtra(m map[string]json.RawMessage) map[string]json.RawMessage {
	if m == nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}

// Equal reports whether e and o are identical: id, path, every value, both
// times and unknown keys. A nil and an empty slice are equal. Merge uses it
// for "identical in both" (§4.11).
func (e Entry) Equal(o Entry) bool {
	return e.ID == o.ID &&
		e.Path == o.Path &&
		e.CreatedAt.Equal(o.CreatedAt) &&
		e.UpdatedAt.Equal(o.UpdatedAt) &&
		sameContent(e, o) &&
		extraEqual(e.extra, o.extra)
}

// sameContent compares the user-visible values, ignoring id, path, times
// and the entry's own unknown keys.
func sameContent(a, b Entry) bool {
	return a.Password == b.Password &&
		a.Username == b.Username &&
		a.URL == b.URL &&
		a.Notes == b.Notes &&
		slices.Equal(a.Tags, b.Tags) &&
		slices.EqualFunc(a.Fields, b.Fields, func(x, y Field) bool {
			return x.Key == y.Key && x.Value == y.Value && extraEqual(x.extra, y.extra)
		})
}

// extraEqual compares unknown keys. Values are stored compacted, so equal
// JSON with the same key order compares equal.
func extraEqual(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}
