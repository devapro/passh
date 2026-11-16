package model

import (
	"slices"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/paths"
)

func (d *Data) index(p paths.Path) int {
	return slices.IndexFunc(d.Entries, func(e Entry) bool { return e.Path == p })
}

func (d *Data) indexID(id string) int {
	return slices.IndexFunc(d.Entries, func(e Entry) bool { return e.ID == id })
}

// Get returns a copy of the entry at p.
func (d *Data) Get(p paths.Path) (Entry, bool) {
	if i := d.index(p); i >= 0 {
		return d.Entries[i].Clone(), true
	}
	return Entry{}, false
}

// GetByID returns a copy of the entry with this id.
func (d *Data) GetByID(id string) (Entry, bool) {
	if i := d.indexID(id); i >= 0 {
		return d.Entries[i].Clone(), true
	}
	return Entry{}, false
}

// Add stores a new entry at e.Path and returns the stored copy. It gives the
// entry a new id and sets created_at and updated_at to now; e.ID and e's
// times are ignored. Content is validated and tags normalized
// (NormalizeContent).
//
// If the path is taken, Add fails with ErrExists, unless overwrite is set:
// then the existing entry keeps its id, created_at and unknown keys, takes
// e's content, and gets updated_at = now (unchanged if the content is the
// same).
func (d *Data) Add(e Entry, now time.Time, overwrite bool) (Entry, error) {
	if e.Path.IsZero() {
		return Entry{}, i18n.Errorf("%w: the path is missing", ErrInvalidEntry)
	}
	c := e.Clone()
	if err := c.NormalizeContent(); err != nil {
		return Entry{}, err
	}
	now = stamp(now)
	if i := d.index(c.Path); i >= 0 {
		if !overwrite {
			return Entry{}, i18n.Errorf("%s: %w", c.Path, ErrExists)
		}
		old := d.Entries[i]
		if sameContent(c, old) {
			return old.Clone(), nil
		}
		c.ID, c.CreatedAt, c.UpdatedAt = old.ID, old.CreatedAt, now
		if c.extra == nil {
			c.extra = old.extra
		}
		d.Entries[i] = c
		return c.Clone(), nil
	}
	c.ID, c.CreatedAt, c.UpdatedAt = NewID(), now, now
	d.Entries = append(d.Entries, c)
	return c.Clone(), nil
}

// Update replaces the entry with id e.ID by e, keeping its created_at (and
// its unknown keys if e has none, e.g. when e wasn't made by Get). If e.Path
// differs, the entry moves, which fails with ErrExists if the new path is
// taken. updated_at becomes now; if nothing changed, Update changes nothing
// and returns false.
func (d *Data) Update(e Entry, now time.Time) (changed bool, err error) {
	i := d.indexID(e.ID)
	if i < 0 {
		return false, i18n.Errorf("entry id %q: %w", e.ID, ErrNotFound)
	}
	if e.Path.IsZero() {
		return false, i18n.Errorf("%w: the path is missing", ErrInvalidEntry)
	}
	c := e.Clone()
	if err := c.NormalizeContent(); err != nil {
		return false, err
	}
	old := d.Entries[i]
	if c.Path != old.Path && d.index(c.Path) >= 0 {
		return false, i18n.Errorf("%s: %w", c.Path, ErrExists)
	}
	if c.extra == nil {
		c.extra = old.extra
	}
	c.CreatedAt, c.UpdatedAt = old.CreatedAt, old.UpdatedAt
	if c.Equal(old) {
		return false, nil
	}
	c.UpdatedAt = stamp(now)
	d.Entries[i] = c
	return true, nil
}

// Move renames the entry at src to dst. It keeps the id and sets updated_at
// to now. It fails with ErrNotFound if src doesn't exist and with ErrExists
// if dst does (including dst == src).
func (d *Data) Move(src, dst paths.Path, now time.Time) error {
	i := d.index(src)
	if i < 0 {
		return i18n.Errorf("%s: %w", src, ErrNotFound)
	}
	if dst.IsZero() {
		return i18n.Errorf("%w: the path is missing", ErrInvalidEntry)
	}
	if d.index(dst) >= 0 {
		return i18n.Errorf("%s: %w", dst, ErrExists)
	}
	d.Entries[i].Path = dst
	d.Entries[i].UpdatedAt = stamp(now)
	return nil
}

// Remove deletes the entry at p, appends a tombstone {id, now} and returns
// the removed entry.
func (d *Data) Remove(p paths.Path, now time.Time) (Entry, error) {
	i := d.index(p)
	if i < 0 {
		return Entry{}, i18n.Errorf("%s: %w", p, ErrNotFound)
	}
	e := d.Entries[i]
	d.Entries = slices.Delete(d.Entries, i, i+1)
	d.Deleted = append(d.Deleted, Tombstone{ID: e.ID, DeletedAt: stamp(now)})
	return e, nil
}

// List returns copies of all entries, sorted by path (paths.Compare).
func (d *Data) List() []Entry { return d.Filter(paths.Path{}, nil) }

// ListFolder returns copies of the entries inside folder, at any depth,
// sorted by path. "work" holds "work/x", not "workshop/x". The zero Path
// means every entry.
func (d *Data) ListFolder(folder paths.Path) []Entry { return d.Filter(folder, nil) }

// WithTags returns copies of the entries that have all the given tags,
// sorted by path. No tags means every entry.
func (d *Data) WithTags(tags ...string) []Entry { return d.Filter(paths.Path{}, tags) }

// Filter combines ListFolder and WithTags: entries inside folder (the zero
// Path means any) that have all of tags. Tags are compared exactly, after
// trimming and NFC normalization.
func (d *Data) Filter(folder paths.Path, tags []string) []Entry {
	want := make([]string, 0, len(tags))
	for _, t := range tags {
		want = append(want, strings.TrimSpace(norm.NFC.String(t)))
	}
	out := []Entry{}
	for _, e := range d.Entries {
		if !folder.IsZero() && !e.Path.InFolder(folder) {
			continue
		}
		if !hasAll(e.Tags, want) {
			continue
		}
		out = append(out, e.Clone())
	}
	slices.SortFunc(out, func(a, b Entry) int { return paths.Compare(a.Path, b.Path) })
	return out
}

func hasAll(have, want []string) bool {
	for _, t := range want {
		if !slices.Contains(have, t) {
			return false
		}
	}
	return true
}

// TagCount is a tag and the number of entries that have it.
type TagCount struct {
	Tag   string
	Count int
}

// TagCounts returns every tag in use with its entry count, sorted by tag.
func (d *Data) TagCounts() []TagCount {
	counts := map[string]int{}
	for _, e := range d.Entries {
		for _, t := range e.Tags {
			counts[t]++
		}
	}
	out := make([]TagCount, 0, len(counts))
	for t, n := range counts {
		out = append(out, TagCount{Tag: t, Count: n})
	}
	slices.SortFunc(out, func(a, b TagCount) int { return strings.Compare(a.Tag, b.Tag) })
	return out
}
