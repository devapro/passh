package model

import (
	"errors"
	"slices"
	"testing"
	"time"

	"passh/internal/paths"
)

var (
	t0 = at("2026-11-15T12:00:00Z")
	t1 = at("2026-11-15T13:00:00Z")
	t2 = at("2026-11-15T14:00:00Z")
)

func pathsOf(es []Entry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Path.String())
	}
	return out
}

func mustAdd(t *testing.T, d *Data, e Entry) Entry {
	t.Helper()
	got, err := d.Add(e, t0, false)
	if err != nil {
		t.Fatalf("Add(%s): %v", e.Path, err)
	}
	return got
}

func TestAdd(t *testing.T) {
	d := NewData()
	now := time.Date(2026, 11, 15, 14, 0, 0, 123456789, time.FixedZone("x", 7200))
	e, err := d.Add(Entry{ID: "ignored", Path: p("work/github"), Password: "pw", Tags: []string{" b", "a", "b "}, CreatedAt: t2}, now, false)
	if err != nil {
		t.Fatal(err)
	}
	if !uuidRE.MatchString(e.ID) {
		t.Errorf("id = %q", e.ID)
	}
	if !e.CreatedAt.Equal(t0) || !e.UpdatedAt.Equal(t0) || e.CreatedAt.Location() != time.UTC {
		t.Errorf("times = %v %v", e.CreatedAt, e.UpdatedAt)
	}
	if !slices.Equal(e.Tags, []string{"b", "a"}) {
		t.Errorf("tags = %q", e.Tags)
	}
	got, ok := d.Get(p("work/github"))
	if !ok || !got.Equal(e) {
		t.Errorf("Get = %+v, %v", got, ok)
	}
	if byID, ok := d.GetByID(e.ID); !ok || !byID.Equal(e) {
		t.Error("GetByID")
	}
	if _, ok := d.GetByID("nope"); ok {
		t.Error("GetByID(nope)")
	}
	if _, ok := d.Get(p("work")); ok {
		t.Error("Get(work)")
	}

	// Taken path.
	_, err = d.Add(Entry{Path: p("work/github"), Password: "other"}, t1, false)
	if !errors.Is(err, ErrExists) || err.Error() != "work/github: already exists" {
		t.Errorf("Add existing error = %v", err)
	}
	if got, _ := d.Get(p("work/github")); got.Password != "pw" {
		t.Error("failed Add changed the entry")
	}

	// Invalid entries.
	bad := []Entry{
		{},
		{Path: p("x"), Password: "a\nb"},
		{Path: p("x"), Username: "a\rb"},
		{Path: p("x"), URL: "\xff"},
		{Path: p("x"), Tags: []string{"a,b"}},
		{Path: p("x"), Fields: []Field{{Key: "has space", Value: "v"}}},
		{Path: p("x"), Fields: []Field{{Key: "Username", Value: "v"}}},
		{Path: p("x"), Fields: []Field{{Key: "k", Value: "a\nb"}}},
		{Path: p("x"), Notes: "\xff"},
	}
	for _, b := range bad {
		if _, err := d.Add(b, t0, false); !errors.Is(err, ErrInvalidEntry) && !errors.Is(err, ErrInvalidTag) {
			t.Errorf("Add(%+v) error = %v", b, err)
		}
	}
	if len(d.Entries) != 1 {
		t.Errorf("failed Adds stored entries: %d", len(d.Entries))
	}
}

func TestAddOverwrite(t *testing.T) {
	d := NewData()
	orig := mustAdd(t, d, Entry{Path: p("a"), Password: "old", Username: "u"})
	d.Entries[0].extra = map[string]jsonRaw{"future": jsonRaw("1")}

	e, err := d.Add(Entry{Path: p("a"), Password: "new"}, t1, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != orig.ID || !e.CreatedAt.Equal(t0) || !e.UpdatedAt.Equal(t1) {
		t.Errorf("overwrite = %+v", e)
	}
	if e.Password != "new" || e.Username != "" {
		t.Errorf("overwrite content = %+v", e)
	}
	if string(e.extra["future"]) != "1" {
		t.Error("overwrite dropped unknown keys")
	}
	if len(d.Entries) != 1 || len(d.Deleted) != 0 {
		t.Error("overwrite must replace in place, without a tombstone")
	}
	// Same content: no change, no new updated_at.
	e, err = d.Add(Entry{Path: p("a"), Password: "new"}, t2, true)
	if err != nil || !e.UpdatedAt.Equal(t1) {
		t.Errorf("same-content overwrite = %+v, %v", e, err)
	}
}

func TestUpdate(t *testing.T) {
	d := NewData()
	e := mustAdd(t, d, Entry{Path: p("a"), Password: "pw", Tags: []string{"x"}})
	mustAdd(t, d, Entry{Path: p("b")})

	e.Password = "new"
	e.CreatedAt = t2 // ignored
	changed, err := d.Update(e, t1)
	if err != nil || !changed {
		t.Fatalf("Update = %v, %v", changed, err)
	}
	got, _ := d.Get(p("a"))
	if got.Password != "new" || !got.CreatedAt.Equal(t0) || !got.UpdatedAt.Equal(t1) || got.ID != e.ID {
		t.Errorf("after Update: %+v", got)
	}

	// No change: no bump. Tags that normalize to the same also count as no change.
	got.Tags = []string{" x ", "x"}
	changed, err = d.Update(got, t2)
	if err != nil || changed {
		t.Errorf("no-op Update = %v, %v", changed, err)
	}
	if g, _ := d.Get(p("a")); !g.UpdatedAt.Equal(t1) {
		t.Error("no-op Update bumped updated_at")
	}

	// Path change moves; a taken path fails.
	got.Path = p("b")
	if _, err := d.Update(got, t2); !errors.Is(err, ErrExists) {
		t.Errorf("Update onto b error = %v", err)
	}
	got.Path = p("c")
	if changed, err := d.Update(got, t2); err != nil || !changed {
		t.Errorf("Update to c = %v, %v", changed, err)
	}
	if _, ok := d.Get(p("a")); ok {
		t.Error("a still exists")
	}
	if g, ok := d.Get(p("c")); !ok || g.ID != e.ID || !g.UpdatedAt.Equal(t2) {
		t.Errorf("c = %+v", g)
	}

	// Errors.
	if _, err := d.Update(Entry{ID: "nope", Path: p("z")}, t2); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update(nope) error = %v", err)
	}
	if _, err := d.Update(Entry{ID: e.ID}, t2); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("Update without path error = %v", err)
	}
	bad := got.Clone()
	bad.Path = p("c")
	bad.Username = "a\nb"
	if _, err := d.Update(bad, t2); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("Update invalid error = %v", err)
	}
	if g, _ := d.Get(p("c")); g.Username != "" {
		t.Error("failed Update changed the entry")
	}
}

func TestMove(t *testing.T) {
	d := NewData()
	e := mustAdd(t, d, Entry{Path: p("work/jira"), Password: "pw"})
	mustAdd(t, d, Entry{Path: p("other")})
	if err := d.Move(p("work/jira"), p("work/atlassian/jira"), t1); err != nil {
		t.Fatal(err)
	}
	got, ok := d.Get(p("work/atlassian/jira"))
	if !ok || got.ID != e.ID || got.Password != "pw" || !got.UpdatedAt.Equal(t1) || !got.CreatedAt.Equal(t0) {
		t.Errorf("moved = %+v", got)
	}
	if _, ok := d.Get(p("work/jira")); ok {
		t.Error("source still exists")
	}
	if len(d.Deleted) != 0 {
		t.Error("Move made a tombstone")
	}
	if err := d.Move(p("work/atlassian/jira"), p("other"), t2); !errors.Is(err, ErrExists) {
		t.Errorf("Move onto existing error = %v", err)
	}
	if err := d.Move(p("other"), p("other"), t2); !errors.Is(err, ErrExists) {
		t.Errorf("Move onto itself error = %v", err)
	}
	if err := d.Move(p("nope"), p("x"), t2); !errors.Is(err, ErrNotFound) || err.Error() != "nope: not found" {
		t.Errorf("Move missing error = %v", err)
	}
	if err := d.Move(p("other"), paths.Path{}, t2); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("Move to zero error = %v", err)
	}
}

func TestRemove(t *testing.T) {
	d := NewData()
	a := mustAdd(t, d, Entry{Path: p("a"), Password: "pw"})
	mustAdd(t, d, Entry{Path: p("b")})
	got, err := d.Remove(p("a"), time.Date(2026, 11, 15, 15, 0, 0, 5, time.FixedZone("x", 3600)))
	if err != nil || got.ID != a.ID || got.Password != "pw" {
		t.Fatalf("Remove = %+v, %v", got, err)
	}
	if _, ok := d.Get(p("a")); ok || len(d.Entries) != 1 {
		t.Error("entry not removed")
	}
	if len(d.Deleted) != 1 || d.Deleted[0].ID != a.ID || !d.Deleted[0].DeletedAt.Equal(t2) || d.Deleted[0].DeletedAt.Location() != time.UTC {
		t.Errorf("tombstones = %+v", d.Deleted)
	}
	if _, err := d.Remove(p("a"), t2); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove missing error = %v", err)
	}
	// Tombstones survive encode/decode.
	out, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(out)
	if err != nil || len(back.Deleted) != 1 || back.Deleted[0].ID != a.ID || !back.Deleted[0].DeletedAt.Equal(t2) {
		t.Errorf("decoded tombstones = %+v, %v", back.Deleted, err)
	}
}

func TestListing(t *testing.T) {
	d := NewData()
	for _, e := range []Entry{
		{Path: p("workshop/x"), Tags: []string{"dev"}},
		{Path: p("work/github"), Tags: []string{"work", "dev", "2fa"}},
		{Path: p("work-old/y")},
		{Path: p("work"), Tags: []string{"work"}},
		{Path: p("bank/My Bank"), Tags: []string{"2fa", "money"}},
		{Path: p("work/a/jira"), Tags: []string{"work", "dev"}},
		{Path: p("Zeta")},
	} {
		mustAdd(t, d, e)
	}
	tests := []struct {
		name string
		got  []Entry
		want []string
	}{
		{"List", d.List(), []string{"Zeta", "bank/My Bank", "work", "work/a/jira", "work/github", "work-old/y", "workshop/x"}},
		{"ListFolder work", d.ListFolder(p("work")), []string{"work/a/jira", "work/github"}},
		{"ListFolder work/a", d.ListFolder(p("work/a")), []string{"work/a/jira"}},
		{"ListFolder root", d.ListFolder(paths.Path{}), []string{"Zeta", "bank/My Bank", "work", "work/a/jira", "work/github", "work-old/y", "workshop/x"}},
		{"ListFolder none", d.ListFolder(p("nope")), []string{}},
		{"WithTags dev", d.WithTags("dev"), []string{"work/a/jira", "work/github", "workshop/x"}},
		{"WithTags dev+2fa", d.WithTags("dev", "2fa"), []string{"work/github"}},
		{"WithTags spaced", d.WithTags(" 2fa "), []string{"bank/My Bank", "work/github"}},
		{"WithTags none", d.WithTags(), []string{"Zeta", "bank/My Bank", "work", "work/a/jira", "work/github", "work-old/y", "workshop/x"}},
		{"WithTags case", d.WithTags("DEV"), []string{}},
		{"Filter", d.Filter(p("work"), []string{"2fa"}), []string{"work/github"}},
	}
	for _, tt := range tests {
		if got := pathsOf(tt.got); !slices.Equal(got, tt.want) {
			t.Errorf("%s = %q, want %q", tt.name, got, tt.want)
		}
	}
	counts := d.TagCounts()
	want := []TagCount{{"2fa", 2}, {"dev", 3}, {"money", 1}, {"work", 3}}
	if !slices.Equal(counts, want) {
		t.Errorf("TagCounts = %v, want %v", counts, want)
	}
	if got := NewData().TagCounts(); len(got) != 0 {
		t.Errorf("empty TagCounts = %v", got)
	}

	// Listings return copies.
	l := d.List()
	l[1].Tags[0] = "changed"
	if g, _ := d.Get(p("bank/My Bank")); g.Tags[0] != "2fa" {
		t.Error("List aliases stored entries")
	}
	g, _ := d.Get(p("bank/My Bank"))
	g.Tags[0] = "changed"
	if g2, _ := d.Get(p("bank/My Bank")); g2.Tags[0] != "2fa" {
		t.Error("Get aliases stored entries")
	}
}
