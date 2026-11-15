package model

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/paths"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

var p = paths.MustParse

// example is the §4.2 example with concrete ids.
const example = `{
  "format": "passh-vault-data",
  "version": 1,
  "vault_id": "0f6c1d2e-0000-4000-8000-000000000001",
  "revision": 42,
  "saved_at": "2026-11-15T12:00:00Z",
  "entries": [
    {
      "id": "8d1e7a90-0000-4000-8000-000000000002",
      "path": "work/github",
      "password": "s3cr3t-P@ss",
      "username": "arsenii",
      "url": "https://github.com",
      "tags": ["work", "dev", "2fa"],
      "fields": [ { "key": "recovery-email", "value": "me@example.com" } ],
      "notes": "Free-form notes. Recovery codes, etc.",
      "created_at": "2026-11-01T09:00:00Z",
      "updated_at": "2026-11-15T12:00:00Z"
    }
  ],
  "deleted": [
    { "id": "3b9f0000-0000-4000-8000-000000000003", "deleted_at": "2026-11-10T18:30:00Z" }
  ]
}`

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewID()
		if !uuidRE.MatchString(id) {
			t.Fatalf("NewID() = %q, not a UUID v4", id)
		}
		if seen[id] {
			t.Fatalf("NewID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestNewData(t *testing.T) {
	d := NewData()
	if !uuidRE.MatchString(d.VaultID) || d.Revision != 0 || len(d.Entries) != 0 || len(d.Deleted) != 0 {
		t.Fatalf("NewData() = %+v", d)
	}
	if NewData().VaultID == d.VaultID {
		t.Fatal("vault ids repeat")
	}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(b); err != nil {
		t.Fatalf("Decode(Encode(NewData())): %v", err)
	}
}

func TestDecodeExample(t *testing.T) {
	d, err := Decode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if d.VaultID != "0f6c1d2e-0000-4000-8000-000000000001" || d.Revision != 42 || !d.SavedAt.Equal(at("2026-11-15T12:00:00Z")) {
		t.Errorf("header = %q %d %v", d.VaultID, d.Revision, d.SavedAt)
	}
	if len(d.Entries) != 1 || len(d.Deleted) != 1 {
		t.Fatalf("entries %d deleted %d", len(d.Entries), len(d.Deleted))
	}
	e := d.Entries[0]
	want := Entry{
		ID:        "8d1e7a90-0000-4000-8000-000000000002",
		Path:      p("work/github"),
		Password:  "s3cr3t-P@ss",
		Username:  "arsenii",
		URL:       "https://github.com",
		Tags:      []string{"work", "dev", "2fa"},
		Fields:    []Field{{Key: "recovery-email", Value: "me@example.com"}},
		Notes:     "Free-form notes. Recovery codes, etc.",
		CreatedAt: at("2026-11-01T09:00:00Z"),
		UpdatedAt: at("2026-11-15T12:00:00Z"),
	}
	if !e.Equal(want) {
		t.Errorf("entry = %+v\nwant %+v", e, want)
	}
	if e.CreatedAt.Location() != time.UTC {
		t.Error("times must be UTC")
	}
	if d.Deleted[0].ID != "3b9f0000-0000-4000-8000-000000000003" || !d.Deleted[0].DeletedAt.Equal(at("2026-11-10T18:30:00Z")) {
		t.Errorf("tombstone = %+v", d.Deleted[0])
	}

	// Encoding gives back the same JSON.
	out, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, out, []byte(example))
	if !strings.HasSuffix(string(out), "}\n") || !strings.Contains(string(out), "\n  \"version\": 1,\n") {
		t.Errorf("Encode output is not indented:\n%s", out)
	}
	if !strings.Contains(string(out), `"saved_at": "2026-11-15T12:00:00Z"`) {
		t.Errorf("time format:\n%s", out)
	}
}

func assertSameJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got invalid JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("want invalid JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("JSON differs\ngot:  %s\nwant: %s", got, want)
	}
}

// Unknown keys at every level survive decode → encode (§4.2).
func TestUnknownKeysPreserved(t *testing.T) {
	in := `{
	  "format": "passh-vault-data", "version": 1,
	  "vault_id": "v", "revision": 7, "saved_at": "2026-11-15T12:00:00Z",
	  "top_future": {"nested": [1, 2, {"x": null}], "s": "<&>"},
	  "a_first": true,
	  "entries": [{
	    "id": "e1", "path": "a/b", "password": "pw", "username": "", "url": "",
	    "tags": [], "notes": "", "created_at": "2026-11-01T09:00:00Z", "updated_at": "2026-11-02T09:00:00Z",
	    "fields": [{"key": "k", "value": "v", "field_future": 3.5, "sensitive": true}],
	    "entry_future": ["attachment"],
	    "history": {"old": "x"}
	  }],
	  "deleted": [{"id": "t1", "deleted_at": "2026-11-03T00:00:00Z", "tomb_future": "who", "device": 9}]
	}`
	d, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, out, []byte(in))

	// Through Clone and an unrelated change, too.
	c := d.Clone()
	if _, err := c.Add(Entry{Path: p("new")}, at("2026-11-16T00:00:00Z"), false); err != nil {
		t.Fatal(err)
	}
	if err := c.Move(p("a/b"), p("a/c"), at("2026-11-16T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	out, err = c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["top_future"] == nil || m["a_first"] != true {
		t.Error("top-level unknown keys lost")
	}
	e0 := m["entries"].([]any)[0].(map[string]any)
	if e0["path"] != "a/c" || e0["history"] == nil || e0["entry_future"] == nil {
		t.Errorf("entry unknown keys lost: %v", e0)
	}
	f0 := e0["fields"].([]any)[0].(map[string]any)
	if f0["field_future"] != 3.5 || f0["sensitive"] != true {
		t.Errorf("field unknown keys lost: %v", f0)
	}
	t0 := m["deleted"].([]any)[0].(map[string]any)
	if t0["tomb_future"] != "who" || t0["device"] != 9.0 {
		t.Errorf("tombstone unknown keys lost: %v", t0)
	}

	// Get, then Update keeps them.
	e, _ := c.Get(p("a/c"))
	e.Password = "new"
	if _, err := c.Update(e, at("2026-11-17T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	// Update with an entry that has no unknown keys keeps the stored ones.
	if _, err := c.Update(Entry{ID: "e1", Path: p("a/c"), Password: "newer"}, at("2026-11-18T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Get(p("a/c"))
	if got.extra["history"] == nil || got.extra["entry_future"] == nil {
		t.Errorf("Update dropped unknown keys: %v", got.extra)
	}
	// The original is untouched by changes to the clone.
	orig, _ := d.Get(p("a/b"))
	if orig.Password != "pw" {
		t.Error("Clone is not deep")
	}
}

func TestDecodeErrors(t *testing.T) {
	head := `"format":"passh-vault-data","version":1,"vault_id":"v","revision":1`
	entry := func(s string) string {
		return `{` + head + `,"entries":[` + s + `]}`
	}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"not JSON", `{`, ErrInvalid},
		{"empty", ``, ErrInvalid},
		{"null", `null`, ErrInvalid},
		{"array", `[]`, ErrInvalid},
		{"missing format", `{"version":1,"vault_id":"v","revision":1}`, ErrFormat},
		{"wrong format", `{"format":"other","version":1,"vault_id":"v","revision":1}`, ErrFormat},
		{"format not a string", `{"format":1,"version":1,"vault_id":"v","revision":1}`, ErrFormat},
		{"newer", `{"format":"passh-vault-data","version":2,"vault_id":"v","revision":1}`, ErrNewerVersion},
		{"newer, different shape", `{"format":"passh-vault-data","version":3,"entries":"elsewhere"}`, ErrNewerVersion},
		{"version 0", `{"format":"passh-vault-data","version":0,"vault_id":"v","revision":1}`, ErrInvalid},
		{"missing version", `{"format":"passh-vault-data","vault_id":"v","revision":1}`, ErrInvalid},
		{"version string", `{"format":"passh-vault-data","version":"1","vault_id":"v","revision":1}`, ErrInvalid},
		{"missing vault_id", `{"format":"passh-vault-data","version":1,"revision":1}`, ErrInvalid},
		{"empty vault_id", `{"format":"passh-vault-data","version":1,"vault_id":"","revision":1}`, ErrInvalid},
		{"missing revision", `{"format":"passh-vault-data","version":1,"vault_id":"v"}`, ErrInvalid},
		{"negative revision", `{"format":"passh-vault-data","version":1,"vault_id":"v","revision":-1}`, ErrInvalid},
		{"bad saved_at", `{` + head + `,"saved_at":"yesterday"}`, ErrInvalid},
		{"entries not array", `{` + head + `,"entries":{}}`, ErrInvalid},
		{"entry null", entry(`null`), ErrInvalid},
		{"entry missing id", entry(`{"path":"a"}`), ErrInvalid},
		{"entry missing path", entry(`{"id":"x"}`), ErrInvalid},
		{"entry bad path", entry(`{"id":"x","path":"a/../b"}`), ErrInvalid},
		{"entry control path", entry(`{"id":"x","path":"a\u001b[31m"}`), ErrInvalid},
		{"entry bad time", entry(`{"id":"x","path":"a","created_at":"2026-13-01T00:00:00Z"}`), ErrInvalid},
		{"entry time not string", entry(`{"id":"x","path":"a","updated_at":5}`), ErrInvalid},
		{"entry password newline", entry(`{"id":"x","path":"a","password":"a\nb"}`), ErrInvalid},
		{"entry bad tag", entry(`{"id":"x","path":"a","tags":["a,b"]}`), ErrInvalid},
		{"entry tags not array", entry(`{"id":"x","path":"a","tags":"a"}`), ErrInvalid},
		{"entry reserved field", entry(`{"id":"x","path":"a","fields":[{"key":"URL","value":"v"}]}`), ErrInvalid},
		{"entry field not object", entry(`{"id":"x","path":"a","fields":["k"]}`), ErrInvalid},
		{"entry field key not string", entry(`{"id":"x","path":"a","fields":[{"key":1}]}`), ErrInvalid},
		{"entry field value not string", entry(`{"id":"x","path":"a","fields":[{"key":"k","value":1}]}`), ErrInvalid},
		{"duplicate id", entry(`{"id":"x","path":"a"},{"id":"x","path":"b"}`), ErrInvalid},
		{"duplicate path", entry(`{"id":"x","path":"a"},{"id":"y","path":"a"}`), ErrInvalid},
		{"duplicate path after NFC", entry(`{"id":"x","path":"caf\u00e9"},{"id":"y","path":"cafe\u0301"}`), ErrInvalid},
		{"tombstone missing id", `{` + head + `,"deleted":[{"deleted_at":"2026-11-03T00:00:00Z"}]}`, ErrInvalid},
		{"tombstone not object", `{` + head + `,"deleted":[1]}`, ErrInvalid},
		{"tombstone bad time", `{` + head + `,"deleted":[{"id":"t","deleted_at":"x"}]}`, ErrInvalid},
		{"tombstone id not string", `{` + head + `,"deleted":[{"id":1}]}`, ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Decode([]byte(tt.in))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Decode error = %v, want %v", err, tt.want)
			}
			if d != nil {
				t.Error("Decode returned data with an error")
			}
		})
	}
}

func TestNewerVersionMessage(t *testing.T) {
	_, err := Decode([]byte(`{"format":"passh-vault-data","version":2}`))
	if err == nil || err.Error() != "made by a newer passh; upgrade passh" {
		t.Fatalf("error = %v", err)
	}
	if errors.Is(err, ErrInvalid) {
		t.Error("a newer version is not damage")
	}
	_, err = Decode([]byte(`{"format":"x","version":1}`))
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrFormat) {
		t.Errorf("format error = %v, want ErrInvalid and ErrFormat", err)
	}
}

func TestDecodeNormalizes(t *testing.T) {
	in := `{"format":"passh-vault-data","version":1,"vault_id":"v","revision":1,
	  "saved_at":"2026-11-15T14:00:00.789+02:00",
	  "entries":[{"id":"x","path":"cafe\u0301/a","tags":[" b ","a","b"],
	    "username":null,"fields":null,"created_at":null}]}`
	d, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !d.SavedAt.Equal(at("2026-11-15T12:00:00Z")) || d.SavedAt.Location() != time.UTC {
		t.Errorf("SavedAt = %v", d.SavedAt)
	}
	e := d.Entries[0]
	if e.Path.String() != "caf\u00e9/a" {
		t.Errorf("path = %q", e.Path)
	}
	if !slices.Equal(e.Tags, []string{"b", "a"}) {
		t.Errorf("tags = %q", e.Tags)
	}
	if !e.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v", e.CreatedAt)
	}
	out, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"tags": [`, `"fields": []`, `"deleted": []`, `"username": ""`, `"created_at": "0001-01-01T00:00:00Z"`} {
		if !strings.Contains(string(out), s) {
			t.Errorf("output lacks %s:\n%s", s, out)
		}
	}
}

func TestEncode(t *testing.T) {
	d := NewData()
	d.Revision = 3
	d.SavedAt = time.Date(2026, 11, 15, 14, 0, 0, 999, time.FixedZone("x", 7200))
	if _, err := d.Add(Entry{Path: p("a"), Password: `<p&ss>"\` + "\x00\t", Notes: "line1\nline2\r\n"}, at("2026-11-15T12:00:00Z"), false); err != nil {
		t.Fatal(err)
	}
	out, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"saved_at": "2026-11-15T12:00:00Z"`) {
		t.Errorf("saved_at not UTC/second precision:\n%s", s)
	}
	if !strings.Contains(s, `<p&ss>`) {
		t.Errorf("HTML characters are escaped:\n%s", s)
	}
	back, err := Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Entries[0].Equal(d.Entries[0]) {
		t.Errorf("round trip: %+v != %+v", back.Entries[0], d.Entries[0])
	}
	// Key order: known keys first, in the §4.2 order.
	order := []string{`"format"`, `"version"`, `"vault_id"`, `"revision"`, `"saved_at"`, `"entries"`, `"deleted"`}
	last := -1
	for _, k := range order {
		i := strings.Index(s, k)
		if i < last {
			t.Errorf("key %s out of order", k)
		}
		last = i
	}
}

func TestEncodeRefusesInvalid(t *testing.T) {
	good := func() *Data {
		d := NewData()
		d.Entries = []Entry{{ID: "a", Path: p("a")}, {ID: "b", Path: p("b")}}
		return d
	}
	tests := []struct {
		name string
		mod  func(d *Data)
	}{
		{"no vault id", func(d *Data) { d.VaultID = "" }},
		{"dup id", func(d *Data) { d.Entries[1].ID = "a" }},
		{"dup path", func(d *Data) { d.Entries[1].Path = p("a") }},
		{"no id", func(d *Data) { d.Entries[0].ID = "" }},
		{"no path", func(d *Data) { d.Entries[0].Path = paths.Path{} }},
		{"bad utf8", func(d *Data) { d.Entries[0].Password = "\xff" }},
		{"bad utf8 notes", func(d *Data) { d.Entries[0].Notes = "\xff" }},
		{"newline", func(d *Data) { d.Entries[0].Username = "a\nb" }},
		{"bad tag", func(d *Data) { d.Entries[0].Tags = []string{""} }},
		{"tombstone", func(d *Data) { d.Deleted = []Tombstone{{}} }},
	}
	if _, err := good().Encode(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		d := good()
		tt.mod(d)
		if _, err := d.Encode(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Encode error = %v", tt.name, err)
		}
	}
}

func TestMarshalEntryRefusesInvalidUTF8(t *testing.T) {
	for _, e := range []Entry{
		{ID: "x", Path: p("a"), Password: "\xff"},
		{ID: "x", Path: p("a"), Tags: []string{"\xff"}},
		{ID: "x", Path: p("a"), Fields: []Field{{Key: "k", Value: "\xfe"}}},
		{ID: "x"},
	} {
		if _, err := json.Marshal(e); err == nil {
			t.Errorf("json.Marshal(%+v) succeeded", e)
		}
	}
}

func TestEncodeExport(t *testing.T) {
	d, err := Decode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	d.extra = map[string]json.RawMessage{"future": json.RawMessage(`1`)}
	out, err := d.EncodeExport(d.List(), at("2026-11-20T08:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["exported_at"] != "2026-11-20T08:00:00Z" || m["vault_id"] != d.VaultID || m["format"] != FormatName || m["version"] != 1.0 || m["revision"] != 42.0 {
		t.Errorf("header = %v", m)
	}
	if _, ok := m["deleted"]; ok {
		t.Error("export has deleted")
	}
	if m["future"] != 1.0 {
		t.Error("export lost unknown top-level key")
	}
	es := m["entries"].([]any)
	if len(es) != 1 || es[0].(map[string]any)["id"] != "8d1e7a90-0000-4000-8000-000000000002" {
		t.Errorf("entries = %v", es)
	}
	out, err = d.EncodeExport(nil, at("2026-11-20T08:00:00Z"))
	if err != nil || !strings.Contains(string(out), `"entries": []`) {
		t.Errorf("empty export = %s, %v", out, err)
	}
	if _, err := d.EncodeExport([]Entry{{ID: "x"}}, time.Time{}); err == nil {
		t.Error("export of an entry without a path succeeded")
	}
}

func TestCloneDeep(t *testing.T) {
	d, err := Decode([]byte(`{"format":"passh-vault-data","version":1,"vault_id":"v","revision":1,"x":[1],
	  "entries":[{"id":"e","path":"a","tags":["t"],"fields":[{"key":"k","value":"v","y":{"z":1}}],"w":"q"}],
	  "deleted":[{"id":"t","u":2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := d.Clone()
	if !reflect.DeepEqual(c, d) {
		t.Fatal("clone differs")
	}
	c.Revision = 9
	c.extra["x"][1] = '9'
	c.Entries[0].Tags[0] = "changed"
	c.Entries[0].Fields[0].Value = "changed"
	c.Entries[0].Fields[0].extra["y"][0] = '['
	c.Entries[0].extra["w"][1] = 'Q'
	c.Deleted[0].ID = "changed"
	c.Deleted[0].extra["u"][0] = '3'
	if d.Revision != 1 || string(d.extra["x"]) != "[1]" || d.Entries[0].Tags[0] != "t" ||
		d.Entries[0].Fields[0].Value != "v" || string(d.Entries[0].Fields[0].extra["y"]) != `{"z":1}` ||
		string(d.Entries[0].extra["w"]) != `"q"` || d.Deleted[0].ID != "t" || string(d.Deleted[0].extra["u"]) != "2" {
		t.Error("Clone shares memory with the original")
	}
	empty := (&Data{VaultID: "v"}).Clone()
	if empty.Entries != nil || empty.Deleted != nil || empty.extra != nil {
		t.Error("Clone of empty data")
	}
}

func TestEntryEqual(t *testing.T) {
	base := Entry{
		ID: "i", Path: p("a"), Password: "pw", Username: "u", URL: "url",
		Tags: []string{"t"}, Fields: []Field{{Key: "k", Value: "v"}}, Notes: "n",
		CreatedAt: at("2026-01-01T00:00:00Z"), UpdatedAt: at("2026-01-02T00:00:00Z"),
	}
	if !base.Equal(base.Clone()) {
		t.Fatal("clone not equal")
	}
	mods := map[string]func(e *Entry){
		"id":       func(e *Entry) { e.ID = "j" },
		"path":     func(e *Entry) { e.Path = p("b") },
		"password": func(e *Entry) { e.Password = "x" },
		"username": func(e *Entry) { e.Username = "x" },
		"url":      func(e *Entry) { e.URL = "x" },
		"tags":     func(e *Entry) { e.Tags = []string{"t", "u"} },
		"tag order": func(e *Entry) {
			e.Tags = []string{"u", "t"}
		},
		"fields":      func(e *Entry) { e.Fields = nil },
		"field key":   func(e *Entry) { e.Fields[0].Key = "x" },
		"field value": func(e *Entry) { e.Fields[0].Value = "x" },
		"field extra": func(e *Entry) { e.Fields[0].extra = map[string]json.RawMessage{"a": json.RawMessage("1")} },
		"notes":       func(e *Entry) { e.Notes = "x" },
		"created":     func(e *Entry) { e.CreatedAt = e.CreatedAt.Add(time.Second) },
		"updated":     func(e *Entry) { e.UpdatedAt = e.UpdatedAt.Add(time.Second) },
		"extra":       func(e *Entry) { e.extra = map[string]json.RawMessage{"a": json.RawMessage("1")} },
	}
	for name, mod := range mods {
		o := base.Clone()
		mod(&o)
		if base.Equal(o) || o.Equal(base) {
			t.Errorf("Equal ignores %s", name)
		}
	}
	a, b := base.Clone(), base.Clone()
	a.extra = map[string]json.RawMessage{"a": json.RawMessage("1")}
	b.extra = map[string]json.RawMessage{"a": json.RawMessage("2")}
	if a.Equal(b) {
		t.Error("Equal ignores unknown key values")
	}
	b.extra = map[string]json.RawMessage{"b": json.RawMessage("1")}
	if a.Equal(b) {
		t.Error("Equal ignores unknown key names")
	}
	// nil and empty slices are equal; so is the same instant in another zone.
	x, y := base.Clone(), base.Clone()
	x.Tags, y.Tags = nil, []string{}
	x.Fields, y.Fields = nil, []Field{}
	y.CreatedAt = y.CreatedAt.In(time.FixedZone("z", 3600))
	if !x.Equal(y) {
		t.Error("nil vs empty, or time zone, makes entries unequal")
	}
}
