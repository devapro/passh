package model

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecode checks that Decode never panics and fails only with ErrInvalid
// or ErrNewerVersion, and that whatever it accepts encodes, decodes again
// to equal data and encodes to the same bytes: the canonical form is
// stable, unknown keys included (§4.2). The seed corpus runs as a normal
// test; `go test -run='^$' -fuzz=FuzzDecode ./internal/model` explores
// further (TEST-12).
func FuzzDecode(f *testing.F) {
	const head = `"format":"passh-vault-data","version":1,"vault_id":"v","revision":1`
	for _, s := range []string{
		example,
		`{` + head + `}`,
		`{` + head + `,"saved_at":"2026-11-15T12:00:00+02:00","future":{"a":[1,"x",null]}}`,
		`{` + head + `,"entries":[{"id":"e","path":"a/b","password":"pw","tags":["b "," a","b"],` +
			`"fields":[{"key":"k","value":"v","more":true},{"key":"notes","value":"n"}],"x":1}]}`,
		`{` + head + `,"entries":[{"id":"e","path":"cafe\u0301","created_at":"2026-11-01T09:00:00.5Z"}]}`,
		`{` + head + `,"deleted":[{"id":"t","deleted_at":"2026-11-03T00:00:00Z","device":9}]}`,
		`{` + head + `,"entries":[{"id":"e","path":"a","created_at":"9999-12-31T23:59:59-23:59"}]}`,
		`{` + head + `,"entries":[{"id":"x","path":"a"},{"id":"x","path":"b"}]}`,
		`{"format":"passh-vault-data","version":2}`,
		`{"format":"other","version":1,"vault_id":"v","revision":1}`,
		`{"format":"passh-vault-data","version":1,"vault_id":"v","revision":-1}`,
		`{`, `null`, `[]`, `""`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		orig := bytes.Clone(b)
		d, err := Decode(b)
		if !bytes.Equal(b, orig) {
			t.Fatal("Decode changed its input")
		}
		if err != nil {
			if d != nil || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrNewerVersion)) {
				t.Fatalf("Decode(%q) = %v, %v", b, d != nil, err)
			}
			return
		}
		out, err := d.Encode()
		if err != nil {
			t.Fatalf("Encode of decoded %q: %v", b, err)
		}
		d2, err := Decode(out)
		if err != nil {
			t.Fatalf("Decode of encoded %q: %v\n%s", b, err, out)
		}
		out2, err := d2.Encode()
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("encoding isn't stable for %q: %v\n%s\n%s", b, err, out, out2)
		}
		if d2.VaultID != d.VaultID || d2.Revision != d.Revision || !d2.SavedAt.Equal(d.SavedAt) ||
			len(d2.Entries) != len(d.Entries) || len(d2.Deleted) != len(d.Deleted) {
			t.Fatalf("round trip of %q changed the data", b)
		}
		for i := range d.Entries {
			if !d.Entries[i].Equal(d2.Entries[i]) {
				t.Fatalf("round trip of %q changed entry %d", b, i+1)
			}
		}
	})
}
