package vaultfile

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzParse checks that Parse never panics, that it fails only with the
// errors of §4.5, that Check agrees with it, and that whatever it accepts
// re-encodes to a canonical file with the same blocks. The seed corpus runs
// as a normal test; `go test -fuzz=FuzzParse` explores further.
func FuzzParse(f *testing.F) {
	fx := newFixture(f)
	crlf := bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r\n"))
	seeds := [][]byte{
		fx.file,
		crlf,
		bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r")),
		append([]byte("\xef\xbb\xbf"), crlf...),
		rewrap(f, fx.file, 76),
		rewrap(f, fx.file, 0),
		append([]byte("junk before\n"), fx.file...),
		append(bytes.Clone(fx.file), "junk after\n"...),
		fx.file[:len(fx.file)/2],
		fx.file[:20],
		bytes.Replace(fx.file, []byte("passh-vault 1"), []byte("passh-vault 2"), 1),
		[]byte("passh-vault 1\n-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n"),
		[]byte("passh-vault 1\n-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n"),
		[]byte("passh-vault"),
		[]byte(""),
		[]byte("\x00\xff\r\r\n\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		orig := bytes.Clone(data)
		file, err := Parse(data)
		info, cerr := Check(data)
		if !bytes.Equal(data, orig) {
			t.Fatal("input modified")
		}
		if (err == nil) != (cerr == nil) {
			t.Fatalf("Parse: %v, Check: %v", err, cerr)
		}
		if info.Size != int64(len(data)) || len(info.SHA256) != 64 {
			t.Fatalf("Check info: %+v", info)
		}
		if err != nil {
			if file != nil {
				t.Fatal("file returned with error")
			}
			for _, target := range []error{ErrNotVault, ErrNewer, ErrTruncated, ErrDamaged} {
				if errors.Is(err, target) {
					return
				}
			}
			t.Fatalf("unexpected error: %v", err)
		}
		if file.Version != Version || info.Version != Version {
			t.Fatalf("version %d", file.Version)
		}
		enc, err := Encode(file.KeyBlock, file.DataBlock)
		if err != nil {
			t.Fatalf("accepted blocks don't encode: %v", err)
		}
		if file.Canonical != bytes.Equal(enc, data) {
			t.Fatalf("Canonical = %v", file.Canonical)
		}
		again, err := Parse(enc)
		if err != nil || !again.Canonical || len(again.Warnings) != 0 ||
			!bytes.Equal(again.KeyBlock, file.KeyBlock) || !bytes.Equal(again.DataBlock, file.DataBlock) {
			t.Fatalf("re-encoded file doesn't round-trip: %v", err)
		}
	})
}
