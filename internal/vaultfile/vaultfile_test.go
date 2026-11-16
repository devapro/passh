package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/devapro/passh/internal/keys"
)

func TestEncodeCanonical(t *testing.T) {
	fx := newFixture(t)
	s := string(fx.file)
	want := "passh-vault 1\n" + armored(fx.keyBlock) + armored(fx.dataBlock)
	if s != want {
		t.Fatalf("not the canonical form:\n%s", s)
	}
	if !strings.HasSuffix(s, "\n-----END AGE ENCRYPTED FILE-----\n") || strings.ContainsRune(s, '\r') {
		t.Fatal("wrong line endings or trailer")
	}
	if strings.Count(s, armor.Header) != 2 || strings.Count(s, armor.Footer) != 2 {
		t.Fatal("expected two armored blocks")
	}
	for i, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if len(line) > 64 {
			t.Fatalf("line %d is %d columns", i+1, len(line))
		}
	}
	// Each block is exactly what the stock age armor reader accepts.
	for i, b := range [][]byte{fx.keyBlock, fx.dataBlock} {
		got, err := io.ReadAll(armor.NewReader(strings.NewReader(armored(b))))
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("block %d: age's armor reader: %v", i+1, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	fx := newFixture(t)
	f, err := Parse(fx.file)
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Warnings) != 0 || !f.Canonical {
		t.Fatalf("got %+v", f)
	}
	if !bytes.Equal(f.KeyBlock, fx.keyBlock) || !bytes.Equal(f.DataBlock, fx.dataBlock) {
		t.Fatal("blocks differ")
	}
	plain, _, err := open(fx.file)
	if err != nil || !bytes.Equal(plain, fx.plain) {
		t.Fatalf("open: %v", err)
	}
}

func TestRoundTripLargeData(t *testing.T) {
	fx := newFixture(t)
	big := bytes.Repeat([]byte("0123456789"), 30_000) // several STREAM chunks
	db, err := keys.EncryptData(fx.id, big)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Encode(fx.keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(rewrap(t, bytes.ReplaceAll(file, []byte("\n"), []byte("\r\n")), 76))
	if err != nil {
		t.Fatal(err)
	}
	got, err := keys.DecryptData(fx.id, f.DataBlock)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("large data: %v", err)
	}
}

func TestLenientVariants(t *testing.T) {
	fx := newFixture(t)
	crlf := bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r\n"))
	bom := []byte("\xef\xbb\xbf")
	junkBefore := "From: me\r\nSubject: my vault\r\n\r\nHere it is:\r\n\r\n"
	junkAfter := "\n-- \nsent from my phone\n"
	indented := strings.ReplaceAll(string(fx.file), "\n", "  \n\t ")

	cases := []struct {
		name     string
		data     []byte
		warnings []string
	}{
		{"CRLF", crlf, nil},
		{"CR", bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r")), nil},
		{"BOM", append(bytes.Clone(bom), fx.file...), nil},
		{"BOM and CRLF", append(bytes.Clone(bom), crlf...), nil},
		{"mixed endings", mixEndings(fx.file), nil},
		{"rewrapped at 76", rewrap(t, fx.file, 76), nil},
		{"rewrapped at 10", rewrap(t, fx.file, 10), nil},
		{"one long line", rewrap(t, fx.file, 0), nil},
		{"rewrapped, CRLF", bytes.ReplaceAll(rewrap(t, fx.file, 76), []byte("\n"), []byte("\r\n")), nil},
		{"whitespace around lines", []byte("\n\n  " + indented + "\n\n"), nil},
		{"blank lines", bytes.ReplaceAll(fx.file, []byte("-----\n"), []byte("-----\n\n\n")), nil},
		{"no final newline", bytes.TrimSuffix(fx.file, []byte("\n")), nil},
		{"junk before", append([]byte(junkBefore), fx.file...),
			[]string{"ignored 3 lines of text before the passh-vault line"}},
		{"junk after", append(bytes.Clone(fx.file), junkAfter...),
			[]string{"ignored 2 lines of text after the last END line"}},
		{"junk around, CRLF", append(append([]byte(junkBefore), crlf...), "\r\nbye\r\n"...),
			[]string{"ignored 3 lines of text before the passh-vault line", "ignored 1 line of text after the last END line"}},
		{"another vault after", append(bytes.Clone(fx.file), fx.file...),
			[]string{fmt.Sprintf("ignored %d lines of text after the last END line", bytes.Count(fx.file, []byte("\n")))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain, f, err := open(c.data)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plain, fx.plain) || !bytes.Equal(f.KeyBlock, fx.keyBlock) || !bytes.Equal(f.DataBlock, fx.dataBlock) {
				t.Fatal("content differs")
			}
			if f.Canonical {
				t.Fatal("reported as canonical")
			}
			if got := englishTexts(f.Warnings); strings.Join(got, "|") != strings.Join(c.warnings, "|") {
				t.Fatalf("warnings %q, want %q", got, c.warnings)
			}
			// Encode turns any accepted copy back into the canonical form.
			again, err := Encode(f.KeyBlock, f.DataBlock)
			if err != nil || !bytes.Equal(again, fx.file) {
				t.Fatalf("re-encode: %v", err)
			}
		})
	}
}

func mixEndings(file []byte) []byte {
	var out []byte
	for i, line := range bytes.SplitAfter(file, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\n"))
		out = append(out, line...)
		out = append(out, []string{"\n", "\r\n", "\r"}[i%3]...)
	}
	return out
}

func TestStrictErrors(t *testing.T) {
	fx := newFixture(t)
	file := string(fx.file)
	keyArm, dataArm := armored(fx.keyBlock), armored(fx.dataBlock)
	b64 := func(arm string) string {
		return strings.TrimSuffix(strings.TrimPrefix(arm, armor.Header+"\n"), armor.Footer+"\n")
	}
	// A data block cut to its header and 20 bytes, re-armored: well-formed
	// base64 and header, but too short for a nonce and one STREAM chunk.
	mac := bytes.Index(fx.dataBlock, []byte("\n---"))
	hdrLen := mac + 1 + bytes.IndexByte(fx.dataBlock[mac+1:], '\n') + 1
	shortData := armored(fx.dataBlock[:hdrLen+20])

	cases := []struct {
		name   string
		data   string
		target error
		msg    string
	}{
		{"empty", "", ErrTruncated, "file is truncated: the file is empty"},
		{"whitespace only", " \r\n\n", ErrTruncated, "file is truncated"},
		{"cut in magic", "passh-va", ErrTruncated, "file is truncated"},
		{"magic only", "passh-vault 1\n", ErrTruncated, "file is truncated: block 1 is missing"},
		{"plain text", "hello\nworld\n", ErrNotVault, "not a passh vault"},
		{"age file", keyArm, ErrNotVault, "not a passh vault"},
		{"magic misspelled", strings.Replace(file, "passh-vault", "passh-vau1t", 1), ErrNotVault, "not a passh vault"},
		{"no version", strings.Replace(file, "passh-vault 1", "passh-vault", 1), ErrNotVault, "not a passh vault"},
		{"version 0", strings.Replace(file, "passh-vault 1", "passh-vault 0", 1), ErrNotVault, "not a passh vault"},
		{"version 2", strings.Replace(file, "passh-vault 1", "passh-vault 2", 1), ErrNewer, "made by a newer passh; upgrade passh"},
		{"version huge", "passh-vault 99999999999999999999999\ngarbage", ErrNewer, "made by a newer passh"},
		{"block 2 missing", "passh-vault 1\n" + keyArm, ErrTruncated, "file is truncated: block 2 is missing"},
		{"block 2 cut", "passh-vault 1\n" + keyArm + dataArm[:100], ErrTruncated, "file is truncated: block 2 has no END line"},
		{"BEGIN 2 cut", "passh-vault 1\n" + keyArm + "-----BEGIN AGE", ErrTruncated, "file is truncated: block 2 is cut short"},
		{"END 2 missing", strings.TrimSuffix(file, armor.Footer+"\n"), ErrTruncated, "file is truncated: block 2 has no END line"},
		{"END 1 missing", "passh-vault 1\n" + strings.TrimSuffix(keyArm, armor.Footer+"\n") + dataArm,
			ErrDamaged, "file is damaged (block 1): its END line is missing or damaged"},
		{"BEGIN 1 damaged", strings.Replace(file, "-----BEGIN AGE", "-----BEGIN AGF", 1), ErrDamaged, "file is damaged (block 1)"},
		{"text between blocks", "passh-vault 1\n" + keyArm + "hello\n" + dataArm, ErrDamaged, "file is damaged (block 2)"},
		{"bad base64 1", "passh-vault 1\n" + armor.Header + "\n" + b64(keyArm)[:20] + "!" + b64(keyArm)[21:] + armor.Footer + "\n" + dataArm,
			ErrDamaged, "file is damaged (block 1): bad base64"},
		{"bad base64 2", "passh-vault 1\n" + keyArm + armor.Header + "\n" + b64(dataArm)[:30] + "\n" + armor.Footer + "\n",
			ErrDamaged, "file is damaged (block 2): bad base64"},
		{"empty block 1", "passh-vault 1\n" + armor.Header + "\n" + armor.Footer + "\n" + dataArm, ErrDamaged, "file is damaged (block 1): the block is empty"},
		{"not age 1", "passh-vault 1\n" + armored([]byte("hello world")) + dataArm, ErrDamaged, "file is damaged (block 1): bad age header"},
		{"swapped blocks", "passh-vault 1\n" + dataArm + keyArm, ErrDamaged, "file is damaged (block 1): the key block isn't encrypted with a passphrase"},
		{"two key blocks", "passh-vault 1\n" + keyArm + keyArm, ErrDamaged, "file is damaged (block 2): the data block isn't encrypted to a vault key"},
		{"data block cut and re-armored", "passh-vault 1\n" + keyArm + shortData, ErrDamaged, "file is damaged (block 2): the encrypted data has an impossible size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := Parse([]byte(c.data))
			if !errors.Is(err, c.target) || f != nil {
				t.Fatalf("got %v, want %v", err, c.target)
			}
			if !strings.HasPrefix(err.Error(), c.msg) {
				t.Fatalf("message %q, want prefix %q", err, c.msg)
			}
			var de *DamagedError
			if errors.As(err, &de) != errors.Is(c.target, ErrDamaged) {
				t.Fatalf("DamagedError mismatch: %v", err)
			}
			info, cerr := Check([]byte(c.data))
			if cerr == nil || cerr.Error() != err.Error() {
				t.Fatalf("Check: %v", cerr)
			}
			if info.Size != int64(len(c.data)) || info.SHA256 == "" {
				t.Fatalf("Check info: %+v", info)
			}
		})
	}
}

func TestEncodeRefusesInvalidBlocks(t *testing.T) {
	fx := newFixture(t)
	dataHeader, err := age.ExtractHeader(bytes.NewReader(fx.dataBlock))
	if err != nil {
		t.Fatal(err)
	}
	for name, blocks := range map[string][2][]byte{
		"empty key block":   {nil, fx.dataBlock},
		"empty data block":  {fx.keyBlock, nil},
		"swapped":           {fx.dataBlock, fx.keyBlock},
		"garbage":           {[]byte("x"), []byte("y")},
		"data header only":  {fx.keyBlock, dataHeader},
		"key as data block": {fx.keyBlock, fx.keyBlock},
	} {
		if out, err := Encode(blocks[0], blocks[1]); err == nil || out != nil || !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// TestDataBlockOtherKey (safety test 10): a data block encrypted to another
// key is structurally fine but rejected on decryption.
func TestDataBlockOtherKey(t *testing.T) {
	fx := newFixture(t)
	stranger, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := keys.EncryptData(stranger, []byte(`{"format":"passh-vault-data","entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Encode(fx.keyBlock, forged)
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := open(file)
	if !errors.Is(err, keys.ErrKeyMismatch) || !errors.Is(err, keys.ErrDataDamaged) || plain != nil {
		t.Fatalf("got %v", err)
	}
}

// TestRecipientNotInFile (S9): the vault key's recipient appears nowhere in
// the file, in its armored or its decoded form.
func TestRecipientNotInFile(t *testing.T) {
	fx := newFixture(t)
	rcpt := fx.id.Recipient().String() // computed only to search for it
	f, err := Parse(fx.file)
	if err != nil {
		t.Fatal(err)
	}
	for _, hay := range [][]byte{fx.file, f.KeyBlock, f.DataBlock} {
		if bytes.Contains(bytes.ToLower(hay), []byte(rcpt)) {
			t.Fatal("recipient found in the vault file")
		}
	}
}

func TestCheck(t *testing.T) {
	fx := newFixture(t)
	sum := sha256.Sum256(fx.file)
	info, err := Check(fx.file)
	if err != nil {
		t.Fatal(err)
	}
	if info.SHA256 != hex.EncodeToString(sum[:]) || info.Size != int64(len(fx.file)) ||
		info.Version != 1 || !info.Canonical || len(info.Warnings) != 0 {
		t.Fatalf("got %+v", info)
	}

	junk := append([]byte("hello\n"), fx.file...)
	info, err = Check(junk)
	if err != nil || info.Canonical || len(info.Warnings) != 1 || info.Size != int64(len(junk)) {
		t.Fatalf("junk: %+v %v", info, err)
	}

	newer := bytes.Replace(fx.file, []byte("passh-vault 1"), []byte("passh-vault 7"), 1)
	info, err = Check(newer)
	if !errors.Is(err, ErrNewer) || info.Version != 7 {
		t.Fatalf("newer: %+v %v", info, err)
	}

	cut := fx.file[:len(fx.file)/2]
	sum = sha256.Sum256(cut)
	info, err = Check(cut)
	if !errors.Is(err, ErrTruncated) || info.SHA256 != hex.EncodeToString(sum[:]) || info.Version != 1 {
		t.Fatalf("truncated: %+v %v", info, err)
	}
}

func TestValidPayloadSize(t *testing.T) {
	const enc = 64*1024 + 16
	for n, want := range map[int]bool{
		-1: false, 0: false, 16: false, 31: false,
		32: true, 33: true, 16 + enc: true, 16 + enc + 1: false,
		16 + enc + 16: false, 16 + enc + 17: true, 16 + 2*enc + 17: true,
	} {
		if got := validPayloadSize(n); got != want {
			t.Errorf("validPayloadSize(%d) = %v", n, got)
		}
	}
}
