package vaultfile

import (
	"bytes"
	"errors"
	"testing"
)

// Safety test 10 (§13.2): truncating the vault at any point, or flipping any
// single byte, gives an error that names the problem, never partial data and
// never a panic. The passh-vault line and the armor text are in scope.
//
// Parse is lenient about layout (§4.5), so a mutation that only changes
// whitespace or line endings — dropping or altering the final newline — opens
// the original content unchanged. Those are the only mutations allowed to
// succeed, and the test checks that each one really is layout-only.

func TestTruncationAtEveryOffset(t *testing.T) {
	fx := newFixture(t)
	for n := range len(fx.file) {
		cut := fx.file[:n]
		plain, f, err := open(cut)
		if err == nil {
			if layout(cut) != layout(fx.file) || !bytes.Equal(plain, fx.plain) {
				t.Fatalf("truncated at %d of %d: opened with different content", n, len(fx.file))
			}
			continue
		}
		if plain != nil {
			t.Fatalf("truncated at %d: data returned with error %v", n, err)
		}
		// Every cut is found by the parser, before any decryption.
		if !errors.Is(err, ErrTruncated) || f != nil {
			t.Fatalf("truncated at %d: got %v, want %v", n, err, ErrTruncated)
		}
	}
	// The only harmless cut is dropping the final newline.
	if _, _, err := open(fx.file[:len(fx.file)-1]); err != nil {
		t.Fatalf("without final newline: %v", err)
	}
}

func TestFlipAtEveryOffset(t *testing.T) {
	fx := newFixture(t)
	masks := []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff}
	var parseErrs, keyErrs, dataErrs, harmless int
	for i := range fx.file {
		for _, m := range masks {
			bad := bytes.Clone(fx.file)
			bad[i] ^= m
			plain, f, err := open(bad)
			if err == nil {
				if layout(bad) != layout(fx.file) || !bytes.Equal(plain, fx.plain) {
					t.Fatalf("flip %#02x at %d (%q): opened with different content", m, i, fx.file[i])
				}
				harmless++
				continue
			}
			if plain != nil {
				t.Fatalf("flip %#02x at %d: data returned with error %v", m, i, err)
			}
			if !knownErr(err) {
				t.Fatalf("flip %#02x at %d (%q): unexpected error %v", m, i, fx.file[i], err)
			}
			switch {
			case f == nil:
				parseErrs++
			case errors.Is(err, ErrDamaged), errors.Is(err, ErrTruncated), errors.Is(err, ErrNotVault), errors.Is(err, ErrNewer):
				t.Fatalf("flip %#02x at %d: parse error after a successful parse: %v", m, i, err)
			case bytes.Equal(f.KeyBlock, fx.keyBlock):
				dataErrs++
			default:
				keyErrs++
			}
		}
	}
	t.Logf("%d flips: %d parse errors, %d key block errors, %d data block errors, %d layout-only",
		len(fx.file)*len(masks), parseErrs, keyErrs, dataErrs, harmless)
	if keyErrs == 0 || dataErrs == 0 || parseErrs == 0 {
		t.Fatal("some kind of damage was never reached")
	}
	// Only the final newline turning into other whitespace (vertical tab) is harmless.
	if harmless > 1 {
		t.Fatalf("%d flips were harmless, want at most 1", harmless)
	}
}

// TestFlipInBlocksNamesBlock: a flip inside a block's base64 that breaks it
// structurally names the right block.
func TestFlipInBlocksNamesBlock(t *testing.T) {
	fx := newFixture(t)
	second := bytes.Index(fx.file[bytes.Index(fx.file, []byte("-----END")):], []byte("-----BEGIN"))
	second += bytes.Index(fx.file, []byte("-----END"))
	for i := range fx.file {
		bad := bytes.Clone(fx.file)
		bad[i] ^= 0x80 // never valid base64
		_, err := Parse(bad)
		var de *DamagedError
		if !errors.As(err, &de) {
			continue
		}
		want := 1
		if i >= second {
			want = 2
		}
		if de.Block != want {
			t.Fatalf("flip at %d: block %d reported, want %d", i, de.Block, want)
		}
	}
}
