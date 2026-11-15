// Package vaultfile reads and writes the vault container (spec §4.1, §4.5,
// §4.8):
//
//	passh-vault 1
//	-----BEGIN AGE ENCRYPTED FILE-----
//	(key block: the vault key, encrypted with the passphrase)
//	-----END AGE ENCRYPTED FILE-----
//	-----BEGIN AGE ENCRYPTED FILE-----
//	(data block: the vault data, encrypted to the vault key)
//	-----END AGE ENCRYPTED FILE-----
//
// Encode writes the canonical form. Parse is lenient about the outside of the
// file (line endings, BOM, re-wrapped lines, text around the vault) and strict
// about its structure. Neither decrypts anything; that is the keys package's
// job. This package works on bytes and never touches the file system.
package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	// Magic starts the first line of a vault.
	Magic = "passh-vault"
	// Version is the container version this package reads and writes.
	Version = 1
)

var (
	// ErrNotVault means there is no passh-vault line.
	ErrNotVault = errors.New("not a passh vault")
	// ErrNewer means the container version is higher than Version.
	ErrNewer = errors.New("made by a newer passh; upgrade passh")
	// ErrTruncated means a block or an END line is missing. Errors wrap it
	// with the detail.
	ErrTruncated = errors.New("file is truncated")
	// ErrDamaged matches every *DamagedError.
	ErrDamaged = errors.New("file is damaged")
)

// DamagedError reports a block with bad armor, bad base64 or a bad age
// header. errors.Is(err, ErrDamaged) is true for it.
type DamagedError struct {
	Block  int    // 1: key block, 2: data block
	Reason string // short detail, e.g. "bad base64"
}

func (e *DamagedError) Error() string {
	return fmt.Sprintf("file is damaged (block %d): %s", e.Block, e.Reason)
}

// Is makes errors.Is(err, ErrDamaged) true.
func (e *DamagedError) Is(target error) bool { return target == ErrDamaged }

func damaged(block int, reason string) error {
	return &DamagedError{Block: block, Reason: reason}
}

func truncated(detail string) error {
	return fmt.Errorf("%w: %s", ErrTruncated, detail)
}

// File is a parsed vault container.
type File struct {
	// Version is the container version from the passh-vault line.
	Version int
	// KeyBlock is the binary age file encrypted with the passphrase.
	KeyBlock []byte
	// DataBlock is the binary age file encrypted to the vault key.
	DataBlock []byte
	// Warnings lists text that was ignored around the vault (§4.5).
	Warnings []string
	// Canonical reports whether the input was byte for byte what Encode
	// writes for these blocks. A copy that went through a mail client or
	// another OS usually isn't; it still opens.
	Canonical bool
}

// Encode returns the canonical vault file for two binary age files: the
// passh-vault line, then each block in age's ASCII armor (LF, 64 columns),
// nothing before or after. Both blocks must pass the same structure checks as
// in Parse, so passh never writes a file it would refuse to open.
func Encode(keyBlock, dataBlock []byte) ([]byte, error) {
	for i, b := range [][]byte{keyBlock, dataBlock} {
		if err := checkBlock(b, i+1); err != nil {
			return nil, fmt.Errorf("vaultfile: refusing to write an invalid block: %w", err)
		}
	}
	return encode(keyBlock, dataBlock), nil
}

func encode(keyBlock, dataBlock []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(Magic + " " + strconv.Itoa(Version) + "\n")
	for _, b := range [][]byte{keyBlock, dataBlock} {
		// Writes to a bytes.Buffer don't fail.
		w := armor.NewWriter(&buf)
		_, _ = w.Write(b)
		_ = w.Close()
	}
	return buf.Bytes()
}

var utf8BOM = []byte("\xef\xbb\xbf")

// Parse reads a vault file (§4.5). It accepts LF, CRLF and CR line endings, a
// UTF-8 BOM, whitespace around lines and base64 wrapped at any line length,
// and ignores text before the passh-vault line and after the second block,
// with a warning. Anything else that is wrong gives an error matching
// ErrNotVault, ErrNewer, ErrTruncated or ErrDamaged, and no File.
func Parse(data []byte) (*File, error) {
	f, _, err := parse(data)
	return f, err
}

// parse is Parse that also returns the container version once it is known,
// even with an error.
func parse(data []byte) (*File, int, error) {
	lines := splitLines(bytes.TrimPrefix(data, utf8BOM))

	start, version := -1, 0
	for i, l := range lines {
		if v, ok := magicVersion(l); ok {
			start, version = i, v
			break
		}
	}
	if start < 0 {
		return nil, 0, noMagic(data)
	}
	if version > Version {
		return nil, version, fmt.Errorf("%w (container version %d)", ErrNewer, version)
	}
	if version < 1 {
		return nil, 0, fmt.Errorf("%w: unknown container version %d", ErrNotVault, version)
	}

	var warnings []string
	if n := countText(lines[:start]); n > 0 {
		warnings = append(warnings, fmt.Sprintf("ignored %s before the %s line", nLines(n), Magic))
	}

	pos := start + 1
	var blocks [2][]byte
	for i := range blocks {
		b, next, err := readBlock(lines, pos, i+1)
		if err == nil {
			err = checkBlock(b, i+1)
		}
		if err != nil {
			return nil, version, err
		}
		blocks[i], pos = b, next
	}
	if n := countText(lines[pos:]); n > 0 {
		warnings = append(warnings, fmt.Sprintf("ignored %s after the last END line", nLines(n)))
	}
	return &File{
		Version:   version,
		KeyBlock:  blocks[0],
		DataBlock: blocks[1],
		Warnings:  warnings,
		Canonical: bytes.Equal(data, encode(blocks[0], blocks[1])),
	}, version, nil
}

// Info is the result of Check.
type Info struct {
	// SHA256 is the file's SHA-256 in lower-case hex, as sha256sum prints it.
	SHA256 string
	// Size is the file's size in bytes.
	Size int64
	// Version is the container version, or 0 if it isn't known.
	Version int
	// Warnings and Canonical are as in File.
	Warnings  []string
	Canonical bool
}

// Check is the structure check of `passh verify` without a passphrase
// (§4.8): the passh-vault line, both blocks complete, base64 and age headers
// valid. SHA256 and Size are set even when it returns an error, and so is
// Version once the passh-vault line was read (e.g. with ErrNewer).
func Check(data []byte) (Info, error) {
	sum := sha256.Sum256(data)
	info := Info{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	f, version, err := parse(data)
	info.Version = version
	if err != nil {
		return info, err
	}
	info.Warnings, info.Canonical = f.Warnings, f.Canonical
	return info, nil
}

// splitLines splits at LF, CRLF and CR and trims whitespace around each line.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	for len(data) > 0 {
		i := bytes.IndexAny(data, "\r\n")
		if i < 0 {
			lines = append(lines, bytes.TrimSpace(data))
			break
		}
		lines = append(lines, bytes.TrimSpace(data[:i]))
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		data = data[i+1:]
	}
	return lines
}

// magicVersion recognizes "passh-vault <version>", with spaces or tabs in between.
func magicVersion(line []byte) (int, bool) {
	rest, ok := bytes.CutPrefix(line, []byte(Magic))
	if !ok {
		return 0, false
	}
	digits := bytes.TrimLeft(rest, " \t")
	if len(digits) == 0 || len(digits) == len(rest) {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(string(digits))
	if err != nil {
		v = math.MaxInt // too many digits: certainly newer
	}
	return v, true
}

// noMagic tells an empty or cut-off file from one that isn't a vault at all.
func noMagic(data []byte) error {
	content := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	switch {
	case len(content) == 0:
		return truncated("the file is empty")
	case bytes.HasPrefix([]byte(Magic+" "), content):
		return truncated("it ends in the " + Magic + " line")
	}
	return ErrNotVault
}

// readBlock reads one armored block starting at lines[pos], skipping blank
// lines before it, and returns its binary content and the line after its
// END line.
func readBlock(lines [][]byte, pos, n int) ([]byte, int, error) {
	for pos < len(lines) && len(lines[pos]) == 0 {
		pos++
	}
	if pos == len(lines) {
		return nil, 0, truncated(fmt.Sprintf("block %d is missing", n))
	}
	if string(lines[pos]) != armor.Header {
		if bytes.HasPrefix([]byte(armor.Header), lines[pos]) && countText(lines[pos+1:]) == 0 {
			return nil, 0, truncated(fmt.Sprintf("block %d is cut short", n))
		}
		return nil, 0, damaged(n, "its BEGIN line is missing or damaged")
	}
	var b64 []byte
	for pos++; pos < len(lines); pos++ {
		switch string(lines[pos]) {
		case armor.Footer:
			raw := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
			k, err := base64.StdEncoding.Strict().Decode(raw, b64)
			if err != nil {
				return nil, 0, damaged(n, "bad base64")
			}
			if k == 0 {
				return nil, 0, damaged(n, "the block is empty")
			}
			return raw[:k], pos + 1, nil
		case armor.Header:
			return nil, 0, damaged(n, "its END line is missing or damaged")
		}
		b64 = append(b64, lines[pos]...)
	}
	return nil, 0, truncated(fmt.Sprintf("block %d has no END line", n))
}

// probe is an age identity that never matches; it only records the stanzas
// of a header, so a header can be checked without any key.
type probe struct{ stanzas []*age.Stanza }

func (p *probe) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	p.stanzas = stanzas
	return nil, age.ErrIncorrectIdentity
}

// checkBlock checks a block's age header, its stanzas and the size of its
// encrypted payload, without decrypting anything. Block 1 needs exactly one
// scrypt stanza, block 2 an X25519 stanza.
func checkBlock(block []byte, n int) error {
	hdr, err := age.ExtractHeader(bytes.NewReader(block))
	if err != nil {
		return damaged(n, "bad age header")
	}
	p := &probe{}
	if _, err := age.DecryptHeader(hdr, p); !errors.As(err, new(*age.NoIdentityMatchError)) {
		return damaged(n, "bad age header")
	}
	switch n {
	case 1:
		if len(p.stanzas) != 1 || p.stanzas[0].Type != "scrypt" || len(p.stanzas[0].Args) != 2 {
			return damaged(n, "the key block isn't encrypted with a passphrase")
		}
	case 2:
		x25519, scrypt := false, false
		for _, s := range p.stanzas {
			switch {
			case s.Type == "scrypt":
				scrypt = true
			case s.Type == "X25519" && len(s.Args) == 1:
				x25519 = true
			}
		}
		if !x25519 || scrypt {
			return damaged(n, "the data block isn't encrypted to a vault key")
		}
	}
	// The header ends with its MAC line, the first line starting with "---".
	end := bytes.Index(block, []byte("\n---"))
	if end < 0 {
		return damaged(n, "bad age header")
	}
	eol := bytes.IndexByte(block[end+1:], '\n')
	if eol < 0 {
		return damaged(n, "bad age header")
	}
	if !validPayloadSize(len(block) - (end + 1 + eol + 1)) {
		return damaged(n, "the encrypted data has an impossible size (cut short or extended)")
	}
	return nil
}

// validPayloadSize mirrors age's STREAM layout: a 16-byte nonce, then chunks
// of 64 KiB plaintext plus a 16-byte tag; only the last chunk is shorter, and
// it is empty only when the whole plaintext is.
func validPayloadSize(n int) bool {
	const (
		nonce = 16
		tag   = 16
		chunk = 64 * 1024
		enc   = chunk + tag
	)
	n -= nonce
	if n < tag {
		return false
	}
	chunks := (n + enc - 1) / enc
	plain := n - chunks*tag
	want := (plain + chunk - 1) / chunk
	if plain == 0 {
		want = 1
	}
	return want == chunks
}

func countText(lines [][]byte) int {
	n := 0
	for _, l := range lines {
		if len(l) > 0 {
			n++
		}
	}
	return n
}

func nLines(n int) string {
	if n == 1 {
		return "1 line of text"
	}
	return strconv.Itoa(n) + " lines of text"
}
