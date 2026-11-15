package vaultfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/devapro/passh/internal/keys"
)

// isolatedVars are pointed at a temporary tree for the whole test binary, so
// no test or subprocess can touch the user's files (IMPLEMENTATION.md).
var isolatedVars = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
	"TMPDIR", "PASSWORD_STORE_DIR", "GNUPGHOME",
}

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "passh-vaultfile-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, v := range isolatedVars {
		dir := filepath.Join(root, strings.ToLower(v))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv(v, dir)
	}
	os.Setenv("PASSH_CONFIG", filepath.Join(root, "passh-config.toml"))
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

// subprocessEnv is the complete environment for programs started by tests.
func subprocessEnv() []string {
	env := []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	for _, v := range append(isolatedVars, "PASSH_CONFIG") {
		env = append(env, v+"="+os.Getenv(v))
	}
	return env
}

// testWorkFactor is a one-digit scrypt work factor, so that no single bit
// flip in a key block header can ask for an expensive scrypt.
const testWorkFactor = 4

const testPass = "orbit velvet cactus lumen harbor quill"

const testData = `{"format":"passh-vault-data","version":1,"entries":[{"path":"work/github","password":"s3cr3t-P@ss"}]}`

type fixture struct {
	id        *age.X25519Identity
	plain     []byte
	keyBlock  []byte
	dataBlock []byte
	file      []byte // canonical encoding
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	id, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return fixtureFor(t, id, scryptKeyBlock(t, id, testPass, testWorkFactor))
}

func fixtureFor(t testing.TB, id *age.X25519Identity, keyBlock []byte) *fixture {
	t.Helper()
	db, err := keys.EncryptData(id, []byte(testData))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Encode(keyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{id: id, plain: []byte(testData), keyBlock: keyBlock, dataBlock: db, file: file}
}

// scryptKeyBlock builds a key block like keys.WrapKey, but with a chosen
// work factor (keys allows lowering it only from its own tests).
func scryptKeyBlock(t testing.TB, id *age.X25519Identity, pass string, logN int) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(logN)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(id.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// open is the whole read path of a vault: parse, unwrap the key block with
// the passphrase, decrypt the data block.
func open(data []byte) ([]byte, *File, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	id, err := keys.UnwrapKey(f.KeyBlock, []byte(testPass))
	if err != nil {
		return nil, f, err
	}
	plain, err := keys.DecryptData(id, f.DataBlock)
	return plain, f, err
}

// knownErr reports whether err is one of the errors of §4.5.
func knownErr(err error) bool {
	for _, target := range []error{ErrNotVault, ErrNewer, ErrTruncated, ErrDamaged, keys.ErrWrongPassphrase, keys.ErrDataDamaged} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// armored returns one block in age's armor, as Encode writes it.
func armored(block []byte) string {
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	w.Write(block)
	w.Close()
	return buf.String()
}

// rewrap re-wraps the base64 of both blocks at width columns (0: one line).
func rewrap(t testing.TB, file []byte, width int) []byte {
	t.Helper()
	var out strings.Builder
	var b64 strings.Builder
	in := false
	for _, line := range strings.Split(strings.TrimSuffix(string(file), "\n"), "\n") {
		switch {
		case line == armor.Header:
			in = true
			b64.Reset()
			out.WriteString(line + "\n")
		case line == armor.Footer:
			in = false
			s := b64.String()
			for width > 0 && len(s) > width {
				out.WriteString(s[:width] + "\n")
				s = s[width:]
			}
			out.WriteString(s + "\n" + line + "\n")
		case in:
			b64.WriteString(line)
		default:
			out.WriteString(line + "\n")
		}
	}
	return []byte(out.String())
}

// layout is the file's text without line-ending, whitespace and blank-line
// differences: two files with the same layout differ only in how they're laid out.
func layout(data []byte) string {
	var out []string
	for _, l := range splitLines(bytes.TrimPrefix(data, utf8BOM)) {
		if len(l) > 0 {
			out = append(out, string(l))
		}
	}
	return strings.Join(out, "\n")
}
