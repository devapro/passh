package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// fixPass is the passphrase of the shared fixture vaults.
const fixPass = "copper tundra violin maple oyster glider"

// The vault's entries as a black box sees them: the JSON of §4.2.
type vField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type vEntry struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Password  string   `json:"password"`
	Username  string   `json:"username"`
	URL       string   `json:"url"`
	Tags      []string `json:"tags"`
	Fields    []vField `json:"fields"`
	Notes     string   `json:"notes"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type vData struct {
	Format   string   `json:"format"`
	Version  int      `json:"version"`
	VaultID  string   `json:"vault_id"`
	Revision int      `json:"revision"`
	SavedAt  string   `json:"saved_at"`
	Entries  []vEntry `json:"entries"`
	Deleted  []struct {
		ID        string `json:"id"`
		DeletedAt string `json:"deleted_at"`
	} `json:"deleted"`
}

func (d *vData) entry(path string) (vEntry, bool) {
	for _, e := range d.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return vEntry{}, false
}

// splitBlocks extracts the two armored blocks the way the §8 awk commands
// do: CR removed, from each BEGIN line to its END line.
func splitBlocks(data []byte) (key, dat []byte, err error) {
	text := strings.ReplaceAll(string(data), "\r", "")
	var blocks [][]byte
	var cur *bytes.Buffer
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, "BEGIN AGE ENCRYPTED FILE") {
			cur = &bytes.Buffer{}
		}
		if cur != nil {
			cur.WriteString(l + "\n")
			if strings.Contains(l, "END AGE ENCRYPTED FILE") {
				blocks = append(blocks, cur.Bytes())
				cur = nil
			}
		}
	}
	if len(blocks) != 2 {
		return nil, nil, fmt.Errorf("found %d armored blocks, want 2", len(blocks))
	}
	return blocks[0], blocks[1], nil
}

// vaultKeyFromPass decrypts the key block with the passphrase (scrypt).
func vaultKeyFromPass(data []byte, pass string) (*age.X25519Identity, error) {
	kb, _, err := splitBlocks(data)
	if err != nil {
		return nil, err
	}
	sid, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(kb)), sid)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(b)))
}

// decryptVault decrypts the data block with the vault key.
func decryptVault(data []byte, id *age.X25519Identity) (*vData, []byte, error) {
	_, db, err := splitBlocks(data)
	if err != nil {
		return nil, nil, err
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(db)), id)
	if err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	var d vData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, raw, err
	}
	return &d, raw, nil
}

func mustDecrypt(t *testing.T, file string, id *age.X25519Identity) *vData {
	t.Helper()
	d, _, err := decryptVault(readFile(t, file), id)
	if err != nil {
		t.Fatalf("decrypting %s with the vault key: %v", file, err)
	}
	return d
}

// ---------------------------------------------------------------------------
// Shared fixtures, made once through the binary.

// fixEntries are added to the populated fixture with `passh add`. Passwords
// starting with = + - @ are for the CSV criterion (§13.1.6).
var fixEntries = []newEntry{
	{path: "work/github", password: "s3cr3t-P@ss", username: "arsenii", url: "https://github.com", tags: "work, dev, 2fa", notes: "Recovery codes: 1111-2222\nsecond line of notes"},
	{path: "bank/chase", password: "=HYPERLINK(\"http://evil\")", username: "bob@example.com", url: "https://chase.example", tags: "money", notes: ""},
	{path: "csv/plus", password: "+41 secret", username: "plus", url: "", tags: "csv", notes: ""},
	{path: "csv/minus", password: "-minus,with \"quote\"", username: "minus", url: "", tags: "csv", notes: ""},
	{path: "csv/at", password: "@SUM(1+1)*cmd", username: "at", url: "", tags: "csv", notes: ""},
	{path: "personal/My Bank", password: "spaces in path", username: "me", url: "https://bank.example/login?a=1&b=2", tags: "money, personal", notes: "multi\nline\nnotes"},
}

type fixtureSet struct {
	empty    string // a vault right after init
	pop      string // the populated vault
	key      *age.X25519Identity
	recip    string // the vault key's public recipient (age1…), never to be written
	popData  *vData
	popRev   int
	emptyRev int
}

var (
	fixOnce sync.Once
	fix     *fixtureSet
	fixErr  error
)

// fixtures returns the shared vaults, making them on first use, with the
// first caller's t. A helper that ends that test with t.Fatal leaves the
// Once done without a result (runtime.Goexit skips the assignment), so the
// error is set before anything can fail, and every later caller fails
// with it instead of using a nil set (CORE-014).
func fixtures(t *testing.T) *fixtureSet {
	t.Helper()
	fixOnce.Do(func() {
		fixErr = errors.New("making the shared fixtures failed in the first test that needed them (see its log)")
		defer func() {
			if r := recover(); r != nil {
				fixErr = fmt.Errorf("panic: %v", r)
			}
		}()
		fix, fixErr = makeFixtureSet(t)
	})
	if fixErr != nil || fix == nil {
		t.Fatalf("fixtures: %v", fixErr)
	}
	if t.Failed() {
		t.FailNow()
	}
	return fix
}

func makeFixtureSet(t *testing.T) (*fixtureSet, error) {
	dir := filepath.Join(testBase, "fix")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	e := newEnv(t)
	// init on a terminal, as a user would.
	if r := e.initVault(fixPass); r.code != 0 {
		return nil, fmt.Errorf("init: %s", r)
	}
	fs := &fixtureSet{empty: filepath.Join(dir, "empty.passh"), pop: filepath.Join(dir, "pop.passh")}
	raw, err := os.ReadFile(e.vault)
	if err != nil {
		return nil, fmt.Errorf("init made no vault at %s: %v", e.vault, err)
	}
	if err := os.WriteFile(fs.empty, raw, 0o600); err != nil {
		return nil, err
	}
	if fs.key, err = vaultKeyFromPass(raw, fixPass); err != nil {
		return nil, fmt.Errorf("the key block doesn't open with the passphrase through the age library: %v", err)
	}
	fs.recip = fs.key.Recipient().String()
	d, _, err := decryptVault(raw, fs.key)
	if err != nil {
		return nil, fmt.Errorf("the data block of a new vault doesn't decrypt: %v", err)
	}
	fs.emptyRev = d.Revision

	e.unlock(fixPass)
	for _, ne := range fixEntries {
		e.add("", ne)
	}
	e.ok("generate", "homelab/nas/admin", "32")
	e.lock()
	raw, err = os.ReadFile(e.vault)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(fs.pop, raw, 0o600); err != nil {
		return nil, err
	}
	if fs.popData, _, err = decryptVault(raw, fs.key); err != nil {
		return nil, fmt.Errorf("populated vault: %v", err)
	}
	fs.popRev = fs.popData.Revision
	if len(fs.popData.Entries) != len(fixEntries)+1 {
		return nil, errors.New("populated vault: wrong entry count")
	}
	return fs, nil
}

// popEnv is a new environment with a copy of the populated vault.
func popEnv(t *testing.T, extraConfig string) (*env, *fixtureSet) {
	t.Helper()
	f := fixtures(t)
	e := newEnv(t)
	e.installVault(f.pop, extraConfig)
	return e, f
}
