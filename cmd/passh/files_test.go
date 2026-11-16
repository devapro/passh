package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vaultfile"
)

// TestEscaping (S4, safety test 3): escape sequences in entry content
// render inert in show, ls, find and tags; show --raw and a piped
// show --field give the exact bytes.
func TestEscaping(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	const (
		osc52 = "\x1b]52;c;SGVsbG8=\x07"
		path  = "evil/\u202egnp.exe"
	)
	e.addEntries(model.Entry{
		Path:     paths.MustParse(path),
		Password: "pw" + osc52 + "end",
		Username: "user\x1b[2J",
		URL:      "https://x\u009b31m",
		Tags:     []string{"t\u202e"},
		Fields:   []model.Field{{Key: "k", Value: "v\x1b[5m"}},
		Notes:    "note\x1b]0;pwned\x07\nline2\rover",
	})
	e.unlock(fixturePass)

	inert := func(what, out string) {
		t.Helper()
		mustNotContain(t, what, out, "\x1b", "\a", "\u202e", "\u009b")
	}
	// On a terminal.
	for _, args := range [][]string{
		{"show", path},
		{"show", path, "--field", "password"},
		{"show", path, "--field", "notes"},
		{"ls"},
		{"find", "evil"},
		{"tags"},
		{"show", "evil/\u202enope"},
	} {
		r := e.start(sessOpts{}, args...).wait()
		inert(strings.Join(args, " "), r.out)
	}
	r := e.start(sessOpts{}, "show", path).waitOK()
	mustContain(t, "show on a terminal", r.out,
		`pw\x1b]52;c;SGVsbG8=\x07end`, `user\x1b[2J`, `https://x\u009b31m`, `tags: t\u202e`,
		`k: v\x1b[5m`, `note\x1b]0;pwned\x07`, `line2\rover`)
	r = e.start(sessOpts{}, "ls").waitOK()
	mustContain(t, "ls", r.out, `\u202egnp.exe`)

	// Not on a terminal: show still escapes...
	r = e.ok("show", path)
	inert("show piped", r.stdout)
	// ...but --raw and a piped --field are exact.
	r = e.ok("show", path, "--raw")
	mustContain(t, "show --raw", r.stdout, "pw"+osc52+"end\n", "username: user\x1b[2J\n", "note\x1b]0;pwned\x07\nline2\rover\n")
	if r = e.ok("show", path, "--field", "password"); r.stdout != "pw"+osc52+"end" {
		t.Errorf("show --field password piped: %q", r.stdout)
	}
	// An error message naming the path is escaped too.
	r = e.fail(1, "show", "evil/\u202enope")
	inert("error", r.stderr)
	e.ok("lock")
}

// rewrap re-joins each armored block's base64 and wraps it at width.
func rewrap(t *testing.T, vault []byte, width int) []byte {
	t.Helper()
	var out, b64 bytes.Buffer
	in := false
	for _, l := range strings.Split(strings.TrimSuffix(string(vault), "\n"), "\n") {
		switch {
		case l == armor.Header:
			in = true
			out.WriteString(l + "\n")
		case l == armor.Footer:
			s := b64.String()
			for len(s) > width {
				out.WriteString(s[:width] + "\n")
				s = s[width:]
			}
			out.WriteString(s + "\n" + l + "\n")
			b64.Reset()
			in = false
		case in:
			b64.WriteString(l)
		default:
			out.WriteString(l + "\n")
		}
	}
	return out.Bytes()
}

// TestCopies (functional criterion 8): copies with CRLF, re-wrapped lines,
// a BOM, indentation and text around them open; verify reports each as OK;
// a byte-exact copy has the original's SHA-256; backup round-trips and
// writes a canonical copy of a non-canonical vault.
func TestCopies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(
		model.Entry{Path: paths.MustParse("work/github"), Password: "p1", Username: "arsenii"},
		model.Entry{Path: paths.MustParse("bank/my bank"), Password: "p2"},
	)
	orig, err := os.ReadFile(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	origSum := sha256Hex(orig)
	r := e.ok("verify")
	mustContain(t, "verify", r.stdout, "vault.passh: OK", "SHA-256   "+origSum)

	crlf := bytes.ReplaceAll(orig, []byte("\n"), []byte("\r\n"))
	var indented bytes.Buffer
	for _, l := range strings.SplitAfter(string(orig), "\n") {
		if l != "" {
			indented.WriteString("    " + l)
		}
	}
	copies := map[string][]byte{
		"exact.passh":     orig,
		"crlf.passh":      crlf,
		"cr.passh":        bytes.ReplaceAll(orig, []byte("\n"), []byte("\r")),
		"rewrapped.passh": rewrap(t, orig, 76),
		"email.passh": append(append([]byte("From: me\r\nSubject: vault\r\n\r\nHere it is:\r\n\r\n"),
			bytes.ReplaceAll(rewrap(t, orig, 72), []byte("\n"), []byte("\r\n"))...),
			"\r\n-- \r\nSent from my phone\r\n"...),
		"bom.passh":      append([]byte("\xef\xbb\xbf"), orig...),
		"indented.passh": indented.Bytes(),
	}
	dir := filepath.Join(e.root, "copies")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range copies {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		r := e.ok("verify", p)
		mustContain(t, "verify "+name, r.stdout, name+": OK", "SHA-256   "+sha256Hex(data), "size      ")
		if name == "exact.passh" {
			mustNotContain(t, "verify exact", r.stderr, "canonical")
		} else {
			mustContain(t, "verify "+name, r.stderr, "canonical form")
		}
	}
	if !strings.Contains(e.ok("verify", filepath.Join(dir, "email.passh")).stderr, "ignored") {
		t.Error("verify email.passh: no note about the ignored text")
	}

	// Damaged copies fail the structure check.
	bad := filepath.Join(dir, "truncated.passh")
	if err := os.WriteFile(bad, orig[:len(orig)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	r = e.fail(1, "verify", bad)
	mustContain(t, "verify truncated", r.stdout, "FAILED", "SHA-256")
	mustContain(t, "verify truncated", r.stderr, "file is truncated")
	i := bytes.LastIndex(orig, []byte("-----END")) - 10
	damaged := bytes.Clone(orig)
	damaged[i] = '*'
	bad = filepath.Join(dir, "damaged.passh")
	if err := os.WriteFile(bad, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	r = e.fail(1, "verify", bad)
	mustContain(t, "verify damaged", r.stderr, "file is damaged (block 2)")

	// backup: into a folder, mode 0600, byte-exact; never overwrites.
	bdir := filepath.Join(e.root, "usb")
	if err := os.Mkdir(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	r = e.ok("backup", bdir+"/")
	// The checksum report is data, the confirmation and hint status.
	mustContain(t, "backup", r.stdout, ": OK\n", "SHA-256   "+origSum)
	mustContain(t, "backup", r.stderr, "Backed up", "byte for byte")
	mustNotContain(t, "backup", r.stdout, "Backed up", "byte for byte")
	made, _ := filepath.Glob(filepath.Join(bdir, "vault-*.passh"))
	if len(made) != 1 {
		t.Fatalf("backup made %v", made)
	}
	if got, _ := os.ReadFile(made[0]); !bytes.Equal(got, orig) {
		t.Error("backup differs from the vault")
	}
	if m := fileMode(t, made[0]); m != 0o600 {
		t.Errorf("backup mode %o", m)
	}
	r = e.fail(1, "backup", made[0])
	mustContain(t, "backup over a file", r.stderr, "already exists")
	if got, _ := os.ReadFile(made[0]); !bytes.Equal(got, orig) {
		t.Error("a refused backup changed the existing file")
	}
	// CLI-003: written through a temporary file that is gone afterwards.
	if left, _ := filepath.Glob(filepath.Join(bdir, ".*.tmp-*")); len(left) > 0 {
		t.Errorf("temporary files left next to the backup: %v", left)
	}
	r = e.ok("verify", made[0])
	mustContain(t, "verify backup", r.stdout, "SHA-256   "+origSum)

	// A non-canonical vault is backed up in canonical form: the same bytes
	// as the original.
	dest := filepath.Join(bdir, "from-email.passh")
	r = e.ok("--vault", filepath.Join(dir, "email.passh"), "backup", dest)
	mustContain(t, "backup non-canonical", r.stderr, "canonical form")
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, orig) {
		t.Errorf("canonical backup of email.passh differs from the original:\n%s", got)
	}
	// The stock age tool reads its blocks (§8 note).
	if ageBin, err := filepath.Abs("../../.tools/bin/age"); err == nil {
		if _, err := os.Stat(ageBin); err == nil {
			ageDecryptsDataBlock(t, ageBin, dest)
		}
	}

	// verify --full opens every copy, with the key of the configured
	// vault's agent (a copy opens with the same key), reporting only.
	e.unlock(fixturePass)
	for name := range copies {
		r := e.ok("verify", "--full", filepath.Join(dir, name))
		mustContain(t, "verify --full "+name, r.stdout, "revision  3", "entries   2", "vault_id  ", "saved_at  ", "rollback  OK")
	}
	r = e.fail(1, "verify", "--full", filepath.Join(dir, "damaged.passh"))
	mustContain(t, "verify --full damaged", r.stderr, "damaged")
	e.ok("lock")
}

// ageDecryptsDataBlock extracts the data block as §8 does and checks that
// the age tool parses it (it can't decrypt it without the key, but it must
// get past the armor and header: the error is about the identity).
func ageDecryptsDataBlock(t *testing.T, ageBin, vault string) {
	t.Helper()
	data, err := os.ReadFile(vault)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte(armor.Footer))
	block := data[i+len(armor.Footer)+1:]
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(filepath.Dir(vault), "id.txt")
	if err := os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ageBin, "-d", "-i", keyFile)
	cmd.Stdin = bytes.NewReader(block)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no identity matched") {
		t.Errorf("age -d on the canonical data block: %v: %s", err, out)
	}
}

// TestExport (§7.1, safety test 5).
func TestExport(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	e.addEntries(
		model.Entry{Path: paths.MustParse("work/github"), Password: "=SUM(A1)", Username: "arsenii",
			Fields: []model.Field{{Key: "recovery-email", Value: "me@example.com"}}},
		model.Entry{Path: paths.MustParse("bank/card"), Password: "+1234", Tags: []string{"money"}},
	)

	// Data never goes to a terminal: refused before anything else.
	r := e.start(sessOpts{}, "export", "--format", "csv").wait()
	if r.code != 1 || !strings.Contains(r.out, "refusing to write export data to a terminal") {
		t.Errorf("export to a terminal: %s", r)
	}
	// Plaintext without a terminal and without --confirm-plaintext fails.
	r = e.fail(1, "export", "--format", "csv")
	mustContain(t, "export unconfirmed", r.stderr, "needs confirmation", "--confirm-plaintext")
	if r.stdout != "" {
		t.Errorf("export unconfirmed wrote %q", r.stdout)
	}

	e.unlock(fixturePass)
	// --confirm-plaintext without a terminal: exact values, no prompt text.
	r = e.ok("export", "--format", "csv", "--confirm-plaintext")
	if !strings.HasPrefix(r.stdout, "folder,name,username,password,url,tags,notes\r\n") ||
		!strings.Contains(r.stdout, "work,github,arsenii,=SUM(A1),") || !strings.Contains(r.stdout, "bank,card,,+1234,") {
		t.Errorf("csv export:\n%s", r.stdout)
	}
	mustNotContain(t, "csv export", r.stdout, "EXPORT PLAINTEXT", "Type", "confirm", "passh")
	mustContain(t, "csv export", r.stderr, "exported 2 entries (csv, plaintext) to stdout", "1 field was left out")

	// With a terminal, the phrase is typed there; stdout gets only data.
	s := e.start(sessOpts{pipeStdout: true}, "export", "--format", "json", "--tag", "money")
	s.answer("Type EXPORT PLAINTEXT to confirm:", "EXPORT PLAINTEXT")
	r = s.waitOK()
	mustNotContain(t, "json export", r.stdout, "EXPORT PLAINTEXT", "Type", "confirm", "exported 1")
	var doc struct {
		Format  string `json:"format"`
		Entries []struct {
			Path string `json:"path"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil || len(doc.Entries) != 1 || doc.Entries[0].Path != "bank/card" {
		t.Errorf("json export (%v):\n%s", err, r.stdout)
	}
	// A wrong phrase refuses.
	s = e.start(sessOpts{pipeStdout: true}, "export", "--format", "json")
	s.answer("Type EXPORT PLAINTEXT to confirm:", "yes")
	if r = s.wait(); r.code != 1 || r.stdout != "" {
		t.Errorf("export with a wrong phrase: %s", r)
	}

	// -o: a new file with mode 0600, a warning off tmpfs; never overwrites.
	out := filepath.Join(e.root, "export.json")
	r = e.ok("export", "--format", "bitwarden-json", "--confirm-plaintext", "-o", out)
	if m := fileMode(t, out); m != 0o600 {
		t.Errorf("export file mode %o", m)
	}
	if !onTmpfs(t, out) {
		mustContain(t, "export -o", r.stderr, "isn't on tmpfs")
	}
	r = e.fail(1, "export", "--format", "json", "--confirm-plaintext", "-o", out)
	mustContain(t, "export -o existing", r.stderr, "already exists")

	// --age: encrypted, no confirmation needed; decrypts to the data.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r = e.ok("export", "--format", "json", "--age", id.Recipient().String())
	mustContain(t, "export --age", r.stdout, "-----BEGIN AGE ENCRYPTED FILE-----")
	dec, err := age.Decrypt(armor.NewReader(strings.NewReader(r.stdout)), id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(dec)
	mustContain(t, "export --age", string(plain), `"work/github"`, `"=SUM(A1)"`)
	r = e.fail(1, "export", "--format", "json", "--age", "AGE-SECRET-KEY-1QQQ")
	mustContain(t, "export --age secret", r.stderr, "secret key")
	mustNotContain(t, "export --age secret", r.stderr, "1QQQ")
	e.ok("lock")
}

// onTmpfs reports whether path is on tmpfs (Linux), where export doesn't
// warn.
func onTmpfs(t *testing.T, path string) bool {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &st); err != nil {
		t.Fatal(err)
	}
	return runtime.GOOS == "linux" && uint64(st.Type) == 0x01021994
}

// TestWorkFactorRefused: a key block that asks for more scrypt work than
// passh uses (2^18) is refused before scrypt runs, with what to do about
// it (keys.ErrWorkFactor, explained by the CLI).
func TestWorkFactorRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.withVault()
	data, err := os.ReadFile(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	kb := bytes.Replace(f.KeyBlock, []byte(" 18\n"), []byte(" 22\n"), 1)
	if bytes.Equal(kb, f.KeyBlock) {
		t.Fatal("no scrypt work factor 18 in the fixture's key block")
	}
	forged, err := vaultfile.Encode(kb, f.DataBlock)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.vault, string(forged))
	s := e.start(sessOpts{}, "ls")
	s.answer("Passphrase:", fixturePass)
	r := s.wait()
	if r.code != 1 || !strings.Contains(r.out, "2^22") || !strings.Contains(r.out, "passh recover") || !strings.Contains(r.out, "passh backups") {
		t.Errorf("ls with a key block asking for 2^22: %s", r)
	}
}
