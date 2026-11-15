package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// lockedHint is the message of §5.1 step 3.
const lockedHint = "vault is locked: run `passh unlock` in a terminal (over SSH: `ssh -t host passh unlock`)"

// §13.1.1: installing = copying the binary and running `passh init`;
// `passh doctor` reports no errors (a swap warning is fine).
func TestF1_InstallInitDoctor(t *testing.T) {
	e := newEnv(t)
	// Install: copy the binary into ~/.local/bin; PATH holds nothing else.
	inst := filepath.Join(e.home, ".local", "bin", "passh")
	writeFile(t, inst, readFile(t, passhBin), 0o755)
	e.path = filepath.Dir(inst)

	// §3.3: without a config file passh says how to make one.
	if r := e.runCmd(inst, nil, "ls"); r.code == 0 || !strings.Contains(r.stderr, "passh init") {
		t.Errorf("ls without a config: want a hint to run passh init, got %s", r)
	}

	s := e.start(sessOpts{bin: inst}, "init")
	s.answer("New passphrase:", fixPass)
	s.answer("Repeat passphrase:", fixPass)
	if s.expectWithin("recovery key now?", 30*time.Second) {
		s.send("n\r")
	}
	r := s.wait()
	if r.code != 0 {
		t.Fatalf("init: %s", r)
	}
	if m := perm(t, e.vault); m != 0o600 {
		t.Errorf("vault mode %o, want 0600 (§4.1)", m)
	}
	cfg := string(readFile(t, e.config))
	if !strings.Contains(cfg, "vault") {
		t.Errorf("config file without vault: %q", cfg)
	}

	before := walkFiles(e.root)
	r = e.runCmd(inst, nil, "doctor")
	if r.code != 0 {
		t.Errorf("doctor without a terminal: want exit 0, got %s", r)
	}
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "error") {
			t.Errorf("doctor reports an error: %q", l)
		}
	}
	// With a terminal too.
	s = e.start(sessOpts{bin: inst}, "doctor")
	r = s.wait()
	if r.code != 0 {
		t.Errorf("doctor on a terminal: want exit 0, got %s", r)
	}
	for _, l := range strings.Split(r.term, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "error") {
			t.Errorf("doctor (terminal) reports an error: %q", l)
		}
	}
	// doctor is read-only (§6.1).
	after := walkFiles(e.root)
	for p, b := range after {
		if ob, ok := before[p]; !ok || !bytes.Equal(ob, b) {
			t.Errorf("doctor wrote %s", p)
		}
	}
	// A second init doesn't overwrite the vault.
	vb := readFile(t, e.vault)
	r = e.runCmd(inst, nil, "init")
	if r.code == 0 || !bytes.Equal(vb, readFile(t, e.vault)) {
		t.Errorf("a second init must refuse and leave the vault: %s", r)
	}
}

// §13.1.4: after `passh unlock` on a terminal, commands work without one;
// after `passh lock` or agent.idle_ttl the agent process is gone and the
// command fails with the hint.
func TestF4_AgentWorkflow(t *testing.T) {
	e, _ := popEnv(t, "[agent]\nidle_ttl = \"3s\"\nmax_ttl = \"1h\"\n")

	pid := e.unlock(fixPass)
	if !alive(pid) {
		t.Fatalf("agent pid %d not running after unlock", pid)
	}
	// `ssh pi passh show … | pbcopy`: no terminal, stdout a pipe.
	r := e.ok("show", "work/github", "--field", "password")
	if r.stdout != "s3cr3t-P@ss" {
		t.Errorf("piped password = %q, want the exact password", r.stdout)
	}
	r = e.ok("ls")
	mustContain(t, "ls via the agent", r.stdout, "github", "My Bank")

	// passh lock: the process is gone, the command fails with the hint.
	r = e.ok("lock")
	if !waitGone(pid, 3*time.Second) {
		t.Errorf("agent pid %d still running after passh lock", pid)
	}
	r = e.run("show", "work/github", "--field", "password")
	if r.code == 0 || r.stdout != "" || !strings.Contains(r.stderr, lockedHint) {
		t.Errorf("after lock: want failure with the hint, got %s", r)
	}

	// Idle TTL: requests keep it alive, then it exits on its own.
	pid = e.unlock(fixPass)
	for i := 0; i < 3; i++ {
		time.Sleep(1200 * time.Millisecond) // time passing under test: within idle_ttl
		e.ok("show", "work/github", "--field", "username")
	}
	if !alive(pid) {
		t.Errorf("agent exited although key requests came every 1.2 s (idle_ttl 3s)")
	}
	last := time.Now()
	if !waitGone(pid, 8*time.Second) {
		t.Fatalf("agent pid %d still running %v after the last request (idle_ttl 3s)", pid, time.Since(last))
	}
	if d := time.Since(last); d < 2*time.Second {
		t.Errorf("agent exited %v after the last request, before idle_ttl (3s)", d)
	}
	r = e.run("show", "work/github", "--field", "password")
	if r.code == 0 || !strings.Contains(r.stderr, lockedHint) {
		t.Errorf("after idle_ttl: want failure with the hint, got %s", r)
	}

	// §5.3: status requests (doctor reports the agent) don't count as use.
	pid = e.unlock(fixPass)
	start := time.Now()
	for alive(pid) && time.Since(start) < 7*time.Second {
		e.run("doctor")
		time.Sleep(500 * time.Millisecond) // time passing under test: status requests during idle_ttl
	}
	if alive(pid) {
		t.Errorf("doctor's status requests kept the agent alive past idle_ttl (3s)")
	}
	if n := len(agentProcs(e.root)); n != 0 {
		t.Errorf("%d agent processes left", n)
	}
}

// §13.1.6: the Bitwarden JSON export follows Bitwarden's unencrypted export
// schema; the CSV keeps passwords starting with = + - @ intact.
func TestF6_Export(t *testing.T) {
	e, f := popEnv(t, "")
	e.unlock(fixPass)
	defer e.lock()

	t.Run("bitwarden-json", func(t *testing.T) {
		r := e.ok("export", "--format", "bitwarden-json", "--confirm-plaintext")
		checkBitwarden(t, []byte(r.stdout), f.popData)
	})

	t.Run("csv", func(t *testing.T) {
		r := e.ok("export", "--format", "csv", "--confirm-plaintext")
		rows := parseCSV(t, r.stdout)
		if got := strings.Join(rows[0], ","); got != "folder,name,username,password,url,tags,notes" {
			t.Errorf("CSV header %q, want folder,name,username,password,url,tags,notes", got)
		}
		byPath := map[string][]string{}
		for _, row := range rows[1:] {
			if len(row) != 7 {
				t.Fatalf("CSV row with %d columns: %q", len(row), row)
			}
			p := row[1]
			if row[0] != "" {
				p = row[0] + "/" + row[1]
			}
			byPath[p] = row
		}
		for _, ve := range f.popData.Entries {
			row, ok := byPath[ve.Path]
			if !ok {
				t.Errorf("CSV lacks %s", ve.Path)
				continue
			}
			if row[2] != ve.Username || row[3] != ve.Password || row[4] != ve.URL || row[6] != ve.Notes {
				t.Errorf("CSV row for %s = %q; want username %q password %q url %q notes %q", ve.Path, row, ve.Username, ve.Password, ve.URL, ve.Notes)
			}
			if row[5] != strings.Join(ve.Tags, ", ") { // §7.1: joined with ", "
				t.Errorf("CSV tags for %s = %q, want %q", ve.Path, row[5], strings.Join(ve.Tags, ", "))
			}
		}
		for _, p := range []string{"bank/chase", "csv/plus", "csv/minus", "csv/at"} {
			if row := byPath[p]; row == nil || !strings.ContainsAny(row[3][:1], "=+-@") {
				t.Errorf("%s: password with a leading = + - @ not intact: %q", p, row)
			}
		}
	})

	t.Run("csv --spreadsheet-safe", func(t *testing.T) {
		r := e.ok("export", "--format", "csv", "--confirm-plaintext", "--spreadsheet-safe")
		rows := parseCSV(t, r.stdout)
		for _, row := range rows[1:] {
			p := row[0] + "/" + row[1]
			ve, ok := f.popData.entry(p)
			if !ok {
				continue
			}
			want := ve.Password
			if strings.ContainsAny(want[:1], "=+-@\t\r") {
				want = "'" + want
			}
			if row[3] != want {
				t.Errorf("--spreadsheet-safe password of %s = %q, want %q", p, row[3], want)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		r := e.ok("export", "--format", "json", "--confirm-plaintext")
		var m map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &m); err != nil {
			t.Fatalf("json export doesn't parse: %v", err)
		}
		if m["vault_id"] != f.popData.VaultID || m["format"] != "passh-vault-data" {
			t.Errorf("json export: vault_id %v format %v", m["vault_id"], m["format"])
		}
		if _, ok := m["exported_at"]; !ok {
			t.Errorf("json export lacks exported_at (§7.3)")
		}
		if _, ok := m["deleted"]; ok {
			t.Errorf("json export has deleted (§7.3 says without)")
		}
		var d vData
		_ = json.Unmarshal([]byte(r.stdout), &d)
		for _, ve := range f.popData.Entries {
			got, ok := d.entry(ve.Path)
			if !ok || got.ID != ve.ID || got.Password != ve.Password || got.CreatedAt != ve.CreatedAt {
				t.Errorf("json export entry %s = %+v, want id/password/created_at of %+v", ve.Path, got, ve)
			}
		}
	})
}

func parseCSV(t *testing.T, s string) [][]string {
	t.Helper()
	rd := csv.NewReader(strings.NewReader(s))
	rd.FieldsPerRecord = -1
	rows, err := rd.ReadAll()
	if err != nil {
		t.Fatalf("CSV doesn't parse (RFC 4180): %v\n%s", err, s)
	}
	if len(rows) < 2 {
		t.Fatalf("CSV with %d rows", len(rows))
	}
	return rows
}

// checkBitwarden checks an export against Bitwarden's unencrypted JSON
// export schema (as its importer reads it: encrypted, folders[{id,name}],
// items[{id,type,name,folderId,notes,favorite,fields,login{username,
// password,uris[{uri,match}],totp}}]) and against the vault's entries.
func checkBitwarden(t *testing.T, raw []byte, want *vData) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("bitwarden-json doesn't parse: %v", err)
	}
	var encrypted bool
	if err := json.Unmarshal(top["encrypted"], &encrypted); err != nil || encrypted {
		t.Errorf(`bitwarden-json: "encrypted" must be false, got %s`, top["encrypted"])
	}
	var folders []map[string]any
	if err := json.Unmarshal(top["folders"], &folders); err != nil {
		t.Fatalf(`bitwarden-json: "folders" must be an array: %v`, err)
	}
	folderName := map[string]string{}
	for _, fo := range folders {
		id, ok1 := fo["id"].(string)
		name, ok2 := fo["name"].(string)
		if !ok1 || !ok2 || id == "" || name == "" {
			t.Errorf("bitwarden-json: folder %v needs string id and name", fo)
		}
		if _, dup := folderName[id]; dup {
			t.Errorf("bitwarden-json: duplicate folder id %s", id)
		}
		folderName[id] = name
	}
	var items []map[string]any
	if err := json.Unmarshal(top["items"], &items); err != nil {
		t.Fatalf(`bitwarden-json: "items" must be an array: %v`, err)
	}
	if len(items) != len(want.Entries) {
		t.Errorf("bitwarden-json: %d items, want %d", len(items), len(want.Entries))
	}
	seen := map[string]bool{}
	for _, it := range items {
		if id, ok := it["id"].(string); !ok || id == "" {
			t.Errorf("item without string id: %v", it)
		}
		if typ, ok := it["type"].(float64); !ok || typ != 1 {
			t.Errorf("item type %v, want 1 (login)", it["type"])
		}
		name, ok := it["name"].(string)
		if !ok || name == "" {
			t.Errorf("item without name: %v", it)
		}
		if v, ok := it["favorite"]; ok {
			if _, isBool := v.(bool); !isBool {
				t.Errorf("favorite must be a bool: %v", v)
			}
		}
		if v := it["notes"]; v != nil {
			if _, ok := v.(string); !ok {
				t.Errorf("notes must be a string or null: %v", v)
			}
		}
		path := name
		switch fid := it["folderId"].(type) {
		case nil:
		case string:
			fn, ok := folderName[fid]
			if !ok {
				t.Errorf("item %s: folderId %s names no folder", name, fid)
			}
			path = fn + "/" + name
		default:
			t.Errorf("folderId must be a string or null: %v", fid)
		}
		login, ok := it["login"].(map[string]any)
		if !ok {
			t.Errorf("item %s: login must be an object", path)
			continue
		}
		for _, k := range []string{"username", "password", "totp"} {
			if v := login[k]; v != nil {
				if _, ok := v.(string); !ok {
					t.Errorf("item %s: login.%s must be a string or null", path, k)
				}
			}
		}
		var uris []string
		if u := login["uris"]; u != nil {
			arr, ok := u.([]any)
			if !ok {
				t.Errorf("item %s: login.uris must be an array", path)
			}
			for _, x := range arr {
				o, ok := x.(map[string]any)
				s, ok2 := o["uri"].(string)
				if !ok || !ok2 {
					t.Errorf("item %s: uri object %v needs a string uri", path, x)
				}
				if m := o["match"]; m != nil {
					if _, isNum := m.(float64); !isNum {
						t.Errorf("item %s: uri match must be null or a number", path)
					}
				}
				uris = append(uris, s)
			}
		}
		var tagsField any
		if fl := it["fields"]; fl != nil {
			arr, ok := fl.([]any)
			if !ok {
				t.Errorf("item %s: fields must be an array", path)
			}
			for _, x := range arr {
				o, _ := x.(map[string]any)
				name, ok1 := o["name"].(string)
				typ, ok2 := o["type"].(float64)
				if !ok1 || !ok2 || typ < 0 || typ > 3 {
					t.Errorf("item %s: field %v needs string name and type 0-3", path, x)
				}
				if name == "tags" {
					tagsField = o["value"]
					if typ != 0 {
						t.Errorf("item %s: the tags field must be text (type 0)", path)
					}
				}
			}
		}
		ve, ok := want.entry(path)
		if !ok {
			t.Errorf("bitwarden-json: item %q (folder/name) is no vault entry", path)
			continue
		}
		seen[path] = true
		if login["password"] != ve.Password || nz(login["username"]) != ve.Username {
			t.Errorf("item %s: username/password %v/%v, want %q/%q", path, login["username"], login["password"], ve.Username, ve.Password)
		}
		if ve.URL != "" && (len(uris) != 1 || uris[0] != ve.URL) {
			t.Errorf("item %s: uris %q, want [%q]", path, uris, ve.URL)
		}
		if nz(it["notes"]) != ve.Notes {
			t.Errorf("item %s: notes %q, want %q", path, it["notes"], ve.Notes)
		}
		// §7.1: tags become one custom field "tags", joined with ", ".
		if len(ve.Tags) > 0 && tagsField != strings.Join(ve.Tags, ", ") {
			t.Errorf("item %s: tags field %v, want %q", path, tagsField, strings.Join(ve.Tags, ", "))
		}
	}
	for _, ve := range want.Entries {
		if !seen[ve.Path] {
			t.Errorf("bitwarden-json lacks %s", ve.Path)
		}
	}
}

func nz(v any) string {
	s, _ := v.(string)
	return s
}

// ---------------------------------------------------------------------------
// §13.1.8: copies that went through different channels open; verify says OK;
// byte-exact copies have the original's SHA-256.

var shaRe = regexp.MustCompile(`SHA-256\s+([0-9a-f]{64})`)

func verifySHA(t *testing.T, out string) string {
	t.Helper()
	m := shaRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no SHA-256 in verify output:\n%s", out)
	}
	return m[1]
}

// rewrap re-wraps the base64 of both blocks of a canonical vault at width
// columns, with eol line endings, indent before and trail after each line,
// as a mail client or a note app does.
func rewrap(data []byte, width int, eol, indent, trail string) []byte {
	var res []string
	var body strings.Builder
	flush := func() {
		s := body.String()
		for len(s) > width {
			res = append(res, indent+s[:width]+trail)
			s = s[width:]
		}
		if s != "" {
			res = append(res, indent+s+trail)
		}
		body.Reset()
	}
	in := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "-----BEGIN"):
			res = append(res, indent+l+trail)
			in = true
		case strings.HasPrefix(l, "-----END"):
			flush()
			res = append(res, indent+l+trail)
			in = false
		case in:
			body.WriteString(l)
		default:
			res = append(res, indent+l+trail)
		}
	}
	return []byte(strings.Join(res, eol) + eol)
}

func TestF8_CopyVariants(t *testing.T) {
	e, f := popEnv(t, "")
	orig := readFile(t, e.vault)
	origSHA := verifySHA(t, e.ok("verify").stdout)
	if sum := sha256.Sum256(orig); hex.EncodeToString(sum[:]) != origSHA {
		t.Errorf("verify's SHA-256 %s isn't the file's", origSHA)
	}
	e.unlock(fixPass)
	defer e.lock()

	dir := filepath.Join(e.root, "copies")
	type variant struct {
		name  string
		data  []byte
		exact bool
	}
	lf := string(orig)
	mime := base64.StdEncoding.EncodeToString(orig)
	var mimeWrapped strings.Builder
	for len(mime) > 76 {
		mimeWrapped.WriteString(mime[:76] + "\r\n")
		mime = mime[76:]
	}
	mimeWrapped.WriteString(mime + "\r\n")
	mimeBack, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(mimeWrapped.String(), "\r\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	variants := []variant{
		{"byte copy (cp/scp/rsync/cloud)", orig, true},
		{"email attachment (MIME base64 round trip)", mimeBack, true},
		{"CRLF", []byte(strings.ReplaceAll(lf, "\n", "\r\n")), false},
		{"CR only", []byte(strings.ReplaceAll(lf, "\n", "\r")), false},
		{"UTF-8 BOM", append([]byte{0xef, 0xbb, 0xbf}, orig...), false},
		{"re-wrapped at 76", rewrap(orig, 76, "\n", "", ""), false},
		{"re-wrapped at 40", rewrap(orig, 40, "\n", "", ""), false},
		{"unwrapped (one line per block)", rewrap(orig, 1<<20, "\n", "", ""), false},
		{"email body: CRLF, 72 columns, indented, trailing spaces", rewrap(orig, 72, "\r\n", "  ", "  "), false},
		{"pasted into a note: text before and after", []byte("Here is my vault, keep it safe:\n\n" + lf + "\n-- \nsent from my phone\n"), false},
		{"mail: text before and after, CRLF", []byte(strings.ReplaceAll("Subject: vault\n\n"+lf+"\nbye\n", "\n", "\r\n")), false},
	}
	if fat, ok := fatCopy(t, e, orig); ok {
		variants = append(variants, variant{"FAT32 image through mtools (mode lost)", fat, true})
	} else {
		t.Log("mtools/mkfs.fat unavailable: FAT copy not tested")
	}
	for i, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			p := filepath.Join(dir, fmt.Sprintf("copy%d.passh", i))
			writeFile(t, p, v.data, 0o644) // a copy that lost the 0600 mode
			r := e.run("verify", p)
			if r.code != 0 || !strings.Contains(r.stdout, ": OK") {
				t.Fatalf("verify %s: want OK, got %s", v.name, r)
			}
			if strings.Contains(v.name, "text before") && !strings.Contains(r.stderr, "ignored") {
				t.Errorf("text around the vault must be ignored with a warning (§4.5): %s", r)
			}
			sha := verifySHA(t, r.stdout)
			if v.exact && sha != origSHA {
				t.Errorf("byte-exact copy: SHA-256 %s, original %s", sha, origSHA)
			}
			if !v.exact && sha == origSHA {
				t.Errorf("a changed copy can't have the original's SHA-256")
			}
			r = e.run("verify", "--full", p)
			if r.code != 0 {
				t.Fatalf("verify --full %s: %s", v.name, r)
			}
			mustContain(t, "verify --full", r.stdout, fmt.Sprintf("revision  %d", f.popRev), "entries   7", f.popData.VaultID)
			// passh backup writes the canonical form back (§4.5, §8).
			out := filepath.Join(dir, fmt.Sprintf("back%d.passh", i))
			r = e.run("--vault", p, "backup", out)
			if r.code != 0 {
				t.Fatalf("backup of the copy: %s", r)
			}
			if !bytes.Equal(readFile(t, out), orig) {
				t.Errorf("backup of a %s copy isn't the canonical original", v.name)
			}
		})
	}
	// A non-exact copy opens with the passphrase and shows the entry.
	p := filepath.Join(dir, "show.passh")
	writeFile(t, p, rewrap(orig, 72, "\r\n", "  ", "  "), 0o644)
	s := e.start(sessOpts{pipeStdout: true}, "--vault", p, "show", "work/github", "--field", "password")
	if s.expectWithin("Passphrase:", 5*time.Second) {
		s.typeSecret(fixPass)
	}
	r := s.waitOK()
	if r.stdout != "s3cr3t-P@ss" {
		t.Errorf("show from a re-wrapped CRLF copy = %q", r.stdout)
	}
}

// fatCopy copies data onto a FAT32 file system image and back with mtools.
func fatCopy(t *testing.T, e *env, data []byte) ([]byte, bool) {
	t.Helper()
	mkfs, err1 := exec.LookPath("mkfs.fat")
	if err1 != nil {
		mkfs, err1 = exec.LookPath("/usr/sbin/mkfs.fat")
	}
	mcopy, err2 := exec.LookPath("mcopy")
	if err1 != nil || err2 != nil {
		return nil, false
	}
	dir := filepath.Join(e.root, "fat")
	img := filepath.Join(dir, "usb.img")
	src := filepath.Join(dir, "vault.passh")
	back := filepath.Join(dir, "back.passh")
	writeFile(t, src, data, 0o600)
	envv := []string{"HOME=" + e.home, "PATH=/usr/bin:/bin:/usr/sbin", "MTOOLS_SKIP_CHECK=1", "TMPDIR=" + e.tmp}
	for _, args := range [][]string{
		{mkfs, "-C", "-F", "32", img, "40960"},
		{mcopy, "-i", img, src, "::/VAULT.PAS"},
		{mcopy, "-i", img, "::/VAULT.PAS", back},
	} {
		c := exec.Command(args[0], args[1:]...)
		c.Env = envv
		if out, err := c.CombinedOutput(); err != nil {
			t.Logf("%v: %v\n%s", args, err, out)
			return nil, false
		}
	}
	return readFile(t, back), true
}

// ---------------------------------------------------------------------------
// §13.1.9: without passh, the §8 commands with the stock age tool produce
// the vault's JSON. The commands are run verbatim, except that /dev/shm/ is
// replaced by a private folder on /dev/shm (so parallel runs and other
// users don't collide).

func TestF9_ManualRecoveryWithAge(t *testing.T) {
	if _, err := os.Stat(ageBin); err != nil {
		t.Skip("no .tools/bin/age")
	}
	e, f := popEnv(t, "")
	shm, err := os.MkdirTemp("/dev/shm", "passh-acc-")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	defer os.RemoveAll(shm)
	e.path = filepath.Dir(ageBin) + ":/usr/bin:/bin" // age on PATH, no passh needed

	run := func(t *testing.T, vaultFile string) {
		work := filepath.Join(e.root, "manual")
		_ = os.RemoveAll(work)
		_ = os.RemoveAll(filepath.Join(shm, "key.txt"))
		_ = os.RemoveAll(filepath.Join(shm, "vault.json"))
		writeFile(t, filepath.Join(work, "vault.passh"), readFile(t, vaultFile), 0o600)
		steps := []string{
			`tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==1{print} n==1 && /END AGE ENCRYPTED FILE/{exit}' > key.age`,
			`tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==2{print} n==2 && /END AGE ENCRYPTED FILE/{exit}' > data.age`,
			`age -d -o /dev/shm/key.txt key.age`,
			`age -d -i /dev/shm/key.txt -o /dev/shm/vault.json data.age`,
		}
		for i, st := range steps {
			st = strings.ReplaceAll(st, "/dev/shm/", shm+"/")
			s := e.start(sessOpts{bin: "/bin/sh"}, "-c", "cd "+work+" && "+st)
			if i == 2 {
				// age asks for the passphrase on the terminal.
				s.answer("passphrase", fixPass)
			}
			if r := s.wait(); r.code != 0 {
				t.Fatalf("step %d %q: %s", i+1, st, r)
			}
		}
		key := readFile(t, filepath.Join(shm, "key.txt"))
		if !strings.HasPrefix(string(key), "AGE-SECRET-KEY-1") {
			t.Errorf("key.txt isn't an age identity: %.20q", key)
		}
		var d vData
		if err := json.Unmarshal(readFile(t, filepath.Join(shm, "vault.json")), &d); err != nil {
			t.Fatalf("vault.json isn't JSON: %v", err)
		}
		if d.Format != "passh-vault-data" || d.VaultID != f.popData.VaultID || d.Revision != f.popRev || len(d.Entries) != len(f.popData.Entries) {
			t.Errorf("vault.json: format %q id %q rev %d entries %d", d.Format, d.VaultID, d.Revision, len(d.Entries))
		}
		if gh, ok := d.entry("work/github"); !ok || gh.Password != "s3cr3t-P@ss" || gh.Username != "arsenii" {
			t.Errorf("vault.json work/github = %+v", gh)
		}
		// rm /dev/shm/key.txt
		if err := os.Remove(filepath.Join(shm, "key.txt")); err != nil {
			t.Error(err)
		}
	}
	t.Run("canonical", func(t *testing.T) { run(t, e.vault) })
	t.Run("CRLF copy", func(t *testing.T) {
		p := filepath.Join(e.root, "crlf.passh")
		writeFile(t, p, []byte(strings.ReplaceAll(string(readFile(t, e.vault)), "\n", "\r\n")), 0o600)
		run(t, p)
	})
	t.Run("text after the vault", func(t *testing.T) {
		p := filepath.Join(e.root, "after.passh")
		writeFile(t, p, append(readFile(t, e.vault), []byte("\n-- \nsignature\n")...), 0o600)
		run(t, p)
	})
}

// What can't be tested on this machine.
func TestNotTestableHere(t *testing.T) {
	for _, c := range []string{
		"13.1.5 copy over a real SSH connection (a pty stands in for it)",
		"13.1.6 an actual import into Vaultwarden/KeePassXC (schema checked instead)",
		"13.1.7 a second device and a VPN (fetched from this host instead)",
		"13.1.8 exFAT, scp between hosts, Linux<->macOS, amd64<->arm",
		"13.2.4 chi-square over 10^6 generated passwords (not in this scope)",
		"13.2.6 a connection from another user (needs a second uid)",
	} {
		t.Run(c, func(t *testing.T) { t.Skip("not testable here") })
	}
}
