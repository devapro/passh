package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/devapro/passh/internal/exec"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

var (
	t0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
)

// vaultJSON has unknown keys at every level and a tombstone.
const vaultJSON = `{
  "format": "passh-vault-data",
  "version": 1,
  "vault_id": "0f6c1d2e-0000-4000-8000-000000000001",
  "revision": 42,
  "saved_at": "2026-11-15T12:00:00Z",
  "future_top": {"a": 1},
  "entries": [
    {
      "id": "8d1e7a90-0000-4000-8000-000000000001",
      "path": "work/github",
      "password": "s3cr3t-P@ss",
      "username": "arsenii",
      "url": "https://github.com",
      "tags": ["work", "dev", "2fa"],
      "fields": [
        {"key": "recovery-email", "value": "me@example.com", "future_field": true},
        {"key": "otp", "value": "otpauth://totp/GitHub:arsenii?secret=JBSWY3DPEHPK3PXP"},
        {"key": "pin", "value": "otpauth://hotp/x?secret=AAAA"}
      ],
      "notes": "Free-form notes.\nRecovery codes.",
      "created_at": "2026-11-01T09:00:00Z",
      "updated_at": "2026-11-15T12:00:00Z",
      "future_entry": "kept"
    },
    {
      "id": "8d1e7a90-0000-4000-8000-000000000002",
      "path": "work/dev/gitlab",
      "password": "=HYPERLINK(\"http://evil\")",
      "username": "",
      "url": "",
      "tags": ["work"],
      "fields": [],
      "notes": "",
      "created_at": "2026-11-01T09:00:00Z",
      "updated_at": "2026-11-01T09:00:00Z"
    },
    {
      "id": "8d1e7a90-0000-4000-8000-000000000003",
      "path": "workshop/lathe",
      "password": "-minus",
      "username": "",
      "url": "",
      "tags": ["dev", "work"],
      "fields": [],
      "notes": "",
      "created_at": "2026-11-01T09:00:00Z",
      "updated_at": "2026-11-01T09:00:00Z"
    },
    {
      "id": "8d1e7a90-0000-4000-8000-000000000004",
      "path": "router",
      "password": "admin",
      "username": "",
      "url": "",
      "tags": [],
      "fields": [],
      "notes": "",
      "created_at": "2026-11-01T09:00:00Z",
      "updated_at": "2026-11-01T09:00:00Z"
    }
  ],
  "deleted": [
    {"id": "3b9f0000-0000-4000-8000-000000000009", "deleted_at": "2026-11-10T18:30:00Z"}
  ]
}`

func testData(t *testing.T) *model.Data {
	t.Helper()
	d, err := model.Decode([]byte(vaultJSON))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func entry(path, password, username, url, notes string, tags ...string) model.Entry {
	return model.Entry{
		ID: model.NewID(), Path: paths.MustParse(path),
		Password: password, Username: username, URL: url, Notes: notes, Tags: tags,
		CreatedAt: t0, UpdatedAt: t1,
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range Formats() {
		if f, err := ParseFormat(s); err != nil || string(f) != s {
			t.Errorf("ParseFormat(%q) = %q, %v", s, f, err)
		}
	}
	for _, s := range []string{"", "CSV", "xml", "bitwarden"} {
		if _, err := ParseFormat(s); err == nil {
			t.Errorf("ParseFormat(%q) succeeded", s)
		}
	}
}

func TestParseFilter(t *testing.T) {
	f, err := ParseFilter("work", []string{" dev ", "2fa"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Folder.String() != "work" || !slices.Equal(f.Tags, []string{"dev", "2fa"}) {
		t.Errorf("filter = %+v", f)
	}
	if f, err := ParseFilter("", nil); err != nil || !f.Folder.IsZero() || f.Tags != nil {
		t.Errorf("empty filter = %+v, %v", f, err)
	}
	for _, folder := range []string{"/work", "work/", "a/../b", "-x", "a\x1bb"} {
		if _, err := ParseFilter(folder, nil); !errors.As(err, new(*paths.Error)) {
			t.Errorf("ParseFilter(%q) error = %v", folder, err)
		}
	}
	for _, tag := range []string{"", "a,b", "a\x07"} {
		if _, err := ParseFilter("", []string{tag}); !errors.Is(err, model.ErrInvalidTag) {
			t.Errorf("tag %q: error = %v", tag, err)
		}
	}
}

func TestFilterSelect(t *testing.T) {
	d := testData(t)
	pathsOf := func(f Filter) []string {
		var out []string
		for _, e := range f.Select(d) {
			out = append(out, e.Path.String())
		}
		return out
	}
	cases := []struct {
		folder string
		tags   []string
		want   []string
	}{
		{"", nil, []string{"router", "work/dev/gitlab", "work/github", "workshop/lathe"}},
		{"work", nil, []string{"work/dev/gitlab", "work/github"}}, // segment-aware: not workshop
		{"work/dev", nil, []string{"work/dev/gitlab"}},
		{"work/github", nil, nil}, // an entry is not a folder holding itself
		{"", []string{"work"}, []string{"work/dev/gitlab", "work/github", "workshop/lathe"}},
		{"", []string{"work", "dev"}, []string{"work/github", "workshop/lathe"}}, // AND
		{"", []string{"work", "dev", "2fa"}, []string{"work/github"}},
		{"work", []string{"dev"}, []string{"work/github"}},
		{"", []string{"nope"}, nil},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.folder, c.tags)
		if err != nil {
			t.Fatal(err)
		}
		if got := pathsOf(f); !slices.Equal(got, c.want) {
			t.Errorf("folder %q tags %q: got %q, want %q", c.folder, c.tags, got, c.want)
		}
	}
}

func TestConfirmPlaintext(t *testing.T) {
	plain := Options{Format: FormatCSV}
	enc := Options{Format: FormatCSV, Recipient: "age1…"}
	cases := []struct {
		o           Options
		term, flag  bool
		wantPrompt  bool
		wantErr     error
		description string
	}{
		{plain, true, false, true, nil, "terminal: prompt"},
		{plain, true, true, true, nil, "terminal: prompt even with the flag"},
		{plain, false, true, false, nil, "no terminal, flag"},
		{plain, false, false, false, ErrNotConfirmed, "no terminal, no flag"},
		{enc, true, false, false, nil, "encrypted, terminal"},
		{enc, false, false, false, nil, "encrypted, no terminal"},
		{enc, false, true, false, ErrAgeAndConfirm, "both flags"},
	}
	for _, c := range cases {
		prompt, err := ConfirmPlaintext(c.o, c.term, c.flag)
		if prompt != c.wantPrompt || !errors.Is(err, c.wantErr) {
			t.Errorf("%s: got %v, %v", c.description, prompt, err)
		}
	}
	if !plain.Plaintext() || enc.Plaintext() {
		t.Error("Plaintext() is wrong")
	}
}

func TestCSVExact(t *testing.T) {
	entries := []model.Entry{
		entry("top", "plain", "", "", ""),
		entry("bank/acme", `pa,ss"word`, "me, myself", "https://x.test/?a=1,2", "line 1\nline \"2\"\n\nline 4", "money", "2fa"),
		entry("f/eq", "=1+1", "+user", "-url", "@note"),
		entry("f/tab", "\tTAB", " lead", "trail ", "\rCR first"),
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, entries, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "folder,name,username,password,url,tags,notes\r\n") {
		t.Fatalf("header: %q", out)
	}
	for _, want := range []string{
		"\r\n,top,,plain,,,\r\n",
		`bank,acme,"me, myself","pa,ss""word","https://x.test/?a=1,2","money, 2fa","line 1` + "\n" + `line ""2""` + "\n\nline 4\"\r\n",
		"f,eq,+user,=1+1,-url,,@note\r\n",
		"f,tab,\" lead\",\"\tTAB\",\"trail \",,\"\rCR first\"\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%q", want, out)
		}
	}

	r := csv.NewReader(strings.NewReader(out))
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		CSVHeader,
		{"", "top", "", "plain", "", "", ""},
		{"bank", "acme", "me, myself", `pa,ss"word`, "https://x.test/?a=1,2", "money, 2fa", "line 1\nline \"2\"\n\nline 4"},
		{"f", "eq", "+user", "=1+1", "-url", "", "@note"},
		{"f", "tab", " lead", "\tTAB", "trail ", "", "\rCR first"},
	}
	if !reflect.DeepEqual(recs, want) {
		t.Errorf("read back:\n%q\nwant\n%q", recs, want)
	}
}

func TestCSVSpreadsheetSafe(t *testing.T) {
	entries := []model.Entry{
		entry("f/a", "=1+1", "+user", "-url", "@note"),
		entry("@at/=eq", "\tTAB", "safe", "", "\rCR"),
		entry("f/b", "x=1", "a-b", "", "", "-tag"),
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, entries, true); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		CSVHeader,
		{"f", "a", "'+user", "'=1+1", "'-url", "", "'@note"},
		{"'@at", "'=eq", "safe", "'\tTAB", "", "", "'\rCR"},
		{"f", "b", "a-b", "x=1", "", "'-tag", ""},
	}
	if !reflect.DeepEqual(recs, want) {
		t.Errorf("got\n%q\nwant\n%q", recs, want)
	}
}

func TestExportCSVSummary(t *testing.T) {
	d := testData(t)
	var buf bytes.Buffer
	sum, err := Export(&buf, d, Options{Format: FormatCSV})
	if err != nil {
		t.Fatal(err)
	}
	if sum != (Summary{Entries: 4, OmittedFields: 3}) {
		t.Errorf("summary = %+v", sum)
	}
	if !strings.Contains(buf.String(), "work/dev,gitlab,,\"=HYPERLINK(\"\"http://evil\"\")\",,work,\r\n") {
		t.Errorf("csv:\n%s", buf.String())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	d := testData(t)
	f, _ := ParseFilter("work", nil)
	var buf bytes.Buffer
	sum, err := Export(&buf, d, Options{Format: FormatJSON, Filter: f, Now: t1.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Entries != 2 || sum.Encrypted || sum.OmittedFields != 0 {
		t.Errorf("summary = %+v", sum)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["deleted"]; ok {
		t.Error(`export has "deleted"`)
	}
	if got := string(raw["exported_at"]); got != `"2026-11-15T13:00:00Z"` {
		t.Errorf("exported_at = %s", got)
	}
	for _, k := range []string{"format", "version", "vault_id", "revision", "saved_at", "future_top"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("export lacks %q", k)
		}
	}
	for _, s := range []string{`"future_entry": "kept"`, `"future_field": true`} {
		if !bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Errorf("unknown key %s lost", s)
		}
	}

	back, err := model.Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("model.Decode of the export: %v", err)
	}
	if back.VaultID != d.VaultID || back.Revision != d.Revision || !back.SavedAt.Equal(d.SavedAt) {
		t.Errorf("header changed: %+v", back)
	}
	if len(back.Deleted) != 0 {
		t.Errorf("tombstones: %v", back.Deleted)
	}
	want := f.Select(d)
	if len(back.Entries) != len(want) {
		t.Fatalf("%d entries, want %d", len(back.Entries), len(want))
	}
	for i := range want {
		if !back.Entries[i].Equal(want[i]) {
			t.Errorf("entry %d differs:\n%+v\n%+v", i, back.Entries[i], want[i])
		}
	}
}

// jsonShape describes a JSON value's structure: an object's keys with
// their shapes, an array's element shape (the union over its elements),
// or the kind of a scalar. null is compatible with any kind.
func jsonShape(v any) any {
	switch v := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, x := range v {
			m[k] = jsonShape(x)
		}
		return m
	case []any:
		var elem any
		for _, x := range v {
			elem = mergeShape(elem, jsonShape(x))
		}
		return []any{elem}
	case nil:
		return "null"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	}
	return "?"
}

func mergeShape(a, b any) any {
	if a == nil || a == "null" {
		return b
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		out := map[string]any{}
		for k, v := range am {
			out[k] = v
		}
		for k, v := range bm {
			out[k] = mergeShape(out[k], v)
		}
		return out
	}
	return a
}

// checkShape reports every key or kind in got that the fixture doesn't
// have, and every fixture key that got lacks, except the optional ones.
func checkShape(t *testing.T, where string, got, want any, optional map[string]bool) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: got %v, want an object", where, got)
			return
		}
		for k, gv := range g {
			wv, ok := w[k]
			if !ok {
				t.Errorf("%s: unexpected key %q", where, k)
				continue
			}
			checkShape(t, where+"."+k, gv, wv, optional)
		}
		for k := range w {
			if _, ok := g[k]; !ok && !optional[where+"."+k] {
				t.Errorf("%s: missing key %q", where, k)
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			t.Errorf("%s: got %v, want an array", where, got)
			return
		}
		if g[0] != nil && w[0] != nil {
			checkShape(t, where+"[]", g[0], w[0], optional)
		}
	default:
		if got != "null" && want != "null" && got != want {
			t.Errorf("%s: got %v, want %v", where, got, want)
		}
	}
}

func TestBitwardenShape(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "bitwarden_export.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Export(&buf, testData(t), Options{Format: FormatBitwarden}); err != nil {
		t.Fatal(err)
	}
	var got any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Bitwarden leaves out "fields" and "login.uris" when there are none.
	optional := map[string]bool{"$.items[].fields": true, "$.items[].login.uris": true}
	checkShape(t, "$", jsonShape(got), jsonShape(want), optional)
}

func TestBitwardenMapping(t *testing.T) {
	d := testData(t)
	var buf bytes.Buffer
	if _, err := Export(&buf, d, Options{Format: FormatBitwarden}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Encrypted *bool `json:"encrypted"`
		Folders   []struct{ ID, Name string }
		Items     []struct {
			ID, Name, RevisionDate, CreationDate string
			FolderID                             *string
			Type                                 int
			Notes                                *string
			Fields                               []struct {
				Name, Value string
				Type        int
			}
			Login struct {
				URIs []struct {
					URI   string
					Match *int
				}
				Username, Password, TOTP *string
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Encrypted == nil || *out.Encrypted {
		t.Error(`"encrypted" must be false`)
	}
	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	folders := map[string]string{} // id → name
	var names []string
	for _, f := range out.Folders {
		if !uuidRE.MatchString(f.ID) {
			t.Errorf("folder id %q", f.ID)
		}
		folders[f.ID] = f.Name
		names = append(names, f.Name)
	}
	if want := []string{"work", "work/dev", "workshop"}; !slices.Equal(names, want) {
		t.Errorf("folders = %q, want %q", names, want)
	}
	if len(out.Items) != 4 {
		t.Fatalf("%d items", len(out.Items))
	}
	byName := map[string]int{}
	for i, it := range out.Items {
		byName[it.Name] = i
		if it.Type != 1 || !uuidRE.MatchString(it.ID) {
			t.Errorf("item %q: type %d id %q", it.Name, it.Type, it.ID)
		}
	}

	gh := out.Items[byName["github"]]
	if gh.FolderID == nil || folders[*gh.FolderID] != "work" {
		t.Errorf("github folder = %v", gh.FolderID)
	}
	if gh.Login.Username == nil || *gh.Login.Username != "arsenii" ||
		gh.Login.Password == nil || *gh.Login.Password != "s3cr3t-P@ss" ||
		len(gh.Login.URIs) != 1 || gh.Login.URIs[0].URI != "https://github.com" || gh.Login.URIs[0].Match != nil {
		t.Errorf("github login = %+v", gh.Login)
	}
	if gh.Login.TOTP == nil || *gh.Login.TOTP != "otpauth://totp/GitHub:arsenii?secret=JBSWY3DPEHPK3PXP" {
		t.Errorf("github totp = %v", gh.Login.TOTP)
	}
	if gh.Notes == nil || *gh.Notes != "Free-form notes.\nRecovery codes." {
		t.Errorf("github notes = %v", gh.Notes)
	}
	if gh.CreationDate != "2026-11-01T09:00:00.000Z" || gh.RevisionDate != "2026-11-15T12:00:00.000Z" {
		t.Errorf("github dates = %s, %s", gh.CreationDate, gh.RevisionDate)
	}
	type field = struct {
		Name, Value string
		Type        int
	}
	wantFields := []field{
		{"recovery-email", "me@example.com", 0},
		{"pin", "otpauth://hotp/x?secret=AAAA", 1}, // otpauth:// value: hidden
		{"tags", "work, dev, 2fa", 0},
	}
	if !reflect.DeepEqual(gh.Fields, wantFields) {
		t.Errorf("github fields = %+v", gh.Fields)
	}

	gl := out.Items[byName["gitlab"]]
	if gl.FolderID == nil || folders[*gl.FolderID] != "work/dev" {
		t.Errorf("gitlab folder = %v", gl.FolderID)
	}
	if gl.Login.Username != nil || gl.Login.TOTP != nil || gl.Notes != nil || gl.Login.URIs != nil {
		t.Errorf("gitlab empty values must be null: %+v", gl)
	}
	if r := out.Items[byName["router"]]; r.FolderID != nil || r.Fields != nil {
		t.Errorf("router = %+v", r)
	}

	// Ids are deterministic.
	var again bytes.Buffer
	if _, err := Export(&again, d, Options{Format: FormatBitwarden}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Error("two exports differ")
	}
	if gh.ID != derivedUUID("item", "8d1e7a90-0000-4000-8000-000000000001") {
		t.Errorf("item id %s is not derived from the entry id", gh.ID)
	}
}

func TestBitwardenOTPWithoutOTPKey(t *testing.T) {
	e := entry("x", "pw", "", "", "")
	e.Fields = []model.Field{{Key: "note", Value: "plain"}, {Key: "totp-uri", Value: "OTPAUTH://totp/x?secret=B"}}
	var buf bytes.Buffer
	if err := WriteBitwarden(&buf, "v", []model.Entry{e}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, `"totp": "OTPAUTH://totp/x?secret=B"`) || strings.Contains(s, `"totp-uri"`) {
		t.Errorf("otpauth value not used as totp:\n%s", s)
	}
}

func decryptArmored(t *testing.T, ct []byte, id age.Identity) []byte {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(ct)), id)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestAgeExport(t *testing.T) {
	d := testData(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []Format{FormatCSV, FormatJSON, FormatBitwarden} {
		var plain, enc bytes.Buffer
		now := t1
		if _, err := Export(&plain, d, Options{Format: format, Now: now}); err != nil {
			t.Fatal(err)
		}
		sum, err := Export(&enc, d, Options{Format: format, Now: now, Recipient: " " + id.Recipient().String() + "\n"})
		if err != nil {
			t.Fatal(err)
		}
		if !sum.Encrypted || sum.Entries != 4 {
			t.Errorf("%s: summary %+v", format, sum)
		}
		if !strings.HasPrefix(enc.String(), "-----BEGIN AGE ENCRYPTED FILE-----\n") ||
			!strings.HasSuffix(enc.String(), "-----END AGE ENCRYPTED FILE-----\n") {
			t.Errorf("%s: not ASCII-armored:\n%s", format, enc.String())
		}
		if bytes.Contains(enc.Bytes(), []byte("s3cr3t")) || bytes.Contains(enc.Bytes(), []byte(id.Recipient().String())) {
			t.Errorf("%s: plaintext or recipient in the ciphertext", format)
		}
		if got := decryptArmored(t, enc.Bytes(), id); !bytes.Equal(got, plain.Bytes()) {
			t.Errorf("%s: decrypted output differs from the plaintext export", format)
		}
	}
}

func TestAgeExportHybrid(t *testing.T) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if _, err := Export(&enc, testData(t), Options{Format: FormatJSON, Recipient: id.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := model.Decode(decryptArmored(t, enc.Bytes(), id)); err != nil {
		t.Fatal(err)
	}
}

// TestAgeExportWithAgeCLI decrypts an export with the standard age tool.
func TestAgeExportWithAgeCLI(t *testing.T) {
	ageBin, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bin", "age"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ageBin); err != nil {
		t.Skip("no age binary in .tools/bin")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var plain, enc bytes.Buffer
	if _, err := Export(&plain, testData(t), Options{Format: FormatCSV}); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(&enc, testData(t), Options{Format: FormatCSV, Recipient: id.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Output(t.Context(), exec.Command{
		Name: ageBin, Args: []string{"-d", "-i", keyFile},
		Stdin: bytes.NewReader(enc.Bytes()), Env: []string{"HOME=" + dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain.Bytes()) {
		t.Error("age -d output differs from the plaintext export")
	}
}

func TestInvalidRecipient(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	secret := id.String()
	cases := []struct{ in, want string }{
		{"age1notvalid", `invalid age recipient "age1notvalid"`},
		{"age1pq1zzz", `invalid age recipient "age1pq1zzz"`},
		{secret, "secret key"},
		{"ssh-ed25519 AAAA", "not an age recipient"},
		{"  ", "empty"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		_, err := Export(&buf, testData(t), Options{Format: FormatJSON, Recipient: c.in})
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "--age: ") {
			t.Errorf("%q: error = %v", c.in, err)
		}
		if err != nil && strings.Contains(err.Error(), secret[15:]) {
			t.Error("the secret key is echoed in the error")
		}
		if buf.Len() != 0 {
			t.Errorf("%q: %d bytes written on error", c.in, buf.Len())
		}
	}
}

func TestExportErrorsWriteNothing(t *testing.T) {
	d := testData(t)
	for _, o := range []Options{
		{Format: "xml"},
		{Format: FormatJSON, SpreadsheetSafe: true},
		{Format: FormatBitwarden, SpreadsheetSafe: true},
	} {
		var buf bytes.Buffer
		if _, err := Export(&buf, d, o); err == nil || buf.Len() != 0 {
			t.Errorf("%+v: err %v, %d bytes", o, err, buf.Len())
		}
	}
	if _, err := Export(io.Discard, d, Options{Format: FormatJSON, SpreadsheetSafe: true}); !errors.Is(err, ErrSpreadsheetSafe) {
		t.Errorf("error = %v", err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestExportWriteError(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for _, o := range []Options{
		{Format: FormatCSV},
		{Format: FormatJSON},
		{Format: FormatBitwarden},
		{Format: FormatJSON, Recipient: id.Recipient().String()},
	} {
		if _, err := Export(failWriter{}, testData(t), o); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Errorf("%s: error = %v", o.Format, err)
		}
	}
}

func TestEmptyExport(t *testing.T) {
	d := model.NewData()
	for _, format := range []Format{FormatCSV, FormatJSON, FormatBitwarden} {
		var buf bytes.Buffer
		sum, err := Export(&buf, d, Options{Format: format})
		if err != nil || sum.Entries != 0 {
			t.Fatalf("%s: %+v %v", format, sum, err)
		}
		switch format {
		case FormatCSV:
			if buf.String() != "folder,name,username,password,url,tags,notes\r\n" {
				t.Errorf("csv = %q", buf.String())
			}
		case FormatJSON:
			if !strings.Contains(buf.String(), `"entries": []`) {
				t.Errorf("json = %s", buf.String())
			}
		case FormatBitwarden:
			if !strings.Contains(buf.String(), `"folders": []`) || !strings.Contains(buf.String(), `"items": []`) {
				t.Errorf("bitwarden = %s", buf.String())
			}
		}
	}
}
