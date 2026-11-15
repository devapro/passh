package export

import (
	"bytes"
	"encoding/csv"
	"slices"
	"strings"
	"testing"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// FuzzWriteCSV (TEST-12, CLI-020): whatever an entry holds, the CSV export
// reads back with encoding/csv as the same cells: no value can add a column
// or a row. encoding/csv drops the CR of a CRLF inside a quoted cell, so
// the comparison does too. The seed corpus runs in every `go test`.
func FuzzWriteCSV(f *testing.F) {
	for _, seed := range [][5]string{
		{"work/github", "arsenii", "pw", "https://github.com", "notes"},
		{"top", "", "=SUM(A1)", "", ""},
		{"a/b/c", `quote " inside`, "comma, inside", " leading space", "line\nbreak\r\nand CRLF"},
		{"x", "\t tab", "@cmd", "+1", "-1"},
		{"x", "\r", "\"", ",", "\n"},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4], false)
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4], true)
	}
	f.Fuzz(func(t *testing.T, path, user, pass, url, notes string, safe bool) {
		p, err := paths.Parse(path)
		if err != nil {
			return
		}
		e := model.Entry{Path: p, Username: user, Password: pass, URL: url, Notes: notes, Tags: []string{"a", "b"}}
		var buf bytes.Buffer
		if err := WriteCSV(&buf, []model.Entry{e}, safe); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatalf("the export doesn't parse as CSV: %v\n%q", err, buf.String())
		}
		cell := func(s string) string {
			if safe && formulaLike(s) {
				s = "'" + s
			}
			return strings.ReplaceAll(s, "\r\n", "\n")
		}
		want := [][]string{
			CSVHeader(),
			{cell(p.Folder()), cell(p.Name()), cell(user), cell(pass), cell(url), cell("a, b"), cell(notes)},
		}
		if len(recs) != 2 || !slices.Equal(recs[0], want[0]) || !slices.Equal(recs[1], want[1]) {
			t.Errorf("read back %q, want %q", recs, want)
		}
	})
}
