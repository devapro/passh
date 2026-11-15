package export

import (
	"bufio"
	"io"
	"slices"
	"strings"

	"github.com/devapro/passh/internal/model"
)

// csvHeader is the first row of a CSV export (§7.1).
var csvHeader = [...]string{"folder", "name", "username", "password", "url", "tags", "notes"}

// CSVHeader returns the first row of a CSV export (§7.1), a copy the caller
// may change.
func CSVHeader() []string { return slices.Clone(csvHeader[:]) }

// WriteCSV writes entries as CSV (RFC 4180): the CSVHeader row, then one
// row per entry. Records end in CRLF. A cell is quoted when it contains a
// comma, a double quote, CR or LF, or starts or ends with a space or tab;
// quotes inside are doubled. Values are written exactly, line breaks in
// notes included (encoding/csv would turn LF into CRLF inside a cell, so
// it isn't used).
//
// folder is the entry's folder ("" at the top level, "a/b" when nested),
// name its last path segment, and tags are joined with ", " (a tag can't
// contain a comma). CSV has no column for custom fields, so they are left
// out; Export counts them in Summary.OmittedFields.
//
// spreadsheetSafe prefixes "'" to every cell that starts with = + - @, tab
// or CR, so a spreadsheet doesn't run it as a formula. That changes values,
// passwords included.
func WriteCSV(w io.Writer, entries []model.Entry, spreadsheetSafe bool) error {
	bw := bufio.NewWriter(w)
	writeCSVRecord(bw, csvHeader[:], false)
	row := make([]string, len(csvHeader))
	for _, e := range entries {
		row[0] = e.Path.Folder()
		row[1] = e.Path.Name()
		row[2] = e.Username
		row[3] = e.Password
		row[4] = e.URL
		row[5] = strings.Join(e.Tags, ", ")
		row[6] = e.Notes
		writeCSVRecord(bw, row, spreadsheetSafe)
	}
	clear(row)
	return bw.Flush()
}

func writeCSVRecord(w *bufio.Writer, cells []string, spreadsheetSafe bool) {
	for i, c := range cells {
		if i > 0 {
			w.WriteByte(',')
		}
		if spreadsheetSafe && formulaLike(c) {
			c = "'" + c
		}
		if !csvNeedsQuotes(c) {
			w.WriteString(c)
			continue
		}
		w.WriteByte('"')
		w.WriteString(strings.ReplaceAll(c, `"`, `""`))
		w.WriteByte('"')
	}
	w.WriteString("\r\n")
}

// formulaLike reports whether a spreadsheet could read the cell as a
// formula (or, with a leading tab or CR, hide such a start).
func formulaLike(c string) bool {
	return c != "" && strings.IndexByte("=+-@\t\r", c[0]) >= 0
}

func csvNeedsQuotes(c string) bool {
	if c == "" {
		return false
	}
	if strings.ContainsAny(c, ",\"\r\n") {
		return true
	}
	first, last := c[0], c[len(c)-1]
	return first == ' ' || first == '\t' || last == ' ' || last == '\t'
}
