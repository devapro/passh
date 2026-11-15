package print

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// TXTPageLines is the length of a plain text page, header and footer
// included. 60 lines fit A4 and Letter at the usual 6 lines per inch with
// the printer's margins.
const TXTPageLines = 60

// WriteTXT writes doc as UTF-8 text in pages of TXTPageLines lines of at
// most Columns columns, separated by a form feed. Every page has the
// CONFIDENTIAL header with the print date and page number, and the legend in
// its footer. The commands of the recovery sheet are the only lines longer
// than Columns: they are kept whole so they can be typed exactly. The QR
// code of the recovery key is only on the PDF and the print page.
func WriteTXT(w io.Writer, doc Document) error {
	legend := doc.Legend()
	const headerLines = 3 // header, rule, blank
	footerLines := 2 + len(legend)
	body := TXTPageLines - headerLines - footerLines
	pages := paginate(doc.blocks(targetTXT), float64(body), txtHeight)

	bw := bufio.NewWriter(w)
	for i, rows := range pages {
		if i > 0 {
			bw.WriteString("\f")
		}
		left := Confidential + " · " + doc.Title()
		right := FormatDate(doc.Date()) + " · page " + strconv.Itoa(i+1) + " of " + strconv.Itoa(len(pages))
		gap := max(1, Columns-displayWidth(left)-displayWidth(right))
		lines := []string{left + strings.Repeat(" ", gap) + right, strings.Repeat("=", Columns), ""}
		for _, r := range rows {
			lines = append(lines, txtLines(r)...)
		}
		for len(lines) < headerLines+body {
			lines = append(lines, "")
		}
		lines = append(lines, "", strings.Repeat("-", Columns))
		lines = append(lines, legend...)
		for _, l := range lines {
			bw.WriteString(l)
			bw.WriteString("\n")
		}
	}
	return bw.Flush()
}

// txtLines renders a row as text lines.
func txtLines(r Row) []string {
	switch r.Kind {
	case RowFolder:
		return []string{r.Text, strings.Repeat("=", displayWidth(r.Text))}
	case RowHeading:
		return []string{r.Text, strings.Repeat("-", displayWidth(r.Text))}
	case RowValue:
		line := r.Prefix + r.Text
		if r.Text == "" {
			line = strings.TrimRight(r.Prefix, " ") // a label alone
		}
		if r.Marks != "" {
			return []string{line, r.Marks}
		}
		return []string{line}
	case RowQR:
		return nil
	case RowSpace:
		return []string{""}
	}
	return []string{r.Text}
}

func txtHeight(r Row) float64 { return float64(len(txtLines(r))) }

// displayWidth is the width of laid-out text in columns.
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		if !zeroWidth(r) {
			n += runeWidth(r)
		}
	}
	return n
}
