package print

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// cell is one unbreakable unit of printed text: a character (with any
// combining marks that follow it) or an escape such as \u200b.
type cell struct {
	s    string // what is printed
	w    int    // width in columns
	mark byte   // ambiguity code, 0 for none
}

// markOf returns the ambiguity code for r: D for a digit that looks like a
// letter, U and L for letters that look like digits or each other, S for a
// space when spaces are marked.
func markOf(r rune, spaces bool) byte {
	switch r {
	case '0', '1':
		return 'D'
	case 'O', 'I':
		return 'U'
	case 'l':
		return 'L'
	case ' ':
		if spaces {
			return 'S'
		}
	}
	return 0
}

// escapeRune writes r as \uXXXX (or \UXXXXXXXX above U+FFFF), the notation
// of internal/sanitize.
func escapeRune(r rune) string {
	if r > 0xffff {
		return fmt.Sprintf(`\U%08x`, r)
	}
	return fmt.Sprintf(`\u%04x`, r)
}

// invisible reports whether r would not show on paper, or would show as
// something else: format characters (zero-width space and joiners, soft
// hyphen, bidi marks), spaces other than U+0020, line and paragraph
// separators, private-use and unassigned code points.
func invisible(r rune) bool {
	switch {
	case r == ' ':
		return false
	case unicode.In(r, unicode.Cf, unicode.Zs, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cc):
		return true
	}
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// zeroWidth reports whether r combines with the character before it.
func zeroWidth(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Me)
}

// runeWidth is the number of columns r takes in a monospaced layout.
func runeWidth(r rune) int {
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}

// cells splits already sanitized text into cells for target t. With
// markSpaces, spaces get the S mark.
func (t target) cells(s string, markSpaces bool) []cell {
	out := make([]cell, 0, len(s))
	for _, r := range s {
		switch {
		case invisible(r):
			e := escapeRune(r)
			out = append(out, cell{s: e, w: len(e)})
		case zeroWidth(r) && len(out) > 0 && out[len(out)-1].mark == 0 && !strings.HasPrefix(out[len(out)-1].s, `\`):
			out[len(out)-1].s += string(r)
		case zeroWidth(r):
			// Nothing to combine with, or a marked or escaped character
			// that must stay recognizable: show the mark on its own.
			e := escapeRune(r)
			out = append(out, cell{s: e, w: len(e)})
		default:
			out = append(out, cell{s: string(r), w: runeWidth(r), mark: markOf(r, markSpaces)})
		}
	}
	return out
}

// text returns s fitted for target t, without marks: what cells would
// print, joined.
func (t target) text(s string) string {
	return joinCells(t.cells(s, false))
}

// textWidth returns the width of s in columns for target t.
func (t target) textWidth(s string) int {
	return cellsWidth(t.cells(s, false))
}

func joinCells(cs []cell) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(c.s)
	}
	return b.String()
}

func cellsWidth(cs []cell) int {
	n := 0
	for _, c := range cs {
		n += c.w
	}
	return n
}

// marksOf returns the marks line for cs: each cell's code (or a blank),
// padded to the cell's width, with trailing blanks removed. It is "" when no
// cell is marked.
func marksOf(cs []cell) string {
	var b strings.Builder
	marked := false
	for _, c := range cs {
		if c.mark != 0 {
			b.WriteByte(c.mark)
			b.WriteString(strings.Repeat(" ", c.w-1))
			marked = true
		} else {
			b.WriteString(strings.Repeat(" ", c.w))
		}
	}
	if !marked {
		return ""
	}
	return strings.TrimRight(b.String(), " ")
}

// wrapCells breaks cs into lines of at most w columns, between cells. A cell
// wider than w gets a line of its own. It always returns at least one line.
func wrapCells(cs []cell, w int) [][]cell {
	var lines [][]cell
	var cur []cell
	n := 0
	for _, c := range cs {
		if n+c.w > w && len(cur) > 0 {
			lines = append(lines, cur)
			cur, n = nil, 0
		}
		cur = append(cur, c)
		n += c.w
	}
	return append(lines, cur)
}

// wrapProse breaks text into lines of at most w columns, at spaces where it
// can; a word longer than a line is broken. Runs of spaces collapse. The text
// must already be sanitized.
func (t target) wrapProse(text string, w int) []string {
	var lines []string
	var cur []cell
	flush := func() {
		lines = append(lines, joinCells(cur))
		cur = nil
	}
	for _, word := range strings.Fields(text) {
		wc := t.cells(word, false)
		if len(cur) > 0 {
			if cellsWidth(cur)+1+cellsWidth(wc) <= w {
				cur = append(cur, cell{s: " ", w: 1})
			} else {
				flush()
			}
		}
		if len(cur) == 0 && cellsWidth(wc) > w {
			parts := wrapCells(wc, w)
			for _, p := range parts[:len(parts)-1] {
				lines = append(lines, joinCells(p))
			}
			wc = parts[len(parts)-1]
		}
		cur = append(cur, wc...)
	}
	if len(cur) > 0 || len(lines) == 0 {
		flush()
	}
	return lines
}

// proseRows wraps text into rows of kind k.
func (t target) proseRows(k RowKind, text string) []Row {
	var rows []Row
	for _, l := range t.wrapProse(text, Columns) {
		rows = append(rows, Row{Kind: k, Text: l})
	}
	return rows
}

// hardRows wraps text at Columns without looking for spaces (names and
// headings, which must stay exact).
func (t target) hardRows(k RowKind, text string, indent int) []Row {
	var rows []Row
	pad := strings.Repeat(" ", indent)
	for _, l := range wrapCells(t.cells(text, false), Columns-indent) {
		rows = append(rows, Row{Kind: k, Text: pad + joinCells(l)})
	}
	return rows
}

// expandTabs replaces each tab with spaces up to the next multiple of 4
// columns (notes keep their indentation readable).
func expandTabs(line string) string {
	if !strings.Contains(line, "\t") {
		return line
	}
	var b strings.Builder
	col := 0
	for _, r := range line {
		if r == '\t' {
			n := 4 - col%4
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		col++
	}
	return b.String()
}

// valueRows lays out one labelled value. lines are the value's lines (one
// for a single-line value), already sanitized. markSpaces marks spaces with
// S. A label too long for the label column gets a row of its own.
func (t target) valueRows(label string, lines []string, markSpaces bool) []Row {
	indent := strings.Repeat(" ", ValueIndent)
	blank := strings.Repeat(" ", ValuePrefixWidth)
	cont := indent + strings.Repeat(" ", LabelWidth-2) + Continuation + " "

	var rows []Row
	lab := t.text(label)
	first := blank
	if lw := t.textWidth(label); lw <= LabelWidth-1 {
		first = indent + lab + strings.Repeat(" ", LabelWidth-lw)
	} else {
		for _, l := range wrapCells(t.cells(label, false), Columns-ValueIndent) {
			rows = append(rows, Row{Kind: RowValue, Prefix: indent + joinCells(l)})
		}
	}
	for i, line := range lines {
		for j, chunk := range wrapCells(t.cells(line, markSpaces), ValueWidth) {
			prefix := blank
			switch {
			case i == 0 && j == 0:
				prefix = first
			case j > 0:
				prefix = cont
			}
			r := Row{Kind: RowValue, Prefix: prefix, Text: joinCells(chunk)}
			if m := marksOf(chunk); m != "" {
				r.Marks = blank + m
			}
			rows = append(rows, r)
		}
	}
	return rows
}

// paginate splits blocks into pages of at most capacity, measured by height.
//
//   - A block that fits on a page is not split; a block taller than a page
//     is split between rows, and its first row (an entry's name) is repeated
//     with " (continued)".
//   - A KeepWithNext block (a heading) moves to the next page with the start
//     of the following block.
//   - A page that starts inside a folder repeats the folder's heading with
//     " (continued)".
//   - RowSpace rows are dropped at the top of a page.
//
// It returns at least one page.
func paginate(blocks []Block, capacity float64, height func(Row) float64) [][]Row {
	var pages [][]Row
	var cur []Row
	used := 0.0
	var folder *Row // the heading of the folder being printed

	place := func(r Row) {
		if r.Kind == RowSpace && len(cur) == 0 {
			return
		}
		cur = append(cur, r)
		used += height(r)
	}
	newPage := func(next RowKind) {
		pages = append(pages, cur)
		cur, used = nil, 0
		if folder != nil && next != RowFolder {
			place(continued(*folder))
		}
	}
	rowsHeight := func(rows []Row) float64 {
		h := 0.0
		for _, r := range rows {
			h += height(r)
		}
		return h
	}
	firstKind := func(b Block) RowKind {
		for _, r := range b.Rows {
			if r.Kind != RowSpace {
				return r.Kind
			}
		}
		return RowSpace
	}

	for i, b := range blocks {
		need := rowsHeight(b.Rows)
		if b.KeepWithNext && i+1 < len(blocks) {
			// The next block moves to a new page whole if it fits on one;
			// otherwise it is split, and only its start must follow.
			next := blocks[i+1].Rows
			if h := rowsHeight(next); h <= capacity {
				need += h
			} else {
				need += rowsHeight(next[:min(len(next), 4)])
			}
		}
		if len(cur) > 0 && used+need > capacity && need <= capacity {
			newPage(firstKind(b))
		}
		var head *Row
		for j, r := range b.Rows {
			if r.Kind == RowSpace && len(cur) > 0 && used+height(r) > capacity {
				continue
			}
			if len(cur) > 0 && used+height(r) > capacity {
				newPage(r.Kind)
				if head != nil && j > 0 {
					place(continued(*head))
				}
			}
			if head == nil && (r.Kind == RowEntry || r.Kind == RowHeading) {
				h := r
				head = &h
			}
			if r.Kind == RowFolder {
				h := r
				folder = &h
			}
			place(r)
		}
	}
	if len(cur) > 0 || len(pages) == 0 {
		pages = append(pages, cur)
	}
	return pages
}

// continued returns a copy of a heading row marked as continued.
func continued(r Row) Row {
	r.Text += " (continued)"
	r.Marks = ""
	return r
}
