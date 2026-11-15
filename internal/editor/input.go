package editor

import (
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"passh/internal/sanitize"
)

// The form's own small text widgets. Bubbles' textinput and textarea are
// not used: they drop control characters from values given to them (an
// imported password would change just by opening the form), render values
// without S4 escaping, and their ctrl+v reads the system clipboard through
// tools started outside internal/exec (S8).
//
// Values are rune slices, kept exactly. Each rune is displayed through
// sanitize.Line, so a control character shows as \x1b and the like, and the
// cursor moves over it as one unit.

var styleCursor = lipgloss.NewStyle().Reverse(true)

// cell returns how rune r is displayed and its width in terminal cells.
func cell(r rune) (string, int) {
	s := sanitize.Line(string(r))
	return s, ansi.StringWidth(s)
}

func cellWidth(r rune) int {
	_, w := cell(r)
	return w
}

func widthOf(rs []rune) int {
	w := 0
	for _, r := range rs {
		w += cellWidth(r)
	}
	return w
}

// renderCells renders rs with the cursor (a reversed cell) before index
// cur; cur == len(rs) puts the cursor after the text, and cur < 0 shows
// none.
func renderCells(rs []rune, cur int) string {
	var b strings.Builder
	for i, r := range rs {
		s, _ := cell(r)
		if i == cur {
			if s == "" {
				s = " "
			}
			s = styleCursor.Render(s)
		}
		b.WriteString(s)
	}
	if cur == len(rs) {
		b.WriteString(styleCursor.Render(" "))
	}
	return b.String()
}

// lineInput edits one line of text.
type lineInput struct {
	value []rune
	pos   int // cursor, 0..len(value)
	off   int // first visible rune
}

func newLineInput(s string) lineInput {
	v := []rune(s)
	return lineInput{value: v, pos: len(v)}
}

func (in *lineInput) String() string { return string(in.value) }

func (in *lineInput) insert(rs []rune) {
	v := make([]rune, 0, len(in.value)+len(rs))
	v = append(v, in.value[:in.pos]...)
	v = append(v, rs...)
	v = append(v, in.value[in.pos:]...)
	in.value = v
	in.pos += len(rs)
}

func (in *lineInput) remove(from, to int) {
	in.value = append(in.value[:from:from], in.value[to:]...)
	in.pos = from
}

// key applies an editing or movement key and reports whether it was one.
// masked limits editing to the end of the value, so that nothing about a
// hidden password's content shows through word movements.
func (in *lineInput) key(k string, masked bool) bool {
	if masked {
		in.pos = len(in.value)
		switch k {
		case "backspace", "ctrl+h":
			if in.pos > 0 {
				in.remove(in.pos-1, in.pos)
			}
		case "ctrl+u", "ctrl+w", "alt+backspace", "ctrl+backspace":
			in.remove(0, len(in.value))
		case "left", "right", "home", "end", "ctrl+a", "ctrl+b", "ctrl+e", "ctrl+f",
			"alt+left", "alt+right", "ctrl+left", "ctrl+right", "alt+b", "alt+f",
			"delete", "ctrl+d", "ctrl+k", "alt+d", "alt+delete", "ctrl+delete":
			// No movement or deletion in a value you can't see.
		default:
			return false
		}
		return true
	}
	switch k {
	case "left", "ctrl+b":
		in.pos = max(in.pos-1, 0)
	case "right", "ctrl+f":
		in.pos = min(in.pos+1, len(in.value))
	case "home", "ctrl+a":
		in.pos = 0
	case "end", "ctrl+e":
		in.pos = len(in.value)
	case "alt+left", "ctrl+left", "alt+b":
		in.pos = wordLeft(in.value, in.pos)
	case "alt+right", "ctrl+right", "alt+f":
		in.pos = wordRight(in.value, in.pos)
	case "backspace", "ctrl+h":
		if in.pos > 0 {
			in.remove(in.pos-1, in.pos)
		}
	case "delete", "ctrl+d":
		if in.pos < len(in.value) {
			in.remove(in.pos, in.pos+1)
		}
	case "ctrl+w", "alt+backspace", "ctrl+backspace":
		in.remove(wordLeft(in.value, in.pos), in.pos)
	case "alt+d", "alt+delete", "ctrl+delete":
		p := in.pos
		in.remove(p, wordRight(in.value, p))
	case "ctrl+u":
		in.remove(0, in.pos)
	case "ctrl+k":
		in.remove(in.pos, len(in.value))
	default:
		return false
	}
	return true
}

// wordLeft returns the start of the word before pos.
func wordLeft(v []rune, pos int) int {
	for pos > 0 && unicode.IsSpace(v[pos-1]) {
		pos--
	}
	for pos > 0 && !unicode.IsSpace(v[pos-1]) {
		pos--
	}
	return pos
}

// wordRight returns the end of the word after pos.
func wordRight(v []rune, pos int) int {
	for pos < len(v) && unicode.IsSpace(v[pos]) {
		pos++
	}
	for pos < len(v) && !unicode.IsSpace(v[pos]) {
		pos++
	}
	return pos
}

// fitOffset returns the first visible rune for a window width cells wide
// that shows the cursor (one cell, after the text at the end), starting
// from the previous offset off.
func fitOffset(v []rune, pos, off, width int) int {
	off = min(max(off, 0), pos)
	cur := 1 // the cursor's cell when it is after the text
	if pos < len(v) {
		cur = cellWidth(v[pos])
	}
	for off < pos && widthOf(v[off:pos])+cur > width {
		off++
	}
	// Use free room on the right to show more on the left.
	tail := widthOf(v[off:])
	if pos == len(v) {
		tail++
	}
	for off > 0 && tail+cellWidth(v[off-1]) <= width {
		off--
		tail += cellWidth(v[off])
	}
	return off
}

// scroll keeps the cursor visible in width cells.
func (in *lineInput) scroll(width int) {
	in.off = fitOffset(in.value, in.pos, in.off, width)
}

// view renders the visible part of the value, at most width cells: with
// the cursor around it when focused, else from the start, with "…" when it
// is cut.
func (in *lineInput) view(width int, focused bool) string {
	if !focused {
		if widthOf(in.value) <= width {
			return renderCells(in.value, -1)
		}
		end, w := 0, 0
		for end < len(in.value) && w+cellWidth(in.value[end]) <= width-1 {
			w += cellWidth(in.value[end])
			end++
		}
		return renderCells(in.value[:end], -1) + "…"
	}
	off := fitOffset(in.value, in.pos, in.off, width)
	end, w := off, 0
	for end < len(in.value) {
		cw := cellWidth(in.value[end])
		if w+cw > width {
			break
		}
		w += cw
		end++
	}
	cur := in.pos - off
	if in.pos == len(in.value) && w+1 > width {
		cur = -1 // no room; fitOffset makes this rare
	}
	return renderCells(in.value[off:end], cur)
}

// textArea edits multi-line text (the notes), soft-wrapped to the width.
type textArea struct {
	lines [][]rune
	row   int // cursor line
	col   int // cursor rune within the line
	top   int // first visible visual row
	goalX int // wanted column for up/down; -1 when unset
}

func newTextArea(s string) textArea {
	var lines [][]rune
	for l := range strings.SplitSeq(s, "\n") {
		lines = append(lines, []rune(l))
	}
	return textArea{lines: lines, goalX: -1}
}

func (ta *textArea) String() string {
	parts := make([]string, len(ta.lines))
	for i, l := range ta.lines {
		parts[i] = string(l)
	}
	return strings.Join(parts, "\n")
}

// vrow is one visual row: runes [start, end) of a line.
type vrow struct{ line, start, end int }

// layout wraps the lines into rows of at most width-1 cells, leaving one
// cell for a cursor at the end of a row. Rows break after a space when
// there is one in the row, else anywhere.
func (ta *textArea) layout(width int) []vrow {
	tw := max(width-1, 2)
	var rows []vrow
	for i, l := range ta.lines {
		start, w, brk := 0, 0, -1 // brk: just after the row's last space
		for j, r := range l {
			cw := cellWidth(r)
			if w+cw > tw && j > start {
				end := j
				if brk > start {
					end = brk
				}
				rows = append(rows, vrow{i, start, end})
				start, w, brk = end, widthOf(l[end:j]), -1
			}
			w += cw
			if r == ' ' {
				brk = j + 1
			}
		}
		rows = append(rows, vrow{i, start, len(l)})
	}
	return rows
}

// cursorRow returns the index of the row that shows the cursor.
func (ta *textArea) cursorRow(rows []vrow) int {
	for i, r := range rows {
		if r.line != ta.row {
			continue
		}
		last := i+1 == len(rows) || rows[i+1].line != r.line
		if ta.col < r.end || (ta.col == r.end && last) {
			return i
		}
	}
	return max(len(rows)-1, 0)
}

// vertical moves the cursor delta visual rows, keeping its column, and
// reports false when there is no such row.
func (ta *textArea) vertical(delta, width int) bool {
	rows := ta.layout(width)
	i := ta.cursorRow(rows)
	if ta.goalX < 0 {
		ta.goalX = widthOf(ta.lines[ta.row][rows[i].start:ta.col])
	}
	j := i + delta
	if j < 0 || j >= len(rows) {
		return false
	}
	r := rows[j]
	line := ta.lines[r.line]
	limit := r.end
	if last := j+1 == len(rows) || rows[j+1].line != r.line; !last && r.end > r.start {
		limit = r.end - 1 // the end of a wrapped row is the next row's start
	}
	col, x := r.start, 0
	for col < limit {
		cw := cellWidth(line[col])
		if x+cw > ta.goalX {
			break
		}
		x += cw
		col++
	}
	ta.row, ta.col = r.line, col
	return true
}

// page moves the cursor by delta visual rows, as far as possible.
func (ta *textArea) page(delta, width int) {
	step := 1
	if delta < 0 {
		step, delta = -1, -delta
	}
	for range delta {
		if !ta.vertical(step, width) {
			break
		}
	}
}

func (ta *textArea) insert(rs []rune) {
	ta.goalX = -1
	for i, part := range strings.Split(string(rs), "\n") {
		if i > 0 {
			ta.newline()
		}
		p := []rune(part)
		l := ta.lines[ta.row]
		n := make([]rune, 0, len(l)+len(p))
		n = append(n, l[:ta.col]...)
		n = append(n, p...)
		n = append(n, l[ta.col:]...)
		ta.lines[ta.row] = n
		ta.col += len(p)
	}
}

func (ta *textArea) newline() {
	l := ta.lines[ta.row]
	head := append([]rune(nil), l[:ta.col]...)
	tail := append([]rune(nil), l[ta.col:]...)
	ta.lines[ta.row] = head
	ta.lines = append(ta.lines[:ta.row+1], append([][]rune{tail}, ta.lines[ta.row+1:]...)...)
	ta.row++
	ta.col = 0
}

// joinNext appends the next line to the cursor line.
func (ta *textArea) joinNext() {
	if ta.row+1 >= len(ta.lines) {
		return
	}
	ta.lines[ta.row] = append(ta.lines[ta.row], ta.lines[ta.row+1]...)
	ta.lines = append(ta.lines[:ta.row+1], ta.lines[ta.row+2:]...)
}

func (ta *textArea) removeInLine(from, to int) {
	l := ta.lines[ta.row]
	ta.lines[ta.row] = append(l[:from:from], l[to:]...)
	ta.col = from
}

// key applies an editing or movement key other than up and down, and
// reports whether it was one.
func (ta *textArea) key(k string, width, height int) bool {
	l := ta.lines[ta.row]
	keepGoal := false
	switch k {
	case "enter", "ctrl+j", "ctrl+m":
		ta.newline()
	case "left", "ctrl+b":
		if ta.col > 0 {
			ta.col--
		} else if ta.row > 0 {
			ta.row--
			ta.col = len(ta.lines[ta.row])
		}
	case "right", "ctrl+f":
		if ta.col < len(l) {
			ta.col++
		} else if ta.row+1 < len(ta.lines) {
			ta.row++
			ta.col = 0
		}
	case "home", "ctrl+a":
		ta.col = 0
	case "end", "ctrl+e":
		ta.col = len(l)
	case "alt+left", "ctrl+left", "alt+b":
		ta.col = wordLeft(l, ta.col)
	case "alt+right", "ctrl+right", "alt+f":
		ta.col = wordRight(l, ta.col)
	case "backspace", "ctrl+h":
		switch {
		case ta.col > 0:
			ta.removeInLine(ta.col-1, ta.col)
		case ta.row > 0:
			ta.row--
			ta.col = len(ta.lines[ta.row])
			ta.joinNext()
		}
	case "delete", "ctrl+d":
		if ta.col < len(l) {
			ta.removeInLine(ta.col, ta.col+1)
		} else {
			ta.joinNext()
		}
	case "ctrl+w", "alt+backspace", "ctrl+backspace":
		if ta.col == 0 {
			return ta.key("backspace", width, height)
		}
		ta.removeInLine(wordLeft(l, ta.col), ta.col)
	case "alt+d", "alt+delete", "ctrl+delete":
		if ta.col == len(l) {
			ta.joinNext()
		} else {
			c := ta.col
			ta.removeInLine(c, wordRight(l, c))
		}
	case "ctrl+u":
		ta.removeInLine(0, ta.col)
	case "ctrl+k":
		if ta.col == len(l) {
			ta.joinNext()
		} else {
			ta.removeInLine(ta.col, len(l))
		}
	case "pgup":
		ta.page(-max(height-1, 1), width)
		keepGoal = true
	case "pgdown":
		ta.page(max(height-1, 1), width)
		keepGoal = true
	default:
		return false
	}
	if !keepGoal {
		ta.goalX = -1
	}
	return true
}

// fitTop returns the first visible row so that row cur shows in height
// rows, starting from the previous top.
func fitTop(n, cur, top, height int) int {
	height = max(height, 1)
	if cur < top {
		top = cur
	}
	if cur >= top+height {
		top = cur - height + 1
	}
	return max(min(top, n-height), 0)
}

// scroll keeps the cursor visible.
func (ta *textArea) scroll(width, height int) {
	rows := ta.layout(width)
	ta.top = fitTop(len(rows), ta.cursorRow(rows), ta.top, height)
}

// view renders exactly height rows (some may be empty) of at most width
// cells.
func (ta *textArea) view(width, height int, focused bool) []string {
	rows := ta.layout(width)
	ci := ta.cursorRow(rows)
	top := fitTop(len(rows), ci, ta.top, height)
	out := make([]string, 0, height)
	for i := top; i < len(rows) && len(out) < height; i++ {
		r := rows[i]
		cur := -1
		if focused && i == ci {
			cur = ta.col - r.start
		}
		out = append(out, renderCells(ta.lines[r.line][r.start:r.end], cur))
	}
	for len(out) < height {
		out = append(out, "")
	}
	return out
}
