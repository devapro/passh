package acceptance

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-runewidth"
)

// vt is a minimal terminal emulator: enough of VT100/xterm to rebuild the
// screen the TUI draws (cursor moves, erasing, scrolling regions), so the
// tests can match text on the screen rather than in the byte stream.
type vt struct {
	rows, cols  int
	cells       [][]rune // 0 = empty; -1 = right half of a wide rune
	r, c        int
	top, bottom int // scrolling region, inclusive
	savedR      int
	savedC      int
	pending     []byte // an incomplete escape sequence or UTF-8 rune
}

func newVT(rows, cols int) *vt {
	v := &vt{rows: rows, cols: cols, bottom: rows - 1}
	v.cells = make([][]rune, rows)
	for i := range v.cells {
		v.cells[i] = make([]rune, cols)
	}
	return v
}

func (v *vt) clamp() {
	v.r = min(max(v.r, 0), v.rows-1)
	v.c = min(max(v.c, 0), v.cols-1)
}

func (v *vt) blankRow() []rune { return make([]rune, v.cols) }

func (v *vt) scrollUp(n int) {
	for ; n > 0; n-- {
		copy(v.cells[v.top:v.bottom], v.cells[v.top+1:v.bottom+1])
		v.cells[v.bottom] = v.blankRow()
	}
}

func (v *vt) scrollDown(n int) {
	for ; n > 0; n-- {
		copy(v.cells[v.top+1:v.bottom+1], v.cells[v.top:v.bottom])
		v.cells[v.top] = v.blankRow()
	}
}

func (v *vt) lineFeed() {
	if v.r == v.bottom {
		v.scrollUp(1)
	} else if v.r < v.rows-1 {
		v.r++
	}
}

func (v *vt) put(ch rune) {
	w := runewidth.RuneWidth(ch)
	if w == 0 {
		return
	}
	if v.c+w > v.cols {
		v.c = 0
		v.lineFeed()
	}
	v.cells[v.r][v.c] = ch
	if w == 2 && v.c+1 < v.cols {
		v.cells[v.r][v.c+1] = -1
	}
	v.c += w
	if v.c >= v.cols {
		v.c = v.cols - 1 // pending wrap, approximated
	}
}

func (v *vt) erase(row, from, to int) {
	for i := max(from, 0); i < min(to, v.cols); i++ {
		v.cells[row][i] = 0
	}
}

// write feeds terminal output.
func (v *vt) write(b []byte) {
	data := append(v.pending, b...)
	v.pending = nil
	i := 0
	for i < len(data) {
		ch := data[i]
		switch {
		case ch == 0x1b:
			n := v.escape(data[i:])
			if n == 0 { // incomplete
				v.pending = append([]byte(nil), data[i:]...)
				return
			}
			i += n
			continue
		case ch == '\r':
			v.c = 0
		case ch == '\n', ch == 0x0b, ch == 0x0c:
			v.lineFeed()
		case ch == '\b':
			v.c = max(v.c-1, 0)
		case ch == '\t':
			v.c = min((v.c/8+1)*8, v.cols-1)
		case ch < 0x20 || ch == 0x7f:
		default:
			if !utf8.FullRune(data[i:]) {
				v.pending = append([]byte(nil), data[i:]...)
				return
			}
			r, size := utf8.DecodeRune(data[i:])
			if r >= 0x80 && r <= 0x9f {
				i += size
				continue // a C1 control: not drawn
			}
			v.put(r)
			i += size
			continue
		}
		i++
	}
}

// escape handles the sequence at the start of b and returns its length, or
// 0 if it is incomplete.
func (v *vt) escape(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	switch b[1] {
	case '[':
		return v.csi(b)
	case ']', 'P', '_', '^', 'X': // OSC, DCS, APC, PM, SOS: skipped
		for j := 2; j < len(b); j++ {
			if b[j] == 0x07 && b[1] == ']' {
				return j + 1
			}
			if b[j] == 0x1b && j+1 < len(b) && b[j+1] == '\\' {
				return j + 2
			}
		}
		return 0
	case '7':
		v.savedR, v.savedC = v.r, v.c
	case '8':
		v.r, v.c = v.savedR, v.savedC
	case 'M': // reverse index
		if v.r == v.top {
			v.scrollDown(1)
		} else {
			v.r = max(v.r-1, 0)
		}
	case 'D':
		v.lineFeed()
	case 'E':
		v.c = 0
		v.lineFeed()
	case '(', ')', '*', '+', '#', ' ', '%':
		if len(b) < 3 {
			return 0
		}
		return 3
	}
	return 2
}

func (v *vt) csi(b []byte) int {
	j := 2
	for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
		j++
	}
	if j >= len(b) {
		return 0
	}
	final := b[j]
	params := string(b[2:j])
	priv := len(params) > 0 && strings.ContainsRune("?<>=", rune(params[0]))
	if priv {
		params = params[1:]
	}
	if k := strings.IndexAny(params, " !\"#$%&'()*+,-./"); k >= 0 {
		// An intermediate byte (e.g. DECRQM "$p"): not drawing.
		return j + 1
	}
	var ps []int
	for _, f := range strings.Split(params, ";") {
		n, _ := strconv.Atoi(strings.Split(f, ":")[0])
		ps = append(ps, n)
	}
	p := func(i, def int) int {
		if i < len(ps) && ps[i] > 0 {
			return ps[i]
		}
		return def
	}
	if priv {
		if final == 'h' || final == 'l' {
			for _, m := range ps {
				if m == 1049 || m == 47 || m == 1047 {
					for r := range v.cells {
						v.cells[r] = v.blankRow()
					}
					v.r, v.c = 0, 0
				}
			}
		}
		return j + 1
	}
	switch final {
	case 'A':
		v.r -= p(0, 1)
	case 'B', 'e':
		v.r += p(0, 1)
	case 'C', 'a':
		v.c += p(0, 1)
	case 'D':
		v.c -= p(0, 1)
	case 'E':
		v.r += p(0, 1)
		v.c = 0
	case 'F':
		v.r -= p(0, 1)
		v.c = 0
	case 'G', '`':
		v.c = p(0, 1) - 1
	case 'd':
		v.r = p(0, 1) - 1
	case 'H', 'f':
		v.r, v.c = p(0, 1)-1, p(1, 1)-1
	case 'J':
		switch p(0, 0) {
		case 0:
			v.erase(v.r, v.c, v.cols)
			for r := v.r + 1; r < v.rows; r++ {
				v.cells[r] = v.blankRow()
			}
		case 1:
			v.erase(v.r, 0, v.c+1)
			for r := 0; r < v.r; r++ {
				v.cells[r] = v.blankRow()
			}
		default:
			for r := range v.cells {
				v.cells[r] = v.blankRow()
			}
		}
	case 'K':
		switch p(0, 0) {
		case 0:
			v.erase(v.r, v.c, v.cols)
		case 1:
			v.erase(v.r, 0, v.c+1)
		default:
			v.erase(v.r, 0, v.cols)
		}
	case 'X':
		v.erase(v.r, v.c, v.c+p(0, 1))
	case 'P':
		n := p(0, 1)
		row := v.cells[v.r]
		copy(row[v.c:], row[min(v.c+n, v.cols):])
		v.erase(v.r, v.cols-n, v.cols)
	case '@':
		n := p(0, 1)
		row := v.cells[v.r]
		copy(row[min(v.c+n, v.cols):], row[v.c:])
		v.erase(v.r, v.c, v.c+n)
	case 'b': // repeat the previous character
		if v.c > 0 {
			ch := v.cells[v.r][v.c-1]
			for k := 0; k < p(0, 1); k++ {
				v.put(ch)
			}
		}
	case 'L', 'M':
		if v.r >= v.top && v.r <= v.bottom {
			saveTop := v.top
			v.top = v.r
			if final == 'L' {
				v.scrollDown(p(0, 1))
			} else {
				v.scrollUp(p(0, 1))
			}
			v.top = saveTop
		}
	case 'S':
		v.scrollUp(p(0, 1))
	case 'T':
		v.scrollDown(p(0, 1))
	case 'r':
		v.top, v.bottom = p(0, 1)-1, p(1, v.rows)-1
		if v.top >= v.bottom || v.bottom >= v.rows {
			v.top, v.bottom = 0, v.rows-1
		}
		v.r, v.c = 0, 0
	case 's':
		v.savedR, v.savedC = v.r, v.c
	case 'u':
		v.r, v.c = v.savedR, v.savedC
	}
	v.clamp()
	return j + 1
}

// text is the screen, one line per row, trailing blanks removed.
func (v *vt) text() string {
	var b strings.Builder
	for _, row := range v.cells {
		var l strings.Builder
		for _, ch := range row {
			switch ch {
			case 0:
				l.WriteByte(' ')
			case -1:
			default:
				l.WriteRune(ch)
			}
		}
		b.WriteString(strings.TrimRight(l.String(), " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// screen is the session's current screen (rows x cols as started).
func (s *session) screen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vt == nil {
		s.vt = newVT(int(s.rows), int(s.cols))
	}
	b := s.buf.Bytes()
	if s.fed < len(b) {
		s.vt.write(b[s.fed:])
		s.fed = len(b)
	}
	return s.vt.text()
}

// waitScreen waits until the screen contains all of wants.
func (s *session) waitScreen(d time.Duration, wants ...string) bool {
	deadline := time.Now().Add(d)
	for {
		sc := s.screen()
		ok := true
		for _, w := range wants {
			if !strings.Contains(sc, w) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-s.readDone:
			sc = s.screen()
			for _, w := range wants {
				if !strings.Contains(sc, w) {
					return false
				}
			}
			return true
		default:
		}
		time.Sleep(10 * time.Millisecond) // polling, with a deadline
	}
}

// mustScreen is waitScreen that fails the test with the screen.
func (s *session) mustScreen(d time.Duration, wants ...string) {
	s.t.Helper()
	if !s.waitScreen(d, wants...) {
		s.t.Fatalf("%s: the screen doesn't show %q within %v:\n%s", s.name, wants, d, s.screen())
	}
}
