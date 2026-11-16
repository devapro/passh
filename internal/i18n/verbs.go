package i18n

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// directive is one formatting directive of a format string, %% excluded.
type directive struct {
	start, end int  // byte offsets in the format, from % to the verb
	arg        int  // the argument it formats, from 0
	verb       rune // d, s, v, w, q, …
	stars      []int
}

// directives parses format as fmt does and returns its directives in
// order. stars lists the arguments a * width or precision consumes.
// Explicit argument indexes ([n]) are honoured. ok is false for a format
// fmt would complain about: a % at the end or a bad index.
func directives(format string) (ds []directive, ok bool) {
	argNum := 0
	for i := 0; i < len(format); {
		if format[i] != '%' {
			i++
			continue
		}
		start := i
		i++
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			i++
		}
		var stars []int
		var good bool
		if argNum, i, good = argIndex(format, i, argNum); !good {
			return ds, false
		}
		if i < len(format) && format[i] == '*' {
			stars = append(stars, argNum)
			argNum++
			i++
		} else {
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
		}
		if i < len(format) && format[i] == '.' {
			i++
			if argNum, i, good = argIndex(format, i, argNum); !good {
				return ds, false
			}
			if i < len(format) && format[i] == '*' {
				stars = append(stars, argNum)
				argNum++
				i++
			} else {
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			}
		}
		if argNum, i, good = argIndex(format, i, argNum); !good {
			return ds, false
		}
		if i >= len(format) {
			return ds, false // %!(NOVERB)
		}
		verb, size := utf8.DecodeRuneInString(format[i:])
		i += size
		if verb == '%' {
			continue // a literal percent sign
		}
		ds = append(ds, directive{start: start, end: i, arg: argNum, verb: verb, stars: stars})
		argNum++
	}
	return ds, true
}

// argIndex reads an explicit argument index [n] at format[i:], if any, and
// returns the argument it selects (n-1), the offset after it and whether it
// was valid.
func argIndex(format string, i, argNum int) (int, int, bool) {
	if i >= len(format) || format[i] != '[' {
		return argNum, i, true
	}
	end := strings.IndexByte(format[i:], ']')
	if end < 0 {
		return argNum, i, false
	}
	n, err := strconv.Atoi(format[i+1 : i+end])
	if err != nil || n < 1 {
		return argNum, i, false
	}
	return n - 1, i + end + 1, true
}

// argsUsed returns how many arguments format needs: one more than the
// highest argument any directive uses.
func argsUsed(ds []directive) int {
	n := 0
	for _, d := range ds {
		n = max(n, d.arg+1)
		for _, s := range d.stars {
			n = max(n, s+1)
		}
	}
	return n
}

// wToV returns format with every %w directive turned into %v: a message
// rendered with fmt.Sprintf wraps nothing.
func wToV(format string) string {
	if !strings.Contains(format, "w") {
		return format
	}
	ds, _ := directives(format)
	var b []byte
	for _, d := range ds {
		if d.verb != 'w' {
			continue
		}
		if b == nil {
			b = []byte(format)
		}
		b[d.end-1] = 'v'
	}
	if b == nil {
		return format
	}
	return string(b)
}
