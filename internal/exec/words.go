package exec

import (
	"strings"

	"github.com/devapro/passh/internal/i18n"
)

// SplitWords splits a command line such as $EDITOR into words without a
// shell (§5.6). It understands a small, predictable subset of POSIX shell
// quoting:
//
//   - words are separated by unquoted spaces, tabs and newlines;
//   - 'single quotes' keep everything literally up to the next single quote;
//   - "double quotes" keep everything literally, except that a backslash
//     before ", \, $ or ` yields that character (any other backslash is kept);
//   - outside quotes, a backslash makes the next character literal
//     (e.g. my\ editor);
//   - quoted and unquoted parts next to each other form one word, and an
//     empty pair of quotes makes an empty word (emacsclient -a "" -t).
//
// Limits, by design: nothing is expanded or interpreted. $VAR, $(...),
// backquotes, ~, globs, and the operators ; | & < > are ordinary characters
// that end up in a word: `vim; rm -rf ~` is the four words "vim;", "rm",
// "-rf" and "~", and running it looks for a program called "vim;". Escape
// sequences other than those above are not decoded. An unterminated quote
// or a trailing backslash is an error. A blank string gives no words and no
// error.
func SplitWords(s string) ([]string, error) {
	var (
		words  []string
		cur    strings.Builder
		inWord bool // cur holds a word, possibly empty ("")
	)
	end := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n':
			end()
		case '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, i18n.Errorf("unterminated single quote in %q", s)
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case '"':
			inWord = true
			closed := false
			for i++; i < len(s); i++ {
				c := s[i]
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
					c = s[i]
				}
				cur.WriteByte(c)
			}
			if !closed {
				return nil, i18n.Errorf("unterminated double quote in %q", s)
			}
		case '\\':
			if i+1 >= len(s) {
				return nil, i18n.Errorf("trailing backslash in %q", s)
			}
			inWord = true
			i++
			cur.WriteByte(s[i])
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	end()
	return words, nil
}
