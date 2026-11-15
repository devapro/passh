package exec

import (
	"slices"
	"strings"
	"testing"
)

// FuzzSplitWords (TEST-12, CLI-020): SplitWords never panics, and the words
// it returns, quoted again for a POSIX shell, split back into the same
// words. The seed corpus runs in every `go test`.
func FuzzSplitWords(f *testing.F) {
	for _, seed := range []string{
		"vim", "code --wait", `emacsclient -a "" -t`, `my\ editor -x`, `"a b" 'c d'`,
		`vim; rm -rf ~`, `"unterminated`, `trailing\`, "\t\n ", `"\$\"\\\x"`, `a''b""c`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		words, err := SplitWords(s)
		if err != nil {
			return
		}
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
		}
		again, err := SplitWords(strings.Join(quoted, " "))
		if err != nil || !slices.Equal(again, words) {
			t.Errorf("SplitWords(%q) = %q; quoted again it splits into %q, %v", s, words, again, err)
		}
	})
}
