package keys

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatRecoveryKeyLayout(t *testing.T) {
	id := mustKey(t)
	s := FormatRecoveryKey(id)
	lines := strings.Split(s, "\n")
	if len(lines) != 4 || lines[0] != "AGE-SECRET-KEY-1" {
		t.Fatalf("layout:\n%s", s)
	}
	var groups []string
	for i, l := range lines[1:] {
		g := strings.Split(l, " ")
		if len(g) != 5 {
			t.Fatalf("line %d has %d groups:\n%s", i+2, len(g), s)
		}
		groups = append(groups, g...)
	}
	for i, g := range groups {
		want := 4
		if i == len(groups)-1 {
			want = 2
		}
		if len(g) != want {
			t.Fatalf("group %d is %q", i+1, g)
		}
	}
	if "AGE-SECRET-KEY-1"+strings.Join(groups, "") != id.String() {
		t.Fatal("groups don't spell the key")
	}
}

func TestParseRecoveryKeyVariants(t *testing.T) {
	id := mustKey(t)
	paper := FormatRecoveryKey(id)
	flat := id.String()
	variants := map[string]string{
		"paper layout":   paper,
		"one line":       flat,
		"lower case":     strings.ToLower(paper),
		"mixed case":     mixCase(paper),
		"CRLF and tabs":  strings.ReplaceAll(strings.ReplaceAll(paper, "\n", "\r\n\t"), " ", "\t"),
		"extra spaces":   "  " + strings.ReplaceAll(paper, " ", "   ") + "\n\n",
		"no spaces":      strings.Join(strings.Fields(paper), ""),
		"dashed groups":  strings.ReplaceAll(paper, " ", "-"),
		"spaced prefix":  "age secret key 1 " + strings.TrimPrefix(flat, "AGE-SECRET-KEY-1"),
		"char by char":   strings.Join(strings.Split(flat, ""), " "),
		"unicode spaces": strings.ReplaceAll(paper, " ", "  "),
	}
	for name, typed := range variants {
		got, err := ParseRecoveryKey(typed)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.String() != id.String() {
			t.Errorf("%s: wrong key", name)
		}
		// The []byte form gives the same key and leaves its input alone.
		b := []byte(typed)
		got, err = ParseRecoveryKeyBytes(b)
		if err != nil || got.String() != id.String() {
			t.Errorf("%s: ParseRecoveryKeyBytes: %v", name, err)
		}
		if string(b) != typed {
			t.Errorf("%s: ParseRecoveryKeyBytes changed its input", name)
		}
	}
}

func mixCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 {
			b[i] = strings.ToLower(string(b[i]))[0]
		}
	}
	return string(b)
}

// TestParseRecoveryKeyTypos: every single substitution and every adjacent
// swap is caught by the checksum.
func TestParseRecoveryKeyTypos(t *testing.T) {
	id := mustKey(t)
	flat := id.String()
	data := flat[len(recoveryPrefix):]
	for i := range len(data) {
		for _, c := range bech32Charset {
			if byte(c) == data[i] {
				continue
			}
			typed := recoveryPrefix + data[:i] + string(c) + data[i+1:]
			_, err := ParseRecoveryKey(typed)
			if !errors.Is(err, ErrRecoveryKeyTypo) {
				t.Fatalf("substitution at %d not caught: %v", i, err)
			}
		}
		if i+1 < len(data) && data[i] != data[i+1] {
			typed := recoveryPrefix + data[:i] + string(data[i+1]) + string(data[i]) + data[i+2:]
			if _, err := ParseRecoveryKey(typed); !errors.Is(err, ErrRecoveryKeyTypo) {
				t.Fatalf("swap at %d not caught: %v", i, err)
			}
		}
	}
	last := "Q"
	if data[len(data)-1] == 'Q' {
		last = "P"
	}
	_, err := ParseRecoveryKey(flat[:len(flat)-1] + last)
	if err == nil || err.Error() != "recovery key has a typo (checksum mismatch)" {
		t.Fatalf("message: %v", err)
	}
}

func TestParseRecoveryKeyInvalid(t *testing.T) {
	id := mustKey(t)
	flat := id.String()
	data := flat[len(recoveryPrefix):]
	cases := map[string]struct {
		typed string
		want  string
	}{
		"empty":         {"  \n ", "nothing was typed"},
		"wrong prefix":  {"AGE-SECRET-KEY-2" + data, "must start with AGE-SECRET-KEY-1"},
		"recipient":     {"age1" + strings.ToLower(data), "must start with"},
		"missing char":  {recoveryPrefix + data[1:], "57 characters"},
		"extra char":    {recoveryPrefix + data + "Q", "59 characters"},
		"letter O":      {recoveryPrefix + data[:9] + "O" + data[10:], "group 3, character 2"},
		"letter B":      {recoveryPrefix + "B" + data[1:], "group 1, character 1"},
		"digit 1":       {recoveryPrefix + data[:57] + "1", "group 15, character 2"},
		"non-ASCII":     {recoveryPrefix + data[:4] + "é" + data[5:], "group 2, character 1"},
		"not UTF-8":     {recoveryPrefix + data[:4] + "\xff" + data[5:], "group 2, character 1"},
		"missing group": {recoveryPrefix + data[4:], "54 characters"},
	}
	for name, c := range cases {
		got, err := ParseRecoveryKey(c.typed)
		if !errors.Is(err, ErrRecoveryKeyInvalid) || got != nil {
			t.Errorf("%s: got %v", name, err)
			continue
		}
		if _, berr := ParseRecoveryKeyBytes([]byte(c.typed)); berr == nil || berr.Error() != err.Error() {
			t.Errorf("%s: ParseRecoveryKeyBytes: %v, want %v", name, berr, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q doesn't mention %q", name, err, c.want)
		}
		if strings.Contains(err.Error(), data[:8]) {
			t.Errorf("%s: error echoes the key", name)
		}
	}
}
