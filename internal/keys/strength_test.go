package keys

import (
	"strings"
	"testing"
	"time"
)

func TestCheckStrength(t *testing.T) {
	weak := map[string]string{
		"":             "empty",
		"password":     "top-10 common password",
		"123456":       "top-10 common password",
		"qwertyuiop":   "",
		"aaaaaaaaaaaa": `repeats like "aaa"`,
		"abcdefgh":     "sequences",
		"P@ssw0rd":     "similar to a commonly used password",
		"cathedral":    "a word by itself",
		"2019":         "",
		"jennifer":     "names and surnames",
	}
	for p, want := range weak {
		s := CheckStrength([]byte(p))
		if !s.Weak() {
			t.Errorf("%q: score %d, want weak", p, s.Score)
			continue
		}
		if !strings.Contains(s.Warning, want) {
			t.Errorf("%q: warning %q, want %q", p, s.Warning, want)
		}
		msg := s.Message()
		if !strings.HasPrefix(msg, "weak passphrase") || !strings.HasSuffix(msg, "use 6 or more random words") {
			t.Errorf("%q: message %q", p, msg)
		}
	}

	strong := []string{
		"orbit velvet cactus lumen harbor quill",
		"tundra-ripple-ochre-kestrel-mosaic-fennel",
		"x8#Kq2!vZr9@Lm4w",
	}
	for _, p := range strong {
		s := CheckStrength([]byte(p))
		if s.Weak() || s.Message() != "" || s.Warning != "" || s.Score < 3 || s.Score > 4 {
			t.Errorf("%q: %+v %q", p, s, s.Message())
		}
	}

	// User inputs count as known words.
	if s := CheckStrength([]byte("alicepi"), "alice", "pi"); !s.Weak() {
		t.Errorf("user input not considered: score %d", s.Score)
	}
}

func TestCheckStrengthLongInput(t *testing.T) {
	start := time.Now()
	if s := CheckStrength([]byte(strings.Repeat("abc", 5000))); !s.Weak() {
		t.Errorf("repeated pattern scored %d", s.Score)
	}
	// Non-ASCII input is cut at a rune boundary and left unchanged.
	long := []byte(strings.Repeat("ab€", 2000))
	CheckStrength(long)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	if string(long) != strings.Repeat("ab€", 2000) {
		t.Fatal("input modified")
	}
	// Invalid UTF-8 doesn't crash and counts as weak, as in zxcvbn.
	if s := CheckStrength([]byte{0xff, 0xfe, 'a'}); !s.Weak() {
		t.Errorf("invalid UTF-8 scored %d", s.Score)
	}
}
