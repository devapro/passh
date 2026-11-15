package gen

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

// pThreshold is the significance level of the uniformity tests. With a
// correct generator a test fails with probability 1e-6, so it doesn't flake.
const pThreshold = 1e-6

const samples = 1_000_000

func TestDefaults(t *testing.T) {
	pw, err := Generate(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(pw); n != DefaultLength {
		t.Errorf("length = %d, want %d", n, DefaultLength)
	}
	for _, r := range pw {
		if !strings.ContainsRune(DefaultAlphabet, r) {
			t.Errorf("character %q is not in the default alphabet", r)
		}
	}
	if len(DefaultAlphabet) != 62 || len(SymbolsAlphabet) != 94 {
		t.Errorf("alphabet sizes = %d, %d; want 62, 94", len(DefaultAlphabet), len(SymbolsAlphabet))
	}
	if err := ValidateAlphabet(SymbolsAlphabet); err != nil {
		t.Errorf("SymbolsAlphabet: %v", err)
	}
}

func TestSymbolsAndCustomAlphabet(t *testing.T) {
	pw, err := Generate(Options{Length: 200, Symbols: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pw {
		if !strings.ContainsRune(SymbolsAlphabet, r) {
			t.Errorf("character %q is not in the symbols alphabet", r)
		}
	}

	alphabet := "абвгдеёжзий日本🔐"
	pw, err = Generate(Options{Length: 50, Alphabet: alphabet, Symbols: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(pw); n != 50 {
		t.Errorf("length = %d runes, want 50", n)
	}
	for _, r := range pw {
		if !strings.ContainsRune(alphabet, r) {
			t.Errorf("character %q is not in the custom alphabet", r)
		}
	}
}

func TestValidation(t *testing.T) {
	big := make([]rune, 257)
	for i := range big {
		big[i] = rune(0x100 + i)
	}
	for _, a := range []string{
		"a",
		"abca",
		"ab\x00",
		"ab\n",
		"ab\x7f",
		"ab\xc2\x9b", // U+009B, 8-bit CSI
		"ab ",
		"ab\xc2\xa0", // U+00A0, no-break space
		"ab\xff",
		string(big),
	} {
		if err := ValidateAlphabet(a); !errors.Is(err, ErrBadAlphabet) {
			t.Errorf("ValidateAlphabet(%q) = %v, want ErrBadAlphabet", a, err)
		}
		if _, err := Generate(Options{Alphabet: a}); !errors.Is(err, ErrBadAlphabet) {
			t.Errorf("Generate(Alphabet: %q) = %v, want ErrBadAlphabet", a, err)
		}
	}
	if err := ValidateAlphabet(string(big[:256])); err != nil {
		t.Errorf("256-rune alphabet: %v", err)
	}
	for _, n := range []int{-1, MaxLength + 1} {
		if _, err := Generate(Options{Length: n}); err == nil {
			t.Errorf("Generate(Length: %d) succeeded", n)
		}
	}
}

func TestBits(t *testing.T) {
	b, err := Bits(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := 24 * math.Log2(62); math.Abs(b-want) > 1e-9 {
		t.Errorf("Bits = %v, want %v", b, want)
	}
	if _, err := Bits(Options{Alphabet: "x"}); err == nil {
		t.Error("Bits with a bad alphabet succeeded")
	}
}

// countingReader serves a fixed byte sequence and records how much was read.
type countingReader struct {
	data []byte
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.read >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.read:])
	r.read += n
	return n, nil
}

// TestRejectsOutOfRangeBytes proves that bytes at or above the rejection
// limit are skipped, not reduced modulo the alphabet size.
func TestRejectsOutOfRangeBytes(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		stream    []byte
		want      string
		modBiased string // what `alphabet[b % n]` without rejection would give
	}{
		{
			// n = 62, limit = 248: 248 and 255 must be dropped.
			name:      "default alphabet",
			opts:      Options{Length: 5},
			stream:    []byte{248, 255, 0, 61, 62, 247, 100},
			want:      "A9A9m",
			modBiased: "AHA9A",
		},
		{
			// n = 94, limit = 188: 188, 200 and 255 must be dropped.
			name:      "symbols alphabet",
			opts:      Options{Length: 4, Symbols: true},
			stream:    []byte{188, 0, 255, 93, 200, 187, 94},
			want:      "A~~A",
			modBiased: "AA&~",
		},
		{
			// n = 3, limit = 255: only 255 is dropped.
			name:      "three letters",
			opts:      Options{Length: 3, Alphabet: "xyz"},
			stream:    []byte{255, 254, 3, 255, 1},
			want:      "zxy",
			modBiased: "xzx",
		},
		{
			// n = 2 divides 256: nothing is dropped.
			name:      "two letters",
			opts:      Options{Length: 4, Alphabet: "01"},
			stream:    []byte{255, 254, 0, 1},
			want:      "1001",
			modBiased: "1001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &countingReader{data: tt.stream}
			tt.opts.Rand = r
			got, err := Generate(tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("Generate = %q, want %q (modulo reduction would give %q)", got, tt.want, tt.modBiased)
			}
			if r.read != len(tt.stream) {
				t.Errorf("read %d bytes, want exactly %d", r.read, len(tt.stream))
			}
		})
	}
}

func TestReaderErrors(t *testing.T) {
	// Only rejected bytes, then EOF: an error, not a hang or a short password.
	r := bytes.NewReader(bytes.Repeat([]byte{255}, 100))
	if _, err := Generate(Options{Rand: r}); err == nil {
		t.Error("Generate with an exhausted reader succeeded")
	}
	boom := errors.New("boom")
	if _, err := Generate(Options{Rand: errReader{boom}}); !errors.Is(err, boom) {
		t.Errorf("Generate error = %v, want %v", err, boom)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestUniformityDefaultAlphabet(t *testing.T) {
	testUniformity(t, Options{}, DefaultAlphabet)
}

func TestUniformitySymbolsAlphabet(t *testing.T) {
	testUniformity(t, Options{Symbols: true}, SymbolsAlphabet)
}

// testUniformity draws 10^6 characters from crypto/rand and runs Pearson's
// chi-square goodness-of-fit test against the uniform distribution.
func testUniformity(t *testing.T, opts Options, alphabet string) {
	if testing.Short() {
		t.Skip("slow")
	}
	pos := make(map[rune]int, len(alphabet))
	for i, r := range []rune(alphabet) {
		pos[r] = i
	}
	counts := make([]int, len(pos))
	opts.Length = 1000
	for drawn := 0; drawn < samples; drawn += opts.Length {
		pw, err := Generate(opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pw {
			i, ok := pos[r]
			if !ok {
				t.Fatalf("character %q is not in the alphabet", r)
			}
			counts[i]++
		}
	}
	stat, p := chiSquare(counts)
	t.Logf("n = %d, chi-square = %.1f, df = %d, p = %.4g", len(counts), stat, len(counts)-1, p)
	if p < pThreshold {
		t.Errorf("distribution is not uniform: chi-square = %.1f, df = %d, p = %.3g < %g", stat, len(counts)-1, p, pThreshold)
	}
}

// TestChiSquareDetectsModuloBias checks that the uniformity test has the
// power to catch the bug it guards against: plain `b % n` over 10^6 bytes.
func TestChiSquareDetectsModuloBias(t *testing.T) {
	r := &countingReader{data: make([]byte, samples)}
	// A perfectly uniform byte stream, reduced modulo 94 without rejection.
	for i := range r.data {
		r.data[i] = byte(i)
	}
	counts := make([]int, 94)
	for _, b := range r.data {
		counts[int(b)%94]++
	}
	if stat, p := chiSquare(counts); p >= pThreshold {
		t.Errorf("modulo-biased counts passed: chi-square = %.1f, p = %.3g", stat, p)
	}
	// The same stream through rejection sampling is uniform.
	counts = make([]int, 94)
	for _, b := range r.data {
		if b < 188 {
			counts[int(b)%94]++
		}
	}
	if stat, p := chiSquare(counts); p < pThreshold {
		t.Errorf("rejection-sampled counts failed: chi-square = %.1f, p = %.3g", stat, p)
	}
}

func TestGammaQ(t *testing.T) {
	// Known chi-square upper-tail values.
	for _, tc := range []struct {
		x  float64
		df int
		p  float64
	}{
		{3.841458820694124, 1, 0.05},
		{18.30703805327515, 10, 0.05},
		{23.20925115758657, 10, 0.01},
		{79.08194449, 60, 0.05},
		{0, 5, 1},
	} {
		got := gammaQ(float64(tc.df)/2, tc.x/2)
		if math.Abs(got-tc.p) > 1e-6 {
			t.Errorf("Q(df=%d, x=%v) = %v, want %v", tc.df, tc.x, got, tc.p)
		}
	}
}

// chiSquare returns Pearson's statistic for counts against a uniform
// expectation, and its p-value (upper tail, n-1 degrees of freedom).
func chiSquare(counts []int) (stat, p float64) {
	total := 0
	for _, c := range counts {
		total += c
	}
	expected := float64(total) / float64(len(counts))
	for _, c := range counts {
		d := float64(c) - expected
		stat += d * d / expected
	}
	df := float64(len(counts) - 1)
	return stat, gammaQ(df/2, stat/2)
}

// gammaQ is the regularized upper incomplete gamma function Q(a, x), the
// chi-square survival function at x = stat/2, a = df/2 (Numerical Recipes,
// series and continued fraction).
func gammaQ(a, x float64) float64 {
	if x <= 0 {
		return 1
	}
	lg, _ := math.Lgamma(a)
	if x < a+1 {
		// Series for P(a, x).
		sum, term := 1/a, 1/a
		for n := 1; n < 10000; n++ {
			term *= x / (a + float64(n))
			sum += term
			if math.Abs(term) < math.Abs(sum)*1e-15 {
				break
			}
		}
		return 1 - sum*math.Exp(-x+a*math.Log(x)-lg)
	}
	// Continued fraction for Q(a, x) (modified Lentz).
	const tiny = 1e-300
	b := x + 1 - a
	c := 1 / tiny
	d := 1 / b
	h := d
	for i := 1; i < 10000; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < 1e-15 {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-lg) * h
}
