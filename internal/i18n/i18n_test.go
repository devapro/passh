package i18n

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Lang
	}{{"en", En}, {"ru", Ru}, {"sr", Sr}} {
		got, err := Parse(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("Parse(%q) = %v, %v, want %v", tc.in, got, err, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("Parse(%q).String() = %q", tc.in, got.String())
		}
	}
	for _, in := range []string{"", "EN", "Ru", "de", "sr-Latn", " ru", "ru\n"} {
		_, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q): no error", in)
			continue
		}
		if want := `is not one of "en", "ru" or "sr"`; !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want it to contain %q", in, err, want)
		}
	}
	if got := Langs(); len(got) != int(numLangs) || got[0] != En {
		t.Errorf("Langs() = %v", got)
	}
	if New(Lang(200)).Lang() != En {
		t.Error("New of an unknown Lang doesn't print English")
	}
}

// TestPluralForms checks the CLDR integer rules: one, few and many/other.
func TestPluralForms(t *testing.T) {
	ruWant := map[int]int{
		0: formMany, 1: formOne, 2: formFew, 4: formFew, 5: formMany, 11: formMany,
		12: formMany, 14: formMany, 21: formOne, 22: formFew, 25: formMany,
		101: formOne, 111: formMany, -1: formOne, -3: formFew,
	}
	for n, want := range ruWant {
		for _, l := range []Lang{Ru, Sr} {
			if got := pluralForm(l, n); got != want {
				t.Errorf("pluralForm(%v, %d) = %d, want %d", l, n, got, want)
			}
		}
		enWant := formMany
		if n == 1 || n == -1 {
			enWant = formOne
		}
		if got := pluralForm(En, n); got != enWant {
			t.Errorf("pluralForm(en, %d) = %d, want %d", n, got, enWant)
		}
	}
}

func TestNFallsBackToEnglish(t *testing.T) {
	for _, p := range []Printer{{}, New(Ru), New(Sr)} {
		if got := p.N(1, "%d test entry", "%d test entries", 1); got != "1 test entry" {
			t.Errorf("%v: N(1) = %q", p.Lang(), got)
		}
		if got := p.N(21, "%d test entry", "%d test entries", 21); got != "21 test entries" {
			t.Errorf("%v: N(21) = %q", p.Lang(), got)
		}
	}
}

func TestT(t *testing.T) {
	en, ru, sr := Printer{}, New(Ru), New(Sr)
	if got := en.T("Created the vault %s.", "~/v"); got != "Created the vault ~/v." {
		t.Errorf("en: %q", got)
	}
	if got := ru.T("Created the vault %s.", "~/v"); got != "Хранилище ~/v создано." {
		t.Errorf("ru: %q", got)
	}
	if got := sr.T("Created the vault %s.", "~/v"); got != "Napravljen je trezor ~/v." {
		t.Errorf("sr: %q", got)
	}
	if got := ru.T("no such message %d", 7); got != "no such message 7" {
		t.Errorf("ru, unknown message: %q", got)
	}
	// Without args a message is plain text.
	if got := ru.T("100% plain"); got != "100% plain" {
		t.Errorf("plain text: %q", got)
	}
	// Error and Localizer arguments are rendered in the language.
	sentinel := NewError("wrong passphrase, or the key block is damaged")
	if got := ru.T("%s: %v", "x", sentinel); got != "x: неверная парольная фраза или повреждён блок ключа" {
		t.Errorf("error argument: %q", got)
	}
	if got := ru.T("%s", Msg("Created the vault %s.", "v")); got != "Хранилище v создано." {
		t.Errorf("Localizer argument: %q", got)
	}
	// TC falls back to the English text, not to the text without context.
	if got := ru.TC("test-context", "Created the vault %s.", "v"); got != "Created the vault v." {
		t.Errorf("TC: %q", got)
	}
}

// TestErrorfLikeFmt: Errorf's text, Unwrap and errors.Is/As are those of
// fmt.Errorf.
func TestErrorfLikeFmt(t *testing.T) {
	a := NewError("wrong passphrase, or the key block is damaged")
	b := &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrNotExist}
	cases := []struct {
		format string
		args   []any
	}{
		{"plain %d", []any{3}},
		{"no args 100%%", nil},
		{"one %w", []any{a}},
		{"two %w and %w", []any{a, b}},
		{"%w: %v", []any{a, b}},
		{"bad %w", []any{nil}},
		{"not an error %w", []any{"s"}},
	}
	for _, tc := range cases {
		got, want := Errorf(tc.format, tc.args...), fmt.Errorf(tc.format, tc.args...)
		if got.Error() != want.Error() {
			t.Errorf("Errorf(%q).Error() = %q, want %q", tc.format, got.Error(), want.Error())
		}
		_, gotOne := got.(interface{ Unwrap() error })
		_, wantOne := want.(interface{ Unwrap() error })
		_, gotMany := got.(interface{ Unwrap() []error })
		_, wantMany := want.(interface{ Unwrap() []error })
		if gotOne != wantOne || gotMany != wantMany {
			t.Errorf("Errorf(%q): Unwrap methods %v/%v, want %v/%v", tc.format, gotOne, gotMany, wantOne, wantMany)
		}
		for _, target := range []error{a, fs.ErrNotExist} {
			if errors.Is(got, target) != errors.Is(want, target) {
				t.Errorf("Errorf(%q): errors.Is(%v) differs from fmt.Errorf", tc.format, target)
			}
		}
		var pe1, pe2 *fs.PathError
		if errors.As(got, &pe1) != errors.As(want, &pe2) || pe1 != pe2 {
			t.Errorf("Errorf(%q): errors.As(*fs.PathError) differs from fmt.Errorf", tc.format)
		}
	}
	if errors.Is(NewError("x"), NewError("x")) {
		t.Error("two NewError sentinels with one text match each other")
	}
}

func TestPrinterError(t *testing.T) {
	ru := New(Ru)
	sentinel := NewError("wrong passphrase, or the key block is damaged")
	const ruText = "неверная парольная фраза или повреждён блок ключа"
	osErr := &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrPermission}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"sentinel", sentinel, ruText},
		{"Errorf %w", Errorf("%s: %w", "/v", sentinel), "/v: " + ruText},
		{"Errorf %v of an error", Errorf("%v (%v)", sentinel, osErr), ruText + " (open /x: permission denied)"},
		{"fmt.Errorf around it", fmt.Errorf("opening /v: %w", sentinel), "opening /v: " + ruText},
		{"text is a key", errors.New("wrong passphrase, or the key block is damaged"), ruText},
		{"join", errors.Join(sentinel, osErr), ruText + "\nopen /x: permission denied"},
		{"os error", osErr, "open /x: permission denied"},
		{"Localizer", testLocalizer{}, "localized ru"},
	}
	for _, tc := range cases {
		if got := ru.Error(tc.err); got != tc.want {
			t.Errorf("%s: ru.Error() = %q, want %q", tc.name, got, tc.want)
		}
		if tc.err == nil {
			continue
		}
		if got := (Printer{}).Error(tc.err); got != tc.err.Error() {
			t.Errorf("%s: English Error() = %q, want %q", tc.name, got, tc.err.Error())
		}
	}
}

type testLocalizer struct{}

func (testLocalizer) Error() string             { return "english" }
func (testLocalizer) Localize(p Printer) string { return "localized " + p.Lang().String() }

func TestMessage(t *testing.T) {
	m := Msg("Created the vault %s.", "v")
	if m.String() != "Created the vault v." || m.Localize(New(Sr)) != "Napravljen je trezor v." {
		t.Errorf("Msg: %q, %q", m.String(), m.Localize(New(Sr)))
	}
	r := Raw("Created the vault %s.")
	if r.String() != "Created the vault %s." || r.Localize(New(Ru)) != "Created the vault %s." {
		t.Errorf("Raw is translated or formatted: %q", r.Localize(New(Ru)))
	}
	if !(Message{}).IsZero() || m.IsZero() || Raw("x").IsZero() {
		t.Error("IsZero")
	}
	if Mark("x %d") != "x %d" {
		t.Error("Mark changed its argument")
	}
}

func TestDirectives(t *testing.T) {
	cases := []struct {
		format string
		args   int
		sig    string
	}{
		{"plain", 0, ""},
		{"100%% sure", 0, ""},
		{"%d of %s", 2, "1d 2s"},
		{"%[2]s, then %[1]d", 2, "1d 2s"},
		{"%-10s|%5.2f|%#q|%+v", 4, "1s 2f 3q 4v"},
		{"%*d", 2, "1* 2d"},
		{"%[3]*.[2]*[1]f", 3, "1f 2* 3*"},
		{"%w: %v", 2, "1w 2v"},
		{"%s and %[1]q", 1, "1q 1s"},
	}
	for _, tc := range cases {
		ds, ok := directives(tc.format)
		if !ok {
			t.Errorf("directives(%q): not ok", tc.format)
			continue
		}
		if got := argsUsed(ds); got != tc.args {
			t.Errorf("argsUsed(%q) = %d, want %d", tc.format, got, tc.args)
		}
		if got := sig(tc.format); got != tc.sig {
			t.Errorf("sig(%q) = %q, want %q", tc.format, got, tc.sig)
		}
	}
	for _, bad := range []string{"%", "x %[0]d", "x %[a]d", "x %[1"} {
		if _, ok := directives(bad); ok {
			t.Errorf("directives(%q) is ok", bad)
		}
	}
	if got := wToV("%w: %v (%%w) %[1]w"); got != "%v: %v (%%w) %[1]v" {
		t.Errorf("wToV = %q", got)
	}
	if !hasLetter("x %d") || hasLetter("%s: %v") || hasLetter("%w (%v)\n") || !hasLetter("%s → ok") {
		t.Error("hasLetter")
	}
}

// TestExtractor runs the extractor on testdata/extract, which has one call
// of each kind it must recognize and each mistake it must report.
func TestExtractor(t *testing.T) {
	f, err := extractTree("testdata/extract", "example.com/m", "", ".")
	if err != nil {
		t.Fatal(err)
	}
	wantMsgs := []string{
		"Hello, %s.", "part one, part two", "shared constant", "menu\x04Open",
		"a sentinel", "reading %s: %w", "deferred %d", "marked", "Said %s.", "warned %d",
		"local call %s", "two %s %d", "100% plain", "bad %d", "spread %s %d",
	}
	for _, k := range wantMsgs {
		if _, ok := f.msgs[k]; !ok {
			t.Errorf("message %q not found", k)
		}
	}
	if len(f.msgs) != len(wantMsgs) {
		t.Errorf("found %d messages, want %d: %q", len(f.msgs), len(wantMsgs), f.msgs)
	}
	if at := f.plurals[pluralKey{"%d file", "%d files"}]; len(at) != 1 || at[0] != "a/a.go:31" {
		t.Errorf("plural found at %v, want a/a.go:31", at)
	}
	wantProblems := []string{
		`a/a.go:42: the message is not a string constant`,
		`a/a.go:43: "two %s %d" uses 2 arguments, the call passes 1`,
		`a/a.go:44: "100% plain" holds a %`,
		`a/a.go:45: NewError("bad %d")`,
		`b/b.go:17: bad is marked i18n:wrapper but has no parameter named format or msg`,
		`c/c.go:2: dot import of internal/i18n`,
	}
	if len(f.problems) != len(wantProblems) {
		t.Errorf("problems:\n%s\nwant %d", strings.Join(f.problems, "\n"), len(wantProblems))
	}
	for _, w := range wantProblems {
		found := false
		for _, p := range f.problems {
			found = found || strings.HasPrefix(p, w)
		}
		if !found {
			t.Errorf("no problem %q in:\n%s", w, strings.Join(f.problems, "\n"))
		}
	}

	// passh itself: the extractor runs from the module root and finds the
	// messages of every area.
	all := extracted(t)
	files := map[string]bool{}
	for _, at := range all.msgs {
		for _, a := range at {
			files[strings.SplitN(a, "/", 3)[1]] = true
		}
	}
	for _, pkg := range []string{"cli", "keys", "tty", "vault"} {
		if !files[pkg] {
			t.Errorf("no message found in internal/%s", pkg)
		}
	}
	if _, err := os.Stat("../../go.mod"); err != nil {
		t.Errorf("the test runs outside internal/i18n: %v", err)
	}
}
