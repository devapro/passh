package print

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

// langCase is what the translated sheets must show in one language
// (§3.3): the catalog's text, checked here word for word so that a
// missing translation shows up as English.
type langCase struct {
	lang      i18n.Lang
	sheet     string // the password sheet's title
	recovery  string // the recovery sheet's title
	conf      string // CONFIDENTIAL
	page1     string // "page 1 of 1"
	count22   string // "22 entries"
	fields    string // "fields: password, username, url"
	top       string // "(top level)"
	continued string // "f (continued)"
	headings  []string
	noScope   string // the error of a tag that matches nothing
	comment   string // the shell comment of the third recovery command
}

var langCases = []langCase{
	{
		lang: i18n.Ru, sheet: "лист паролей passh", recovery: "ключ восстановления passh",
		conf: "КОНФИДЕНЦИАЛЬНО", page1: "страница 1 из 1", count22: "22 записи",
		fields: "поля: password, username, url", top: "(верхний уровень)", continued: "f (продолжение)",
		headings: []string{"Ключ хранилища", "Если забыта парольная фраза", "Без passh"},
		noScope:  "нет записей для печати: нет совпадений (тег nope)",
		comment:  "# запросит парольную фразу",
	},
	{
		lang: i18n.Sr, sheet: "passh list sa lozinkama", recovery: "passh papirni ključ za oporavak",
		conf: "POVERLJIVO", page1: "strana 1 od 1", count22: "22 stavke",
		fields: "polja: password, username, url", top: "(najviši nivo)", continued: "f (nastavak)",
		headings: []string{"Ključ trezora", "Zaboravljena pristupna fraza", "Bez programa passh"},
		noScope:  "nema stavki za štampu: nema poklapanja (oznaka nope)",
		comment:  "# traži pristupnu frazu",
	},
}

// i18nEntries are 22 entries: enough for several pages, with Cyrillic and
// Serbian letters in names and values, and ambiguous characters among them.
func i18nEntries() []model.Entry {
	var es []model.Entry
	for i := range 18 {
		name := fmt.Sprintf("сайт%02d", i)
		es = append(es, entry("f/"+name, func(e *model.Entry) {
			e.Password, e.Username, e.URL = "pw-"+name, "Đorđe Šćekić", "https://example.com/"+name
		}))
	}
	return append(es,
		entry("почта", func(e *model.Entry) { e.Password, e.Username = "Жш0lO", "Иван" }),
		entry("lični/banka", func(e *model.Entry) { e.Password, e.Username = "čćđšž-ЧЋЂШЖ", "Đurđa" }),
		entry("lični/ključ", func(e *model.Entry) { e.Password = "x" }),
		entry("work/github", func(e *model.Entry) { e.Password, e.Username = "Xk0Olp1I", "alice" }),
	)
}

func TestSheetInLanguages(t *testing.T) {
	es := i18nEntries()
	for _, lc := range langCases {
		t.Run(lc.lang.String(), func(t *testing.T) {
			p := i18n.New(lc.lang)
			s := mustSheet(t, es, Options{Printer: p})
			if s.Title() != lc.sheet {
				t.Errorf("title %q, want %q", s.Title(), lc.sheet)
			}
			txt := writeTXT(t, s)
			pages := strings.Split(txt, "\f")
			if len(pages) < 2 {
				t.Fatalf("%d pages", len(pages))
			}
			legend := s.Legend()
			for i, l := range legend {
				if l == (&Sheet{}).Legend()[i] {
					t.Errorf("legend line %d is English: %q", i+1, l)
				}
			}
			for i, pg := range pages {
				lines := strings.Split(strings.TrimSuffix(pg, "\n"), "\n")
				if len(lines) != TXTPageLines {
					t.Errorf("page %d has %d lines", i+1, len(lines))
				}
				head := lc.conf + " · " + lc.sheet
				tail := FormatDate(testDate) + " · " + p.T("page %d of %d", i+1, len(pages))
				// The header fills exactly Columns columns, counted in
				// characters, not bytes.
				if !strings.HasPrefix(lines[0], head) || !strings.HasSuffix(lines[0], tail) ||
					displayWidth(lines[0]) != Columns || utf8.RuneCountInString(lines[0]) != Columns {
					t.Errorf("page %d header %q (%d columns)", i+1, lines[0], displayWidth(lines[0]))
				}
				if !slices.Equal(lines[len(lines)-len(legend):], legend) {
					t.Errorf("page %d: no translated legend at the bottom", i+1)
				}
				for j, l := range lines {
					if displayWidth(l) > Columns {
						t.Errorf("page %d line %d is %d columns: %q", i+1, j+1, displayWidth(l), l)
					}
				}
				if i > 0 && !strings.HasPrefix(lines[3], lc.continued) && lines[3] != "lični" && lines[3] != "work" {
					t.Errorf("page %d starts with %q", i+1, lines[3])
				}
			}
			for _, want := range []string{
				p.T("printed %s", FormatDate(testDate)) + " · " + lc.count22,
				"\n" + lc.fields + "\n",
				"\n" + lc.top + "\n" + strings.Repeat("=", utf8.RuneCountInString(lc.top)) + "\n",
				// A heading is underlined to its width in columns.
				"\nlični\n=====\n",
				// Field names are names: the same in every language.
				"\n  username  Иван\n",
				"\n  password  čćđšž-ЧЋЂШЖ\n",
				"\n  username  Đorđe Šćekić\n",
			} {
				if !strings.Contains(txt, want) {
					t.Errorf("the sheet lacks %q", want)
				}
			}
			if !strings.Contains(txt, "\n"+lc.continued+"\n") {
				t.Errorf("no %q heading", lc.continued)
			}
			// The marks are under their characters, counted in columns:
			// Ж and ш take one column each.
			if !strings.Contains(txt, "\n  password  Жш0lO\n"+strings.Repeat(" ", ValuePrefixWidth+2)+"DLU\n") {
				t.Error("the marks under a Cyrillic value are misaligned")
			}
			for _, en := range []string{"passh password sheet", "printed ", "entries", "fields: ", "(top level)", "(continued)", "page 1 of", Confidential} {
				if strings.Contains(txt, en) {
					t.Errorf("English %q in the %s sheet", en, lc.lang)
				}
			}

			// The selection, in the error when nothing matches and on the
			// sheet; the English error stays as it was.
			_, err := NewSheet(es, Options{Tags: []string{"nope"}, Printer: p})
			if err == nil || err.Error() != "no entries to print: none matches tag nope" {
				t.Fatalf("English error %v", err)
			}
			if got := p.Error(err); got != lc.noScope {
				t.Errorf("error %q, want %q", got, lc.noScope)
			}
			one := mustSheet(t, es, Options{Folder: paths.MustParse("lični"), Printer: p})
			if txt := writeTXT(t, one); !strings.Contains(txt, p.N(2, "%d entry", "%d entries", 2)+" · "+p.T("folder %s", "lični")+"\n") {
				t.Errorf("no translated selection:\n%s", txt)
			}
		})
	}
}

func TestRecoverySheetInLanguages(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyLines := strings.Split(keys.FormatRecoveryKey(id), "\n")
	for _, lc := range langCases {
		t.Run(lc.lang.String(), func(t *testing.T) {
			p := i18n.New(lc.lang)
			r, err := NewRecoverySheet(id, "6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", testDate, p)
			if err != nil {
				t.Fatal(err)
			}
			txt := writeTXT(t, r)
			if strings.Contains(txt, "\f") {
				t.Fatal("more than one page")
			}
			lines := strings.Split(strings.TrimSuffix(txt, "\n"), "\n")
			if want := lc.conf + " · " + lc.recovery; !strings.HasPrefix(lines[0], want) ||
				!strings.HasSuffix(lines[0], lc.page1) || displayWidth(lines[0]) != Columns {
				t.Errorf("header %q (%d columns)", lines[0], displayWidth(lines[0]))
			}
			// The commands are the spec's, byte for byte; only the shell
			// comment of the third one is in the sheet's language.
			commands := RecoveryCommandList()
			translated := 0
			for i, c := range commands {
				if cmd, ok := strings.CutSuffix(c, "# asks for the passphrase"); ok {
					commands[i] = cmd + lc.comment
					translated++
				}
			}
			if translated != 1 {
				t.Fatalf("%d commands end with the comment", translated)
			}
			for _, l := range lines {
				if displayWidth(l) > Columns && !slices.Contains(commands, l) {
					t.Errorf("line too long (%d columns): %q", displayWidth(l), l)
				}
			}
			// The commands are printed exactly, each on a line of its own.
			for _, c := range commands {
				if !slices.Contains(lines, c) {
					t.Errorf("command not printed as is: %q", c)
				}
			}
			// Headings are translated and underlined to their width.
			for _, h := range lc.headings {
				if !strings.Contains(txt, "\n"+h+"\n"+strings.Repeat("-", utf8.RuneCountInString(h))+"\n") {
					t.Errorf("no heading %q", h)
				}
			}
			for _, want := range append([]string{
				"vault_id 6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00",
				p.T("printed %s", FormatDate(testDate)),
				"`passh rekey`", "`passh recover`", "`passh recovery-key print --web`",
				"/dev/shm/key.txt", "AGE-SECRET-KEY-1", "vault.json", "`passh backup`",
			}, keyLines...) {
				if !strings.Contains(txt, want) {
					t.Errorf("missing %q", want)
				}
			}
			for _, en := range []string{"Whoever has this sheet", "Vault key", "Forgotten passphrase", "Without passh",
				"With this key instead", "is plaintext", "re-wrapped", "QR code is on the web page", "printed ", "asks for the passphrase"} {
				if strings.Contains(txt, en) {
					t.Errorf("English %q in the %s recovery sheet", en, lc.lang)
				}
			}
			for _, bad := range []string{"age1", id.Recipient().String(), id.String()} {
				if strings.Contains(txt, bad) {
					t.Errorf("the sheet contains %q (S9)", bad)
				}
			}
			// The page's layout still has the QR code.
			qr := 0
			for _, row := range allRows(r, targetWeb) {
				if row.Kind == RowQR && row.Text == id.String() {
					qr++
				}
			}
			if qr != 1 {
				t.Errorf("%d QR rows", qr)
			}
		})
	}
}

func TestPaginateContinuedInLanguages(t *testing.T) {
	one := func(Row) float64 { return 1 }
	blocks := []Block{
		{KeepWithNext: true, Rows: []Row{{Kind: RowFolder, Text: "папка"}}},
		{Rows: []Row{{Kind: RowEntry, Text: "big"}, {Kind: RowValue}, {Kind: RowValue}, {Kind: RowValue}, {Kind: RowValue}}},
	}
	for l, want := range map[i18n.Lang][]string{
		i18n.En: {"папка (continued)", "big (continued)"},
		i18n.Ru: {"папка (продолжение)", "big (продолжение)"},
		i18n.Sr: {"папка (nastavak)", "big (nastavak)"},
	} {
		pages := paginate(blocks, 4, one, i18n.New(l))
		if len(pages) != 2 || len(pages[1]) < 2 || pages[1][0].Text != want[0] || pages[1][1].Text != want[1] {
			t.Errorf("%s: pages %v", l, pages)
		}
	}
}
