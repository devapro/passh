package print

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
)

var testDate = time.Date(2026, 11, 15, 14, 3, 0, 0, time.UTC)

func entry(path string, mod func(*model.Entry)) model.Entry {
	e := model.Entry{Path: paths.MustParse(path)}
	if mod != nil {
		mod(&e)
	}
	return e
}

func testEntries() []model.Entry {
	return []model.Entry{
		entry("work/github", func(e *model.Entry) {
			e.Password, e.Username, e.URL = "Xk0Olp1I", "alice", "https://github.com"
			e.Tags = []string{"dev", "2fa"}
		}),
		entry("work/dev/aws", func(e *model.Entry) {
			e.Password, e.Username = "aws-secret", "root"
			e.Tags = []string{"dev"}
			e.Fields = []model.Field{{Key: "pin", Value: "4711"}, {Key: "account", Value: "1234"}}
		}),
		entry("email", func(e *model.Entry) {
			e.Password, e.Username = "Пароль-Ωλ", "Иван"
		}),
		entry("bank/main", func(e *model.Entry) {
			e.Password = "hunter2"
			e.Tags = []string{"2fa"}
			e.Notes = "first line\n\tsecond line\n\n"
		}),
	}
}

func mustSheet(t *testing.T, es []model.Entry, opts Options) *Sheet {
	t.Helper()
	if opts.Date.IsZero() {
		opts.Date = testDate
	}
	s, err := NewSheet(es, opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustRecovery(t *testing.T) (*RecoverySheet, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRecoverySheet(id, "6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", testDate)
	if err != nil {
		t.Fatal(err)
	}
	return r, id
}

// allRows flattens the layout of doc for target t.
func allRows(doc Document, t target) []Row {
	var rows []Row
	for _, b := range doc.blocks(t) {
		rows = append(rows, b.Rows...)
	}
	return rows
}

func TestParseFields(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", DefaultFields},
		{" , ", DefaultFields},
		{"password,username,url", []string{"password", "username", "url"}},
		{"username, Password ,username", []string{"username", "password"}},
		{"URL,notes,tags,fields", []string{"url", "notes", "tags", "fields"}},
		{"pin,PIN", []string{"pin", "PIN"}},
	}
	for _, c := range cases {
		got, err := ParseFields(c.in)
		if err != nil {
			t.Errorf("ParseFields(%q): %v", c.in, err)
			continue
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("ParseFields(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"pass word", "-x", "a/b", "x:y"} {
		if _, err := ParseFields(bad); !errors.Is(err, ErrField) {
			t.Errorf("ParseFields(%q) = %v, want ErrField", bad, err)
		}
	}
	// The default is a copy.
	got, _ := ParseFields("")
	got[0] = "changed"
	if DefaultFields[0] != FieldPassword {
		t.Fatal("ParseFields returned DefaultFields itself")
	}
}

func TestNewSheetSelectionAndOrder(t *testing.T) {
	s := mustSheet(t, testEntries(), Options{})
	if s.Len() != 4 {
		t.Fatalf("Len = %d", s.Len())
	}
	var order []string
	for _, r := range allRows(s, targetTXT) {
		if r.Kind == RowFolder || r.Kind == RowEntry {
			order = append(order, r.Text)
		}
	}
	want := []string{"(top level)", "email", "bank", "main", "work", "github", "work/dev", "aws"}
	if !slices.Equal(order, want) {
		t.Fatalf("order = %q, want %q", order, want)
	}

	s = mustSheet(t, testEntries(), Options{Folder: paths.MustParse("work")})
	if s.Len() != 2 {
		t.Fatalf("folder work: Len = %d", s.Len())
	}
	s = mustSheet(t, testEntries(), Options{Tags: []string{" 2fa "}})
	if s.Len() != 2 {
		t.Fatalf("tag 2fa: Len = %d", s.Len())
	}
	s = mustSheet(t, testEntries(), Options{Folder: paths.MustParse("work"), Tags: []string{"2fa", "dev"}})
	if s.Len() != 1 {
		t.Fatalf("work + 2fa + dev: Len = %d", s.Len())
	}
	txt := writeTXT(t, s)
	if !strings.Contains(txt, "folder work; tags 2fa, dev") {
		t.Errorf("the sheet doesn't describe the selection:\n%s", txt)
	}

	if _, err := NewSheet(testEntries(), Options{Tags: []string{"none"}}); !errors.Is(err, ErrNoEntries) {
		t.Errorf("no match: %v", err)
	}
	if _, err := NewSheet(nil, Options{}); !errors.Is(err, ErrNoEntries) {
		t.Errorf("empty vault: %v", err)
	}
	if _, err := NewSheet(testEntries(), Options{Fields: []string{"password", "pni"}}); !errors.Is(err, ErrField) {
		t.Errorf("unknown custom field: %v", err)
	}
	if _, err := NewSheet(testEntries(), Options{Fields: []string{}}); !errors.Is(err, ErrField) {
		t.Errorf("no fields: %v", err)
	}
	if _, err := NewSheet(testEntries(), Options{Fields: []string{"a b"}}); !errors.Is(err, ErrField) {
		t.Errorf("invalid field: %v", err)
	}
}

func TestSheetFields(t *testing.T) {
	es := testEntries()
	// Default fields: password, username, url, in that order; no tags, notes
	// or custom fields; empty values left out.
	txt := writeTXT(t, mustSheet(t, es, Options{}))
	for _, want := range []string{"  password  Xk0Olp1I\n", "  username  alice\n", "  url       https://github.com\n"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Index(txt, "password  Xk0Olp1I") > strings.Index(txt, "username  alice") {
		t.Error("fields are not in the default order")
	}
	for _, unwanted := range []string{"tags", "4711", "first line", "username  \n"} {
		if strings.Contains(txt, unwanted) {
			t.Errorf("unexpected %q", unwanted)
		}
	}

	txt = writeTXT(t, mustSheet(t, es, Options{Fields: []string{"username", "fields", "tags", "notes"}}))
	for _, want := range []string{
		"  pin       4711\n", "  account   1234\n", "  tags      dev, 2fa\n",
		"  notes     first line\n", "                second line\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "hunter2") {
		t.Error("password printed although not chosen")
	}

	txt = writeTXT(t, mustSheet(t, es, Options{Fields: []string{"pin"}}))
	if !strings.Contains(txt, "  pin       4711\n") || strings.Contains(txt, "1234") {
		t.Errorf("custom field by key:\n%s", txt)
	}
}

func TestMarks(t *testing.T) {
	rows := targetTXT.valueRows("password", []string{"a0O1lI b"}, true)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	r := rows[0]
	if r.Prefix != "  password  " || r.Text != "a0O1lI b" {
		t.Fatalf("row = %+v", r)
	}
	want := strings.Repeat(" ", ValuePrefixWidth) + " DUDLUS"
	if r.Marks != want {
		t.Fatalf("marks = %q, want %q", r.Marks, want)
	}
	// Marks line up under wide characters too.
	rows = targetTXT.valueRows("x", []string{"中0"}, true)
	if got := rows[0].Marks; got != strings.Repeat(" ", ValuePrefixWidth)+"  D" {
		t.Fatalf("marks after a wide character = %q", got)
	}
	// Nothing to mark: no marks line. Spaces are marked only on request.
	if rows := targetTXT.valueRows("notes", []string{"a b"}, false); rows[0].Marks != "" {
		t.Fatalf("marks = %q", rows[0].Marks)
	}
}

func TestWrapKeepsEveryCharacter(t *testing.T) {
	long := strings.Repeat("abcdefghij0123456789", 12) + "Пароль" // 246 characters
	for _, tg := range []target{targetTXT, targetPDF, targetWeb} {
		rows := tg.valueRows("password", []string{long}, true)
		if len(rows) < 4 {
			t.Fatalf("%d rows", len(rows))
		}
		var b strings.Builder
		for i, r := range rows {
			if w := utf8.RuneCountInString(r.Text); w > ValueWidth {
				t.Fatalf("row %d is %d columns wide", i, w)
			}
			if utf8.RuneCountInString(r.Prefix) != ValuePrefixWidth {
				t.Fatalf("row %d: prefix %q", i, r.Prefix)
			}
			if i > 0 && !strings.Contains(r.Prefix, Continuation) {
				t.Fatalf("row %d has no continuation mark: %q", i, r.Prefix)
			}
			b.WriteString(r.Text)
		}
		if b.String() != long {
			t.Fatalf("wrapped value lost characters:\n%q\n%q", b.String(), long)
		}
	}

	// A label too long for the label column gets its own row.
	rows := targetTXT.valueRows("recovery-code-1", []string{"x"}, true)
	if len(rows) != 2 || rows[0].Prefix != "  recovery-code-1" || rows[0].Text != "" || rows[1].Text != "x" {
		t.Fatalf("long label: %+v", rows)
	}

	// Prose wraps at spaces and breaks words longer than a line.
	lines := targetTXT.wrapProse("aa bb "+strings.Repeat("c", 25)+" dd", 10)
	if want := []string{"aa bb", "cccccccccc", "cccccccccc", "ccccc dd"}; !slices.Equal(lines, want) {
		t.Fatalf("wrapProse = %q, want %q", lines, want)
	}
}

func TestEscapingS4(t *testing.T) {
	es := []model.Entry{entry("evil", func(e *model.Entry) {
		e.Password = "a\x1b]52;c;ZXZpbA==\x07b\u202ec"
		e.Username = "zero\u200bwidth\u00a0nbsp"
		e.Notes = "line\x1b[2Jone\rtwo"
	})}
	s := mustSheet(t, es, Options{Fields: []string{"password", "username", "notes"}})
	txt := writeTXT(t, s)
	pdf := pdfText(t, writePDF(t, s, A4))
	for name, out := range map[string]string{"txt": txt, "pdf": pdf} {
		for _, bad := range []string{"\x1b", "\x07", "\r", "\u202e", "\u200b", "\u00a0"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: raw %q in output", name, bad)
			}
		}
		for _, want := range []string{`a\x1b]52;c;ZXZpbA==\x07b\u202ec`, `zero\u200bwidth\u00a0nbsp`, `line\x1b[2Jone\rtwo`} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
	}
	// HTML layout: the same escapes.
	var web strings.Builder
	for _, r := range allRows(s, targetWeb) {
		web.WriteString(r.Prefix + r.Text + "\n")
	}
	if strings.Contains(web.String(), "\x1b") || !strings.Contains(web.String(), `\x1b]52`) {
		t.Errorf("web layout not escaped:\n%s", web.String())
	}
}

func TestPDFFontFallback(t *testing.T) {
	es := []model.Entry{entry("x", func(e *model.Entry) { e.Password = "中文😀é\u0301" })}
	s := mustSheet(t, es, Options{})
	pdf := pdfText(t, writePDF(t, s, A4))
	if !strings.Contains(pdf, (`\u4e2d\u6587\U0001f600é\u0301`)) {
		t.Error("characters without a glyph are not escaped in the PDF")
	}
	txt := writeTXT(t, s)
	if !strings.Contains(txt, "中文😀é\u0301") {
		t.Error("the TXT doesn't keep characters as they are")
	}
}

// TestPDF checks the structure of the PDF for both paper sizes: header,
// trailer, cross-reference offset, page count and size, and the expected
// text on every page.
func TestPDF(t *testing.T) {
	var es []model.Entry
	for i := range 60 {
		name := fmt.Sprintf("site%02d", i)
		es = append(es, entry("folder"+strconv.Itoa(i/20)+"/"+name, func(e *model.Entry) {
			e.Password, e.Username = "pw-"+name, "user-"+name
		}))
	}
	es = append(es, testEntries()...)
	s := mustSheet(t, es, Options{})
	for _, size := range []PaperSize{A4, Letter} {
		t.Run(size.String(), func(t *testing.T) {
			pdf := writePDF(t, s, size)
			pages := checkPDF(t, pdf)
			text := pdfText(t, pdf)
			if pages < 2 {
				t.Fatalf("%d pages, want several", pages)
			}
			box := map[PaperSize]string{A4: "/MediaBox [0 0 595.28 841.89]", Letter: "/MediaBox [0 0 612.00 792.00]"}[size]
			if !strings.Contains(pdf, box) {
				t.Errorf("no %s", box)
			}
			for _, want := range []string{Confidential, FormatDate(testDate)} {
				if n := strings.Count(text, want); n < pages {
					t.Errorf("%q on %d of %d pages", want, n, pages)
				}
			}
			for i := range pages {
				want := fmt.Sprintf("page %d of %d", i+1, pages)
				if !strings.Contains(text, want) {
					t.Errorf("missing %q", want)
				}
			}
			for _, e := range es {
				for _, v := range []string{e.Path.Name(), e.Password, e.Username} {
					if !strings.Contains(text, v) {
						t.Errorf("missing %q", v)
					}
				}
			}
			for _, cyr := range []string{"Пароль-Ωλ", "Иван"} {
				if !strings.Contains(text, cyr) {
					t.Errorf("Cyrillic %q lost", cyr)
				}
			}
			if !strings.Contains(text, "folder1 (continued)") && !strings.Contains(text, "folder0 (continued)") {
				t.Error("no folder heading is repeated on a new page")
			}
			if !strings.Contains(text, s.Legend()[0]) {
				t.Error("no legend")
			}
			if !strings.Contains(pdf, "/FontFile2") || !strings.Contains(pdf, "/Encoding /Identity-H") {
				t.Error("the UTF-8 font is not embedded")
			}
		})
	}

	// The default, compressed output is a valid PDF too.
	var b bytes.Buffer
	if err := WritePDF(&b, s, A4); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); !strings.HasPrefix(got, "%PDF-1.") || strings.Contains(got, pdfString("hunter2")) {
		t.Error("compressed PDF: wrong header or readable content")
	}
	checkPDF(t, b.String())
}

func TestTXT(t *testing.T) {
	var es []model.Entry
	for i := range 40 {
		name := fmt.Sprintf("site%02d", i)
		es = append(es, entry("f/"+name, func(e *model.Entry) {
			e.Password, e.Username = "pw0-"+name, "user-"+name
			if i == 7 {
				e.Password = strings.Repeat("0123456789", 30)
			}
		}))
	}
	es = append(es, testEntries()...)
	s := mustSheet(t, es, Options{})
	txt := writeTXT(t, s)
	if !strings.HasSuffix(txt, "\n") || strings.HasSuffix(txt, "\f") {
		t.Fatal("bad ending")
	}
	pages := strings.Split(txt, "\f")
	if len(pages) < 3 {
		t.Fatalf("%d pages", len(pages))
	}
	for i, p := range pages {
		lines := strings.Split(strings.TrimSuffix(p, "\n"), "\n")
		if len(lines) != TXTPageLines {
			t.Errorf("page %d has %d lines, want %d", i+1, len(lines), TXTPageLines)
		}
		head := fmt.Sprintf("%s · %s", Confidential, s.Title())
		tail := fmt.Sprintf("%s · page %d of %d", FormatDate(testDate), i+1, len(pages))
		if !strings.HasPrefix(lines[0], head) || !strings.HasSuffix(lines[0], tail) || displayWidth(lines[0]) != Columns {
			t.Errorf("page %d header %q", i+1, lines[0])
		}
		legend := s.Legend()
		if !slices.Equal(lines[len(lines)-len(legend):], legend) {
			t.Errorf("page %d: no legend at the bottom", i+1)
		}
		for j, l := range lines {
			if displayWidth(l) > Columns {
				t.Errorf("page %d line %d is %d columns: %q", i+1, j+1, displayWidth(l), l)
			}
		}
		if i > 0 && lines[3] != "f (continued)" && lines[3] != "work" && lines[3] != "work/dev" {
			t.Errorf("page %d starts with %q", i+1, lines[3])
		}
	}
	// Every value is there, and the long one wraps without loss.
	for _, e := range es {
		if e.Password == strings.Repeat("0123456789", 30) {
			continue
		}
		if !strings.Contains(txt, e.Password) {
			t.Errorf("missing %q", e.Password)
		}
	}
	var long strings.Builder
	inLong := false
	for l := range strings.SplitSeq(txt, "\n") {
		switch {
		case l == "site07":
			inLong = true
		case inLong && strings.HasPrefix(l, "  password  "):
			long.WriteString(strings.TrimPrefix(l, "  password  "))
		case inLong && strings.HasPrefix(l, "          "+Continuation+" "):
			long.WriteString(strings.TrimPrefix(l, "          "+Continuation+" "))
		case inLong && strings.HasPrefix(l, "  username"):
			inLong = false
		}
	}
	if long.String() != strings.Repeat("0123456789", 30) {
		t.Errorf("long password in the TXT: %q", long.String())
	}
	// Ambiguity marks under the first password.
	if !strings.Contains(txt, "  password  pw0-site00\n"+strings.Repeat(" ", 14)+"D     DD\n") {
		t.Error("no marks line")
	}
}

func TestPaginate(t *testing.T) {
	one := func(Row) float64 { return 1 }
	entryBlock := func(name string, values int) Block {
		b := Block{Rows: []Row{{Kind: RowSpace}, {Kind: RowEntry, Text: name}}}
		for range values {
			b.Rows = append(b.Rows, Row{Kind: RowValue, Text: "v"})
		}
		return b
	}
	folder := func(name string) Block {
		return Block{KeepWithNext: true, Rows: []Row{{Kind: RowSpace}, {Kind: RowFolder, Text: name}}}
	}
	texts := func(rows []Row) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r.Text)
		}
		return out
	}

	// A block that doesn't fit moves to the next page; a heading moves with
	// it; a page inside a folder repeats the folder's heading.
	pages := paginate([]Block{folder("A"), entryBlock("a1", 3), folder("B"), entryBlock("b1", 3), entryBlock("b2", 3)}, 10, one)
	got := make([][]string, len(pages))
	for i, p := range pages {
		got[i] = texts(p)
	}
	want := [][]string{
		{"A", "", "a1", "v", "v", "v"},
		{"B", "", "b1", "v", "v", "v"},
		{"B (continued)", "", "b2", "v", "v", "v"},
	}
	if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", want) {
		t.Fatalf("pages = %q\nwant    %q", got, want)
	}

	// A block taller than a page is split, its name repeated.
	pages = paginate([]Block{folder("A"), entryBlock("big", 10)}, 8, one)
	got = got[:0]
	for _, p := range pages {
		got = append(got, texts(p))
	}
	want = [][]string{
		{"A", "", "big", "v", "v", "v", "v", "v"},
		{"A (continued)", "big (continued)", "v", "v", "v", "v", "v"},
	}
	if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", want) {
		t.Fatalf("pages = %q\nwant    %q", got, want)
	}

	if pages := paginate(nil, 10, one); len(pages) != 1 {
		t.Fatalf("no blocks: %d pages", len(pages))
	}
}

func TestRecoverySheet(t *testing.T) {
	r, id := mustRecovery(t)
	recipient := id.Recipient().String()
	keyLines := strings.Split(keys.FormatRecoveryKey(id), "\n")
	if len(keyLines) != 4 || !strings.HasPrefix(keyLines[1], keyLines[1][:4]+" ") {
		t.Fatalf("unexpected key format %q", keyLines)
	}
	check := func(name, out string, enc func(string) string) {
		t.Helper()
		for _, want := range append([]string{
			"6f1c2a7e-0d4b-4c1e-9a55-3b7c9e2d1f00", FormatDate(testDate), Confidential,
			"Whoever has this sheet and a copy of the vault can read everything",
			"passh recover",
		}, keyLines...) {
			if !strings.Contains(out, enc(want)) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		for _, c := range RecoveryCommands {
			if !strings.Contains(out, enc(c)) {
				t.Errorf("%s: missing command %q", name, c)
			}
		}
		for _, bad := range []string{"age1", recipient, strings.ToUpper(recipient)} {
			if strings.Contains(out, bad) || strings.Contains(out, enc(bad)) {
				t.Errorf("%s contains %q (S9)", name, bad)
			}
		}
		// The bare key is printed only in groups, never in one piece (the
		// QR code holds it).
		if strings.Contains(out, enc(id.String())) {
			t.Errorf("%s: the key is printed in one piece", name)
		}
	}
	for _, size := range []PaperSize{A4, Letter} {
		pdf := writePDF(t, r, size)
		if pages := checkPDF(t, pdf); pages != 1 {
			t.Errorf("%s: %d pages, want 1", size, pages)
		}
		check("pdf "+size.String(), pdfText(t, pdf), func(s string) string { return s })
		if strings.Contains(pdf, "age1") {
			t.Errorf("%s: age1 in the PDF bytes", size)
		}
		// The QR code is drawn as filled rectangles.
		if n := strings.Count(pdf, " re f"); n < 100 {
			t.Errorf("%s: %d rectangles; no QR code?", size, n)
		}
	}
	txt := writeTXT(t, r)
	check("txt", txt, func(s string) string { return s })
	if strings.Count(txt, "\f") != 0 {
		t.Error("the TXT recovery sheet has more than one page")
	}
	for l := range strings.SplitSeq(txt, "\n") {
		if displayWidth(l) > Columns && !slices.Contains(RecoveryCommands, l) {
			t.Errorf("line too long: %q", l)
		}
	}
	if !strings.Contains(txt, "QR code") {
		t.Error("the TXT doesn't say where the QR code is")
	}

	// The web layout has the QR code of the bare key.
	var qr []string
	for _, row := range allRows(r, targetWeb) {
		if row.Kind == RowQR {
			qr = append(qr, row.Text)
		}
	}
	if len(qr) != 1 || qr[0] != id.String() {
		t.Fatalf("QR rows = %d", len(qr))
	}
	bm, err := QRBitmap(qr[0])
	if err != nil || len(bm) < 21 || len(bm) != len(bm[0]) {
		t.Fatalf("QRBitmap: %v, %d", err, len(bm))
	}

	if _, err := NewRecoverySheet(nil, "x", testDate); err == nil {
		t.Error("nil key accepted")
	}
	if _, err := NewRecoverySheet(id, "", testDate); err == nil {
		t.Error("empty vault_id accepted")
	}
}

// TestRecoveryCommandsMatchSpec keeps the printed commands identical to the
// ones in spec.md §8.
func TestRecoveryCommandsMatchSpec(t *testing.T) {
	spec, err := os.ReadFile("../../spec.md")
	if err != nil {
		t.Skip("spec.md not found:", err)
	}
	_, after, ok := strings.Cut(string(spec), "**Without passh**")
	if !ok {
		t.Fatal("no **Without passh** in spec.md")
	}
	_, block, ok := strings.Cut(after, "```bash\n")
	if !ok {
		t.Fatal("no bash block")
	}
	block, _, _ = strings.Cut(block, "```")
	got := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	if !slices.Equal(got, RecoveryCommands) {
		t.Fatalf("spec.md §8 has\n%q\nthe sheet prints\n%q", got, RecoveryCommands)
	}
}

func TestPaperSize(t *testing.T) {
	for in, want := range map[string]PaperSize{"a4": A4, "A4": A4, " Letter ": Letter} {
		if got, err := ParsePaperSize(in); err != nil || got != want {
			t.Errorf("ParsePaperSize(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParsePaperSize("legal"); !errors.Is(err, ErrPaperSize) {
		t.Errorf("legal: %v", err)
	}
}

// --- helpers ---

func writeTXT(t *testing.T, doc Document) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteTXT(&b, doc); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// writePDF writes doc uncompressed, so the text can be searched.
func writePDF(t *testing.T, doc Document, size PaperSize) string {
	t.Helper()
	compress = false
	defer func() { compress = true }()
	var b bytes.Buffer
	if err := WritePDF(&b, doc, size); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// pdfTexts returns the strings shown with Tj in the PDF's (uncompressed)
// page content, decoded from fpdf's UTF-16BE form, one per text operation.
func pdfTexts(t *testing.T, pdf string) []string {
	t.Helper()
	var out []string
	for rest := pdf; ; {
		i := strings.Index(rest, " Td (")
		if i < 0 {
			return out
		}
		rest = rest[i+len(" Td ("):]
		var raw []byte
		j := 0
		for ; j < len(rest) && rest[j] != ')'; j++ {
			c := rest[j]
			if c == '\\' {
				j++
				switch rest[j] {
				case 'r':
					c = '\r'
				default:
					c = rest[j]
				}
			}
			raw = append(raw, c)
		}
		if j == len(rest) || !strings.HasPrefix(rest[j:], ")Tj") || len(raw)%2 != 0 {
			t.Fatalf("unexpected text operation near %q", rest[:min(40, len(rest))])
		}
		u := make([]uint16, len(raw)/2)
		for k := range u {
			u[k] = uint16(raw[2*k])<<8 | uint16(raw[2*k+1])
		}
		out = append(out, string(utf16.Decode(u)))
		rest = rest[j:]
	}
}

// pdfText is all text shown in the PDF, one text operation per line.
func pdfText(t *testing.T, pdf string) string {
	return strings.Join(pdfTexts(t, pdf), "\n")
}

func utf16be(s string) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(s)) {
		b.WriteByte(byte(u >> 8))
		b.WriteByte(byte(u))
	}
	return b.String()
}

// pdfString is s as fpdf writes it in a content stream with a UTF-8 font:
// UTF-16BE, with \ ( ) and CR escaped.
func pdfString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`, "\r", `\r`)
	return r.Replace(utf16be(s))
}

var (
	pageObj   = regexp.MustCompile(`/Type /Page\b[^s]`)
	countRe   = regexp.MustCompile(`/Type /Pages\s*/Kids \[[^\]]*\]\s*/Count (\d+)`)
	startxref = regexp.MustCompile(`startxref\s+(\d+)\s+%%EOF\s*$`)
)

// checkPDF checks the header, the trailer and the cross-reference offset,
// and returns the number of pages, which must agree between the page tree
// and the page objects.
func checkPDF(t *testing.T, pdf string) int {
	t.Helper()
	if !strings.HasPrefix(pdf, "%PDF-1.") {
		t.Fatalf("no PDF header: %q", pdf[:min(20, len(pdf))])
	}
	m := startxref.FindStringSubmatch(pdf)
	if m == nil {
		t.Fatal("no startxref and EOF trailer")
	}
	off, _ := strconv.Atoi(m[1])
	if off <= 0 || off >= len(pdf) || !strings.HasPrefix(pdf[off:], "xref") {
		t.Fatalf("startxref %d doesn't point at the xref table", off)
	}
	if !strings.Contains(pdf, "trailer") || !strings.Contains(pdf, "/Root") {
		t.Fatal("no trailer dictionary")
	}
	c := countRe.FindStringSubmatch(pdf)
	if c == nil {
		t.Fatal("no page tree")
	}
	n, _ := strconv.Atoi(c[1])
	if objs := len(pageObj.FindAllString(pdf, -1)); objs != n {
		t.Fatalf("/Count %d but %d page objects", n, objs)
	}
	return n
}

func TestWebLayout(t *testing.T) {
	s := mustSheet(t, testEntries(), Options{Fields: []string{"password", "fields"}})
	if got := s.Fields(); !slices.Equal(got, []string{"password", "fields"}) {
		t.Errorf("Fields = %q", got)
	}
	var web, txt []Row
	for _, b := range s.Blocks() {
		web = append(web, b.Rows...)
	}
	txt = allRows(s, targetTXT)
	if fmt.Sprint(web) != fmt.Sprint(txt) {
		t.Error("the page's layout differs from the TXT layout")
	}
	r, _ := mustRecovery(t)
	qr := 0
	for _, b := range r.Blocks() {
		for _, row := range b.Rows {
			if row.Kind == RowQR {
				qr++
			}
		}
	}
	if qr != 1 || r.Legend() != nil || r.Title() == s.Title() {
		t.Errorf("recovery layout: %d QR rows", qr)
	}
	one := mustSheet(t, testEntries()[:1], Options{})
	if txt := writeTXT(t, one); !strings.Contains(txt, "· 1 entry\n") {
		t.Error("no singular for one entry")
	}
}
