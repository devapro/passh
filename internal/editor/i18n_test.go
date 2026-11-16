package editor

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/gen"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
)

// TestFormInLanguages: the form's own text is translated; the labels are
// the field names, the same in every language (§4.3).
func TestFormInLanguages(t *testing.T) {
	for _, tc := range []struct {
		lang                                   i18n.Lang
		help, notesHelp, kept, refused, reveal string
		generated, discard, empty              string
	}{
		{
			lang: i18n.Ru, help: "ctrl+s сохранить · esc отменить · tab далее", notesHelp: "enter новая строка",
			kept:      "recovery-email, pin (сохраняются как есть; изменить их можно через --editor)",
			refused:   "вставка отклонена: username — однострочное поле, а в тексте есть переводы строк",
			reveal:    "Пароль показан; он скроется через 10 с (ctrl+r — скрыть сейчас).",
			generated: "Сгенерирован новый пароль (12 символов); он показан.",
			discard:   "Отбросить несохранённые изменения? esc: отбросить", empty: "(пусто)",
		},
		{
			lang: i18n.Sr, help: "ctrl+s sačuvaj · esc otkaži · tab sledeće polje", notesHelp: "enter novi red",
			kept:      "recovery-email, pin (ostaju kakva jesu; izmenite ih pomoću --editor)",
			refused:   "lepljenje je odbijeno: username je polje u jednom redu, a tekst ima prelome redova",
			reveal:    "Lozinka je prikazana; ponovo se skriva za 10 s (ctrl+r je odmah skriva).",
			generated: "Generisana je nova lozinka (12 znakova); prikazana je.",
			discard:   "Odbaciti nesačuvane izmene? esc: odbaci", empty: "(prazno)",
		},
	} {
		t.Run(tc.lang.String(), func(t *testing.T) {
			p := i18n.New(tc.lang)
			rnd := bytes.NewReader(bytes.Repeat([]byte{0, 1, 2, 3}, 16))
			f := NewForm(sampleEntry(t), FormOptions{Title: "edit work/github", Printer: p, Gen: gen.Options{Length: 12, Rand: rnd}})
			f.SetSize(120, 30)
			v := plain(f)
			for _, want := range []string{tc.help, tc.kept, "password  ••••••••", "username  arsenii", "     url  https://github.com", "    tags  work, dev", "   notes  │", "  fields  recovery-email"} {
				if !strings.Contains(v, want) {
					t.Errorf("view lacks %q:\n%s", want, v)
				}
			}
			press(t, f, "tab")
			paste(f, "a\nb")
			if v := plain(f); !strings.Contains(v, tc.refused) {
				t.Errorf("view lacks %q:\n%s", tc.refused, v)
			}
			press(t, f, "ctrl+r")
			if v := plain(f); !strings.Contains(v, tc.reveal) {
				t.Errorf("view lacks %q:\n%s", tc.reveal, v)
			}
			press(t, f, "ctrl+g")
			if v := plain(f); !strings.Contains(v, tc.generated) {
				t.Errorf("view lacks %q:\n%s", tc.generated, v)
			}
			press(t, f, "shift+tab", "shift+tab") // to the notes
			if v := plain(f); !strings.Contains(v, tc.notesHelp) {
				t.Errorf("view lacks %q:\n%s", tc.notesHelp, v)
			}
			press(t, f, "esc")
			if v := plain(f); !strings.Contains(v, tc.discard) {
				t.Errorf("view lacks %q:\n%s", tc.discard, v)
			}
			press(t, f, "esc")
			if _, err := f.Result(); !errors.Is(err, ErrCancelled) {
				t.Fatalf("Result: %v", err)
			}

			empty := NewForm(model.Entry{}, FormOptions{Printer: p})
			if v := plain(empty); !strings.Contains(v, "password   "+tc.empty) { // the cursor, then the placeholder
				t.Errorf("empty password:\n%s", v)
			}
		})
	}
}

func TestEditorErrorsInLanguages(t *testing.T) {
	ru := i18n.New(i18n.Ru)
	_, err := parseText("pw\nusername: a\n\xff")
	pe, ok := errors.AsType[*ParseError](err)
	if !ok || pe.Line != 3 {
		t.Fatalf("parseText = %v", err)
	}
	if got := ru.Error(err); got != "строка 3: текст не является корректным UTF-8" {
		t.Errorf("ParseError in Russian: %q", got)
	}
	if err.Error() != "line 3: the text is not valid UTF-8" {
		t.Errorf("English: %q", err)
	}

	fakeEditors(t)
	ed, err := NewEditor("emacs -nw")
	if err != nil || ed.Kind != KindOther {
		t.Fatalf("NewEditor: %v", err)
	}
	if ed.Warning != ed.WarningMsg.String() || !strings.HasPrefix(ed.Warning, "passh can't control backup, swap or history files of emacs:") {
		t.Errorf("English warning %q", ed.Warning)
	}
	if got := ed.WarningMsg.Localize(i18n.New(i18n.Sr)); !strings.HasPrefix(got, "passh ne može da kontroliše") || !strings.Contains(got, " emacs: ") {
		t.Errorf("Serbian warning %q", got)
	}
	if ed, err := NewEditor("nano"); err != nil || ed.Warning != "" || !ed.WarningMsg.IsZero() {
		t.Errorf("nano: %v %q", err, ed.Warning)
	}
	for l, want := range map[i18n.Lang]string{i18n.Ru: "отменено", i18n.Sr: "otkazano", i18n.En: "cancelled"} {
		if got := i18n.New(l).Error(ErrCancelled); got != want {
			t.Errorf("%s: %q", l, got)
		}
	}
}

// TestFormFieldsListWraps: the list of custom fields wraps under the value
// column by display width, at spaces only (a flag stays whole), instead of
// being cut, in every language; a terminal too low for it gets "…".
func TestFormFieldsListWraps(t *testing.T) {
	e := sampleEntry(t)
	e.Fields = append(e.Fields, model.Field{Key: "security-question", Value: "x"}, model.Field{Key: "pin2", Value: "y"})
	const keys = "recovery-email, pin, security-question, pin2"
	for _, l := range i18n.Langs() {
		p := i18n.New(l)
		want := p.T("%s (kept as they are; edit them with --editor)", keys)
		for _, w := range []int{80, 60} {
			f := NewForm(e, FormOptions{Title: "edit work/github", Printer: p})
			f.SetSize(w, 24)
			lines := strings.Split(plain(f), "\n")
			if len(lines) > 24 {
				t.Errorf("%s %d: %d lines", l, w, len(lines))
			}
			var got []string
			for i, line := range lines {
				if ansi.StringWidth(line) > w {
					t.Errorf("%s %d: line wider than %d: %q", l, w, w, line)
				}
				if rest, ok := strings.CutPrefix(line, "    fields  "); ok {
					got = append(got, rest)
					for _, next := range lines[i+1:] {
						cont, ok := strings.CutPrefix(next, strings.Repeat(" ", prefixWidth))
						if !ok || cont == "" || strings.HasPrefix(cont, " ") {
							break
						}
						got = append(got, cont)
					}
				}
			}
			if strings.Join(got, " ") != want || len(got) < 2 {
				t.Errorf("%s %d: fields lines %q, want %q wrapped", l, w, got, want)
			}
			for _, g := range got {
				if strings.HasSuffix(g, "-") || strings.HasPrefix(g, "-editor") {
					t.Errorf("%s %d: a word was split: %q", l, w, got)
				}
			}
		}

		// No room: at most what the height leaves, the cut marked.
		f := NewForm(e, FormOptions{Title: "edit work/github", Printer: p})
		f.SetSize(30, 12)
		v := plain(f)
		if n := len(strings.Split(v, "\n")); n > 12 {
			t.Errorf("%s 30x12: %d lines", l, n)
		}
		if !regexp.MustCompile(`(?m)^ {4}fields  .*\n( {12}.*\n)*? {12}\S.*…$`).MatchString(v) {
			t.Errorf("%s 30x12: the cut list isn't marked:\n%s", l, v)
		}
	}

	// English with a short list stays on one line, as before.
	f := NewForm(sampleEntry(t), FormOptions{})
	if v := plain(f); !strings.Contains(v, "\n    fields  recovery-email, pin (kept as they are; edit them with --editor)\n") {
		t.Errorf("English fields line:\n%s", v)
	}
}
